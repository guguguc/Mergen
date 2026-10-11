
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#endif

// magic_enum's range is a compile-time contract that must be fixed before the
// header is seen, hence these defines ahead of every include. The -1000..1000
// window exists because the lift synthesises magic_enum values (folders,
// diagnostics kinds) that are not real enum members but still need name
// conversion.
#define MAGIC_ENUM_RANGE_MIN -1000
#define MAGIC_ENUM_RANGE_MAX 1000

#include "CommandLineHelpers.hpp"
#include "LifterApplication.hpp"
#include "LifterPipeline.hpp"
#include "LifterStages.hpp"
#include "MergenPB.hpp"
#include "Includes.h"
#include "LifterClass.hpp"
#include "LifterClass_Concolic.hpp"
#include "LifterClass_Symbolic.hpp"


#include "TestInstructions.h"
#include "Semantics.ipp"
#include "Utils.h"
#include <cstdlib>
#include <coff/line_number.hpp>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <llvm/ADT/STLExtras.h>
#include <llvm/Analysis/InstSimplifyFolder.h>
#include <llvm/Analysis/LazyCallGraph.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/IRBuilderFolder.h>
#include <llvm/IR/Constants.h>
#include <llvm/Support/NativeFormatting.h>
#include <magic_enum/magic_enum.hpp>

#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#endif

// #define TEST

// Windows-only crash reporting, installed before anything else runs.
//
// A lift can take minutes on a VM-protected sample and can fault deep inside
// an LLVM pass or a backend instruction decoder. Without this, a fault is an
// anonymous dialog and the run is lost. The handler writes crash.txt (a
// symbolised stack trace) and crash.dmp (a full minidump) before letting the
// crash propagate.
//
// Everything here is _WIN32-guarded because the lifter's primary build lane is
// windows-latest; there is no equivalent path for other hosts, which do not
// install this at all rather than installing a stub.

#ifdef _WIN32
namespace {

// Reentrancy guard. The handler itself allocates (ostringstream, std::string,
// ofstream), so a fault *inside* the handler would re-enter it and recurse
// until the stack overflowed -- replacing one useful crash report with a
// useless one. The interlocked exchange makes the second entry a no-op.
//
// volatile LONG with InterlockedExchange rather than std::atomic: this runs
// from an exception filter where the C++ runtime's guarantees do not
// obviously hold, and the Win32 primitive is the honest choice.
volatile LONG g_crashHandlerActive = 0;

// Bound on stack-walk depth. StackWalk64 can walk a long way on a recursive
// or corrupted stack; the cap keeps the handler itself from running out of
// stack while trying to report that the stack was the problem.
constexpr int kMaxCrashFrames = 96;

std::string hexAddr(uint64_t value) {
  std::ostringstream os;
  os << "0x" << std::hex << value;
  return os.str();
}

bool writeMinidump(EXCEPTION_POINTERS* exceptionInfo) {
  HANDLE file = CreateFileA("crash.dmp", GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }
  MINIDUMP_EXCEPTION_INFORMATION info{};
  info.ThreadId = GetCurrentThreadId();
  info.ExceptionPointers = exceptionInfo;
  info.ClientPointers = FALSE;
  const BOOL ok = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(),
                                    file, MiniDumpNormal, &info, nullptr,
                                    nullptr);
  CloseHandle(file);
  return ok == TRUE;
}

// Interpret the first ExceptionInformation word of an access violation.
// These are the documented IMAGE_*_FAULTING / EXCEPTION_*_FAULTING values;
// the default arm covers the codes that are not memory faults at all.
const char* accessKind(ULONG_PTR kind) {
  switch (kind) {
    case 0:
      return "read";
    case 1:
      return "write";
    case 8:
      return "execute";
    default:
      return "unknown";
  }
}

// Dump every GPR. A lift fault is nearly always about one register holding a
// bad pointer, and having all sixteen on one line is what makes the report
// worth reading without re-running under a debugger.
void logRegistryState(std::ofstream& out, PCONTEXT ctx) {
  out << "  RIP=" << hexAddr(ctx->Rip) << " RSP=" << hexAddr(ctx->Rsp)
      << " RBP=" << hexAddr(ctx->Rbp) << "\n";
  out << "  RAX=" << hexAddr(ctx->Rax) << " RBX=" << hexAddr(ctx->Rbx)
      << " RCX=" << hexAddr(ctx->Rcx) << " RDX=" << hexAddr(ctx->Rdx) << "\n";
  out << "  RSI=" << hexAddr(ctx->Rsi) << " RDI=" << hexAddr(ctx->Rdi)
      << " R8=" << hexAddr(ctx->R8) << " R9=" << hexAddr(ctx->R9) << "\n";
  out << "  R10=" << hexAddr(ctx->R10) << " R11=" << hexAddr(ctx->R11)
      << " R12=" << hexAddr(ctx->R12) << " R13=" << hexAddr(ctx->R13) << "\n";
  out << "  R14=" << hexAddr(ctx->R14) << " R15=" << hexAddr(ctx->R15) << "\n";
}

// Symbolised stack trace via dbghelp.
//
// UNDNAME expands decorated C++ names, DEFERRED_LOADS avoids paying symbol
// load cost for modules that are never touched, LOAD_LINES adds file:line.
// The SYMBOL_INFO buffer is over-allocated by 512 because SYMBOL_INFO requires
// MaxNameLen bytes of name storage to follow the fixed header, and MaxNameLen
// excludes the terminator.
void logStackTrace(std::ofstream& out, HANDLE process, HANDLE thread,
                   PCONTEXT ctx) {
  STACKFRAME64 frame{};
  frame.AddrPC.Offset = ctx->Rip;
  frame.AddrPC.Mode = AddrModeFlat;
  frame.AddrFrame.Offset = ctx->Rbp;
  frame.AddrFrame.Mode = AddrModeFlat;
  frame.AddrStack.Offset = ctx->Rsp;
  frame.AddrStack.Mode = AddrModeFlat;

  CONTEXT walkContext = *ctx;
  for (int i = 0; i < kMaxCrashFrames; ++i) {
    if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, process, thread, &frame,
                     &walkContext, nullptr, SymFunctionTableAccess64,
                     SymGetModuleBase64, nullptr)) {
      break;
    }
    const DWORD64 address = frame.AddrPC.Offset;
    if (address == 0) {
      break;
    }

    std::vector<char> symbolBuffer(sizeof(SYMBOL_INFO) + 512);
    auto* symbol = reinterpret_cast<SYMBOL_INFO*>(symbolBuffer.data());
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = 511;
    DWORD64 displacement = 0;
    std::string symbolText = "?";
    if (SymFromAddr(process, address, &displacement, symbol)) {
      symbolText = symbol->Name;
      if (displacement != 0) {
        std::ostringstream os;
        os << "+0x" << std::hex << displacement;
        symbolText += os.str();
      }
    }

    std::string location;
    IMAGEHLP_LINE64 line{};
    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    DWORD lineDisplacement = 0;
    if (SymGetLineFromAddr64(process, address, &lineDisplacement, &line)) {
      location = std::string(line.FileName) + ":" +
                 std::to_string(line.LineNumber);
    }

    out << "  #" << i << " " << hexAddr(address) << " " << symbolText;
    if (!location.empty()) {
      out << "  [" << location << "]";
    }
    out << "\n";
  }
}

}  // namespace

// Install the unhandled-exception filter. Windows-only; a no-op elsewhere.
void installCrashHandler() {
  SetUnhandledExceptionFilter([](EXCEPTION_POINTERS* exceptionInfo) -> LONG {
    if (InterlockedExchange(&g_crashHandlerActive, 1) != 0) {
      return EXCEPTION_EXECUTE_HANDLER;
    }

    HANDLE process = GetCurrentProcess();
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    SymInitialize(process, nullptr, TRUE);

    std::ofstream out("crash.txt");
    const EXCEPTION_RECORD& record = *exceptionInfo->ExceptionRecord;
    out << "=== Mergen crash ===\n";
    out << "code=" << hexAddr(record.ExceptionCode) << " address="
        << hexAddr(reinterpret_cast<uint64_t>(record.ExceptionAddress)) << "\n";
    if (record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        record.NumberParameters >= 2) {
      out << "access=" << accessKind(record.ExceptionInformation[0])
          << " at " << hexAddr(record.ExceptionInformation[1]) << "\n";
    }
    logRegistryState(out, exceptionInfo->ContextRecord);
    out << "--- stack ---\n";
    logStackTrace(out, process, GetCurrentThread(), exceptionInfo->ContextRecord);
    out << "minidump="
        << (writeMinidump(exceptionInfo) ? "crash.dmp" : "unavailable") << "\n";
    out.flush();

    const std::string message =
        "!!! Mergen crashed - see crash.txt / crash.dmp (signal " +
        hexAddr(record.ExceptionCode) + ")\n";
    DWORD written = 0;
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), message.data(),
              static_cast<DWORD>(message.size()), &written, nullptr);
    return EXCEPTION_EXECUTE_HANDLER;
  });
}
#endif




// Apply --reg overrides after InitRegisters.
//
// The register name type is backend-dependent, so which enum to parse against
// depends on whether the iced lane or the Zydis fallback lane was built. The
// conditional alias is the only place the two backends are distinguished at
// this level; everything below is backend-agnostic.
//
// Parsing by name through magic_enum rather than by index means the CLI
// surface stays stable when the backend's register enum is reordered, which
// both backends do freely between releases. An unknown name is a hard failure
// rather than a skipped line: silently ignoring it would lift from the wrong
// initial state and produce confidently wrong IR.
bool applyEntryRegisterSeeds(
    lifterConcolic<>* lifter,
    const std::vector<std::pair<std::string, uint64_t>>& entryRegs) {
#ifdef ICED_FOUND
  using EntryRegister = Mergen::IcedRegister;
#else
  using EntryRegister = Mergen::ZydisRegister;
#endif
  for (const auto& [name, value] : entryRegs) {
    const auto parsed = magic_enum::enum_cast<EntryRegister>(name);
    if (!parsed.has_value()) {
      std::cerr << "Unknown --reg name: " << name << std::endl;
      return false;
    }
    auto* ci = llvm::ConstantInt::get(lifter->builder->getInt64Ty(), value);
    lifter->SetRegisterValue(*parsed, ci);
    std::cerr << "[entry-reg] " << name << "=0x" << std::hex << value
              << std::dec << "\n";
  }
  return true;
}

// Run the full pipeline for one start address. Returns whether the lift
// produced no errors.
//
// Note what "success" means: the pipeline returning diagnostics with errors is
// treated as failure even though output.ll was written. That is deliberate --
// a partial lift that mislifted a block must not be reported as a clean run
// to an automated regression gate.
bool InitFunction_and_LiftInstructions(const uint64_t runtime_address,
                                       std::vector<uint8_t>&& fileData,
                                       const std::vector<uint64_t>& outlineAddresses,
                                       const std::string& memDumpPath,
                                       const std::vector<std::pair<std::string, uint64_t>>& entryRegs) {
  std::string stageError;
  auto stageContext =
      prepareLifterStageContext(runtime_address, fileData, stageError,
                                memDumpPath);
  if (!stageContext.has_value()) {
    std::cerr << stageError << std::endl;
    return false;
  }

  if (!applyEntryRegisterSeeds(stageContext->lifter.get(), entryRegs)) {
    return false;
  }

  for (const auto addr : outlineAddresses) {
    stageContext->lifter->inlinePolicy.addAddress(addr);
  }

  runLifterPipeline(stageContext->lifter.get(), stageContext->runtimeContext,
                    fileData.data(), fileData);
  return !stageContext->lifter->diagnostics.hasErrors();
}

// #define TEST
int main(int argc, char* argv[]) {
#ifdef _WIN32
  // Before anything else: if argument parsing itself faults, there is still a
  // handler to report it.
  installCrashHandler();
#endif
  std::vector<std::string> rawArgs(argv, argv + argc);
#ifdef MERGEN_TEST
  // The test binary accepts options the production binary rejects, so that
  // harnesses can pass through flags meant for the in-process test runner.
  constexpr bool allowUnknownOptions = true;
#else
  constexpr bool allowUnknownOptions = false;
#endif
  auto parseResult = argparser::parseArguments(rawArgs, allowUnknownOptions);

  if (!parseResult.ok()) {
    for (const auto& error : parseResult.errors) {
      std::cerr << error << std::endl;
    }
    argparser::printHelp();
    return 1;
  }

  if (parseResult.showHelp) {
    argparser::printHelp();
    return 0;
  }

  if (parseResult.enableDebug) {
    debugging::enableDebug("debug.txt");
  }

  // Declared-but-unimplemented options are rejected explicitly rather than
  // accepted and ignored. Silently ignoring --concretize-unsafe-reads would
  // produce IR that is wrong in exactly the way the flag was meant to fix,
  // and the user would have no reason to look.
  if (parseResult.concretizeUnsafeReads) {
    std::cerr << "Option '--concretize-unsafe-reads' is recognized but "
                 "not implemented yet."
              << std::endl;
    return 1;
  }

  std::vector<std::string> args = std::move(parseResult.positionalArgs);
  // Started after argument parsing and option validation, so the reported
  // elapsed time reflects lifting work rather than startup.
  timer::startTimer();

#ifdef MERGEN_TEST
  if (args.size() > 1 &&
      (args[1] == "--build-full-seed" || args[1] == "build-full-seed")) {
    const std::string outputPath =
        args.size() > 2 ? args[2] : "scripts/rewrite/oracle_seed_full_handlers.json";
    uint64_t maxAttempts = 2'500'000;
    uint64_t randomSeed = 1337;
    try {
      if (args.size() > 3) {
        maxAttempts = std::stoull(args[3], nullptr, 0);
      }
      if (args.size() > 4) {
        randomSeed = std::stoull(args[4], nullptr, 0);
      }
    } catch (const std::exception& ex) {
      std::cerr << "Invalid build-full-seed numeric arguments: " << ex.what()
                << std::endl;
      return 1;
    }

    return buildFullHandlerSeed(outputPath, "lifter/semantics/x86_64_opcodes.x",
                                maxAttempts, randomSeed);
  }

  // MERGEN_TEST builds a *different* binary: same sources, but main dispatches
  // to the in-process instruction/oracle harness instead of lifting a file.
  // The two modes are mutually exclusive below, which is why this return path
  // does not fall through to the production flow.
  const std::string suiteFilter = args.size() > 1 ? args[1] : "";
  return testInit(suiteFilter);
#endif
  const auto& outlineAddrs = parseResult.outlineAddresses;
  const auto& entryRegs = parseResult.entryRegs;

  // --mem-dump path, falling back to the environment variable so CI and
  // scripts do not have to thread the flag through every invocation.
  std::string memDumpPath = parseResult.memDumpPath;
  if (memDumpPath.empty()) {
    if (const char* env = std::getenv("MERGEN_MEM_DUMP")) {
      memDumpPath = env;
    }
  }

  // The lambda captures by reference on purpose: outlineAddrs and entryRegs
  // are views into parseResult, which outlives this call, so copying them
  // would only duplicate potentially large vectors.
  return runLifterApplication(args,
      [&outlineAddrs, &entryRegs, memDumpPath](uint64_t runtime_address,
                                   std::vector<uint8_t>&& fileData) {
        return InitFunction_and_LiftInstructions(runtime_address,
                                                  std::move(fileData),
                                                  outlineAddrs, memDumpPath,
                                                  entryRegs);
      });
}
