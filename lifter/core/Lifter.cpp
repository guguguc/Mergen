
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#endif

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
#include <llvm/Support/NativeFormatting.h>
#include <magic_enum/magic_enum.hpp>

#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#endif

// #define TEST

#ifdef _WIN32
namespace {

volatile LONG g_crashHandlerActive = 0;
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




bool InitFunction_and_LiftInstructions(const uint64_t runtime_address,
                                       std::vector<uint8_t>&& fileData,
                                       const std::vector<uint64_t>& outlineAddresses) {
  std::string stageError;
  auto stageContext =
      prepareLifterStageContext(runtime_address, fileData, stageError);
  if (!stageContext.has_value()) {
    std::cerr << stageError << std::endl;
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
  installCrashHandler();
#endif
  std::vector<std::string> rawArgs(argv, argv + argc);
#ifdef MERGEN_TEST
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

  if (parseResult.concretizeUnsafeReads) {
    std::cerr << "Option '--concretize-unsafe-reads' is recognized but "
                 "not implemented yet."
              << std::endl;
    return 1;
  }

  std::vector<std::string> args = std::move(parseResult.positionalArgs);
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

  const std::string suiteFilter = args.size() > 1 ? args[1] : "";
  return testInit(suiteFilter);
#endif
  const auto& outlineAddrs = parseResult.outlineAddresses;
  return runLifterApplication(args,
      [&outlineAddrs](uint64_t runtime_address, std::vector<uint8_t>&& fileData) {
        return InitFunction_and_LiftInstructions(runtime_address,
                                                  std::move(fileData), outlineAddrs);
      });
}
