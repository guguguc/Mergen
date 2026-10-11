#include "Utils.h"
#include "llvm/IR/Value.h"
#include <cctype>
#include <chrono>
#include <iostream>
#include <sstream>
#include <llvm/Analysis/ValueLattice.h>
#include <llvm/Support/KnownBits.h>
#include <map>
#include <utility>
// #include <z3++.h>

#ifdef _WIN32
// winternl.h, for RTL_OSVERSIONINFOW. It does not declare RtlGetVersion itself,
// and it is not safe to include from a header this widely included, so the
// signature is spelled out here. It is a documented, stable ntdll export
// (the unversioned alternative to the shimmed GetVersionEx).
#include <windows.h>
#include <winternl.h>

using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
#endif

/*


float intBitsToFloat(int bits) {
    // Extract components from the int using IEEE 754 single precision format
    int sign = (bits >> 31) & 0x1;
    int exponent = (bits >> 23) & 0xFF;
    int mantissa = bits & 0x7FFFFF;

    // Build float value according to IEEE 754 formula
    float value = 0;
    if (exponent == 0) {
        if (mantissa == 0) {
            value = sign ? -0.0f : 0.0f;
        } else {
            // Denormalized number
            value = (sign ? -1.0f : 1.0f) * (mantissa / (float)(1 << 23)) *
powf(2.0f, -126);
        }
    } else if (exponent == 0xFF) {
        if (mantissa == 0) {
            value = sign ? -INFINITY : INFINITY;
        } else {
            value = NAN;
        }
    } else {
        // Normalized number
        value = (sign ? -1.0f : 1.0f) * (1.0f + mantissa / (float)(1 << 23)) *
powf(2.0f, exponent - 127);
    }

    return value;
}
int floatBitsToInt(float f) {
    if (f == 0.0f) {
        return (std::signbit(f) ? 0x80000000 : 0);
    }

    if (std::isinf(f)) {
        return (f < 0 ? 0xFF800000 : 0x7F800000);
    }

    if (std::isnan(f)) {
        return 0x7FC00000;  // One common NaN pattern
    }

    int sign = std::signbit(f) ? 1 : 0;
    float abs_f = std::fabs(f);

    int exponent = std::ilogbf(abs_f) + 127;  // Get biased exponent

    // Handle denormals
    if (exponent <= 0) {
        float mantissa_f = abs_f * powf(2.0f, 149);  // 126 + 23
        int mantissa = (int)mantissa_f;
        return (sign << 31) | mantissa;
    }

    // Extract mantissa (23 bits of precision)
    float mantissa_f = (abs_f / powf(2.0f, std::ilogbf(abs_f)) - 1.0f) *
(float)(1 << 23); int mantissa = (int)mantissa_f;

    return (sign << 31) | (exponent << 23) | mantissa;
}

*/

// Debug output plumbing.
//
// Every diagnostic in the lifter routes through doIfDebug, which reads
// shouldDebug first. That single gate is what lets the printvalue* family stay
// inline in the semantics handlers: when debugging is off the cost is one
// branch, and when it is on the output lands wherever enableDebug pointed
// debugStream (a file, or stdout).
namespace debugging {
  // Monotonic instruction counter. Used by printvalue2 to distinguish two
  // values printed from the same source line, and by the diag dumps to
  // correlate an IR value with the instruction that produced it.
  int ic = 1;
  int increaseInstCounter() { return ++ic; }
  bool shouldDebug = false;
  llvm::raw_ostream* debugStream = nullptr;
  // unique_ptr rather than a bare stream: the file must outlive every
  // debugStream reference, and it owns a file handle.
  std::unique_ptr<llvm::raw_fd_ostream> fileStream;

  // Enabling debug output is not best-effort. If the requested file cannot be
  // opened, the function reports the error, falls back to stderr, and turns
  // debugging back off. Silently debugging to stdout instead would bury the
  // lifter's own output, and silently leaving debugging on with a null stream
  // would crash on first use.
  void enableDebug(const std::string& filename = "") {
    shouldDebug = true;
    if (!filename.empty()) {
      std::error_code EC;
      fileStream = std::make_unique<llvm::raw_fd_ostream>(filename, EC);
      if (EC) {
        llvm::errs() << "Error opening debug file: " << EC.message() << "\n";
        fileStream.reset();
        debugStream = &llvm::errs();
        shouldDebug = false;
        return;
      }
      debugStream = fileStream.get();
    } else {
      debugStream = &llvm::outs();
    }
    llvm::outs() << "Debugging enabled\n";
  }

  // Accepting a std::function rather than a template keeps the call sites free
  // of lambda boilerplate, and these are not hot enough for that to matter.
  // The check is on shouldDebug alone -- debugStream is guaranteed non-null
  // whenever shouldDebug is true, because enableDebug guarantees it.
  void doIfDebug(const std::function<void(void)>& dothis) {
    if (!shouldDebug)
      return;
    (dothis)();
  }

} // namespace debugging

namespace argparser {
namespace {
bool isOptionToken(const std::string& arg) {
  return !arg.empty() && arg.front() == '-';
}

std::string toUpperAscii(std::string value) {
  for (char& ch : value) {
    ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
  }
  return value;
}

// Map any spelling of a GPR onto its canonical 64-bit name.
//
// This exists because --reg must accept what an analyst actually types. The
// backends disagree about sub-registers -- one may call the 8-bit view of RSP
// "SPL" and the other "R8PL" -- and the lift loop compares against a single
// canonical name. Normalising here keeps that disagreement out of every
// register comparison downstream.
//
// Uppercased first so the lookup is case-insensitive without needing a
// lowercase duplicate of every entry.
std::string canonicalizeGpr64(std::string name) {
  name = toUpperAscii(std::move(name));
  if (name == "AL" || name == "AH" || name == "AX" || name == "EAX" ||
      name == "RAX")
    return "RAX";
  if (name == "CL" || name == "CH" || name == "CX" || name == "ECX" ||
      name == "RCX")
    return "RCX";
  if (name == "DL" || name == "DH" || name == "DX" || name == "EDX" ||
      name == "RDX")
    return "RDX";
  if (name == "BL" || name == "BH" || name == "BX" || name == "EBX" ||
      name == "RBX")
    return "RBX";
  if (name == "SPL" || name == "SP" || name == "ESP" || name == "RSP")
    return "RSP";
  if (name == "BPL" || name == "BP" || name == "EBP" || name == "RBP")
    return "RBP";
  if (name == "SIL" || name == "SI" || name == "ESI" || name == "RSI")
    return "RSI";
  if (name == "DIL" || name == "DI" || name == "EDI" || name == "RDI")
    return "RDI";
  if (name == "R8B" || name == "R8W" || name == "R8D" || name == "R8")
    return "R8";
  if (name == "R9B" || name == "R9W" || name == "R9D" || name == "R9")
    return "R9";
  if (name == "R10B" || name == "R10W" || name == "R10D" || name == "R10")
    return "R10";
  if (name == "R11B" || name == "R11W" || name == "R11D" || name == "R11")
    return "R11";
  if (name == "R12B" || name == "R12W" || name == "R12D" || name == "R12")
    return "R12";
  if (name == "R13B" || name == "R13W" || name == "R13D" || name == "R13")
    return "R13";
  if (name == "R14B" || name == "R14W" || name == "R14D" || name == "R14")
    return "R14";
  if (name == "R15B" || name == "R15W" || name == "R15D" || name == "R15")
    return "R15";
  return name;
}

// Parse --reg into entryRegs.
//
// Errors are accumulated rather than thrown: one bad spec on a command line
// that supplies five should report all five, not just the first. Empty tokens
// are skipped so a trailing comma is harmless.
void parseEntryRegSpecs(const std::string& value, ParseResult& result) {
  std::istringstream stream(value);
  std::string token;
  while (std::getline(stream, token, ',')) {
    if (token.empty())
      continue;
    // Reject a malformed spec before the '=' is located: eq == npos means no
    // separator at all, eq == 0 an empty name, and eq + 1 == size an empty
    // value. Each would otherwise reach stoull or the register table and fail
    // somewhere much less obvious.
    const auto eq = token.find('=');
    if (eq == std::string::npos || eq == 0 || eq + 1 == token.size()) {
      result.errors.push_back("Invalid --reg spec: " + token);
      continue;
    }
    const std::string name = canonicalizeGpr64(token.substr(0, eq));
    const std::string imm = token.substr(eq + 1);
    // Base 0 so immediates accept decimal and 0x-hex alike -- addresses on a
    // command line are overwhelmingly quoted in hex. std::stoull throws on a
    // non-numeric string, which is the reliable failure signal here (unlike
    // strtoull, which reports 0).
    try {
      result.entryRegs.emplace_back(name, std::stoull(imm, nullptr, 0));
    } catch (const std::exception&) {
      result.errors.push_back("Invalid --reg immediate: " + token);
    }
  }
}
} // namespace

void printHelp() {
  std::cerr << "Options:\n"
            << "  -d, --enable-debug        Enable debugging mode\n"
            << "  -h, --help                Display this help message\n"
            << "  --concretize-unsafe-reads Concretizes potentially unsafe "
               "reads to writable sections\n"
            << "  --outline <addrs>         Comma-separated addresses to outline (not inline)\n"
            << "  --mem-dump <file>         Process RW snapshot at the lift RVA\n"
            << "  --reg <name>=<imm>        Concretize a GPR at lift entry after InitRegisters\n"
            << "                            (repeatable; rcx/ecx map to RCX)\n"
            << "  --                        Stop option parsing\n";
}

// Command-line parsing.
//
// Every option accepts both spellings: "--opt value" and "--opt=value". That
// is a deliberate choice -- scripts and CI invocations are written both ways
// and refusing one of them produces a confusing "unknown option" rather than
// an obvious usage error.
//
// Parsing is non-fatal throughout. Errors accumulate into ParseResult::errors
// and parsing continues, so one bad argument does not hide the rest, and the
// caller decides what to do with the result (main prints them all and exits).
ParseResult parseArguments(const std::vector<std::string>& args,
                           bool allowUnknownOptions) {
  ParseResult result;
  if (args.empty()) {
    return result;
  }

  // argv[0] is preserved as the first positional so downstream code can treat
  // the whole vector uniformly.
  result.positionalArgs.reserve(args.size());
  result.positionalArgs.push_back(args.front());

  bool parsingOptions = true;
  for (size_t index = 1; index < args.size(); ++index) {
    const auto& arg = args[index];

    // "--" ends option parsing. Everything after it is positional, which is the
    // standard escape hatch and matters here because the file argument can
    // legitimately look like an option on some platforms.
    if (parsingOptions && arg == "--") {
      parsingOptions = false;
      continue;
    }

    if (parsingOptions) {
      if (arg == "-h" || arg == "--help") {
        result.showHelp = true;
        continue;
      }
      if (arg == "-d" || arg == "--enable-debug") {
        result.enableDebug = true;
        continue;
      }
      if (arg == "--concretize-unsafe-reads") {
        result.concretizeUnsafeReads = true;
        continue;
      }
      // --outline feeds InlinePolicy's outline set. The `rfind(..., 0) == 0`
      // form is a prefix test: it matches "--outline=" at the start without
      // allocating a substring first.
      if (arg == "--outline" || arg.rfind("--outline=", 0) == 0) {
        std::string value;
        if (arg.rfind("--outline=", 0) == 0) {
          // substr(10) skips "--outline=", the opening quote's worth of
          // characters. The empty check matters because getline on an empty
          // stream produces nothing, and the result would be an empty address
          // list with no error at all.
          value = arg.substr(10);
          if (value.empty()) {
            result.errors.push_back("--outline= requires a value after '='");
            continue;
          }
        } else if (index + 1 < args.size()) {
          // Consume the next argv entry. ++index here is why the loop
          // variable is declared outside the condition.
          value = args[++index];
        } else {
          result.errors.push_back("--outline requires an argument");
          continue;
        }
        // Comma-separated, empty tokens skipped so a trailing comma is harmless.
        // Same base-0 / accumulate-don't-throw policy as parseEntryRegSpecs.
        std::istringstream stream(value);
        std::string token;
        while (std::getline(stream, token, ',')) {
          if (token.empty()) continue;
          try {
            result.outlineAddresses.push_back(std::stoull(token, nullptr, 0));
          } catch (const std::exception&) {
            result.errors.push_back("Invalid outline address: " + token);
          }
        }
        continue;
      }
      if (arg == "--mem-dump" || arg.rfind("--mem-dump=", 0) == 0) {
        std::string value;
        if (arg.rfind("--mem-dump=", 0) == 0) {
          value = arg.substr(11);
          if (value.empty()) {
            result.errors.push_back("--mem-dump= requires a value after '='");
            continue;
          }
        } else if (index + 1 < args.size()) {
          value = args[++index];
        } else {
          result.errors.push_back("--mem-dump requires an argument");
          continue;
        }
        result.memDumpPath = value;
        continue;
      }
      if (arg == "--reg" || arg.rfind("--reg=", 0) == 0) {
        std::string value;
        if (arg.rfind("--reg=", 0) == 0) {
          value = arg.substr(6);
          if (value.empty()) {
            result.errors.push_back("--reg= requires a value after '='");
            continue;
          }
        } else if (index + 1 < args.size()) {
          value = args[++index];
        } else {
          result.errors.push_back("--reg requires an argument");
          continue;
        }
        // --reg is repeatable, so parseEntryRegSpecs appends rather than assigns.
        parseEntryRegSpecs(value, result);
        continue;
      }

      // An unrecognised option. The test binary sets allowUnknownOptions so
      // harnesses can pass through flags meant for the in-process test runner
      // rather than the lifter; the production binary treats it as an error.
      if (isOptionToken(arg)) {
        if (allowUnknownOptions) {
          result.positionalArgs.push_back(arg);
        } else {
          result.errors.push_back("Unknown option: " + arg);
        }
        continue;
      }
    }

    result.positionalArgs.push_back(arg);
  }

  return result;
}

} // namespace argparser

// Process-wide stopwatch, not a scoped timer. It measures from wherever
// startTimer was called -- during CLI parsing, before the lift begins -- to
// wherever stopTimer is called, so the figure it reports is total wall time
// for the run rather than time spent in any particular phase. For per-stage
// timings use PipelineProfiler, which is what the diagnostics JSON carries.
namespace timer {
  using clock = std::chrono::high_resolution_clock;
  using time_point = std::chrono::time_point<clock>;
  // Milliseconds as a double rather than an integer count: the per-stage
  // callers in LifterPipelineStages pass the result straight to the profiler,
  // which accumulates it.
  using duration = std::chrono::duration<double, std::milli>;

  time_point startTime;
  bool running = false;

  void startTimer() {
    startTime = clock::now();
    running = true;
  }

  // Both accessors return 0.0 rather than a huge or negative number when the
  // timer was never started. That keeps a missing startTimer from producing a
  // nonsensical duration in the output rather than a clearly wrong one.
  double getTimer() {
    if (running) {
      return std::chrono::duration_cast<duration>(clock::now() - startTime)
          .count();
    }
    return 0.0;
  }

  // Idempotent: a second stopTimer returns 0.0 rather than re-measuring, so a
  // caller that stops "just in case" cannot inflate or corrupt the total.
  double stopTimer() {
    if (running) {
      running = false;
      return std::chrono::duration_cast<duration>(clock::now() - startTime)
          .count();
    }
    return 0.0;
  }

  void resetTimer() {
    startTime = clock::now();
    running = true;
  }
} // namespace timer
namespace {
  unsigned long long g_memEventSeq = 0;
}

unsigned long long nextMemEventSeq() {
  return ++g_memEventSeq;
}

uint64_t queryHostOsBuildNumber() {
#ifdef _WIN32
  // Cached: the answer cannot change under a running process, and this sits on
  // the lifter setup path.
  static const uint64_t cached = []() -> uint64_t {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
      return uint64_t{0};
    }
    auto rtlGetVersion = reinterpret_cast<RtlGetVersionFn>(
        GetProcAddress(ntdll, "RtlGetVersion"));
    if (rtlGetVersion == nullptr) {
      return uint64_t{0};
    }
    RTL_OSVERSIONINFOW info{};
    info.dwOSVersionInfoSize = sizeof(info);
    if (rtlGetVersion(&info) != 0 /* STATUS_SUCCESS */) {
      return uint64_t{0};
    }
    return static_cast<uint64_t>(info.dwBuildNumber);
  }();
  return cached;
#else
  return 0;
#endif
}
