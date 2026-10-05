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

namespace debugging {
  int ic = 1;
  int increaseInstCounter() { return ++ic; }
  bool shouldDebug = false;
  llvm::raw_ostream* debugStream = nullptr;
  std::unique_ptr<llvm::raw_fd_ostream> fileStream;

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

  // Other functions remain the same, but use debugStream instead of
  // llvm::outs() For example:

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

void parseEntryRegSpecs(const std::string& value, ParseResult& result) {
  std::istringstream stream(value);
  std::string token;
  while (std::getline(stream, token, ',')) {
    if (token.empty())
      continue;
    const auto eq = token.find('=');
    if (eq == std::string::npos || eq == 0 || eq + 1 == token.size()) {
      result.errors.push_back("Invalid --reg spec: " + token);
      continue;
    }
    const std::string name = canonicalizeGpr64(token.substr(0, eq));
    const std::string imm = token.substr(eq + 1);
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

ParseResult parseArguments(const std::vector<std::string>& args,
                           bool allowUnknownOptions) {
  ParseResult result;
  if (args.empty()) {
    return result;
  }

  result.positionalArgs.reserve(args.size());
  result.positionalArgs.push_back(args.front());

  bool parsingOptions = true;
  for (size_t index = 1; index < args.size(); ++index) {
    const auto& arg = args[index];

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
      if (arg == "--outline" || arg.rfind("--outline=", 0) == 0) {
        std::string value;
        if (arg.rfind("--outline=", 0) == 0) {
          value = arg.substr(10);
          if (value.empty()) {
            result.errors.push_back("--outline= requires a value after '='");
            continue;
          }
        } else if (index + 1 < args.size()) {
          value = args[++index];
        } else {
          result.errors.push_back("--outline requires an argument");
          continue;
        }
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
        parseEntryRegSpecs(value, result);
        continue;
      }

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

namespace timer {
  using clock = std::chrono::high_resolution_clock;
  using time_point = std::chrono::time_point<clock>;
  using duration = std::chrono::duration<double, std::milli>;

  time_point startTime;
  bool running = false;

  void startTimer() {
    startTime = clock::now();
    running = true;
  }

  double getTimer() {
    if (running) {
      return std::chrono::duration_cast<duration>(clock::now() - startTime)
          .count();
    }
    return 0.0;
  }

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
