#ifndef FUNCSIGNATURES_H
#define FUNCSIGNATURES_H

// Recognises well-known library functions in a PE by their prologue bytes, so
// the lifter can give them a real signature instead of guessing.
//
// Why bother: the lift loop is ABI-aware. When it hits a call it has to know
// which registers are arguments, which are caller-saved, and what the return
// convention is. For an unknown function it has to assume the worst and the
// surrounding code stays symbolic. Matching a prologue such as
// `swprintf_s`'s against the image converts an opaque call into a typed one,
// and that difference propagates all the way into whether the caller's
// concrete walk survives.
//
// Search is Aho-Corasick rather than a per-pattern scan: the signature table
// grows with the number of recognised functions, and a single automaton pass
// over the image stays O(1) per byte regardless of how many patterns exist.

#include "AbiCallContract.hpp"
#include "FileReader.hpp"
#include <array>
#include <cstddef>
#include <iostream>
#include <map>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

// Argument width. The values are small ordinals (not byte widths) because
// they are stored in a 4-bit bitfield -- 8 << (size - 1) recovers the width,
// so I8..I128 map to 1,2,4,8,16 bytes and stay representable in 4 bits.
enum ArgType { NONE = 0, I8 = 1, I16 = 2, I32 = 3, I64 = 4, I128 = 5 };

template <typename Register> class funcsignatures {
public:
  // One argument: which register it arrives in, how wide it is, and whether
  // the value is a pointer (which the ABI layer needs in order to decide
  // whether the callee may legally write through it).
  struct funcArgInfo {
    Register reg;

    // Packed into a single byte: the arglist is built for every matched
    // function during the image scan, so keeping funcArgInfo small keeps that
    // scan's allocation down.
    struct argTypeInfo {
      uint8_t size : 4; // 4 bits for size
      uint8_t isPtr : 1;
      uint8_t pad : 3;
      constexpr argTypeInfo(ArgType type, bool isPtr)
          : size(static_cast<uint8_t>(type)), isPtr(isPtr ? 1 : 0), pad(0) {}
    } argtype;
    constexpr funcArgInfo(Register Reg, ArgType type, bool isPtr)
        : reg(Reg), argtype(type, isPtr){};
  };

  using funcArgInfos = std::vector<funcsignatures::funcArgInfo>;
  struct functioninfo {
    functioninfo() {}

    functioninfo(const std::string& Name) : name(Name) {}

    functioninfo(const std::string& Name, std::vector<funcArgInfo> Args)
        : name(Name), args(Args) {}
    std::string name;
    //
    // Default argument model: every GPR plus a memory pseudo-argument.
    //
    // This is deliberately the *union* of everything that could be an
    // argument, not a guess at the real ABI. It is what an unknown function
    // gets, so it is the widest set consistent with the Microsoft x64
    // calling convention: RAX..R15 plus the stack shadow space. Narrowing this
    // to a specific ABI is the job of AbiCallContract, which has the
    // information this table does not.
    funcArgInfos args = {
        funcArgInfo(Register::RAX, I64, 0), funcArgInfo(Register::RCX, I64, 0),
        funcArgInfo(Register::RDX, I64, 0), funcArgInfo(Register::RBX, I64, 0),
        funcArgInfo(Register::RSP, I64, 0), funcArgInfo(Register::RBP, I64, 0),
        funcArgInfo(Register::RSI, I64, 0), funcArgInfo(Register::RDI, I64, 0),
        funcArgInfo(Register::R8, I64, 0),  funcArgInfo(Register::R9, I64, 0),
        funcArgInfo(Register::R10, I64, 0), funcArgInfo(Register::R11, I64, 0),
        funcArgInfo(Register::R12, I64, 0), funcArgInfo(Register::R13, I64, 0),
        funcArgInfo(Register::R14, I64, 0), funcArgInfo(Register::R15, I64, 0),
        funcArgInfo(Register::DS, I64, 1)};

    // ABI metadata (optional). Default values preserve backward compatibility.
    AbiKind      abiKind      = AbiKind::Unknown;
    StackCleanup stackCleanup = StackCleanup::Unknown;
    // DS represents memory
    // (yeah i hate it aswell)
    // so the default is
    // rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15,memory
    // also
    // should SS represent stack ? (rsp+0x20 + (8 * arg) )
    // (SS is always ptr)
  };

private:
  // One entry in the signature table: a name, the bytes to search for, and the
  // argument list to apply if it matches.
  //
  // `args` may be null with argCount 0, meaning "recognise this function but
  // do not claim to know its signature". That distinction matters -- see
  // buildFunctionInfo.
  struct SignatureSpec {
    const char*        name;
    const unsigned char* bytes;
    size_t             byteCount;
    const funcArgInfo* args;
    size_t             argCount;
  };

  // Aho-Corasick multi-pattern matcher over the raw image bytes.
  //
  // One pass, O(text length) independent of pattern count, and it reports
  // overlapping matches. The alternatives both fail here: searching each
  // pattern separately scales with pattern count, and hashing fixed-length
  // windows would miss matches at unaligned offsets -- which is exactly where
  // prologues sit.
  class AhoCorasick {
  public:
    template <size_t N>
    explicit AhoCorasick(const std::array<SignatureSpec, N>& specs) {
      trie.emplace_back();
      patternLengths.reserve(N);
      for (size_t id = 0; id < N; ++id) {
        const auto& spec = specs[id];
        int current = 0;
        for (size_t i = 0; i < spec.byteCount; ++i) {
          const unsigned char c = spec.bytes[i];
          auto childIt = trie[current].children.find(c);
          if (childIt == trie[current].children.end()) {
            trie[current].children[c] = static_cast<int>(trie.size());
            trie.emplace_back();
            current = static_cast<int>(trie.size()) - 1;
          } else {
            current = childIt->second;
          }
        }
        trie[current].output.push_back(id);
        patternLengths.push_back(spec.byteCount);
      }
      build();
    };

    std::vector<std::pair<uint64_t, size_t>>
    search(const std::vector<unsigned char>& text) const {
      std::vector<std::pair<uint64_t, size_t>> results;
      int current = 0;
      for (uint64_t i = 0; i < text.size(); ++i) {
        const unsigned char c = text[i];
        while (current != -1) {
          auto childIt = trie[current].children.find(c);
          if (childIt != trie[current].children.end()) {
            current = childIt->second;
            break;
          }
          current = trie[current].fail;
        }
        if (current == -1) {
          current = 0;
          continue;
        }
        for (size_t id : trie[current].output) {
          results.emplace_back(i - patternLengths[id] + 1, id);
        }
      }
      return results;
    };

    // Automaton state. `fail` is the longest proper suffix of this node's path
    // that is also a prefix in the trie -- following it on a miss is what
    // keeps the search linear instead of backtracking.
    //
    // `output` lists every pattern ending here, including ones that reached
    // this node via a failure link. That inheritance is what makes shorter
    // patterns contained within longer ones still get reported.
    struct Node {
      std::map<unsigned char, int> children;
      int fail = -1;
      std::vector<size_t> output;
    };

    std::vector<Node> trie;
    std::vector<size_t> patternLengths;

    // Build failure links breadth-first, propagating each node's output list
    // down from its fail target.
    //
    // That propagation is what allows overlapping signatures to be reported
    // without rescanning: a node inherits the patterns of its longest proper
    // suffix, so a shorter signature nested inside a longer one fires from the
    // same automaton state.
    void build() {
      std::queue<int> q;
      for (const auto& [c, next] : trie[0].children) {
        trie[next].fail = 0;
        q.push(next);
      }
      while (!q.empty()) {
        int current = q.front();
        q.pop();
        for (const auto& [c, next] : trie[current].children) {
          int fail = trie[current].fail;
          while (fail != -1) {
            auto failIt = trie[fail].children.find(c);
            if (failIt != trie[fail].children.end()) {
              trie[next].fail = failIt->second;
              break;
            }
            fail = trie[fail].fail;
          }
          if (fail == -1) {
            trie[next].fail = 0;
          }
          trie[next].output.insert(trie[next].output.end(),
                                   trie[trie[next].fail].output.begin(),
                                   trie[trie[next].fail].output.end());
          q.push(next);
        }
      }
    };
  };

  // Prologue bytes for a recognised function.
  //
  // These are the first N bytes of the prologue, chosen to be stable across
  // builds: a push/sub-rsp/lea sequence for the iostream operator<<, and the
  // register-save preamble for swprintf_s. Matching on prologue rather than on
  // the exported name is deliberate -- at lift time the export table may not be
  // present (the function may be internal), whereas the prologue bytes are
  // always in the image.
  static inline constexpr std::array<unsigned char, 16> kOstreamBytes = {
      0x55, 0x48, 0x81, 0xEC, 0xA0, 0x00, 0x00, 0x00,
      0x48, 0x8D, 0xAC, 0x24, 0x80, 0x00, 0x00, 0x00};

  static inline constexpr std::array<unsigned char, 15> kSwprintfBytes = {
      0x4C, 0x8B, 0xDC, 0x4D, 0x89, 0x43, 0x18,
      0x4D, 0x89, 0x4B, 0x20, 0x48, 0x83, 0xEC, 0x38};

  // swprintf_s takes four register arguments under the Microsoft x64
  // convention. RCX (arg 0) and R8 (arg 2) are the wide-string buffer and its
  // size and are therefore pointers; RDX (the format string, arg 1) and R9
  // (the va_list, arg 3) are carried as plain i64 here because the variadic
  // tail cannot be described positionally.
  static inline constexpr std::array<funcArgInfo, 4> kSwprintfArgs = {
      funcArgInfo(Register::RCX, I64, 1),
      funcArgInfo(Register::RDX, I64, 0),
      funcArgInfo(Register::R8, I64, 1),
      funcArgInfo(Register::R9, I64, 0),
  };

  static inline constexpr std::array<SignatureSpec, 2> kBinarySignatureSpecs = {{
      {"??$?6U?$char_traits@D@std@@@std@@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@0@AEAV10@PEBD@Z",
       kOstreamBytes.data(), kOstreamBytes.size(), nullptr, 0},
      {"swprintf_s", kSwprintfBytes.data(), kSwprintfBytes.size(),
       kSwprintfArgs.data(), kSwprintfArgs.size()},
  }};

  // Turn a matched spec into a functioninfo.
  //
  // preserveDefaultArgsWhenUnspecified is the interesting branch. A spec with
  // no argument list is a weaker claim than one with: "this is ostream
  // operator<<" is much weaker than "this is swprintf_s, here is its exact
  // signature". A caller that has not yet established ABI context should ask
  // for the defaults in the first case, because the default union-of-all-GPRs
  // model is safer than a guessed specific list, whereas in the second case
  // the spec's list is authoritative and the default would throw it away.
  static functioninfo buildFunctionInfo(
      const SignatureSpec& spec, bool preserveDefaultArgsWhenUnspecified = false) {
    if (spec.argCount == 0 && preserveDefaultArgsWhenUnspecified) {
      return functioninfo(spec.name);
    }
    funcArgInfos args;
    args.reserve(spec.argCount);
    for (size_t i = 0; i < spec.argCount; ++i) {
      args.push_back(spec.args[i]);
    }
    return functioninfo(spec.name, args);
  }

  static const AhoCorasick& getBinarySignatureMatcher() {
    static const AhoCorasick matcher(kBinarySignatureSpecs);
    return matcher;
  }

public:
  static inline std::unordered_map<uint64_t, functioninfo> functions;
  static inline std::unordered_map<std::string, std::vector<uint64_t>>
      signatureOffsets;

  // Known Win32 API signatures for named import call emission.
  // Only register-passed arguments (RCX, RDX, R8, R9) are modeled;
  // stack-passed arguments (5th+ params) are not yet supported.
  // Functions with >4 params emit declarations for the first 4 only.
  static inline constexpr std::array<funcArgInfo, 4> kMessageBoxArgs = {
      funcArgInfo(Register::RCX, I64, 0),
      funcArgInfo(Register::RDX, I64, 1),
      funcArgInfo(Register::R8, I64, 1),
      funcArgInfo(Register::R9, I64, 0),
  };
  static inline constexpr std::array<funcArgInfo, 1> kQueryCounterArgs = {
      funcArgInfo(Register::RCX, I64, 1),
  };
  static inline constexpr std::array<funcArgInfo, 1> kSleepArgs = {
      funcArgInfo(Register::RCX, I32, 0),
  };
  static inline constexpr std::array<funcArgInfo, 4> kVirtualAllocArgs = {
      funcArgInfo(Register::RCX, I64, 1),
      funcArgInfo(Register::RDX, I64, 0),
      funcArgInfo(Register::R8, I32, 0),
      funcArgInfo(Register::R9, I32, 0),
  };
  static inline constexpr std::array<funcArgInfo, 3> kVirtualFreeArgs = {
      funcArgInfo(Register::RCX, I64, 1),
      funcArgInfo(Register::RDX, I64, 0),
      funcArgInfo(Register::R8, I32, 0),
  };
  static inline constexpr std::array<funcArgInfo, 4> kVirtualProtectArgs = {
      funcArgInfo(Register::RCX, I64, 1),
      funcArgInfo(Register::RDX, I64, 0),
      funcArgInfo(Register::R8, I32, 0),
      funcArgInfo(Register::R9, I64, 1),
  };
  static inline constexpr std::array<funcArgInfo, 3> kHeapAllocArgs = {
      funcArgInfo(Register::RCX, I64, 0),
      funcArgInfo(Register::RDX, I32, 0),
      funcArgInfo(Register::R8, I64, 0),
  };
  static inline constexpr std::array<funcArgInfo, 3> kHeapFreeArgs = {
      funcArgInfo(Register::RCX, I64, 0),
      funcArgInfo(Register::RDX, I32, 0),
      funcArgInfo(Register::R8, I64, 1),
  };
  static inline constexpr std::array<funcArgInfo, 4> kCreateFileArgs = {
      funcArgInfo(Register::RCX, I64, 1),
      funcArgInfo(Register::RDX, I32, 0),
      funcArgInfo(Register::R8, I32, 0),
      funcArgInfo(Register::R9, I64, 1),
  };
  static inline constexpr std::array<funcArgInfo, 4> kReadWriteFileArgs = {
      funcArgInfo(Register::RCX, I64, 0),
      funcArgInfo(Register::RDX, I64, 1),
      funcArgInfo(Register::R8, I32, 0),
      funcArgInfo(Register::R9, I64, 1),
  };
  static inline constexpr std::array<funcArgInfo, 1> kCloseHandleArgs = {
      funcArgInfo(Register::RCX, I64, 0),
  };
  static inline constexpr std::array<funcArgInfo, 1> kModuleHandleArgs = {
      funcArgInfo(Register::RCX, I64, 1),
  };
  static inline constexpr std::array<funcArgInfo, 2> kGetProcAddressArgs = {
      funcArgInfo(Register::RCX, I64, 0),
      funcArgInfo(Register::RDX, I64, 1),
  };
  static inline constexpr std::array<funcArgInfo, 3> kLoadLibraryExWArgs = {
      funcArgInfo(Register::RCX, I64, 1),
      funcArgInfo(Register::RDX, I64, 0),
      funcArgInfo(Register::R8, I32, 0),
  };
  static inline constexpr std::array<funcArgInfo, 1> kExitProcessArgs = {
      funcArgInfo(Register::RCX, I32, 0),
  };
  static inline constexpr std::array<funcArgInfo, 2> kWaitForSingleObjectArgs = {
      funcArgInfo(Register::RCX, I64, 0),
      funcArgInfo(Register::RDX, I32, 0),
  };
  static inline constexpr std::array<funcArgInfo, 4> kRegOpenKeyExWArgs = {
      funcArgInfo(Register::RCX, I64, 0),
      funcArgInfo(Register::RDX, I64, 1),
      funcArgInfo(Register::R8, I32, 0),
      funcArgInfo(Register::R9, I32, 0),
  };
  static inline constexpr std::array<funcArgInfo, 4> kRegQueryValueExWArgs = {
      funcArgInfo(Register::RCX, I64, 0),
      funcArgInfo(Register::RDX, I64, 1),
      funcArgInfo(Register::R8, I64, 1),
      funcArgInfo(Register::R9, I64, 1),
  };

  // GetStdHandle(DWORD nStdHandle) -> HANDLE
  // WriteConsoleA / ReadConsoleA  (HANDLE, ptr buf, count, ptr out)
  static inline constexpr std::array<funcArgInfo, 4> kConsoleIOArgs = {
      funcArgInfo(Register::RCX, I64, 0),
      funcArgInfo(Register::RDX, I64, 1),
      funcArgInfo(Register::R8,  I32, 0),
      funcArgInfo(Register::R9,  I64, 1),
  };
  static inline constexpr std::array<funcArgInfo, 1> kCharUpperArgs = {
      funcArgInfo(Register::RCX, I64, 1),
  };
  static inline constexpr std::array<funcArgInfo, 1> kGetStdHandleArgs = {
      funcArgInfo(Register::RCX, I32, 0),
  };

  // Name-resolved function table: 37 Win32 API names with their argument
  // models, no byte patterns at all (bytes == nullptr, byteCount == 0).
  //
  // This is the complement of kBinarySignatureSpecs above, and the two differ
  // in WHERE the name comes from:
  //
  //   kBinarySignatureSpecs  matched by prologue bytes, because the export
  //                          table may not have the function (it can be
  //                          internal). Survives a stripped image.
  //   kNamedFunctionSpecs   keyed purely by name. Reached only when the name
  //                          is already known -- i.e. the PE import table, or
  //                          a resolved import thunk.
  //
  // So this table is not a search step. It is a lookup consulted at the point
  // the lifter has already decided the call is external and knows what to call
  // it (Semantics_ControlFlow.ipp:572 in the ret-to-IAT chain,
  // Semantics_Helpers.ipp:186 in callFunctionIR, Semantics.ipp:255 for
  // address-keyed lookups). Its job is to supply the argument model so the
  // emitted call has a real signature instead of the conservative
  // all-GPRs-plus-memory default.
  //
  // The `nullptr, 0` entries are deliberate and mean "recognise the name, do
  // not claim to know the signature" -- GetTickCount, GetCurrentProcess and
  // friends take no arguments, so the wide default would over-approximate and
  // the narrow true answer is simply the empty list. Passing a genuinely empty
  // array would also work, but nullptr makes the intent visible in the table.
  //
  // Arg-sharing across entries is intentional, not copy-paste: the W/A pairs
  // (MessageBoxW/A, CreateFileW/A, GetModuleHandleW/A, LoadLibraryW/A) and the
  // file/console pairs take identical arguments under the same ABI, so they
  // point at one kXxxArgs array. If a future SDK diverges them (some CRT
  // variants do for the narrow-string entry points), the two rows must be
  // split -- a shared array silently gives both the same model.
  static inline constexpr std::array<SignatureSpec, 37> kNamedFunctionSpecs = {{
      {"MessageBoxW", nullptr, 0, kMessageBoxArgs.data(), kMessageBoxArgs.size()},
      {"MessageBoxA", nullptr, 0, kMessageBoxArgs.data(), kMessageBoxArgs.size()},
      {"GetTickCount64", nullptr, 0, nullptr, 0},
      {"GetTickCount", nullptr, 0, nullptr, 0},
      {"QueryPerformanceCounter", nullptr, 0, kQueryCounterArgs.data(), kQueryCounterArgs.size()},
      {"QueryPerformanceFrequency", nullptr, 0, kQueryCounterArgs.data(), kQueryCounterArgs.size()},
      {"Sleep", nullptr, 0, kSleepArgs.data(), kSleepArgs.size()},
      {"VirtualAlloc", nullptr, 0, kVirtualAllocArgs.data(), kVirtualAllocArgs.size()},
      {"VirtualFree", nullptr, 0, kVirtualFreeArgs.data(), kVirtualFreeArgs.size()},
      {"VirtualProtect", nullptr, 0, kVirtualProtectArgs.data(), kVirtualProtectArgs.size()},
      {"HeapAlloc", nullptr, 0, kHeapAllocArgs.data(), kHeapAllocArgs.size()},
      {"HeapFree", nullptr, 0, kHeapFreeArgs.data(), kHeapFreeArgs.size()},
      {"CreateFileW", nullptr, 0, kCreateFileArgs.data(), kCreateFileArgs.size()},
      {"CreateFileA", nullptr, 0, kCreateFileArgs.data(), kCreateFileArgs.size()},
      {"ReadFile", nullptr, 0, kReadWriteFileArgs.data(), kReadWriteFileArgs.size()},
      {"WriteFile", nullptr, 0, kReadWriteFileArgs.data(), kReadWriteFileArgs.size()},
      {"CloseHandle", nullptr, 0, kCloseHandleArgs.data(), kCloseHandleArgs.size()},
      {"GetCurrentProcess", nullptr, 0, nullptr, 0},
      {"GetCurrentProcessId", nullptr, 0, nullptr, 0},
      {"GetCurrentThreadId", nullptr, 0, nullptr, 0},
      {"GetModuleHandleW", nullptr, 0, kModuleHandleArgs.data(), kModuleHandleArgs.size()},
      {"GetModuleHandleA", nullptr, 0, kModuleHandleArgs.data(), kModuleHandleArgs.size()},
      {"GetProcAddress", nullptr, 0, kGetProcAddressArgs.data(), kGetProcAddressArgs.size()},
      {"LoadLibraryW", nullptr, 0, kModuleHandleArgs.data(), kModuleHandleArgs.size()},
      {"LoadLibraryA", nullptr, 0, kModuleHandleArgs.data(), kModuleHandleArgs.size()},
      {"LoadLibraryExW", nullptr, 0, kLoadLibraryExWArgs.data(), kLoadLibraryExWArgs.size()},
      {"ExitProcess", nullptr, 0, kExitProcessArgs.data(), kExitProcessArgs.size()},
      {"GetLastError", nullptr, 0, nullptr, 0},
      {"SetLastError", nullptr, 0, kExitProcessArgs.data(), kExitProcessArgs.size()},
      {"WaitForSingleObject", nullptr, 0, kWaitForSingleObjectArgs.data(), kWaitForSingleObjectArgs.size()},
      {"RegOpenKeyExW", nullptr, 0, kRegOpenKeyExWArgs.data(), kRegOpenKeyExWArgs.size()},
      {"RegQueryValueExW", nullptr, 0, kRegQueryValueExWArgs.data(), kRegQueryValueExWArgs.size()},
      {"RegCloseKey", nullptr, 0, kCloseHandleArgs.data(), kCloseHandleArgs.size()},
      {"GetStdHandle", nullptr, 0, kGetStdHandleArgs.data(), kGetStdHandleArgs.size()},
      {"WriteConsoleA", nullptr, 0, kConsoleIOArgs.data(), kConsoleIOArgs.size()},
      {"ReadConsoleA",  nullptr, 0, kConsoleIOArgs.data(), kConsoleIOArgs.size()},
      {"CharUpperA",    nullptr, 0, kCharUpperArgs.data(), kCharUpperArgs.size()},
  }};

  // The name -> functioninfo map, built once on first use.
  //
  // Function-local static initialised by an immediately-invoked lambda, rather
  // than a namespace-scope object, so construction happens on first lookup
  // instead of during static init. That matters because buildFunctionInfo reads
  // context-dependent defaults; building at static-init time would run before
  // the LLVMContext exists.
  //
  // Both tables land in the SAME map. The named specs pass buildFunctionInfo
  // without the second argument, the binary specs with it -- the flag marks a
  // spec as byte-matched rather than name-matched, so a name resolved from the
  // import table and the same name resolved by prologue bytes produce
  // distinguishable functioninfo entries.
  //
  // emplace, not operator[]: a duplicate name across the two tables keeps the
  // first insert rather than silently overwriting, so the tables can overlap
  // without the later one winning by accident.
  static std::unordered_map<std::string, functioninfo>& getNamedFunctionsByName() {
    static std::unordered_map<std::string, functioninfo> functionsByName = []() {
      std::unordered_map<std::string, functioninfo> map;
      map.reserve(kNamedFunctionSpecs.size() + kBinarySignatureSpecs.size());
      for (const auto& spec : kNamedFunctionSpecs) {
        map.emplace(spec.name, buildFunctionInfo(spec));
      }
      for (const auto& spec : kBinarySignatureSpecs) {
        map.emplace(spec.name, buildFunctionInfo(spec, true));
      }
      return map;
    }();
    return functionsByName;
  }

  // Step 1: scan the raw image bytes for the prologue patterns.
  //
  // Takes the whole file, not the mapped view, because it is looking for byte
  // patterns in the on-disk image -- not for values the emulated process would
  // read. That is also why it must run before the lift: once IR is built, the
  // original bytes are no longer the thing being consulted.
  //
  // Offsets are converted from file position to RVA here, so everything
  // downstream (createOffsetMap, getFunctionInfo by address) speaks RVA and
  // never has to think about file layout.
  //
  // signatureOffsets is cleared first rather than appended to: the stage is
  // re-runnable, and a stale hit from a previous image would resolve an address
  // in the wrong binary to a known function.
  static void search_signatures(std::vector<unsigned char>& data) {
    signatureOffsets.clear();
    if (data.empty()) {
      return;
    }

    x86_64FileReader file(data.data());
    const auto& matcher = getBinarySignatureMatcher();
    std::vector<std::pair<uint64_t, size_t>> matches = matcher.search(data);
    for (const auto& [pos, id] : matches) {
      const auto& spec = kBinarySignatureSpecs[id];
      signatureOffsets[spec.name].push_back(file.fileOffsetToRVA(pos));
    }
  };

  // Step 2: turn the name->offsets map into an address->functioninfo map.
  //
  // Must run after search_signatures and is what makes the results usable by
  // address. Running it against an empty or stale signatureOffsets produces a
  // well-formed but empty `functions` map, which looks valid and silently
  // disables every signature-derived improvement -- the reason runSignatureStage
  // calls both steps and does not treat either as optional.
  //
  // Only kBinarySignatureSpecs is walked here. The named specs need no offset
  // map: they are looked up by name at the call site (see
  // kNamedFunctionSpecs and getNamedFunctionsByName).
  static void createOffsetMap() {
    functions.clear();
    for (const auto& spec : kBinarySignatureSpecs) {
      auto it = signatureOffsets.find(spec.name);
      if (it == signatureOffsets.end())
        continue;

      functioninfo info = buildFunctionInfo(spec, true);
      for (const auto offset : it->second) {
        functions[offset] = info;
      }
    }
  };

  // Debug-only dump of what the signature stage found.
  //
  // Prints every pattern in the table, including the ones with no hits -- the
  // "end" with nothing before it is the signal that a pattern did not match
  // this sample. That is the fastest way to tell whether signature
  // recognition is working at all, and which specific prologue is missing.
  //
  // Only walks kBinarySignatureSpecs: the named specs have no offsets to show,
  // and whether they were hit is visible in the emitted IR instead (a named
  // `call @LoadLibraryW` rather than an inttoptr).
  static void displayMatches() {
    for (const auto& spec : kBinarySignatureSpecs) {
      std::cout << "Function Name: " << spec.name << ", Offsets: ";
      auto it = signatureOffsets.find(spec.name);
      if (it != signatureOffsets.end()) {
        for (const auto& offset : it->second) {
          std::cout << offset << " ";
        }
      }
      std::cout << "end" << std::endl;
    }
  }

  // Address lookup, served by the map createOffsetMap built. Keyed by RVA, so
  // the caller must have normalised the address first -- a 0x140000000-base
  // address will miss against a 0x40000000-base key and the signature-derived
  // argument model silently degrades to the conservative default.
  //
  // Null means "not a recognised function", which is the overwhelmingly common
  // case and is not an error.
  static functioninfo* getFunctionInfo(uint64_t addr) {
    auto it = functions.find(addr);
    if (it == functions.end())
      return nullptr;
    return &it->second;
  };

  // Name lookup, served by getNamedFunctionsByName. This is the overload that
  // actually matters for imports: at a call site the lifter usually knows the
  // name (from the IAT or a resolved thunk) even when it never had the
  // address in a signature table.
  static functioninfo* getFunctionInfo(const std::string& name) {
    auto& functionsByName = getNamedFunctionsByName();
    auto it = functionsByName.find(name);
    if (it == functionsByName.end())
      return nullptr;
    return &it->second;
  };
}; // funcsignatures

#endif // FUNCSIGNATURES_H
