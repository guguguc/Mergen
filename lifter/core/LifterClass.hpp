#ifndef LIFTERCLASSBASE_H
#define LIFTERCLASSBASE_H
#include "CommonDisassembler.hpp"
#include "AbiCallContract.hpp"
#include "FunctionSignatures.hpp"
#include "GEPTracker.h"
#include "InlinePolicy.hpp"
#include "LiftDiagnostics.hpp"
#include "PathSolver.h"
#include "RegisterManager.hpp"
#include "ZydisDisassembler.hpp"
#include "ZydisDisassemblerMnemonics.h"
#include "ZydisDisassemblerRegisters.h"
#include "FileReader.hpp"
#include "IcedDisassembler.hpp"
#include "IcedDisassemblerMnemonics.h"
#include "IcedDisassemblerRegisters.h"
#include "Includes.h"
#include "Utils.h"
#include "../vmp/VmpModel.hpp"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/TargetTransformInfo.h"

#include <concepts>
#include <deque>
#include <fstream>
#include <sstream>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/DomConditionCache.h>
#include <llvm/Analysis/DomTreeUpdater.h>
#include <llvm/Analysis/InstSimplifyFolder.h>
#include <llvm/Analysis/MemorySSAUpdater.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/Analysis/SimplifyQuery.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/Support/KnownBits.h>
#include <memory>
#include <set>
#include <type_traits>
#include <unordered_map>
#include <utility>

using namespace llvm;

#ifndef DEFINE_FUNCTION
#define DEFINE_FUNCTION(name) void lift_##name()
#endif

enum class ControlFlow {
  Basic,
  Unflatten,
};

struct InstructionKey {
  Value* operand1;
  union {
    Value* operand2;
    Type* destType;
  };

  InstructionKey() : operand1(nullptr), operand2(nullptr){};

  InstructionKey(Value* operand1, Value* operand2)
      : operand1(operand1), operand2(operand2){};

  InstructionKey(Value* operand1, Type* destType)
      : operand1(operand1), destType(destType){};

  bool operator==(const InstructionKey& other) const {
    if (operand1 != other.operand1)
      return false;
    return operand2 == other.operand2;
  }
  struct InstructionKeyInfo {
    // Custom hash function
    static inline unsigned getHashValue(const InstructionKey& key) {
      return llvm::hash_combine(key.operand1, key.operand2);
    }

    // Equality function
    static inline bool isEqual(const InstructionKey& lhs,
                               const InstructionKey& rhs) {
      return lhs == rhs;
    }

    // Define empty and tombstone keys �?MUST be distinct for DenseMap.
    static inline InstructionKey getEmptyKey() {
      return InstructionKey(
          reinterpret_cast<Value*>(static_cast<uintptr_t>(-1)),
          reinterpret_cast<Value*>(static_cast<uintptr_t>(-1)));
    }

    static inline InstructionKey getTombstoneKey() {
      return InstructionKey(
          reinterpret_cast<Value*>(static_cast<uintptr_t>(-2)),
          reinterpret_cast<Value*>(static_cast<uintptr_t>(-2)));
    }
  };
};

class InstructionCache {
private:
  using CacheMap = llvm::SmallDenseMap<InstructionKey, Value*, 4,
                                       InstructionKey::InstructionKeyInfo>;

  struct Layer {
    CacheMap map;
    std::shared_ptr<Layer> prev;
  };

  static constexpr unsigned kCowDeltaLayers = 32;

  std::array<std::shared_ptr<Layer>, 100> opcodeCaches;
  std::array<CacheMap, 100> hot;
  std::array<std::shared_ptr<CacheMap>, 100> index;
  std::array<std::shared_ptr<Layer>, 100> indexAt;

  static void mergeInto(CacheMap& dest, const CacheMap& src) {
    for (const auto& kv : src) {
      dest[kv.first] = kv.second;
    }
  }

  unsigned deltaDepth(uint8_t opcode) const {
    unsigned depth = 0;
    Layer* stop = indexAt[opcode].get();
    for (Layer* p = opcodeCaches[opcode].get(); p && p != stop; p = p->prev.get()) {
      ++depth;
    }
    return depth;
  }

  void cowIndex(uint8_t opcode) {
    llvm::SmallVector<Layer*, 16> newer;
    Layer* stop = indexAt[opcode].get();
    for (Layer* p = opcodeCaches[opcode].get(); p && p != stop; p = p->prev.get()) {
      newer.push_back(p);
    }
    auto next = index[opcode] ? std::make_shared<CacheMap>(*index[opcode])
                              : std::make_shared<CacheMap>();
    for (int i = static_cast<int>(newer.size()) - 1; i >= 0; --i) {
      mergeInto(*next, newer[i]->map);
    }
    index[opcode] = std::move(next);
    indexAt[opcode] = opcodeCaches[opcode];
  }

  void publish() {
    for (unsigned op = 0; op < opcodeCaches.size(); ++op) {
      if (hot[op].empty()) {
        continue;
      }
      auto layer = std::make_shared<Layer>();
      layer->map = std::move(hot[op]);
      layer->prev = opcodeCaches[op];
      if (!index[op]) {
        index[op] = std::make_shared<CacheMap>(layer->map);
        indexAt[op] = layer;
      } else if (index[op].use_count() == 1) {
        mergeInto(*index[op], layer->map);
        indexAt[op] = layer;
      }
      opcodeCaches[op] = std::move(layer);
      if (index[op] && index[op].use_count() > 1 &&
          deltaDepth(static_cast<uint8_t>(op)) >= kCowDeltaLayers) {
        cowIndex(static_cast<uint8_t>(op));
      }
    }
  }

public:
  InstructionCache() = default;

  InstructionCache(const InstructionCache& other) {
    const_cast<InstructionCache&>(other).publish();
    opcodeCaches = other.opcodeCaches;
    index = other.index;
    indexAt = other.indexAt;
  }

  InstructionCache(InstructionCache&& other) noexcept = default;

  InstructionCache& operator=(const InstructionCache& other) {
    if (this != &other) {
      const_cast<InstructionCache&>(other).publish();
      opcodeCaches = other.opcodeCaches;
      index = other.index;
      indexAt = other.indexAt;
      for (auto& h : hot) {
        h.clear();
      }
    }
    return *this;
  }

  InstructionCache& operator=(InstructionCache&& other) noexcept = default;

  void insert(uint8_t opcode, const InstructionKey& key, Value* value) {
    hot[opcode][key] = value;
    if (index[opcode] && index[opcode].use_count() == 1) {
      (*index[opcode])[key] = value;
    }
  }

  Value* lookup(uint8_t opcode, const InstructionKey& key) const {
    const auto& hotMap = hot[opcode];
    auto it = hotMap.find(key);
    if (it != hotMap.end()) {
      return it->second;
    }
    Layer* stop = indexAt[opcode].get();
    for (Layer* p = opcodeCaches[opcode].get(); p && p != stop;
         p = p->prev.get()) {
      auto lit = p->map.find(key);
      if (lit != p->map.end()) {
        return lit->second;
      }
    }
    if (index[opcode]) {
      auto iit = index[opcode]->find(key);
      if (iit != index[opcode]->end()) {
        return iit->second;
      }
    }
    return nullptr;
  }
};


struct BBInfo {
  uint64_t block_address = 0;
  llvm::BasicBlock* block = nullptr;

  BBInfo() = default;

  BBInfo(uint64_t runtime_address, llvm::BasicBlock* block)
      : block_address(runtime_address), block(block) {}

  // bool operator==(const BBInfo& other) const {
  //   if (block_address != other.block_address)
  //     return false;
  //   return block == other.block;
  // }

  // struct BBInfoKeyInfo {
  //   // Custom hash function
  //   static inline unsigned getHashValue(const BBInfo& key) {
  //     return llvm::hash_combine(key.block_address, key.block);
  //   }

  //   // Equality function
  //   static inline bool isEqual(const BBInfo& lhs, const BBInfo& rhs) {
  //     return lhs == rhs;
  //   }

  //   // Define empty and tombstone keys
  //   static inline BBInfo getEmptyKey() {
  //     return BBInfo(-1, static_cast<BasicBlock*>(nullptr));
  //   }

  //   static inline BBInfo getTombstoneKey() {
  //     return BBInfo(0, static_cast<BasicBlock*>(nullptr));
  //   }
  // };
};

class LazyValue {
public:
  using ComputeFunc = std::function<llvm::Value*()>;

  mutable std::optional<llvm::Value*> value;

  ComputeFunc computeFunc;

  LazyValue() : value(nullptr) {}
  LazyValue(llvm::Value* val) : value(val) {}
  LazyValue(std::function<llvm::Value*()> calc)
      : value(std::nullopt), computeFunc(calc) {}

  // get value, calculate if doesnt exist
  llvm::Value* get() const {
    if (!value.has_value() && computeFunc) {

      value = (computeFunc)();
    }

    return value.value_or(nullptr);
  }

  // Set a new value directly, bypassing lazy evaluation
  void set(llvm::Value* newValue) {
    value = newValue;
    computeFunc = nullptr;
  }
  void setCalculation(const std::function<llvm::Value*()> calc) {
    computeFunc = calc;
    value = std::nullopt; // Reset the stored value
  }
};

template <typename T, typename R>
concept lifterConcept = Registers<R> && requires(T t) {
  { t.GetRegisterValue_impl(std::declval<R>()) } -> std::same_as<llvm::Value*>;
  {
    t.SetRegisterValue_impl(std::declval<R>(), std::declval<llvm::Value*>())
  } -> std::same_as<void>;
  {
    t.branch_backup_impl(std::declval<llvm::BasicBlock*>(), false)
  } -> std::same_as<void>;
  {
    t.load_backup_impl(std::declval<llvm::BasicBlock*>())
  } -> std::same_as<void>;
  {
    t.load_generalized_backup_impl(std::declval<llvm::BasicBlock*>())
  } -> std::same_as<void>;
};

#define MERGEN_LIFTER_DEFINITION_TEMPLATES(ret)                                \
  template <typename Derived, Mnemonics Mnemonic, Registers Register,          \
            template <typename, typename> class DisassemblerBase>              \
    requires Disassembler<DisassemblerBase<Mnemonic, Register>, Mnemonic,      \
                          Register>                                            \
  ret lifterClassBase<Derived, Mnemonic, Register, DisassemblerBase>

// LiftStats is defined in LiftDiagnostics.hpp

// Shared by the register and memory event streams so the two files can be
// merged into one execution-ordered timeline. Both are opt-in diagnostics.
// Single shared event counter for the register and memory streams, so their
// sequence numbers form one execution-ordered timeline. It must be a single
// object: the register-stream hook lives in a member template, so a static local
// there would be instantiated once per translation unit and the two streams would
// disagree on numbering. Defined in Utils.cpp.
unsigned long long nextMemEventSeq();

// main lifter
template <typename Derived = void,
#ifdef ICED_FOUND
          Mnemonics Mnemonic = Mergen::IcedMnemonics,
          Registers Register = Mergen::IcedRegister,
          template <typename, typename> class DisassemblerBase =
              Mergen::icedDisassembler
#else
          Mnemonics Mnemonic = Mergen::ZydisMnemonic,
          Registers Register = Mergen::ZydisRegister,
          template <typename, typename> class DisassemblerBase =
              Mergen::ZydisDisassembler
#endif
          >
  requires Disassembler<DisassemblerBase<Mnemonic, Register>, Mnemonic,
                        Register>
class lifterClassBase {
public:
  using Disassembler = DisassemblerBase<Mnemonic, Register>;

  // ConstantFolder (not InstSimplifyFolder): the simplifier folder can delete an
  // instruction it just created when it folds it to an existing value, which
  // invalidates ValueHandles held by the concolic state during lifting.
  std::unique_ptr<llvm::IRBuilder<>> builder;
  BBInfo blockInfo;
  uint64_t current_address;
  bool run = 0;      // we may set 0 so to trigger jumping to next basic block
  bool finished = 0; // finished, unfinished, unreachable
  bool isUnreachable = 0;
  uint32_t counter = 0;
  // unique

  funcsignatures<Register> signatures;
  MergenDisassembledInstruction_base<Mnemonic, Register> instruction;

  Disassembler dis;
  MemoryPolicy memoryPolicy;
  uint64_t stackReserve = 0x1000; // clamped reserve, set by configureDefaultMemoryPolicy
  bool isTrackedStackAddress(uint64_t address) const {
    const uint64_t stackLower =
        stackReserve <= STACKP_VALUE ? STACKP_VALUE - stackReserve : 0;
    const uint64_t stackUpper = STACKP_VALUE + stackReserve;
    return address >= stackLower && address <= stackUpper;
  }
  bool isTrackedLocalStackAddress(uint64_t address) const {
    return isTrackedStackAddress(address) && address < STACKP_VALUE;
  }

  enum class BlockRestoreMode {
    Normal,
    GeneralizedLoop,
  };
  enum class PathSolveContext {
    Unknown,
    ConditionalBranch,
    DirectJump,
    IndirectJump,
    Ret,
  };
  FunctionInlinePolicy inlinePolicy;

  // ABI call-boundary configuration.
  // Strict: clobber volatile regs after non-inlineable calls (ABI-correct).
  // Compat: preserve all registers (legacy behavior, for diagnostics only).
  CallModelMode callModelMode = CallModelMode::Strict;
  AbiKind       defaultAbi    = AbiKind::Unknown; // auto-detected from arch mode

  // Returns the effective ABI for this binary. If defaultAbi is Unknown,
  // infers from file mode.
  AbiKind getEffectiveAbi() {
    if (defaultAbi != AbiKind::Unknown) return defaultAbi;
    return (file.getMode() == arch_mode::X64) ? AbiKind::X64_MSVC
                                                : AbiKind::X86_CDECL;
  }

  // Build CallEffects for an unknown call target using current config.
  CallEffects<Register> buildUnknownCallFx() {
    return abi::buildUnknownCallEffects<Register>(getEffectiveAbi(),
                                                  callModelMode);
  }

  // Parse an FF 25 (jmp [rip+disp32]) import thunk at targetVA.
  // Returns the IAT slot VA on success, or 0 if not a thunk.
  uint64_t parseImportThunk(uint64_t targetVA) {
    // Read opcode (2 bytes) and displacement (4 bytes) via readMemory
    // to avoid raw pointer access past section boundaries.
    uint64_t opcodeVal = 0;
    if (!file.readMemory(targetVA, 2, opcodeVal)) return 0;
    // Little-endian: FF 25 -> 0x25FF.
    if ((opcodeVal & 0xFFFF) != 0x25FF) return 0;

    uint64_t dispVal = 0;
    if (!file.readMemory(targetVA + 2, 4, dispVal)) return 0;
    int32_t disp = static_cast<int32_t>(dispVal & 0xFFFFFFFF);
    return targetVA + 6 + disp;
  }

  // Detects `jmp [rip+disp32]` (FF 25) thunks that read from the IAT.
  // Returns true if targetVA is an import thunk pointing outside the PE.
  bool isImportThunk(uint64_t targetVA) {
    uint64_t iatSlot = parseImportThunk(targetVA);
    if (iatSlot == 0) return false;

    uint64_t importAddr = 0;
    if (!file.readMemory(iatSlot, 8, importAddr)) return false;
    return file.address_to_mapped_address(importAddr) == 0;
  }

  // Import name resolution map: IAT slot VA -> import function name.
  // Built from PE import directory at setup. Used to emit named
  // function declarations instead of opaque inttoptr calls.
  std::unordered_map<uint64_t, std::string> importMap;

  // Register-indirect import provenance: maps a register (canonicalized to
  // its 64-bit encoding via getBiggestEncoding) to the import name last
  // loaded into it.  Set by lift_mov when the source is `[rip+disp]` with
  // disp+RIP in importMap.  Cleared on every SetRegisterValue so any other
  // write invalidates the binding.  Read by lift_call for register-indirect
  // calls so `mov rsi, [rip+iat]; call rsi` resolves to a named external
  // call instead of an opaque inttoptr.
  std::unordered_map<Register, std::string> registerImportSource;

  // If targetVA is an import thunk, returns the import name.
  // Otherwise returns empty string.
  std::string resolveImportName(uint64_t targetVA) {
    uint64_t iatSlot = parseImportThunk(targetVA);
    if (iatSlot == 0) return {};

    auto it = importMap.find(iatSlot);
    if (it != importMap.end()) return it->second;
    return {};
  }

  // Returns true if the target should be outlined instead of inlined.
  bool shouldOutlineCall(uint64_t targetVA) {
    return isImportThunk(targetVA);
  }

  // ── Speculative call inlining with rollback ──────────────────────
  //
  // When the lifter encounters a `call` to a constant in-binary target,
  // it tries to inline the callee (Unflatten path). But if the callee
  // is too complex (statically-linked library, deep STL code), inlining
  // explodes. Speculative inlining sets a budget: if the callee exceeds
  // it, the lifter bails out and emits CreateCall + ABI effects instead.
  //
  // The return continuation BB is pre-created with a backup of the
  // pre-call state. On bail-out, the worklist resumes from that BB.

  struct SpeculativeCallInfo {
    bool     active         = false;
    uint64_t returnAddr     = 0;      // instruction after the call
    size_t   worklistFloor  = 0;      // worklist size before inlining
    bool     bailedOut      = false;   // set when budget exhausted
  };
  bool shouldInlineTinyOutlinedCall(uint64_t targetVA) {
    if (!isMemPaged(targetVA) || !inlinePolicy.isOutline(targetVA)) {
      return false;
    }
    auto it = inlinePolicy.range.find(targetVA);
    if (it == inlinePolicy.range.end()) {
      return false;
    }
    auto next = std::next(it);
    if (next == inlinePolicy.range.end()) {
      return false;
    }
    const uint64_t span = *next - targetVA;
    return span <= 0x40;
  }

  SpeculativeCallInfo speculativeCall;
  uint32_t speculativeCallBudget    = 0;   // instructions remaining (0 = inactive)
  uint32_t maxCallInlineBudget      = 0;   // 0 = disabled (no speculative limit)
  bool liftBudgetExceeded          = false;
  uint32_t maxBasicBlockBudget     = 4096;  // 0 = disabled
  llvm::BasicBlock* liftAbortBlock = nullptr;
  bool bypassStackConcolicTracking = false;
  BlockRestoreMode currentBlockRestoreMode = BlockRestoreMode::Normal;
  PathSolveContext currentPathSolveContext = PathSolveContext::Unknown;
  
  class ScopedPathSolveContext {
    lifterClassBase<Derived, Mnemonic, Register, DisassemblerBase>* lifter;
    PathSolveContext previous;
  
  public:
    ScopedPathSolveContext(
        lifterClassBase<Derived, Mnemonic, Register, DisassemblerBase>* lifter,
        PathSolveContext next)
        : lifter(lifter), previous(lifter->currentPathSolveContext) {
      lifter->currentPathSolveContext = next;
    }
  
    ~ScopedPathSolveContext() { lifter->currentPathSolveContext = previous; }
  };

  void runDisassembler(const void* buffer, size_t size = 15) {

    instruction = dis.disassemble(buffer, size);
  }

  // handle the file here
  uint8_t* fileBase;

  // lifts single instruction
  void liftBytes(const void* bytes, size_t size = 15) {
    // what about the basicblock?
    this->hadConditionalBranch = false;
    this->lastConditionalBranchResolved = false;
    this->lastBranchTaken = false;
    runDisassembler(bytes, size);
    current_address += instruction.length;
    liftInstructionSemantics();
    this->counter++;
  };

  x86_64FileReader file;

  void loadFile(uint8_t* file_start) {
    fileBase = file_start;
    file = x86_64FileReader(file_start);
  }

  // also lifts single inst
  void liftAddress(uint64_t addr, size_t size = 15) {

    file.filebase_exists();
    this->hadConditionalBranch = false;
    this->lastConditionalBranchResolved = false;
    this->lastBranchTaken = false;

    {
      auto decodeSample = profiler.sample("lift_decode");
      this->current_address = addr;
      // Per-instruction VA breadcrumb: complements MERGEN_BLOCK_TRACE_FILE
      // by pinning the exact instruction PC when a crash occurs within a
      // block. Set MERGEN_INSTR_TRACE_FILE to enable.
      if (const char* trace = std::getenv("MERGEN_INSTR_TRACE_FILE")) {
        FILE* f = std::fopen(trace, "a");
        if (f) {
          std::fprintf(f, "0x%llx\n", (unsigned long long)addr);
          std::fflush(f);
          std::fclose(f);
        }
      }
      auto offset = file.address_to_mapped_address(addr);
      if (offset == 0) {
        this->run = 0;
        this->finished = 1;
        builder->CreateUnreachable();
        // Surface the bailout as a warning so callers can see that the
        // lift reached an unmapped address (typically the result of a
        // queued constant target that turned out not to be real code).
        diagnostics.warning(
            DiagCode::UnresolvedIndirectJump, addr,
            "liftAddress: target address not mapped in image; emitted unreachable");
        return;
      }
      // what about the basicblock?
      printvalue2(offset);
      printvalue2(*(uint8_t*)offset);

      runDisassembler((void*)offset, size);

      if (const char* insnPath = std::getenv("MERGEN_INSN_STREAM_FILE")) {
        static std::ofstream* insnStream = nullptr;
        static bool insnInit = false;
        static unsigned long long insnSeq = 0;
        if (!insnInit) {
          insnInit = true;
          insnStream = new std::ofstream(insnPath, std::ios::out);
        }
        if (insnStream && insnStream->is_open()) {
          auto hexOrDash = [this](Register reg) -> std::string {
            llvm::Value* v = GetRegisterValue(reg);
            if (auto* ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(v)) {
              std::ostringstream os;
              os << "0x" << std::hex << ci->getZExtValue();
              return os.str();
            }
            return "-";
          };
          uint64_t rva = this->current_address;
          if (rva >= 0x140000000ULL)
            rva -= 0x140000000ULL;
          else if ((rva & 0xFF000000ULL) == 0x40000000ULL)
            rva &= 0x00FFFFFFULL;
          ++insnSeq;
          *insnStream << "I," << insnSeq << ",0x" << std::hex << rva << std::dec
                      << "," << hexOrDash(Register::RAX) << ","
                      << hexOrDash(Register::RBX) << ","
                      << hexOrDash(Register::RCX) << ","
                      << hexOrDash(Register::RDX) << ","
                      << hexOrDash(Register::RSI) << ","
                      << hexOrDash(Register::RDI) << ","
                      << hexOrDash(Register::RBP) << ","
                      << hexOrDash(Register::RSP) << ","
                      << hexOrDash(Register::R8) << ","
                      << hexOrDash(Register::R9) << ","
                      << hexOrDash(Register::R10) << ","
                      << hexOrDash(Register::R11) << "\n";
        }
      }

      {
        const uint64_t va = this->current_address;
        const bool vipSite =
            va == 0x140301D45ULL || va == 0x40301D45ULL ||
            va == 0x1402E6FF6ULL || va == 0x402E6FF6ULL ||
            va == 0x1402E7043ULL || va == 0x402E7043ULL ||
            va == 0x1403357C6ULL || va == 0x403357C6ULL ||
            va == 0x1403357D1ULL || va == 0x403357D1ULL ||
            va == 0x1402C28ECULL || va == 0x402C28ECULL ||
            va == 0x1403C2BA9ULL || va == 0x403C2BA9ULL ||
            va == 0x1403F8AC4ULL || va == 0x403F8AC4ULL ||
            va == 0x14031BE9DULL || va == 0x4031BE9DULL ||
            va == 0x14035A499ULL || va == 0x4035A499ULL ||
            va == 0x140360B07ULL || va == 0x40360B07ULL ||
            va == 0x1403D0FB9ULL || va == 0x403D0FB9ULL ||
            va == 0x1403BC020ULL || va == 0x403BC020ULL ||
            va == 0x140389410ULL || va == 0x40389410ULL ||
            va == 0x1403E3AB9ULL || va == 0x403E3AB9ULL ||
            va == 0x1403D2682ULL || va == 0x403D2682ULL ||
            va == 0x1403CC19CULL || va == 0x403CC19CULL ||
            va == 0x1403EA92BULL || va == 0x403EA92BULL ||
            va == 0x1403EA94DULL || va == 0x403EA94DULL ||
            va == 0x1402E63E1ULL || va == 0x402E63E1ULL ||
            va == 0x1402E6408ULL || va == 0x402E6408ULL ||
            va == 0x14031EA21ULL || va == 0x4031EA21ULL ||
            va == 0x14031EA2BULL || va == 0x4031EA2BULL ||
            va == 0x14034BBD0ULL || va == 0x4034BBD0ULL ||
            va == 0x14034BBE5ULL || va == 0x4034BBE5ULL ||
            va == 0x14034BBEBULL || va == 0x4034BBEBULL ||
            va == 0x14034BBF3ULL || va == 0x4034BBF3ULL ||
            va == 0x1402D34FEULL || va == 0x402D34FEULL ||
            va == 0x1402D3505ULL || va == 0x402D3505ULL ||
            va == 0x1402D3524ULL || va == 0x402D3524ULL ||
            va == 0x1402D353EULL || va == 0x402D353EULL ||
            va == 0x140364A8FULL || va == 0x40364A8FULL ||
            va == 0x14032415BULL || va == 0x4032415BULL ||
            va == 0x14037507AULL || va == 0x4037507AULL ||
            va == 0x14038447DULL || va == 0x4038447DULL ||
            va == 0x140384484ULL || va == 0x40384484ULL ||
            va == 0x1403DC6F9ULL || va == 0x403DC6F9ULL ||
            va == 0x1403BD63FULL || va == 0x403BD63FULL ||
            va == 0x1403A861CULL || va == 0x403A861CULL ||
            va == 0x1403BD90BULL || va == 0x403BD90BULL ||
            va == 0x1403DCE97ULL || va == 0x403DCE97ULL ||
            va == 0x14030D3FBULL || va == 0x4030D3FBULL ||
            va == 0x14030D415ULL || va == 0x4030D415ULL ||
            va == 0x1403108ECULL || va == 0x403108ECULL ||
            va == 0x14031BE9DULL || va == 0x4031BE9DULL ||
            va == 0x1403A8609ULL || va == 0x403A8609ULL ||
            va == 0x1402E17D5ULL || va == 0x402E17D5ULL ||
            va == 0x1402E17EEULL || va == 0x402E17EEULL ||
            va == 0x1403E9AF2ULL || va == 0x403E9AF2ULL ||
            va == 0x14034ECFDULL || va == 0x4034ECFDULL ||
            va == 0x14034ED0EULL || va == 0x4034ED0EULL ||
            va == 0x1402F2468ULL || va == 0x402F2468ULL ||
            va == 0x1402F2484ULL || va == 0x402F2484ULL ||
            va == 0x1402F2499ULL || va == 0x402F2499ULL ||
            va == 0x1402D8040ULL || va == 0x402D8040ULL ||
            va == 0x1403D44FBULL || va == 0x403D44FBULL ||
            va == 0x140377013ULL || va == 0x40377013ULL;
        if (vipSite) {
          auto hexOrIr = [](llvm::Value* v) -> std::string {
            if (!v) {
              return "<null>";
            }
            if (auto* ci = llvm::dyn_cast<llvm::ConstantInt>(v)) {
              std::ostringstream os;
              os << "0x" << std::hex << ci->getZExtValue();
              return os.str();
            }
            std::string text;
            llvm::raw_string_ostream os(text);
            v->print(os);
            return text.substr(0, 140);
          };
          auto dumpMem = [&](const char* tag, llvm::Value* ptrV, unsigned nbytes) {
            auto* ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(ptrV);
            if (!ci) {
              std::cout << " " << tag << "=<nonconst>";
              return;
            }
            const uint64_t p = ci->getZExtValue();
            uint64_t raw = 0;
            if (!file.readMemory(p, nbytes, raw)) {
              std::cout << " " << tag << "@0x" << std::hex << p << "=<unreadable>";
              return;
            }
            if (nbytes == 4) {
              raw &= 0xffffffffULL;
            }
            std::cout << " " << tag << "@0x" << std::hex << p << "=0x" << raw;
          };
          std::cout << "[vip] pre addr=0x" << std::hex << va
                    << " rax=" << hexOrIr(this->GetRegisterValue(Register::RAX))
                    << " rbx=" << hexOrIr(this->GetRegisterValue(Register::RBX))
                    << " r9=" << hexOrIr(this->GetRegisterValue(Register::R9))
                    << " rsi=" << hexOrIr(this->GetRegisterValue(Register::RSI))
                    << " r8=" << hexOrIr(this->GetRegisterValue(Register::R8))
                    << " r11=" << hexOrIr(this->GetRegisterValue(Register::R11))
                    << " rbp=" << hexOrIr(this->GetRegisterValue(Register::RBP))
                    << " rdx=" << hexOrIr(this->GetRegisterValue(Register::RDX))
                    << " rsp=" << hexOrIr(this->GetRegisterValue(Register::RSP))
                    << " rdi=" << hexOrIr(this->GetRegisterValue(Register::RDI))
                    << " rcx=" << hexOrIr(this->GetRegisterValue(Register::RCX))
                    << " lastmod=0x" << this->vmp.vipOffset();
          dumpMem("[rbx]", this->GetRegisterValue(Register::RBX), 8);
          dumpMem("[r9]", this->GetRegisterValue(Register::R9), 8);
          dumpMem("dword[r9]", this->GetRegisterValue(Register::R9), 4);
          if (auto* rspCi = llvm::dyn_cast_or_null<llvm::ConstantInt>(
                  this->GetRegisterValue(Register::RSP))) {
            if (auto* r8Ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(
                    this->GetRegisterValue(Register::R8))) {
              const uint64_t ea =
                  rspCi->getZExtValue() + r8Ci->getZExtValue();
              std::cout << " rsp+r8=0x" << std::hex << ea;
              dumpMem("[rsp+r8]", ConstantInt::get(rspCi->getType(), ea), 4);
            }
          }
          auto dumpBuf = [&](const char* tag, uint64_t slot) {
            auto it = this->buffer.find(slot);
            if (it == this->buffer.end() || !it->second.value) {
              std::cout << " " << tag << "=<empty>";
            } else {
              std::cout << " " << tag << "=" << hexOrIr(it->second.value)
                        << " off=" << (unsigned)it->second.byteOffset;
            }
          };
          if (auto* rbxCi = llvm::dyn_cast_or_null<llvm::ConstantInt>(
                  this->GetRegisterValue(Register::RBX))) {
            const uint64_t slot = rbxCi->getZExtValue();
            dumpBuf("buf[rbx]", slot);
            dumpBuf("buf[rbx+8]", slot + 8);
          }
          std::cout << std::dec << "\n" << std::flush;
        }
      }

      // RSP-drift tracker. The real machine keeps RSP fixed inside a VM handler
      // (the VM stack lives in a GPR); if the lifter's pseudo-RSP is seeded a
      // constant amount away from the machine's entry RSP, every absolute
      // [rsp+imm] access lands in a neighbouring slot while the relative
      // offsets within one frame still look self-consistent. Logged at the VAs
      // where DR can supply the ground-truth RSP (customer entry, veneer,
      // dispatcher, and the handler read site).
      if (liftProgressDiagEnabled) {
        const uint64_t va = this->current_address;
        const bool watch =
            va == 0x140007210ULL || va == 0x140007215ULL || va == 0x140007216ULL ||
            va == 0x1401F0EFBULL || va == 0x1401F0F00ULL || va == 0x1401F0F05ULL ||
            va == 0x1403A5FF4ULL || va == 0x1403A6049ULL || va == 0x1402E17D5ULL;
        if (watch) {
          std::string rs;
          llvm::raw_string_ostream ros(rs);
          if (auto* sp = this->GetRegisterValue(Register::RSP)) {
            sp->print(ros);
          }
          std::cout << "[rspmod] @0x" << std::hex << va << std::dec
                    << " mnem=" << magic_enum::enum_name(this->instruction.mnemonic)
                    << " rsp=" << ros.str().substr(0, 60) << "\n"
                    << std::flush;
        }
      }

      const auto ct = (llvm::format_hex_no_prefix(this->counter, 0));
      const auto runtime_address =
          (llvm::format_hex_no_prefix(this->current_address, 0));
      printvalue2(ct);
      printvalue2(runtime_address);
#ifndef _NODEV
      debugging::doIfDebug([&]() { printvalue2(this->instruction.text); });
#endif
      if (liftProgressDiagEnabled && this->current_address >= 0x140023582ULL &&
          this->current_address <= 0x1400237FFULL) {
        std::cout << "[diag] hot-instr addr=0x" << std::hex << this->current_address
                  << std::dec << " text=" << this->instruction.text;
        if ((this->current_address >= 0x1400234C8ULL &&
             this->current_address <= 0x140023552ULL) ||
            (this->current_address >= 0x140023500ULL &&
             this->current_address <= 0x140023620ULL) ||
            this->current_address == 0x14002366EULL ||
            this->current_address == 0x140023689ULL ||
            this->current_address == 0x14002368DULL ||
            this->current_address == 0x140023690ULL ||
            this->current_address == 0x140023693ULL ||
            this->current_address == 0x14002373DULL ||
            this->current_address == 0x140023741ULL ||
            this->current_address == 0x140023744ULL ||
            this->current_address == 0x14002374AULL ||
            this->current_address == 0x140023751ULL ||
            this->current_address == 0x140023754ULL ||
            this->current_address == 0x14002375BULL ||
            this->current_address == 0x140023762ULL ||
            this->current_address == 0x140023765ULL ||
            this->current_address == 0x14002376CULL ||
            this->current_address == 0x14002376FULL ||
            this->current_address == 0x140023776ULL ||
            this->current_address == 0x14002377DULL ||
            this->current_address == 0x140023784ULL ||
            this->current_address == 0x14002378BULL ||
            this->current_address == 0x14002378EULL ||
            this->current_address == 0x140023795ULL ||
            this->current_address == 0x140023799ULL ||
            this->current_address == 0x1400237AAULL ||
            this->current_address == 0x1400237CFULL ||
            this->current_address == 0x1400237DCULL ||
            this->current_address == 0x1400237EFULL ||
            this->current_address == 0x1400237F6ULL ||
            this->current_address == 0x1400237F9ULL) {
          auto valueText = [&](llvm::Value* value) {
            if (!value) return std::string("<null>");
            std::string text;
            llvm::raw_string_ostream os(text);
            value->print(os);
            return text;
          };
          std::cout << " mnemonic="
                    << magic_enum::enum_name(this->instruction.mnemonic)
                    << " srcType="
                    << magic_enum::enum_name(this->instruction.types[1])
                    << " dstType="
                    << magic_enum::enum_name(this->instruction.types[0])
                    << " reg0=" << magic_enum::enum_name(this->instruction.regs[0])
                    << " reg1=" << magic_enum::enum_name(this->instruction.regs[1])
                    << " mem_base="
                    << magic_enum::enum_name(this->instruction.mem_base)
                    << " mem_index="
                    << magic_enum::enum_name(this->instruction.mem_index)
                    << " mem_disp=" << this->instruction.mem_disp
                    << " RAX=" << valueText(this->GetRegisterValue(Register::RAX))
                    << " RBX=" << valueText(this->GetRegisterValue(Register::RBX))
                    << " RCX=" << valueText(this->GetRegisterValue(Register::RCX))
                    << " RDX=" << valueText(this->GetRegisterValue(Register::RDX))
                    << " RSI=" << valueText(this->GetRegisterValue(Register::RSI))
                    << " R8=" << valueText(this->GetRegisterValue(Register::R8))
                    << " R9=" << valueText(this->GetRegisterValue(Register::R9))
                    << " R10=" << valueText(this->GetRegisterValue(Register::R10))
                    << " R14=" << valueText(this->GetRegisterValue(Register::R14))
                    << " R15=" << valueText(this->GetRegisterValue(Register::R15))
                    << " ZF=" << valueText(this->getFlag(FLAG_ZF));
        }
        std::cout << "\n";
      }

      // also pass the file to address_to_mapped_address?
      this->current_address += instruction.length;
    }

    liftInstruction();
    this->counter++;
  };

  void liftBasicBlockFromBytes(std::vector<uint8_t> bytes) {
    //
  }

  // useless in symbolic?
  void branch_backup(BasicBlock* bb, bool generalized = false) {
    static_cast<Derived*>(this)->branch_backup_impl(bb, generalized);
  }
  void migrate_generalized_loop_block(BasicBlock* oldBlock, BasicBlock* newBlock) {
    static_cast<Derived*>(this)->migrate_generalized_loop_block_impl(oldBlock, newBlock);
  }

  void record_generalized_loop_backedge(BasicBlock* bb) {
    static_cast<Derived*>(this)->record_generalized_loop_backedge_impl(bb);
  }

  // useless in symbolic?
  void load_backup(BasicBlock* bb) {
    static_cast<Derived*>(this)->load_backup_impl(bb);
  }
  void load_generalized_backup(BasicBlock* bb) {
    static_cast<Derived*>(this)->load_generalized_backup_impl(bb);
  }
  llvm::Value* retrieve_generalized_loop_local_value(uint64_t startAddress,
                                                     uint8_t byteCount) {
    return static_cast<Derived*>(this)->retrieve_generalized_loop_local_value_impl(
        startAddress, byteCount);
  }
  llvm::Value* retrieve_generalized_loop_control_slot_value(uint64_t startAddress,
                                                            uint8_t byteCount) {
    return static_cast<Derived*>(this)
        ->retrieve_generalized_loop_control_slot_value_impl(startAddress,
                                                            byteCount);
  }
  llvm::Value* retrieve_generalized_loop_control_field_value(llvm::Value* loadOffset,
                                                             uint8_t byteCount,
                                                             LazyValue orgLoad) {
    return static_cast<Derived*>(this)
        ->retrieve_generalized_loop_control_field_value_impl(loadOffset,
                                                             byteCount, orgLoad);
  }
  llvm::Value* retrieve_generalized_loop_local_phi_address_value(
      llvm::Value* loadOffset, uint8_t byteCount, LazyValue orgLoad) {
    return static_cast<Derived*>(this)
        ->retrieve_generalized_loop_local_phi_address_value_impl(loadOffset,
                                                                 byteCount, orgLoad);
  }
  llvm::Value* retrieve_generalized_loop_target_slot_value(uint64_t startAddress,
                                                           uint8_t byteCount) {
    return static_cast<Derived*>(this)->retrieve_generalized_loop_target_slot_value_impl(
        startAddress, byteCount);
  }
  llvm::Value* retrieve_generalized_loop_phi_address_value(
      llvm::Value* loadOffset, uint8_t byteCount, LazyValue orgLoad) {
    return static_cast<Derived*>(this)->retrieve_generalized_loop_phi_address_value_impl(
        loadOffset, byteCount, orgLoad);
  }
  bool currentBlockUsesGeneralizedLoopState() const {
    return currentBlockRestoreMode == BlockRestoreMode::GeneralizedLoop;
  }
  bool currentPathSolveAllowsStructuredLoopGeneralization() const {
    return currentPathSolveContext == PathSolveContext::ConditionalBranch ||
           currentPathSolveContext == PathSolveContext::DirectJump;
  }
  // Widened variant: when the path solver has already resolved the branch
  // target to a concrete address, an indirect jump is no longer speculative.
  // If its target also points backward at a visited block it is legitimately
  // a loop back-edge and should enter structured loop generalization alongside
  // direct and conditional jumps. Ret-path contexts have their own lifecycle
  // and stay excluded here.
  bool currentPathSolveAllowsStructuredLoopGeneralizationForResolvedTarget() const {
    return currentPathSolveAllowsStructuredLoopGeneralization() ||
           currentPathSolveContext == PathSolveContext::IndirectJump;
  }
  // Aftermath Labs, "Static Devirtualization of Themida": with VMProtect the
  // last module load that feeds into the indirect jump/return computation is
  // by definition the current VIP. Walking the IR DAG backwards from the SSA
  // value holding the transfer target finds that load.
  llvm::Value* findVipLoad(llvm::Value* target) const {
    if (!target) {
      return nullptr;
    }
    std::set<llvm::Value*> seen;
    std::vector<llvm::Value*> work{target};
    llvm::Value* best = nullptr;
    unsigned visited = 0;
    while (!work.empty() && visited < 20000) {
      llvm::Value* v = work.back();
      work.pop_back();
      if (!v || !seen.insert(v).second) {
        continue;
      }
      ++visited;
      if (auto* li = llvm::dyn_cast<llvm::LoadInst>(v)) {
        best = li;
      }
      if (auto* u = llvm::dyn_cast<llvm::User>(v)) {
        for (auto& op : u->operands()) {
          work.push_back(op.get());
        }
      }
    }
    return best;
  }

  // VMProtect keeps its virtual stack on the native stack, so a dispatch
  // target is usually a value loaded back out of a memory slot rather than an
  // SSA value. The concolic buffer holds the value that was stored there, so
  // follow the store before walking the DAG - otherwise the provenance stops
  // at the GEP and the bytecode load is never reached.
  llvm::Value* transferSourceValue(llvm::Value* transfer) const {
    if (auto* li = llvm::dyn_cast_or_null<llvm::LoadInst>(transfer)) {
      if (auto* gep =
              llvm::dyn_cast<llvm::GetElementPtrInst>(li->getPointerOperand())) {
        if (gep->getPointerOperand()->stripPointerCasts() ==
            memoryAlloc->stripPointerCasts()) {
          if (auto* off = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1))) {
            auto it = buffer.find(off->getZExtValue());
            if (it != buffer.end() && it->second.value) {
              return it->second.value;
            }
          }
        }
      }
    }
    return transfer;
  }

  // Bytecode offset of the load that produced `value`, walking the SSA DAG
  // (and through the concolic buffer's last store first). 0 when unavailable.
  // VMProtect keeps its VM stack on the native stack; in the flat memory model
  // that region overlaps the image's virtual range, so address_to_mapped_address
  // alone cannot separate a bytecode read from a VM-stack read.
  void addBytecodeRange(uint64_t start, uint64_t end) {
    vmp.addBytecodeRange(start, end);
  }
  bool isBytecodeAddress(uint64_t address) const {
    return vmp.isBytecodeAddress(address);
  }
  bool isStackAddress(uint64_t address) {
    constexpr uint64_t kReserve = 0x100000;
    return address >= STACKP_VALUE - kReserve &&
           address <= STACKP_VALUE + kReserve;
  }
  bool isModuleAddress(uint64_t address) {
    return !isStackAddress(address) &&
           file.address_to_mapped_address(address) != 0;
  }
  // True when `v` (transitively) feeds a comparison or a select/branch
  // condition. Such a value is guard state: it must stay symbolic so the
  // virtualized loop guard survives as a real branch, unlike the pure VIP
  // carrier, which is frozen to keep the dispatch resolvable.
  bool feedsCondition(llvm::Value* v) {
    if (!v) return false;
    std::set<llvm::Value*> seen;
    std::vector<llvm::Value*> work{v};
    unsigned visited = 0;
    while (!work.empty() && visited < 6000) {
      llvm::Value* x = work.back();
      work.pop_back();
      if (!x || !seen.insert(x).second) continue;
      ++visited;
      for (auto* u : x->users()) {
        if (llvm::isa<llvm::CmpInst>(u)) return true;
        if (auto* sel = llvm::dyn_cast<llvm::SelectInst>(u)) {
          if (sel->getCondition() == x) return true;
        }
        if (auto* br = llvm::dyn_cast<llvm::BranchInst>(u)) {
          if (br->isConditional()) return true;
        }
        work.push_back(u);
      }
    }
    return false;
  }
  uint64_t vipModuleOffset(llvm::Value* value, bool* exactFromLoad = nullptr) {
    llvm::Value* source = transferSourceValue(value);
    if (!source) {
      if (exactFromLoad) *exactFromLoad = false;
      return 0;
    }
    std::set<llvm::Value*> seen;
    std::vector<llvm::Value*> work{source};
    uint64_t fromLoad = 0;
    unsigned visited = 0;
    while (!work.empty() && visited < 20000) {
      llvm::Value* v = work.back();
      work.pop_back();
      if (!v || !seen.insert(v).second) {
        continue;
      }
      ++visited;
      if (auto* li = llvm::dyn_cast<llvm::LoadInst>(v)) {
        if (auto* gep =
                llvm::dyn_cast<llvm::GetElementPtrInst>(li->getPointerOperand())) {
          if (gep->getPointerOperand()->stripPointerCasts() ==
            memoryAlloc->stripPointerCasts()) {
            if (auto* off =
                    llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1))) {
              const uint64_t gepOff = off->getZExtValue();
              // VIP candidates are bytecode-range loads only. Handler RX /
              // table module addresses in the transfer DAG must not become
              // exact VIP (that fabricated confirm=1 on 0x403c48fc).
              if (isBytecodeAddress(gepOff)) {
                fromLoad = gepOff;
              } else if (fromLoad == 0) {
                auto stickyIt = stickyNonArgSlot.find(gepOff);
                if (stickyIt != stickyNonArgSlot.end() &&
                    isBytecodeAddress(stickyIt->second)) {
                  fromLoad = stickyIt->second;
                }
              }
            }
          }
        }
      }
      if (auto* u = llvm::dyn_cast<llvm::User>(v)) {
        for (auto& op : u->operands()) {
          work.push_back(op.get());
        }
      }
    }
    if (exactFromLoad) {
      *exactFromLoad = fromLoad != 0;
    }
    // Deliberately no loadProvenance fallback. LLVM uniques constants, so a
    // folded constant's provenance is ambiguous: dozens of distinct bytecode
    // reads collapse onto one ConstantInt and overwrite each other, fabricating
    // a VIP and therefore a bogus loop backedge. Returning 0 lets the caller
    // fall back to the pre-fold chain and then to vmp.vipOffset(), which
    // VMP's codegen makes exact (the dispatch bytecode read is the last module
    // load appended to a handler, intel.cc:27836).
    return fromLoad;
  }
  llvm::Value* currentTransferValue = nullptr;
  llvm::DenseMap<llvm::Value*, uint64_t> loadProvenance;
  // Address of the most recent module-backed load that was lifted. VMProtect's
  // codegen appends the bytecode read as the final module load of a handler
  // (AddEndHandlerCommands, intel.cc:27836), so at a transfer this is the VIP.
  VmpModel<Register> vmp;
  std::set<uint64_t> lmlSeen;
  uint64_t lmlLast = 0;
  std::deque<uint64_t> recentModuleLoads;
  std::unordered_map<uint64_t, uint64_t> stickyNonArgSlot;
  static uint64_t fetchRva(uint64_t addr) {
    if (addr >= 0x140000000ULL) {
      return addr - 0x140000000ULL;
    }
    if ((addr & 0xFF000000ULL) == 0x40000000ULL) {
      return addr & 0x00FFFFFFULL;
    }
    return addr;
  }
  // Memory policy ranges are registered at imageBase+RVA. Lifted GEP/load
  // addresses may still be in the rebased 0x40000000 lane; map those back
  // before consulting MemoryPolicy or isImmutableImageAddress.
  uint64_t memoryPolicyAddress(uint64_t addr) const {
    if (file.imageBase == 0) {
      return addr;
    }
    if (addr >= file.imageBase) {
      return addr;
    }
    if ((addr & 0xFF000000ULL) == 0x40000000ULL) {
      return file.imageBase + (addr & 0x00FFFFFFULL);
    }
    return addr;
  }
  bool isRecentModuleFetch(uint64_t addr) {
    if (addr == 0) {
      return false;
    }
    if (!isBytecodeAddress(addr) && !isModuleAddress(addr)) {
      return false;
    }
    const uint64_t rva = fetchRva(addr);
    auto matches = [&](uint64_t other) {
      return other != 0 && (other == addr || fetchRva(other) == rva);
    };
    if (matches(vmp.vipOffset()) || matches(currentVipOffset)) {
      return true;
    }
    for (uint64_t recent : recentModuleLoads) {
      if (matches(recent)) {
        return true;
      }
    }
    return false;
  }
  bool isArgumentDerived(llvm::Value* v) {
    if (v == nullptr) {
      return false;
    }
    std::set<llvm::Value*> seen;
    std::vector<llvm::Value*> work{v};
    unsigned visited = 0;
    while (!work.empty() && visited < 4000) {
      llvm::Value* x = work.back();
      work.pop_back();
      if (!x || !seen.insert(x).second) {
        continue;
      }
      ++visited;
      if (llvm::isa<llvm::Argument>(x)) {
        return true;
      }
      if (llvm::isa<llvm::Constant>(x)) {
        continue;
      }
      if (auto* u = llvm::dyn_cast<llvm::User>(x)) {
        for (auto& op : u->operands()) {
          work.push_back(op.get());
        }
      }
    }
    return false;
  }
  bool isStickyPredicate(uint64_t v) {
    if (v > 0xFFFULL) {
      return false;
    }
    return !isModuleAddress(v) && !isBytecodeAddress(v);
  }
  void noteModuleLoad(uint64_t addr) {
    const uint64_t prevCursor = vmp.vipOffset();
    if (!lmlSeen.insert(addr).second && addr != lmlLast) {
      std::cout << "[lmlrep] addr=0x" << std::hex << addr << " cur=0x"
                << lmlLast << std::dec << "\n"
                << std::flush;
    }
    lmlLast = addr;
    vmp.onModuleLoad(addr);
    recentModuleLoads.push_back(addr);
    while (recentModuleLoads.size() > 64) {
      recentModuleLoads.pop_front();
    }
    // MERGEN_DIAG_VIP=1: every cursor write. Look for loadBc=0 while prevBc=1
    // (handler RX / table clobbering a live bytecode VIP).
    const char* vipDiag = std::getenv("MERGEN_DIAG_VIP");
    if (vipDiag && vipDiag[0] != '\0' && vipDiag[0] != '0') {
      const uint64_t now = vmp.vipOffset();
      const bool loadBc = isBytecodeAddress(addr);
      const bool prevBc = isBytecodeAddress(prevCursor);
      const bool nowBc = isBytecodeAddress(now);
      const bool clobber = prevBc && !loadBc && now == addr;
      const bool skip = prevBc && !loadBc && now == prevCursor && now != addr;
      if (now != prevCursor || skip || clobber) {
        std::cout << "[vipcur] insn=0x" << std::hex
                  << (current_address - instruction.length) << " load=0x" << addr
                  << " prev=0x" << prevCursor << " now=0x" << now << std::dec
                  << " loadBc=" << (loadBc ? 1 : 0) << " prevBc="
                  << (prevBc ? 1 : 0) << " nowBc=" << (nowBc ? 1 : 0)
                  << " clobber=" << (clobber ? 1 : 0)
                  << " skip=" << (skip ? 1 : 0) << "\n"
                  << std::flush;
      }
    }
  }
  void logTransferVipPick(const char* kind, llvm::Value* /*transferVal*/,
                          uint64_t fromMod, uint64_t fromChain, uint64_t fromCur) {
    const char* env = std::getenv("MERGEN_DIAG_VIP");
    if (!env || env[0] == '\0' || env[0] == '0') {
      return;
    }
    const bool verbose = env[0] == '2';
    const char* src = "none";
    if (fromMod != 0 && currentVipOffset == fromMod) {
      src = "mod";
    } else if (fromChain != 0 && currentVipOffset == fromChain) {
      src = "chain";
    } else if (fromCur != 0 && currentVipOffset == fromCur) {
      src = "cursor";
    } else if (currentVipOffset != 0) {
      src = "other";
    }
    // =1: only suspicious picks (cursor fallback that is not bytecode).
    // =2: every transfer.
    const bool cursorBad =
        src[0] == 'c' && !isBytecodeAddress(currentVipOffset);
    if (!verbose && !cursorBad) {
      return;
    }
    std::cout << "[vippick] kind=" << kind << " insn=0x" << std::hex
              << (current_address - instruction.length) << " mod=0x" << fromMod
              << " chain=0x" << fromChain << " cursor=0x" << fromCur
              << " pick=0x" << currentVipOffset << std::dec
              << " exact=" << (currentVipIsExact ? 1 : 0) << " src=" << src
              << " cursorBc=" << (isBytecodeAddress(fromCur) ? 1 : 0) << "\n"
              << std::flush;
  }
  bool isSimpleRegMemOp() const {
    return instruction.mem_base != Register::None &&
           instruction.mem_index == Register::None &&
           instruction.mem_disp == 0 &&
           instruction.mem_segment != Register::GS &&
           instruction.mem_segment != Register::FS;
  }
  uint64_t currentVipOffset = 0;
  bool currentVipIsExact = false;
  std::set<uint64_t> seenVipOffsets;
  // Loop backedges are recognised by edge revisit, not by node revisit. The VM
  // dispatch trampoline is shared: many different handlers jump to the same
  // native target, which is what made a target-only criterion over-generalize.
  // A real loop repeats the same (source -> target) edge; a shared trampoline
  // is entered through different sources.
  std::set<uint64_t> seenBackedgeEdges;

  bool isStructuredLoopHeaderShape(BasicBlock* block) const {
    const bool trace = liftProgressDiagEnabled &&
                       (block == addrToBB.lookup(0x1401BAE0FULL) ||
                        block == addrToBB.lookup(0x1401BAE18ULL));
    // Detect the trampoline pattern at the header: a single unconditional br
    // (no other instructions). When the header is a trampoline, its successor
    // is the real per-instruction lift block; if that successor is mid-lift
    // (no proper terminator yet) we still want to recognise the loop. Without
    // a trampoline header we keep the original strict shape semantics so
    // ordinary linear lifts (VMP-style) don't get mis-classified as loops.
    auto isTrampoline = [](BasicBlock* bb) {
      if (!bb || bb->size() != 1) return false;
      auto* term = bb->getTerminator();
      auto* br = llvm::dyn_cast_or_null<llvm::BranchInst>(term);
      return br && !br->isConditional();
    };
    const bool entryIsTrampoline = isTrampoline(block);
    std::set<BasicBlock*> seenBlocks;
    auto* current = block;
    for (unsigned depth = 0; current && depth < 8; ++depth) {
      if (!seenBlocks.insert(current).second || current->empty()) {
        if (trace) std::cout << "[diag] shape depth=" << depth << " reject="
                             << (current->empty() ? "empty" : "cycle") << "\n";
        return false;
      }
      const size_t maxPreds = depth == 0 ? 2 : 1;
      const size_t preds = llvm::pred_size(current);
      if (preds > maxPreds) {
        if (trace) std::cout << "[diag] shape depth=" << depth
                             << " reject=pred-count preds=" << preds
                             << " max=" << maxPreds << "\n";
        return false;
      }
      auto* term = current->getTerminator();
      auto* branch = llvm::dyn_cast_or_null<llvm::BranchInst>(term);
      if (!branch) {
        // Trampoline-header relaxation: when the original header was a single
        // unconditional-br trampoline and we walked into a successor that is
        // currently being lifted (no proper terminator yet, but already has
        // instructions), accept the chain so loop generalization can latch
        // onto the header. The rest of canGeneralizeStructuredLoopHeader
        // (backwardVisitedTarget and blockCanReach) still filters out chains
        // that aren't actually loops.
        const bool hasProperTerminator = term && term->isTerminator();
        if (entryIsTrampoline && !hasProperTerminator && depth > 0 &&
            !current->empty()) {
          if (trace) std::cout << "[diag] shape depth=" << depth
                               << " ACCEPT partial-chain-after-trampoline\n";
          return true;
        }
        if (trace) std::cout << "[diag] shape depth=" << depth
                             << " reject=not-branch term="
                             << (term ? term->getOpcodeName() : "none")
                             << " isTerm=" << (hasProperTerminator ? 1 : 0)
                             << " entryTrampoline=" << (entryIsTrampoline ? 1 : 0)
                             << "\n";
        return false;
      }
      if (branch->isConditional()) {
        if (trace) std::cout << "[diag] shape depth=" << depth << " ACCEPT cond-br\n";
        return true;
      }
      if (branch->getNumSuccessors() != 1) {
        if (trace) std::cout << "[diag] shape depth=" << depth
                             << " reject=multi-succ count="
                             << branch->getNumSuccessors() << "\n";
        return false;
      }
      current = branch->getSuccessor(0);
    }
    if (trace) std::cout << "[diag] shape reject=depth-exceeded\n";
    return false;
  }
  bool blockCanReach(BasicBlock* source, BasicBlock* target) const {
    if (!source || !target) {
      return false;
    }
    std::vector<BasicBlock*> worklist{source};
    std::set<BasicBlock*> seenBlocks;
    while (!worklist.empty()) {
      auto* current = worklist.back();
      worklist.pop_back();
      if (!seenBlocks.insert(current).second) {
        continue;
      }
      if (current == target) {
        return true;
      }
      auto* terminator = current->getTerminator();
      if (!terminator) {
        continue;
      }
      for (unsigned i = 0; i < terminator->getNumSuccessors(); ++i) {
        worklist.push_back(terminator->getSuccessor(i));
      }
    }
    return false;
  }

  bool canGeneralizeStructuredLoopHeader(uint64_t addr,
                                         bool targetResolvedConcretely = false) {
    const bool contextAllows =
        targetResolvedConcretely
            ? currentPathSolveAllowsStructuredLoopGeneralizationForResolvedTarget()
            : currentPathSolveAllowsStructuredLoopGeneralization();
    const bool traceHere = liftProgressDiagEnabled &&
                           (addr == 0x1401BAE0FULL || addr == 0x1401BAE18ULL);
    auto reject = [&](const char* reason) {
      if (traceHere) {
        std::cout << "[diag] canGeneralize addr=0x" << std::hex << addr
                  << " current=0x" << blockInfo.block_address << std::dec
                  << " ctx=" << static_cast<int>(currentPathSolveContext)
                  << " resolved=" << (targetResolvedConcretely ? 1 : 0)
                  << " reject=" << reason << "\n";
      }
      return false;
    };
    // Diagnostic toggle: MERGEN_NO_LOOP_GEN=1 disables the entire loop-
    // generalization gate.  Use this to measure how much of a lift's
    // coverage/reachability depends on generalization vs. pure concrete
    // exploration.  Expected effect: more instructions visited, smaller
    // loops (no phi widening), potentially runaway lifts on real loops.
    if (const char* env = std::getenv("MERGEN_NO_LOOP_GEN")) {
      if (env[0] == '1' && env[1] == 0) return reject("env-disabled");
    }
    if (getControlFlow() != ControlFlow::Unflatten) return reject("not-unflatten");
    // Emergency generalization: when the BB budget is critically low and this
    // backward target has been visited several times, force generalization
    // regardless of path-solve context (except Ret, which has its own lifecycle).
    // This prevents vm_callret_loop and vm_bubblesort_loop style patterns from
    // exhausting the budget through concrete unrolling of what is clearly a loop.
    bool emergencyBypass = false;
    {
      const bool budgetCritical =
          maxBasicBlockBudget > 0 &&
          fnc->size() > (maxBasicBlockBudget * 3u / 4u);
      if (budgetCritical &&
          currentPathSolveContext != PathSolveContext::Ret &&
          visitedAddresses.contains(addr) &&
          addr <= blockInfo.block_address) {
        auto emergencyAttemptIt = liftAttemptCounts.find(addr);
        const unsigned emergencyAttempts =
            emergencyAttemptIt == liftAttemptCounts.end() ? 0 : emergencyAttemptIt->second;
        if (emergencyAttempts >= 4) {
          emergencyBypass = true;
        }
      }
    }
    if (!emergencyBypass) {
      if (!contextAllows) return reject("context-not-allowed");
      if (addr > blockInfo.block_address) return reject("forward-target");
      if (!visitedAddresses.contains(addr)) return reject("not-visited");
      // Revisit-count threshold: let a structured-loop header execute
      // concretely for the first N visits before switching to generalization.
      // Short guest loops (< N iterations) fully unroll; long loops and VM
      // dispatchers (which re-enter the header many times) still generalize.
      // Tunable via MERGEN_GEN_MIN_REVISITS.
      //
      // Shape-aware default: when the current path-solve context is
      // IndirectJump (or a resolved-target widening from one), the header
      // is most likely a VM dispatcher that re-enters with different
      // opcodes on every iteration. Holding off generalisation until the
      // header has been revisited enough times lets concrete exploration
      // cover more handlers before the state is abstracted to phis.
      // Simple guest loops reached through ConditionalBranch/DirectJump
      // keep threshold 0 so their first backedge immediately generalises
      // (which is what rewrite_smoke VM-loop samples rely on).
      //
      // Values {6, 8, 12} crash on example2-virt.bin - unrelated
      // dispatcher-state bug; avoid those when sweeping manually via
      // MERGEN_GEN_MIN_REVISITS.
      // Only IndirectJump context indicates a dispatcher (jmp reg / jmp [mem])
      // whose targets come from indirect computation. DirectJump and
      // ConditionalBranch paths belong to simple guest loops and keep
      // threshold 0 so their first backedge immediately generalises. This
      // preserves the rewrite_smoke VM-loop sample patterns while still
      // holding off generalisation on Themida-style dispatchers long enough
      // for concrete exploration to cover the IAT-gadget ret sites.
      const bool dispatcherShape =
          currentPathSolveContext == PathSolveContext::IndirectJump;
      unsigned revisitThreshold = dispatcherShape ? 128u : 0u;
      if (const char* env = std::getenv("MERGEN_GEN_MIN_REVISITS")) {
        char* end = nullptr;
        unsigned long parsed = std::strtoul(env, &end, 10);
        if (end != env && *end == '\0') {
          revisitThreshold = static_cast<unsigned>(parsed);
        }
      }
      auto attemptIt = liftAttemptCounts.find(addr);
      const unsigned attempts =
          attemptIt == liftAttemptCounts.end() ? 0 : attemptIt->second;
      if (attempts < revisitThreshold) return reject("below-revisit-threshold");
    }
    if (pendingLoopGeneralizationAddresses.contains(addr)) return reject("already-pending");
    if (generalizedLoopAddresses.contains(addr)) return reject("already-generalized");
    auto it = addrToBB.find(addr);
    if (it == addrToBB.end() || !it->second || it->second->empty())
      return reject("empty-or-missing-bb");
    // Only treat a visited header as reusable when it already reaches the
    // current block; acyclic backward jumps into earlier diamonds are not loops.
    if (traceHere) {
      auto* bb = it->second;
      std::string termName = bb->getTerminator()
                                 ? bb->getTerminator()->getOpcodeName()
                                 : std::string("NO-TERM");
      std::cout << "[diag] canGeneralize addr=0x" << std::hex << addr << std::dec
                << " bb-size=" << bb->size()
                << " term=" << termName
                << " succs=" << (bb->getTerminator() ? bb->getTerminator()->getNumSuccessors() : 0)
                << " preds=" << llvm::pred_size(bb)
                << "\n" << std::flush;
    }
    if (traceHere) {
      auto* bb = it->second;
      std::string bbText;
      llvm::raw_string_ostream os(bbText);
      bb->print(os);
      if (bbText.size() > 500) bbText = bbText.substr(0, 500) + " ...";
      std::cout << "[diag] canGeneralize addr=0x" << std::hex << addr << std::dec
                << " bb-ir: " << bbText << "\n" << std::flush;
    }
    if (!isStructuredLoopHeaderShape(it->second)) return reject("bad-shape");
    if (!blockInfo.block) return reject("no-current-block");
    if (!blockCanReach(it->second, blockInfo.block)) return reject("no-reach");
    if (traceHere) {
      std::cout << "[diag] canGeneralize addr=0x" << std::hex << addr
                << " current=0x" << blockInfo.block_address << std::dec
                << " ACCEPT\n";
    }
    return true;
  }

  void liftBasicBlockFromAddress(uint64_t addr) {
    ++liftStats.blocks_attempted;
    ++liftAttemptCounts[addr];
    if (liftProgressDiagEnabled) {
      std::string bbName = "<none>";
      auto bbIt = addrToBB.find(addr);
      if (bbIt != addrToBB.end() && bbIt->second) {
        bbName = bbIt->second->getName().str();
      }
      std::cout << "[bb] 0x" << std::hex << addr << std::dec << " " << bbName
                << "\n"
                << std::flush;
    }
    {
      if (addr == 0x1403B4FF9ULL || addr == 0x403B4FF9ULL) {
        auto hexOrIr = [](llvm::Value* v) -> std::string {
          if (!v) {
            return "<null>";
          }
          if (auto* ci = llvm::dyn_cast<llvm::ConstantInt>(v)) {
            std::ostringstream os;
            os << "0x" << std::hex << ci->getZExtValue();
            return os.str();
          }
          std::string text;
          llvm::raw_string_ostream os(text);
          v->print(os);
          return text.substr(0, 120);
        };
        static unsigned trampVisits = 0;
        ++trampVisits;
        std::cout << "[tramp] enter n=" << trampVisits << " addr=0x" << std::hex
                  << addr << " r8=" << hexOrIr(this->GetRegisterValue(Register::R8))
                  << " r10=" << hexOrIr(this->GetRegisterValue(Register::R10))
                  << std::dec << "\n"
                  << std::flush;
      }
    }
    printvalue2(this->finished);
    printvalue2(this->run);
    this->run = 1;
    while (this->finished == 0 && this->run) {
      {
        auto blockSetupSample = profiler.sample("lift_block_setup");
        // Speculative call budget check: bail if callee is too complex.
        if (speculativeCall.active && speculativeCallBudget > 0) {
          speculativeCallBudget--;
          if (speculativeCallBudget == 0) {
            // Budget exhausted �?abandon speculative inline.
            if (!builder->GetInsertBlock()->getTerminator()) {
              builder->CreateUnreachable();
            }
            run = 0;
            speculativeCall.bailedOut = true;
            speculativeCall.active = false;

            // Trim worklist: remove all callee blocks pushed since the call.
            unvisitedBlocks.resize(speculativeCall.worklistFloor);

            // Push the return continuation BB onto the worklist.
            auto it = addrToBB.find(speculativeCall.returnAddr);
            if (it != addrToBB.end()) {
              BBInfo retInfo(speculativeCall.returnAddr, it->second);
              unvisitedBlocks.push_back(retInfo);
            }

            std::cout << "[call-abi] speculative inline bail-out at 0x"
                      << std::hex << (addr) << std::dec
                      << ", resuming at 0x" << std::hex
                      << speculativeCall.returnAddr << std::dec
                      << "\n" << std::flush;
            diagnostics.info(DiagCode::CallOutlinedSpecBailout, addr,
                             "Speculative inline bail-out, resuming at return address");
            return;
          }
        }

        auto currentblock = builder->GetInsertBlock()->getName();
        printvalue2(currentblock);
      }
      liftAddress(addr);
      ++liftStats.instructions_lifted;
      addr = current_address;
    }
    if (this->finished)
      ++liftStats.blocks_completed;
  }

  void sealIncompleteBlocks() {
    for (auto& BB : *fnc) {
      if (BB.getTerminator())
        continue;
      llvm::IRBuilder<> fallbackBuilder(&BB);
      fallbackBuilder.CreateRet(llvm::UndefValue::get(fnc->getReturnType()));
      // Surface the seal as a warning so silent dataflow corruption
      // (ret undef -> noundef UB -> O2 unreachable) is visible in
      // output_diagnostics.json instead of having to read the IR.
      diagnostics.warning(
          DiagCode::IncompleteBlockSealed, 0,
          "Basic block '" + BB.getName().str() +
              "' had no terminator; sealed with ret undef");
    }
  }

  // Prints a compact summary of which addresses the lift attempted and how
  // often. Useful for diagnosing whether progress through a VM's handler graph
  // is genuine (many distinct addresses, low revisit count) or the dispatcher
  // is spinning (few distinct addresses, high revisit counts).
  void dumpLiftProgressReport(std::ostream& os) const {
    if (!liftProgressDiagEnabled || liftAttemptCounts.empty()) {
      return;
    }
    // Sort addresses by revisit count, descending.
    std::vector<std::pair<uint64_t, uint32_t>> entries;
    entries.reserve(liftAttemptCounts.size());
    for (const auto& kv : liftAttemptCounts) {
      entries.emplace_back(kv.first, kv.second);
    }
    std::sort(entries.begin(), entries.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    uint64_t totalAttempts = 0;
    uint32_t maxCount = 0;
    // Histogram buckets: 1, 2, 3-4, 5-8, 9-16, 17-32, 33+
    std::array<uint32_t, 7> histogram{};
    auto bucket = [](uint32_t count) -> size_t {
      if (count <= 1) return 0;
      if (count == 2) return 1;
      if (count <= 4) return 2;
      if (count <= 8) return 3;
      if (count <= 16) return 4;
      if (count <= 32) return 5;
      return 6;
    };
    for (const auto& [addr, count] : entries) {
      totalAttempts += count;
      if (count > maxCount) maxCount = count;
      ++histogram[bucket(count)];
    }
    os << "[diag] lift-progress unique_addresses=" << entries.size()
       << " total_attempts=" << totalAttempts
       << " max_revisits=" << maxCount << "\n";
    os << "[diag] lift-progress histogram 1/2/3-4/5-8/9-16/17-32/33+:";
    for (uint32_t count : histogram) os << " " << count;
    os << "\n";
    const size_t top = std::min<size_t>(entries.size(), 16);
    os << "[diag] lift-progress top-" << top << " revisited addresses:\n";
    for (size_t i = 0; i < top; ++i) {
      os << "  0x" << std::hex << entries[i].first << std::dec
         << " x" << entries[i].second << "\n";
    }
    std::vector<uint64_t> reachedAddresses;
    reachedAddresses.reserve(entries.size());
    for (const auto& [addr, _count] : entries) {
      reachedAddresses.push_back(addr);
    }
    std::sort(reachedAddresses.begin(), reachedAddresses.end());
    os << "[diag] lift-progress reached addresses:";
    for (uint64_t addr : reachedAddresses) {
      os << " 0x" << std::hex << addr << std::dec;
    }
    os << "\n";
    constexpr std::array<uint64_t, 12> kExpectedSecondFeedbackWindow = {
        0x140023582ULL, 0x1400235B4ULL, 0x14002360DULL, 0x140023627ULL,
        0x14002366EULL, 0x140023689ULL, 0x140023693ULL, 0x1400236B3ULL,
        0x140023799ULL, 0x1400237AAULL, 0x1400237CFULL, 0x1400237DCULL,
    };
    os << "[diag] lift-progress expected second-feedback window:";
    for (uint64_t addr : kExpectedSecondFeedbackWindow) {
      const bool reached =
          std::binary_search(reachedAddresses.begin(), reachedAddresses.end(), addr);
      os << " 0x" << std::hex << addr << (reached ? ":hit" : ":miss") << std::dec;
    }
    os << "\n" << std::flush;
  }

  bool addUnvisitedAddr(BBInfo bb) {
    printvalue2(bb.block_address);
    printvalue2("added");
    unvisitedBlocks.push_back(std::move(bb));
    return true;
  }

  /*
  filter : filter for empty blocks
  */
  bool getUnvisitedAddr(BBInfo& out, bool filter = 0) {
    if (liftBudgetExceeded) {
      unvisitedBlocks.clear();
      sealIncompleteBlocks();
      return false;
    }
    while (!unvisitedBlocks.empty()) {
      out = std::move(unvisitedBlocks.back());
      unvisitedBlocks.pop_back();

      const uint64_t normalizedAddr =
          normalizeFileBackedRuntimeTargetAddress(out.block_address);
      if (normalizedAddr != out.block_address) {
        addrToBB[normalizedAddr] = out.block;
        out.block_address = normalizedAddr;
      }

      // In Basic mode, skip blocks that already have instructions
      // (they were processed in a previous iteration).
      if (getControlFlow() == ControlFlow::Basic && !out.block->empty() &&
          filter) {
        printvalue2("not empty ;D ");
        continue;
      }

      printvalue2("adding :" + std::to_string(out.block_address) +
                  out.block->getName());
      const bool bypassesStackTracking =
          pendingLoopGeneralizationAddresses.contains(out.block_address) &&
          stackBypassGeneralizedLoopAddresses.contains(out.block_address);
      bypassStackConcolicTracking = bypassesStackTracking;
      currentBlockRestoreMode = bypassesStackTracking
                                    ? BlockRestoreMode::GeneralizedLoop
                                    : BlockRestoreMode::Normal;
      if (pendingLoopGeneralizationAddresses.contains(out.block_address)) {
        pendingLoopGeneralizationAddresses.erase(out.block_address);
        stackBypassGeneralizedLoopAddresses.erase(out.block_address);
        generalizedLoopAddresses.insert(out.block_address);
      }
      visitedAddresses.insert(out.block_address);
      // Per-block VA breadcrumb to pin crashes when a debugger is not
      // available. Emitted only when MERGEN_BLOCK_TRACE_FILE is set.
      if (const char* trace = std::getenv("MERGEN_BLOCK_TRACE_FILE")) {
        FILE* f = std::fopen(trace, "a");
        if (f) {
          std::fprintf(f, "%zu 0x%llx\n", fnc->size(),
              (unsigned long long)out.block_address);
          std::fflush(f);
          std::fclose(f);
        }
      }
      blockInfo = out;
      return true;
    }
    return false;
  }

  void writeFunctionToFile(const std::string filename) {

    std::error_code EC_noopt;
    llvm::raw_fd_ostream OS_noopt(filename, EC_noopt);
    M->print(OS_noopt, nullptr);
  }

  // ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
  llvm::DenseMap<llvm::Instruction*, llvm::APInt> assumptions;
  // Memoization cache for computePossibleValues, cleared per solvePath call.
  llvm::DenseMap<llvm::Value*, std::set<llvm::APInt, APIntComparator>> pv_cache;
  llvm::DenseMap<uint64_t, ValueByteReference> buffer;
  using flagManager = std::array<LazyValue, FLAGS_END>;
  // llvm::DenseMap<Value*, flagManager> flagbuffer;

  flagManager FlagList;
  struct FoldOrigin {
    unsigned opcode;
    llvm::Value* lhs;
    llvm::Value* rhs;
  };
  llvm::DenseMap<llvm::Value*, FoldOrigin> foldOrigin;
  // Record the pre-fold operands of a meaningful fold (at least one operand is
  // not a constant). Trivial constant-from-constant folds are skipped and the
  // first meaningful fold wins, so a uniqued constant is not overwritten by a
  // later identity fold such as `or C, C` - that overwrite is what turned the
  // reconstruction into a self-loop.
  bool recordFoldOrigin(llvm::Value* result, unsigned opcode, llvm::Value* lhs,
                        llvm::Value* rhs) {
    if (!result || !llvm::isa<llvm::Constant>(result)) return false;
    // An identity fold (the result is one of the operands, e.g. a same-width
    // sext or `or C, C`) carries no provenance; recording it would overwrite
    // the meaningful fold that produced this constant.
    if (lhs == result || rhs == result) return false;
    // First meaningful fold wins: LLVM uniques constants, so a later fold of
    // the same constant must not replace the chain that reaches the load.
    if (foldOrigin.find(result) != foldOrigin.end()) return false;
    foldOrigin[result] = FoldOrigin{opcode, lhs, rhs};
    return true;
  }
  // Blog rule (Devirtualization of Themida, Virtualized Control Flow): walk the
  // transfer target backwards to the module load that feeds it. The load itself
  // was folded away, so the walk follows the recorded pre-fold chain
  // (foldOrigin) and, per VMP codegen, at each node follows the operand that is
  // not the per-instance base constant - the target is
  // `jmp_registr_ + sext(decrypt(load))` (intel.cc:27845).
  uint64_t vipFromFoldChain(llvm::Value* target) {
    static int chainDbg = 0;
    const bool dbg = chainDbg < 400;
    if (dbg) {
      ++chainDbg;
      std::cout << "[chain] start " << (target ? "v" : "null") << "\n"
                << std::flush;
    }
    std::set<llvm::Value*> seen;
    llvm::Value* v = target;
    for (int depth = 0; v && depth < 64; ++depth) {
      if (dbg) {
        auto dumpV = [&](const char* tag, llvm::Value* x) {
          if (!x) {
            std::cout << "   " << tag << " null\n";
            return;
          }
          std::string s;
          llvm::raw_string_ostream os(s);
          x->print(os);
          std::cout << "   " << tag << " " << os.str().substr(0, 80)
                    << " fold=" << foldOrigin.count(x)
                    << " prov=" << loadProvenance.count(x) << "\n";
        };
        std::cout << "[chain] d" << depth << " fold=" << foldOrigin.count(v)
                  << " prov=" << loadProvenance.count(v) << "\n";
        auto itD = foldOrigin.find(v);
        if (itD != foldOrigin.end()) {
          dumpV("lhs", itD->second.lhs);
          dumpV("rhs", itD->second.rhs);
        }
        std::cout << std::flush;
      }
      // Prefer the recorded pre-fold chain: a constant that a fold produced has
      // a foldOrigin entry, and its loadProvenance entry (if any) is stale
      // because LLVM uniques constants.
      auto it = foldOrigin.find(v);
      if (it == foldOrigin.end()) {
        auto prov = loadProvenance.find(v);
        return prov != loadProvenance.end() ? prov->second : 0;
      }
      auto isModuleConst = [&](llvm::Value* x) {
        auto* ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(x);
        return ci && isModuleAddress(ci->getZExtValue());
      };
      auto hasChain = [&](llvm::Value* x) {
        return x && (foldOrigin.count(x) || loadProvenance.count(x));
      };
      llvm::Value* next = nullptr;
      if (hasChain(it->second.lhs) && hasChain(it->second.rhs)) {
        // Both sides continue; the base is the module-address constant, so the
        // other side is the decrypt chain that reaches the bytecode load.
        next = vmp.pickDecryptOperand(
            it->second.lhs, it->second.rhs, isModuleConst(it->second.lhs),
            hasChain(it->second.lhs), hasChain(it->second.rhs));
      } else if (hasChain(it->second.lhs)) {
        next = it->second.lhs;
      } else if (hasChain(it->second.rhs)) {
        next = it->second.rhs;
      }
      if (!next || !seen.insert(next).second) {
        return 0;
      }
      v = next;
    }
    return 0;
  }
  RegisterManagerConcolic<Register> Registers;

  llvm::DomConditionCache* DC = new llvm::DomConditionCache();

  unsigned int instct = 0;
  LiftStats liftStats;
  // Per-address lift attempt counts. Only populated when the lift-progress diag
  // is requested (MERGEN_DIAG_LIFT_PROGRESS=1); otherwise stays empty and the
  // increment below is a no-op on a DenseMap miss because we gate it behind the
  // same flag. Used by dumpLiftProgressReport to show whether the dispatcher
  // is genuinely advancing through distinct VM handlers or churning on a few.
  llvm::DenseMap<uint64_t, uint32_t> liftAttemptCounts;
  bool liftProgressDiagEnabled = false;
  LiftDiagnostics diagnostics;
  PipelineProfiler profiler;
  llvm::SimplifyQuery* cachedquery;

  llvm::BasicBlock* lastBB = nullptr;
  unsigned int BIlistsize = 0;

  std::map<uint64_t, uint64_t> pageMap;
  std::vector<llvm::BranchInst*> BIlist;

  // Set by branchHelper after resolving a conditional branch.
  // Test framework reads this to verify jcc taken/not-taken.
  bool hadConditionalBranch = false;
  bool lastConditionalBranchResolved = false;
  bool lastBranchTaken = false;
  // DenseMap<InstructionKey, Value*, InstructionKey::InstructionKeyInfo>
  // cache;
  InstructionCache cache;
  struct GEPinfo {
    Value* addr;
    uint8_t type;
    bool TEB;

    GEPinfo() : addr(nullptr), type(0), TEB(0){};

    GEPinfo(Value* addr, uint8_t type, bool TEB)
        : addr(addr), type(type), TEB(TEB){};

    GEPinfo(const GEPinfo& other)
        : addr(other.addr), type(other.type), TEB(other.TEB){};

    GEPinfo(GEPinfo& other)
        : addr(other.addr), type(other.type), TEB(other.TEB){};

    bool operator==(const GEPinfo& other) const {
      if (addr != other.addr)
        return false;
      if (type != other.type)
        return false;
      return TEB == other.TEB;
    }

    struct GEPinfoKeyInfo {
      // Custom hash function
      static inline unsigned getHashValue(const GEPinfo& key) {
        return llvm::hash_combine(key.addr, key.type + key.TEB);
      }

      // Equality function
      static inline bool isEqual(const GEPinfo& lhs, const GEPinfo& rhs) {
        return lhs == rhs;
      }

      // Define empty and tombstone keys
      static inline GEPinfo getEmptyKey() { return GEPinfo(nullptr, 0, 0); }

      static inline GEPinfo getTombstoneKey() {
        return GEPinfo(nullptr, static_cast<uint8_t>(-1), true);
      }
    };
  };
  llvm::DenseMap<GEPinfo, Value*, typename GEPinfo::GEPinfoKeyInfo> GEPcache;
  std::vector<llvm::Instruction*> memInfos;

  // todo : std::set
  std::vector<BBInfo> unvisitedBlocks;
  std::set<uint64_t> visitedAddresses;
  std::set<uint64_t> generalizedLoopAddresses;
  std::set<uint64_t> pendingLoopGeneralizationAddresses;
  std::set<uint64_t> stackBypassGeneralizedLoopAddresses;
  // PCs where the ret-to-IAT chain (lift_ret) has successfully recognised
  // a concrete import call. Used to suppress the UnresolvedRetChain
  // warning for downstream symbolic re-entries of the same PC - the
  // concrete semantics are already captured by the earlier chain site.
  std::set<uint64_t> chainedImportRetSites;
  llvm::DenseMap<uint64_t, llvm::BasicBlock*> addrToBB;

  // creates an edge to created bb
  // TODO: wrapper for createbr, condbr, switch and update it there.
  BasicBlock* createBudgetedBasicBlock(const std::string& name, uint64_t diagAddr) {
    if (maxBasicBlockBudget > 0 && fnc->size() >= maxBasicBlockBudget) {
      if (!liftBudgetExceeded) {
        diagnostics.error(
            DiagCode::LiftBlockBudgetExceeded, diagAddr,
            "Basic-block budget exceeded during lifting; aborting to avoid loop/state explosion");
        liftBudgetExceeded = true;
      }
      if (!liftAbortBlock) {
        liftAbortBlock =
            BasicBlock::Create(context, "bb_lift_budget_exceeded", fnc);
        llvm::IRBuilder<> abortBuilder(liftAbortBlock);
        abortBuilder.CreateRet(llvm::UndefValue::get(fnc->getReturnType()));
      }
      return liftAbortBlock;
    }

    return BasicBlock::Create(context, name, fnc);
  }


  BasicBlock* replaceWithGeneralizedLoopBlock(uint64_t addr, const std::string& name) {
    auto* newBlock = createBudgetedBasicBlock(name, addr);
    if (newBlock == liftAbortBlock) {
      return newBlock;
    }

    auto it = addrToBB.find(addr);
    if (it != addrToBB.end() && it->second && it->second != newBlock) {
      static_cast<Derived*>(this)->migrate_generalized_loop_block_impl(it->second,
                                                                      newBlock);
      it->second->replaceAllUsesWith(newBlock);
    }

    addrToBB[addr] = newBlock;
    return newBlock;
  }


  BasicBlock* getLiftedBackedgeBB(uint64_t addr) {
    // A resolved backward target is eligible for reuse regardless of whether
    // the branching source was direct, conditional, or indirect. Once we have
    // a non-empty generalized block for the address, re-entering it on a
    // subsequent iteration should branch into that block rather than cutting a
    // fresh empty one through `getOrCreateBB` (which would orphan the body).
    if (getControlFlow() != ControlFlow::Unflatten ||
        !currentPathSolveAllowsStructuredLoopGeneralizationForResolvedTarget()) {
      return nullptr;
    }
    if (addr > blockInfo.block_address ||
        !generalizedLoopAddresses.contains(addr)) {
      return nullptr;
    }
    auto it = addrToBB.find(addr);
    if (it == addrToBB.end() || it->second->empty()) {
      return nullptr;
    }
    return it->second;
  }


  BasicBlock* getOrCreateBB(uint64_t addr, std::string name) {
    addr = normalizeFileBackedRuntimeTargetAddress(addr);
    auto it = addrToBB.find(addr);
    if (getControlFlow() == ControlFlow::Basic) {
      if (it != addrToBB.end()) {
        return it->second;
      }
    }
    if (getControlFlow() == ControlFlow::Unflatten &&
        it != addrToBB.end() && it->second && inlinePolicy.isOutline(addr)) {
      // Real function entry points are not path-sensitive jump-table states:
      // reuse their lifted block instead of replacing it on every call site.
      return it->second;
    }
    auto bb = createBudgetedBasicBlock(name, addr);
    if (bb == liftAbortBlock) {
      return bb;
    }
    addrToBB[addr] = bb;
    DTU->applyUpdates({{DominatorTree::Insert, this->blockInfo.block, bb}});

    return bb;
  }

  // global
  llvm::LLVMContext context;
  llvm::Value* memoryAlloc;
  llvm::Function* fnc;
  llvm::Module* M;
  llvm::BasicBlock* bb;

protected:
  void createFunction() {
    return static_cast<Derived*>(this)->createFunction_impl();
  }

  void InitRegisters() {

    return static_cast<Derived*>(this)->InitRegisters_impl();
  }

  llvm::Value* getFlagValue(Flag f) {
    return static_cast<Derived*>(this)->GetFlagValue_impl(f);
  }
  void setFlagValue(Flag f, Value* v) {
    return static_cast<Derived*>(this)->SetFlagValue_impl(f, v);
  }

  constexpr ControlFlow getControlFlow() {
    return static_cast<Derived*>(this)->getControlFlow_impl();
  }

public:
  void finalizeIncompleteBlocks() { sealIncompleteBlocks(); }
  AliasAnalysis* AA;
  DominatorTree* DT;
  PostDominatorTree* PDT;
  DomTreeUpdater* DTU;
  MemorySSA* MSSA;
  MemorySSAUpdater* MSSAU;
  TargetLibraryInfo* TLI;
  AssumptionCache* AC;
  TargetTransformInfo* TTI;
  lifterClassBase() {
    static_assert(lifterConcept<Derived, Register>,
                  "Derived should satisfy lifterConcept");
    M = new llvm::Module("lifter_module", context);

    createFunction();
    this->bb = llvm::BasicBlock::Create(this->context, "entry", this->fnc);

    this->builder = std::make_unique<llvm::IRBuilder<>>(this->bb);
    // InitRegisters() is deliberately NOT called here: it writes the derived
    // class's register array, which is not constructed yet at this point. The
    // derived constructor calls it once its members exist.
    TargetLibraryInfoImpl TLIImpl(Triple(fnc->getParent()->getTargetTriple()));
    TLI = new TargetLibraryInfo(TLIImpl);

    AA = new AliasAnalysis(*TLI);
    DT = new DominatorTree(*fnc);
    PDT = new PostDominatorTree(*fnc);
    DTU = new DomTreeUpdater(DT, PDT, DomTreeUpdater::UpdateStrategy::Lazy);
    MSSA = new MemorySSA(*fnc, AA, DT);
    MSSAU = new MemorySSAUpdater(MSSA);

    TTI = new TargetTransformInfo(fnc->getParent()->getDataLayout());
    AC = new AssumptionCache(*fnc, TTI);
  };

  ~lifterClassBase() {
    // LLVM analysis objects have interdependent destructors (MemorySSA
    // references DT and AA, MSSAU references MSSA, etc.). Deleting in any
    // order risks use-after-free inside LLVM's own teardown. Since this is
    // a CLI process that exits after the pipeline, we intentionally leak
    // these allocations. The OS reclaims everything on process exit.
    //
    // TODO: Migrate to unique_ptr with a custom deleter that tears down in
    // dependency order, or use LLVM's AnalysisManager which handles this.
  }

  lifterClassBase(const lifterClassBase& other) = delete;

  void liftInstruction();
  void liftInstructionSemantics();
  void branchHelper(llvm::Value* condition, const std::string& instname,
                    const int numbered, const bool reverse = false);

  std::optional<llvm::Value*> evaluateLLVMExpression(llvm::Value* value);

  // getters-setters
  void setFlag(const Flag flag, llvm::Value* newValue);
  void setFlagUndef(const Flag flag) {
    auto undef = UndefValue::get(builder->getInt1Ty());
    FlagList[flag].set(undef); // Set the new value directly
  }

  void setFlag(const Flag flag, std::function<llvm::Value*()> calculation);
  LazyValue getLazyFlag(const Flag flag);
  llvm::Value* getFlag(const Flag flag);
  llvm::Value* GetValueFromHighByteRegister(Register reg);
  llvm::Value* GetRegisterValue(const Register key);

protected:
  llvm::Value* GetRegisterValue_internal(const Register key) {
    return static_cast<Derived*>(this)->GetRegisterValue_impl(key);
  }
  void SetRegisterValue_internal(const Register key, llvm::Value* val) {
    {
      const Register canonicalReg = getBiggestEncoding<Register>(key);
      const bool watchReg = canonicalReg == Register::RAX ||
                            canonicalReg == Register::R11 ||
                            canonicalReg == Register::RBP;
      auto* ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(val);
      const bool isConst = ci != nullptr;
      const uint64_t cval = isConst ? ci->getZExtValue() : 0;
      const uint64_t lo32 = cval & 0xFFFFFFFFULL;
      const uint64_t insnVA = current_address - instruction.length;
      const bool watchInsn =
          insnVA == 0x14038447DULL || insnVA == 0x4038447DULL ||
          insnVA == 0x1403DC6F9ULL || insnVA == 0x403DC6F9ULL ||
          insnVA == 0x1403BD63FULL || insnVA == 0x403BD63FULL ||
          insnVA == 0x1403A861CULL || insnVA == 0x403A861CULL ||
          insnVA == 0x1403BD90BULL || insnVA == 0x403BD90BULL;
      const bool watchVal =
          isConst && (lo32 == 0xF1FFEA81ULL || lo32 == 0xF1FAEA31ULL ||
                      lo32 == 0xE0515CEULL || lo32 == 0x5004FULL ||
                      lo32 == 0xD348EA81ULL || lo32 == 0xD348EAC1ULL);
      if (watchReg && (watchInsn || watchVal)) {
        std::cout << "[regwr] insn=0x" << std::hex << insnVA << " reg="
                  << magic_enum::enum_name(canonicalReg)
                  << " val=" << (isConst ? "" : "<ssa>");
        if (isConst) {
          std::cout << "0x" << cval;
        }
        std::cout << std::dec << "\n" << std::flush;
      }
    }
    if (const char* path = std::getenv("MERGEN_REG_STREAM_FILE")) {
      // One long-lived stream: opening the file per write would mean hundreds of
      // thousands of open/close cycles and dominate the lift.
      static std::ofstream* regStream = nullptr;
      static bool streamInit = false;
      if (!streamInit) {
        streamInit = true;
        regStream = new std::ofstream(path, std::ios::out);
      }
      // Every register write consumes a sequence number, including the ones the
      // filter below drops, so the number is a true execution-order key shared
      // with the memory stream. A ring of recent events is retained so the writes
      // leading up to a watched instruction can be dumped even though they were
      // not interesting when they happened.
      const unsigned long long seq = nextMemEventSeq();
      static std::deque<std::string> ring;
      static int windowLeft = 0;
      const uint64_t insnVA = current_address - instruction.length;
      const Register canonicalReg = getBiggestEncoding<Register>(key);
      std::string line = "REG," + std::to_string(seq) + ",0x";
      {
        std::ostringstream os;
        os << std::hex << insnVA;
        line += os.str();
      }
      line += "," + std::string(magic_enum::enum_name(canonicalReg)) + ",";
      line += (val && llvm::isa<llvm::Constant>(val)) ? "1," : "0,";
      if (auto* ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(val)) {
        std::ostringstream os;
        os << "0x" << std::hex << ci->getZExtValue();
        line += os.str();
      } else {
        line += "-";
      }
      // A store writes no register, so the interesting events cannot be found by
      // watching an instruction VA. Persist every register write instead and let
      // the reader join this stream with the memory stream on the shared sequence
      // number; that is the only way to see which write set R8 before a store.
      if (const char* winPath = std::getenv("MERGEN_REG_WINDOW_FILE")) {
        static std::ofstream* winStream = nullptr;
        static bool winInit = false;
        if (!winInit) {
          winInit = true;
          winStream = new std::ofstream(winPath, std::ios::out);
        }
        if (winStream && *winStream) {
          *winStream << line << "\n";
        }
      }
      ring.push_back(line);
      if (ring.size() > 32) {
        ring.pop_front();
      }
      if (regStream && *regStream &&
          (canonicalReg == Register::R8 || canonicalReg == Register::R10 ||
           canonicalReg == Register::R11 || canonicalReg == Register::RSP ||
           canonicalReg == Register::RDI || canonicalReg == Register::RAX ||
           canonicalReg == Register::RCX || canonicalReg == Register::RDX ||
           canonicalReg == Register::RBX || canonicalReg == Register::RSI ||
           canonicalReg == Register::RBP || canonicalReg == Register::R9 ||
           canonicalReg == Register::R12 || canonicalReg == Register::R13 ||
           canonicalReg == Register::R14 || canonicalReg == Register::R15)) {
        *regStream << line << "\n";
      }
    }
    return static_cast<Derived*>(this)->SetRegisterValue_impl(key, val);
  }

public:
  llvm::Value* GetMemoryValue(llvm::Value* address, uint8_t size);
  llvm::Value* SetValueToHighByteRegister(const Register reg,
                                          llvm::Value* value);
  llvm::Value* SetValueToSubRegister_8b(const Register reg, llvm::Value* value);
  llvm::Value* SetValueToSubRegister_16b(const Register reg,
                                         llvm::Value* value);

  // this actually might be a good reason for static polymorphism, since
  // current implementation cant be encapsulated in a class very efficently
  void createMemcpy(llvm::Value* src, llvm::Value* dest, llvm::Value* size);

  void SetRegisterValue(const Register key, llvm::Value* value);

  template <uint8_t count, bool little_endian = true>
  Value* LoadValueFromMemByBytes(llvm::Value* address) {
    llvm::Value* returnv = builder->getIntN(count * 8, 0);
    for (int i = 0; i < count; i++) {

      auto offset =
          builder->getIntN(address->getType()->getIntegerBitWidth(), i);

      auto pointer = getPointer(createAddFolder(address, offset));

      loadMemoryOp(pointer);
      printvalue(pointer);
      LazyValue retval([this, pointer]() {
        auto ret = builder->CreateLoad(builder->getIntNTy(8),
                                       pointer /*, "Loadxd-" + address + "-"*/);
        return ret;
      });

      if (Value* solvedLoad = solveLoad(retval, pointer, 8)) {
        printvalue(solvedLoad);
        if constexpr (little_endian) {
          // shl by i,
          solvedLoad = createShlFolder(
              createZExtFolder(solvedLoad, builder->getIntNTy(count * 8)),
              i * 8);

        } else {
          // shl by count-i-1*8
          solvedLoad = createShlFolder(
              createZExtFolder(solvedLoad, builder->getIntNTy(count * 8)),
              (count - 1 - i) * 8);
        }
        printvalue(returnv);
        printvalue(solvedLoad);
        Value* lhsPrev;
        ConstantInt* ci = builder->getIntN(count * 8, 0);
        if (llvm::PatternMatch::match(
                returnv, llvm::PatternMatch::m_ZExt(llvm::PatternMatch::m_Trunc(
                             llvm::PatternMatch::m_Value(lhsPrev)))) &&
            llvm::PatternMatch::match(solvedLoad,
                                      llvm::PatternMatch::m_ConstantInt(ci))) {
          printvalue2("0, postreturn");
          returnv = createTruncFolder(lhsPrev, builder->getIntNTy(count * 8));
        } else {
          printvalue2("1, postreturn");

          returnv = createOrFolder(returnv, solvedLoad);
        }
      } else {
        returnv = createOrFolder(returnv, retval.get());
      }
    }
    return returnv;
  }

  template <int count, bool little_endian = true>
  void StoreValueToMemByBytes(llvm::Value* address, llvm::Value* value) {
    printvalue(value);
    for (int i = 0; i < count; i++) {
      llvm::Value* storeval = nullptr;
      auto offset =
          builder->getIntN(address->getType()->getIntegerBitWidth(), i);
      auto pointer = getPointer(createAddFolder(address, offset));
      if constexpr (little_endian) {

        storeval = createTruncFolder(createLShrFolder(value, (i) * 8),
                                     builder->getIntNTy(8));
      } else {
        storeval =
            createTruncFolder(createLShrFolder(value, (count - 1 - i) * 8),
                              builder->getIntNTy(8));
      }
      printvalue(storeval);
      auto store = builder->CreateStore(storeval, pointer);
      insertMemoryOp(cast<StoreInst>(store));
    }
  }

  void SetMemoryValue(llvm::Value* address, llvm::Value* value);
  llvm::Value* privilegeAllowsIF();
  void SetRFLAGSValue(llvm::Value* value);
  PATH_info solvePath(llvm::Function* function, uint64_t& dest,
                      llvm::Value* simplifyValue);
  llvm::Value* popStack(int size);
  void pushFlags(const std::vector<llvm::Value*>& value,
                 const std::string& address);
  std::vector<llvm::Value*> GetRFLAGS();


  Register GetAccumulatorRegister(uint8_t size = 64) {
    switch (size) {
    case 64:
      return Register::RAX;
    case 32:
      return Register::EAX;
    case 16:
      return Register::AX;
    case 8:
      return Register::AL;
    default:
      UNREACHABLE("invalid acc");
    }
  }

  llvm::Value* createLoad(llvm::Value* ptr) {
    //
    return nullptr;
  }
  void createStore(llvm::Value* ptr, llvm::Value* val) {
    //
  }

  llvm::Value* GetIndexValue(uint8_t index);

  void SetIndexValue(uint8_t index, Value* value);
  /*
    llvm::Value* GetOperandValue(const ZydisDecodedOperand& op,
                                 const int possiblesize,
                                 const std::string& address = "");
    llvm::Value* SetOperandValue(const ZydisDecodedOperand& op,
                                 llvm::Value* value,
                                 const std::string& address = "");
                                 */
  llvm::Value* GetRFLAGSByte(unsigned byteIndex);
  llvm::Value* GetRFLAGSValue();
  void dumpRflagsDiag(const char* tag, uint64_t rva,
                      llvm::Value* rflagsIr = nullptr, uint64_t extraAddr = 0);

  llvm::Value* getSPaddress() { return GetRegisterValue(Register::RSP); }
  llvm::Value* getSP() { return getPointer(getSPaddress()); };
  // end getters-setters
  // misc
  llvm::Value* callFunctionIR(const std::string& functionName,
                              funcsignatures<Register>::functioninfo* funcInfo);
  llvm::Value* GetEffectiveAddress();
  llvm::Value* getPointer(llvm::Value* value);

  std::vector<llvm::Value*>
  parseArgs(funcsignatures<Register>::functioninfo* funcInfo);
  llvm::FunctionType*
  parseArgsType(funcsignatures<Register>::functioninfo* funcInfo,
                llvm::LLVMContext& context);

  // Apply post-call ABI effects: write return value, clobber volatile regs.
  void applyPostCallEffects(llvm::Value* callResult,
                            const CallEffects<Register>& fx);

  llvm::Value* computeSignFlag(Value* value);
  llvm::Value* computeZeroFlag(Value* value);
  llvm::Value* computeParityFlag(Value* value);
  llvm::Value* computeAuxFlag(Value* Lvalue, Value* Rvalue, Value* result);
  llvm::Value* computeOverflowFlagSbb(Value* Lvalue, Value* Rvalue, Value* cf,
                                      Value* sub);

  llvm::Value* computeOverflowFlagSub(Value* Lvalue, Value* Rvalue, Value* sub);
  llvm::Value* computeOverflowFlagAdd(Value* Lvalue, Value* Rvalue, Value* add);
  llvm::Value* computeOverflowFlagAdc(Value* Lvalue, Value* Rvalue, Value* cf,
                                      Value* add);
  // end misc
  // analysis
  llvm::KnownBits analyzeValueKnownBits(Value* value, Instruction* ctxI);

  llvm::Value* solveLoad(LazyValue load, Value* ptr, uint8_t size);

  llvm::SimplifyQuery createSimplifyQuery(Instruction* Inst);

  void RegisterBranch(llvm::BranchInst* BI) {
    //
    BIlist.push_back(BI);
  }

  void markMemPaged(uint64_t start, uint64_t end) {
    pageMap[start] = end;
  }

  bool isMemPaged(uint64_t address) {
    auto it = pageMap.upper_bound(address);
    if (it == pageMap.begin())
      return false;

    --it;
    return address >= it->first && address < it->second;

  }

  bool isFileBackedRuntimeAddress(uint64_t address) {
    uint64_t ignored = 0;
    return file.readMemory(address, 1, ignored);
  }

  uint64_t normalizeRuntimeTargetAddress(uint64_t target) {
    if (isMemPaged(target)) {
      return target;
    }

    if (target <= std::numeric_limits<uint32_t>::max() &&
        file.imageBase > std::numeric_limits<uint32_t>::max()) {
      const uint64_t highBits = file.imageBase & 0xFFFFFFFF00000000ULL;
      const uint64_t widenedLow32 = highBits | target;
      const uint64_t widenedRva = file.imageBase + target;
      if (isMemPaged(widenedLow32)) {
        return widenedLow32;
      }
      if (isMemPaged(widenedRva)) {
        return widenedRva;
      }
    }

    return target;
  }

  uint64_t normalizeFileBackedRuntimeTargetAddress(uint64_t target) {
    if (isFileBackedRuntimeAddress(target)) {
      return target;
    }

    if (target <= std::numeric_limits<uint32_t>::max() &&
        file.imageBase > std::numeric_limits<uint32_t>::max()) {
      const uint64_t highBits = file.imageBase & 0xFFFFFFFF00000000ULL;
      const uint64_t widenedLow32 = highBits | target;
      const uint64_t widenedRva = file.imageBase + target;
      if (isFileBackedRuntimeAddress(widenedLow32)) {
        return widenedLow32;
      }
      if (isFileBackedRuntimeAddress(widenedRva)) {
        return widenedRva;
      }
    }

    return target;
  }

  std::set<llvm::APInt, APIntComparator>
  getPossibleValues(const llvm::KnownBits& known, unsigned max_unknown);

  Value* retrieveCombinedValue(const uint64_t startAddress,
                               const uint8_t byteCount, LazyValue orgLoad);
  Value* retrieveCombinedValueImpl(const uint64_t startAddress,
                                   const uint8_t byteCount, LazyValue orgLoad);

  void addValueReference(Value* value, const uint64_t address);

  // x86 segment-relative addressing (gs:/fs:) is TEB-relative. The lifter has
  // no real TEB, so model one at tebBase (Aftermath Labs memory-modeling range
  // policy): GetEffectiveAddress folds the segment override to tebBase, and the
  // structural TEB/PEB links are seeded here.
  //
  // OSBuildNumber used to be left unknown here on the theory that the virtualized
  // fingerprint condition would fork on it. It does not: this lifter has no fork
  // at a symbolic load, it symbolizes and loses the path. Leaving it unknown made
  // the VM key computation symbolic, which propagated into the RFLAGS value that
  // selects the next handler, so `jmp r10` became unresolvable and the concrete
  // walk stopped. Since the protector salts the key with the machine's real build
  // number, and the sample was protected on the analysis host, seeding the host's
  // value reproduces the key. Override with MERGEN_OS_BUILD_NUMBER when analysing
  // a sample protected elsewhere.
  static constexpr uint64_t tebBase = 0x7FFD0000ULL;
  static constexpr uint64_t pebBase = 0x7FFD1000ULL;
  static uint64_t hostOsBuildNumber() {
    if (const char* env = std::getenv("MERGEN_OS_BUILD_NUMBER")) {
      char* end = nullptr;
      const unsigned long long parsed = std::strtoull(env, &end, 0);
      if (end != env && *end == '\0') {
        return parsed;
      }
    }
    return 26200ULL; // build this sample was protected with (Win10 25H2 host)
  }
  void modelProcessEnvironment() {
    llvm::LLVMContext& ctx = builder->getContext();
    auto put = [&](uint64_t addr, uint64_t value, unsigned bits) {
      addValueReference(
          llvm::ConstantInt::get(llvm::Type::getIntNTy(ctx, bits), value), addr);
    };
    put(tebBase + 0x30, tebBase, 64); // TEB.Self
    put(tebBase + 0x58, 0, 64);       // TEB.EnvironmentPointer
    put(tebBase + 0x60, pebBase, 64); // TEB.ProcessEnvironmentBlock
    put(pebBase + 0x2, 0, 8);         // PEB.BeingDebugged
    put(pebBase + 0x68, 0, 32);       // PEB.NtGlobalFlag
    // x64 TEB+0x120 is read back through the TEB self-pointer (gs:[0x30]), which
    // is why the word is seeded at PEB-base + 0x120 as well.
    const uint64_t build = hostOsBuildNumber();
    put(tebBase + 0x120, build, 16);
    put(pebBase + 0x120, build, 16);
  }

  isPaged isValuePaged(Value* address, Instruction* ctxI);

  void pagedCheck(Value* address, Instruction* ctxI);

  void loadMemoryOp(Value* inst);

  void insertMemoryOp(llvm::StoreInst* inst);
  std::set<llvm::APInt, APIntComparator>
  computePossibleValues(Value* V, const uint8_t Depth = 0);

  Value* extractBytes(Value* value, const uint8_t startOffset,
                      const uint8_t endOffset);
  // end analysis

  // folders
  Value* createSelectFolder(Value* C, Value* True, Value* False,
                            const Twine& Name = "");

  Value* createGEPFolder(Type* Type, Value* Address, Value* Base,
                         const Twine& Name = "");

  Value* createAddFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createSubFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createOrFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createXorFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createICMPFolder(llvm::CmpInst::Predicate P, Value* LHS, Value* RHS,
                          const Twine& Name = "");
  Value* createNotFolder(Value* LHS, const Twine& Name = "");
  Value* createMulFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createSDivFolder(Value* LHS, Value* RHS, const Twine& Name = "");
  Value* createUDivFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createSRemFolder(Value* LHS, Value* RHS, const Twine& Name = "");
  Value* createURemFolder(Value* LHS, Value* RHS, const Twine& Name = "");
  Value* createAShrFolder(Value* LHS, Value* RHS, const Twine& Name = "");
  Value* createAndFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createTruncFolder(Value* V, Type* DestTy, const Twine& Name = "");

  Value* createZExtFolder(Value* V, Type* DestTy, const Twine& Name = "");

  Value* createZExtOrTruncFolder(Value* V, Type* DestTy,
                                 const Twine& Name = "");

  Value* createSExtFolder(Value* V, Type* DestTy, const Twine& Name = "");

  Value* createSExtOrTruncFolder(Value* V, Type* DestTy,
                                 const Twine& Name = "");

  Value* createLShrFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createLShrFolder(Value* LHS, const uint64_t RHS,
                          const Twine& Name = "");

  Value* createLShrFolder(Value* LHS, const llvm::APInt RHS,
                          const Twine& Name = "");

  Value* createShlFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createShlFolder(Value* LHS, const uint64_t RHS,
                         const Twine& Name = "");

  Value* createShlFolder(Value* LHS, const llvm::APInt RHS,
                         const Twine& Name = "");
  Value* folderBinOps(Value* LHS, Value* RHS, const Twine& Name,
                      Instruction::BinaryOps opcode);
  Value* folderBinOpsImpl(Value* LHS, Value* RHS, const Twine& Name,
                          Instruction::BinaryOps opcode);
  Value* createInstruction(const unsigned opcode, Value* operand1,
                           Value* operand2, Type* destType, const Twine& Name);

  Value* getOrCreate(const InstructionKey& key, uint8_t opcode,
                     const Twine& Name);
  Value* doPatternMatching(Instruction::BinaryOps const I, Value* const op0,
                           Value* const op1);

  void run_opts();
  // Folds just the module-backed loads (GEPLoadPass) once, without the
  // pseudo-stack/pseudo-memory rewrites: those change memory addressing and
  // would desynchronise the concolic buffer mid-lift.
  void promoteModuleLoads();
  // Folds the bytecode loads that are still live by replacing them with their
  // concrete value (image + concolic buffer). Unlike GEPLoadPass it touches
  // nothing else, so the concolic memory model stays valid; the tracked
  // register/flag handles follow the RAUW, keeping the VM state concrete for
  // the next block.
  void concretizeBytecodeLoads();
  // end folders

#define OPCODE(fncname, ...) DEFINE_FUNCTION(fncname);
#include "x86_64_opcodes.x"
#undef OPCODE

  // end semantics definition
};

#undef DEFINE_FUNCTION
#endif // LIFTERCLASS_H
