#ifndef LIFTERCLASS_CONCRETE_H
#define LIFTERCLASS_CONCRETE_H

// The concolic execution model: lifterSymbolic plus path exploration.
//
// The division of labour with its base is worth stating before reading any of
// it. lifterSymbolic (LifterClass_Symbolic.hpp) owns the architectural state
// -- registers as a memory-resident struct, pseudo-memory as an alloca -- and
// has no notion of exploring alternatives. This class adds exactly one idea on
// top: when a symbolic value could be more than one thing, the lifter can
// *choose* a value, lift down that path, and remember the choice so a later
// block can be entered under the other assumption.
//
// That turns a single symbolic walk into a guided concrete one. The mechanism
// is the `assumptions` map -- an SSA value mapped to the value it was assumed
// to hold -- plus the worklist of blocks to visit. A block queued twice with
// different assumptions is visited twice.
//
// The cost, and the reason this is bounded rather than exhaustive: the
// worklist can grow multiplicatively with branch depth, so LiftBlockBudgetExceeded
// is a real diagnostic rather than a theoretical one.

#include "CommonDisassembler.hpp"
#include "RegisterManager.hpp"
#include "IcedDisassembler.hpp"
#include "IcedDisassemblerMnemonics.h"
#include "IcedDisassemblerRegisters.h"
#include "LifterClass.hpp"
#include <magic_enum/magic_enum.hpp>

template <
#ifdef ICED_FOUND
    Registers Register = Mergen::IcedRegister,
    Mnemonics Mnemonic = Mergen::IcedMnemonics,
    template <typename, typename> class DisassemblerBase =
        Mergen::icedDisassembler
#else

    Registers Register = Mergen::ZydisRegister,
    Mnemonics Mnemonic = Mergen::ZydisMnemonic,
    template <typename, typename> class DisassemblerBase =
        Mergen::ZydisDisassembler
#endif
    >

  requires Disassembler<DisassemblerBase<Mnemonic, Register>, Mnemonic,
                        Register>

class lifterConcolic : public lifterClassBase<
                           lifterConcolic<Register, Mnemonic, DisassemblerBase>,
                           Mnemonic, Register, DisassemblerBase> {
public:
  // lifterConcolic constructor will be executed after lifterClassBase
  // https://godbolt.org/z/f986zK5j1

  enum RegisterIndex {
    RAX_ = 0,
    RCX_ = 1,
    RDX_ = 2,
    RBX_ = 3,
    RSP_ = 4,
    RBP_ = 5,
    RSI_ = 6,
    RDI_ = 7,
    R8_ = 8,
    R9_ = 9,
    R10_ = 10,
    R11_ = 11,
    R12_ = 12,
    R13_ = 13,
    R14_ = 14,
    R15_ = 15,
    RIP_ = 16,
    RFLAGS_ = 17,
    XMM0_ = 18,
    XMM1_ = 19,
    XMM2_ = 20,
    XMM3_ = 21,
    XMM4_ = 22,
    XMM5_ = 23,
    XMM6_ = 24,
    XMM7_ = 25,
    XMM8_ = 26,
    XMM9_ = 27,
    XMM10_ = 28,
    XMM11_ = 29,
    XMM12_ = 30,
    XMM13_ = 31,
    XMM14_ = 32,
    XMM15_ = 33,
    REGISTER_COUNT // Total number of registers
  };
  std::array<llvm::WeakTrackingVH, REGISTER_COUNT> vec;
  std::array<llvm::WeakTrackingVH, FLAGS_END> vecflag;

  // The base constructor calls InitRegisters() before this class's members are
  // constructed. For a raw pointer array that wrote into raw storage and
  // happened to survive; a tracking array is constructed afterwards and would
  // null every slot. Re-binding the function arguments here runs after `vec`
  // exists.
  lifterConcolic() {
    this->InitRegisters();
    this->modelProcessEnvironment();
  }

  // Map a Register enum onto a slot in `vec`.
  //
  // Written as explicit cases rather than a cast because the three register
  // families are not contiguous in Register: RAX..R15 are contiguous but RIP
  // and RFLAGS are special (each also spelled EIP/EFLAGS), and XMM0..XMM15 are
  // contiguous but start much later. A single subtraction would be wrong for two
  // of the three families.
  //
  // EIP/EFLAGS folding onto RIP/RFLAGS is deliberate and is what makes partial
  // writes work: `mov eax, ...` and `mov rax, ...` address the same slot, so the
  // 32-bit write and the 64-bit value cannot drift apart.
  int getRegisterIndex(Register key) const {

    switch (key) {
    case Register::EIP:
    case Register::RIP: {
      return RIP_;
    }
    case Register::EFLAGS:
    case Register::RFLAGS: {
      return RFLAGS_;
    }
    default: {
      if (key >= Register::RAX && key <= Register::R15) {
        return (static_cast<int>(key) - static_cast<int>(Register::RAX));
      }

      if (key >= Register::XMM0 && key <= Register::XMM15) {
        return XMM0_ + (static_cast<int>(key) - static_cast<int>(Register::XMM0));
      }

      // Coverage limit: an instruction whose operand is a register the concolic
      // manager does not model (x87/MMX/...). Aborting the whole lift for a path
      // the concrete execution never takes is worse than degrading; the
      // instruction is reported unsupported (Semantics.ipp) and its semantics
      // are not relied upon.
      //
      // RAX_ is the landing slot: a real register, so the read returns a valid
      // Value rather than dereferencing out of bounds, and every unmodelled
      // register shares it so the damage is confined to one aliased slot
      // instead of corrupting an arbitrary one. The aliasing is a genuine
      // mis-model, accepted because the alternative -- an out-of-range index
      // into `vec` -- is undefined behaviour. This is the one place where the
      // degradation is visible in the IR: an x87 operand appears to read RAX.
      return RAX_;
    }
    }
  }

  llvm::Value* get_impl(Register key) {
    int index = getRegisterIndex(key);

    return vec[index];
  }

  void set_impl(Register key, llvm::Value* val) {
    // printvalue2(int(key));
    // printvalue2(magic_enum::enum_name(key))
    int keyindex = getRegisterIndex(key);
    // printvalue2(keyindex);
    // printvalue(val);
    vec[keyindex] = val;
  }

  void init_impl(
      std::array<std::pair<Register, llvm::Value*>, REGISTER_COUNT> values) {
    for (auto& [reg, val] : values) {
      int index = getRegisterIndex(reg);
      vec[index] = val;
    }
  }
  // Read a flag.
  //
  // An unset flag reads as a concrete false, not null. This matters more than
  // it looks: the path solver asks for flags constantly, and a null return would
  // send it down a "unknown" path for every flag the code never wrote. Fabricating
  // false makes those reads concrete, which is the same choice an uninitialised
  // flag gets from real hardware -- x86 guarantees the reserved bits are 1, but
  // the arithmetic flags after a `xor eax, eax` really are false, and by far
  // the most common way a flag is "unset" here is that the preceding instruction
  // zeroed it.
  llvm::Value* get_flag_impl(Flag key) {
    auto val = vecflag[static_cast<uint8_t>(key)];
    if (val)
      return val;
    return ConstantInt::getSigned(Type::getInt1Ty(this->context), 0);
  }
  // Write a flag, narrowing to i1 first.
  //
  // The trunc is unconditional on width rather than type-checked. A caller
  // passing a non-integer (a float comparison result, say) would hit an
  // assertion inside LLVM rather than a clean diagnostic here; in practice every
  // flag writer passes a comparison or an arithmetic result, which are integers.
  void set_flag_impl(Flag key, llvm::Value* val) {
    if (val->getType()->getIntegerBitWidth() > 1)
      val = this->builder->CreateTrunc(val, this->builder->getIntNTy(1));
    vecflag[static_cast<uint8_t>(key)] = val;
  }
  // Bulk flag restore.
  //
  // WARNING: this writes `vec[...],` not `vecflag[...]`. The index is a Flag,
  // so it stores flag values into the *register* array at register-sized slots.
  // The two are different arrays with different lengths (vec is REGISTER_COUNT,
  // vecflag is FLAGS_END), so this is also an out-of-range store for any Flag
  // index at or beyond REGISTER_COUNT.
  //
  // Currently unreachable: RegisterManagerBase::init_flag is the only caller and
  // nothing in lifter/ calls it, so no snapshot round-trips through here today.
  // Flagged rather than fixed because fixing it is a behaviour change outside a
  // comment-only pass -- but the moment someone wires init_flag up, flag restore
  // becomes either a no-op or a corruption of the register file, depending on
  // which array the snapshot was taken from. Fixing the index alone is not
  // sufficient; the caller has to be checked too.
  void
  init_flag_impl(std::array<std::pair<Flag, llvm::Value*>, FLAGS_END> values) {
    for (auto& [reg, val] : values) {
      vec[static_cast<uint8_t>(reg)] = val;
    }
  }

  // The _impl family below is the CRTP forwarding surface: RegisterManagerBase
  // calls these, and each is a one-line pass-through. They are separate
  // functions rather than aliases because lifterSymbolic has to be able to
  // override exactly one of them -- SetRegisterValue_impl is where the import
  // provenance gets invalidated -- without reimplementing the rest.
  llvm::Value* GetRegisterValue_impl(Register key) { return get_impl(key); }
  // NOTE: registerImportSource is NOT cleared here.
  //
  // LifterClass.hpp documents that member as "cleared on every
  // SetRegisterValue". The clearing actually happens one layer down, in
  // SetRegisterValue_internal (OperandUtils.ipp), which erases the binding after
  // the write. So the documented invariant holds -- but only because every
  // caller goes through that function, not because this one does it.
  //
  // Worth knowing when reading either file: adding a write path that bypasses
  // SetRegisterValue_internal silently drops the invalidation, and the failure
  // mode is a register-indirect call resolving to an import that is no longer
  // the one being called -- a named call to the wrong function, which verifies
  // and runs.
  void SetRegisterValue_impl(Register key, llvm::Value* val) {

    set_impl(key, val);
  }

  llvm::Value* GetFlagValue_impl(Flag key) { return get_flag_impl(key); }

  void SetFlagValue_impl(Flag key, llvm::Value* v) { set_flag_impl(key, v); }

  // The block a generalized loop was entered from, or null outside one.
  //
  // Set by the generalization machinery and read by the restore paths to tell
  // "re-entering the loop" from "entering for the first time". A raw pointer
  // rather than an address because the source block may have been replaced --
  // see replaceWithGeneralizedLoopBlock -- and an address-keyed lookup would
  // then miss the block it is supposed to refer to.
  llvm::BasicBlock* activeGeneralizedLoopEntrySourceBlock = nullptr;

  // Unflatten unconditionally.
  //
  // Not configurable on this class. lifterConcolic exists to explore multiple
  // paths, and Basic mode cannot express that; a mode switch here would only
  // produce a lift that cannot resolve its own branches.
  constexpr ControlFlow getControlFlow_impl() { return ControlFlow::Unflatten; }

  // A snapshot of everything needed to resume a block later under possibly
  // different assumptions.
  //
  // This is what makes concolic exploration possible: the lift loop reaches a
  // branch, cannot resolve the condition, and must try both sides. Each side
  // needs the state as it was *at the branch*, not as it is now -- so a
  // backup_point is taken before either side is explored and restored when that
  // side's block is reached.
  //
  // The fields are WeakTrackingVH rather than raw pointers on purpose. The
  // module is mutated constantly during lifting, and a raw pointer into it
  // would dangle after any pass or promotion replaced an instruction.
  // WeakTrackingVH nulls itself instead, which turns a use-after-free into a
  // visible null.
  struct backup_point {
    std::array<llvm::WeakTrackingVH, REGISTER_COUNT> vec;
    std::array<llvm::WeakTrackingVH, FLAGS_END> vecflag;
    llvm::DenseMap<uint64_t, ValueByteReference> buffer;
    InstructionCache cache;
    llvm::DenseMap<llvm::Instruction*, llvm::APInt> assumptions;
    uint64_t ct;
    llvm::BasicBlock* sourceBlock;

    // Equality is used to decide whether a backup point is redundant with one
    // already stored -- queueing a block whose state is identical to an
    // existing entry would visit it twice for the same result.
    //
    // Note `cache` and `assumptions` are deliberately NOT compared. Both are
    // derived artefacts that can differ without the architectural state
    // differing, and treating a cache difference as a state difference would
    // make almost every backup point look unique and defeat the check.
    //
    // `ct` (the instruction counter) is also not compared, for the same reason:
    // two points taken at the same state but different instruction positions are
    // still the same architectural state, and the lift cannot tell them apart
    // in any way that matters.
    bool operator==(const backup_point& other) const {
      // buffer first. It is the most expensive comparison and also the one that
      // most often differs -- tracked memory diverges far more readily than
      // registers do -- so checking it first avoids the array walks in the
      // common negative case.
      if (buffer != other.buffer)
        return false;
      return vec == other.vec && vecflag == other.vecflag &&
             sourceBlock == other.sourceBlock;
    }

    // Copy/move constructors.
    //
    // backup_point(backup_point&) is a non-const lvalue overload, which means it
    // is NOT what a `backup_point b = a;` with a mutable `a` selects -- that
    // binds to the defaulted copy ctor below. It exists for callers passing a
    // mutable lvalue to a by-value parameter. The two paths produce the same
    // state, so the distinction is a compile-time detail rather than a semantic
    // one, but it is the kind of thing worth knowing before "simplifying" one
    // away.
    backup_point(backup_point& other)
        : vec(other.vec), vecflag(other.vecflag), buffer(other.buffer),
          cache(other.cache), assumptions(other.assumptions), ct(other.ct),
          sourceBlock(other.sourceBlock){};

    backup_point(backup_point&& other) noexcept
        : vec(std::move(other.vec)), vecflag(std::move(other.vecflag)),
          buffer(std::move(other.buffer)), cache(std::move(other.cache)),
          assumptions(std::move(other.assumptions)), ct(other.ct),
          sourceBlock(other.sourceBlock) {}

    // By-value params: lvalue args copy once into the parameter, rvalue args
    // move. Members always take ownership via move (avoids a second DenseMap
    // deep-copy that previously dominated solvePath const-path time).
    backup_point(std::array<llvm::WeakTrackingVH, REGISTER_COUNT> vec,
                 std::array<llvm::WeakTrackingVH, FLAGS_END> vecflag,
                 llvm::DenseMap<uint64_t, ValueByteReference> buffer,
                 InstructionCache cc,
                 llvm::DenseMap<llvm::Instruction*, llvm::APInt> assumptions,
                 uint64_t ct, llvm::BasicBlock* sourceBlock)
        : vec(std::move(vec)), vecflag(std::move(vecflag)),
          buffer(std::move(buffer)), cache(std::move(cc)),
          assumptions(std::move(assumptions)), ct(ct),
          sourceBlock(sourceBlock) {}
    backup_point() = default;
    backup_point(const backup_point&) = default;
    backup_point& operator=(const backup_point&) = default;
    backup_point& operator=(backup_point&&) noexcept = default;
  };

  // Ordinary backup points, one per block.
  //
  // Single-valued, unlike the generalized map below. A non-generalized block
  // has exactly one way to be re-entered, so one snapshot describes it; making
  // this a SmallVector too would cost an allocation on every block for a case
  // that does not occur.
  llvm::DenseMap<BasicBlock*, backup_point> BBbackup;

  // Backedge-side state is a variable-width vector keyed by header. A loop
  // header may be reached from multiple backedges - each distinct backedge
  // sourceBlock contributes its own backup_point. Size 1 is the common
  // 2-way loop case (canonical + single backedge). Size >=2 is a multi-way
  // loop (e.g. a VM dispatcher whose body has several handler tails that
  // all jump back to the same header).
  llvm::DenseMap<BasicBlock*, llvm::SmallVector<backup_point, 2>> generalizedLoopBackedgeBackup;

  // The phis that *are* the loop-carried variables.
  //
  // One phi per register per header, built once at generalization time and then
  // reused by every subsequent iteration. That is what makes the loop a loop in
  // the IR rather than a chain of copies, and it is why these are keyed by
  // header: the phi has to live in the header block for LLVM's dominance rules
  // to accept it.
  //
  // std::array rather than a map of PHINode* because the register count is
  // fixed and dense. A null entry means "this register does not vary across the
  // loop", which is the common case and saves building a phi that would just
  // forward one value.
  llvm::DenseMap<BasicBlock*, std::array<llvm::PHINode*, REGISTER_COUNT>>
      generalizedLoopRegisterPhis;
  llvm::DenseMap<BasicBlock*, std::array<llvm::PHINode*, FLAGS_END>>
      generalizedLoopFlagPhis;

  // The tracked buffer as it stands inside a generalized loop.
  //
  // Separate from the lifter's main `buffer` because the restore path needs to
  // compare the loop's own state against each backedge's, and doing that against
  // the live buffer would mean mutating it during a comparison.
  llvm::DenseMap<uint64_t, ValueByteReference> activeGeneralizedLoopLocalBuffer;

  // A non-primary loop-carried memory qword: tracked across the loop boundary
  // with per-backedge values, but not the primary dispatcher control cursor.
  // Used by the generalized retrieve helpers to build phis for all varying
  // memory slots, not just the first two (control + target).
  //
  // `canonicalValue` is the value on the first iteration and `backedgeValues`
  // the ones that arrive on each backedge; the phi for this slot is
  // canonical -> [0], backedge[0] -> [1], and so on. Storing the canonical value
  // separately rather than as backedgeValues[0] is what lets the phi have a
  // different first incoming block than the rest.
  struct LoopCarriedSlot {
    uint64_t address = 0;
    uint64_t canonicalValue = 0;
    llvm::SmallVector<uint64_t, 2> backedgeValues;
  };

  // Everything known about one generalized loop's control field.
  //
  // The canonical/backedge pairing runs through the whole struct and is the
  // central idea: a generalized loop was reached in two or more ways, and each
  // way carried a different value. Rather than choosing one, the lift records
  // all of them and builds a phi, so the loop body is emitted once and the
  // dispatcher's variable part becomes an explicit incoming value.
  struct GeneralizedLoopControlFieldState {
    // Guards every other field. `valid` exists because the struct is a member of
    // the lifter and therefore always constructed; without it, the default-
    // constructed state would be indistinguishable from a discovered one whose
    // control value happens to be 0.
    bool valid = false;
    llvm::BasicBlock* headerBlock = nullptr;
    llvm::BasicBlock* canonicalSource = nullptr;
    // Backedge side is variable-width; see generalizedLoopBackedgeBackup.
    llvm::SmallVector<llvm::BasicBlock*, 2> backedgeSources;
    uint64_t canonicalControl = 0;
    llvm::SmallVector<uint64_t, 2> backedgeControls;
    // Buffer snapshots parallel to the above: the canonical source's tracked
    // memory and each backedge's. Needed because a phi over a memory slot
    // requires knowing which bytes that slot spans *per incoming edge* -- a
    // byte that varies on one backedge but not another still needs the edge's
    // value to build a correct phi.
    llvm::DenseMap<uint64_t, ValueByteReference> canonicalBuffer;
    llvm::SmallVector<llvm::DenseMap<uint64_t, ValueByteReference>, 2> backedgeBuffers;
    // Per-loop-discovered memory slots (Phase A: seeded to the Themida defaults
    // by the populator; Phase B will replace the seed with active discovery).
    // controlSlot is the qword whose value advances across loop iterations and
    // drives the dispatcher cursor; targetSlot is the loop-carried output slot
    // consumed by retrieve_generalized_loop_target_slot_value_impl.
    uint64_t controlSlot = 0;
    uint64_t targetSlot = 0;
    // Additional loop-carried memory slots beyond controlSlot/targetSlot.
    // Each varying qword discovered during slot discovery gets an entry here
    // so retrieve helpers can build phis for ALL loop-carried state, not just
    // the primary two. This fixes the TEA-round class of bugs where a third+
    // varying slot was silently dropped.
    llvm::SmallVector<LoopCarriedSlot, 4> carriedSlots;
  } activeGeneralizedLoopControlFieldState;
  llvm::DenseMap<llvm::BasicBlock*, GeneralizedLoopControlFieldState>
      generalizedLoopControlFieldStates;

  // Sample-specific seeds, and they are exactly that.
  //
  // These addresses come from one Themida-protected binary. They are the
  // dispatcher's control-cursor slot and one loop-carried slot in that sample,
  // used until active discovery (Phase B) replaces them. They are NOT derived
  // from anything the lifter can compute, and nothing validates them against the
  // sample being lifted -- a different protector, or the same protector with a
  // different layout, will seed the wrong slots and the resulting loop will be
  // structurally plausible and wrong.
  //
  // Kept as constants rather than removed because they are the only thing that
  // makes generalization work at all today. The offsets list below has the same
  // property: three offsets that happened to be right for this sample's control
  // field encoding.
  static constexpr uint64_t kThemidaControlCursorSlot = 0x14004DD19ULL;
  static constexpr uint64_t kThemidaLoopCarriedSlot = 0x14004DC67ULL;
  static constexpr std::array<uint64_t, 3> kSupportedGeneralizedControlFieldOffsets = {
      0x6ULL, 0xAULL, 0xCULL};

  // Read a qword out of a tracked-buffer snapshot, byte by byte.
  //
  // Byte-wise rather than through retrieveCombinedValue because the source here
  // is a *snapshot* (canonicalBuffer, a backedgeBuffer, or the live buffer) and
  // not the lifter's buffer. The tracked-buffer helpers read the live map, so
  // routing through them would read the wrong edge's value -- which is exactly
  // the bug the phi construction is supposed to avoid.
  //
  // All-or-nothing: any missing or non-constant byte fails the whole read. A
  // partially-known qword has no correct phi representation here, and returning
  // a value built from the known bytes would be worse than declining.
  bool readConstantTrackedQword(
      const llvm::DenseMap<uint64_t, ValueByteReference>& src, uint64_t qwordStart,
      uint64_t& out) {
    llvm::APInt combined(64, 0);
    for (uint8_t i = 0; i < 8; ++i) {
      auto it = src.find(qwordStart + i);
      if (it == src.end() || !it->second.value) {
        return false;
      }
      auto* ci = llvm::dyn_cast<llvm::ConstantInt>(it->second.value);
      if (!ci) {
        return false;
      }
      auto byteValue = ci->getValue().lshr(it->second.byteOffset * 8).trunc(8);
      combined |= byteValue.zext(64).shl(i * 8);
    }
    out = combined.getZExtValue();
    return true;
  }
  // The fast path: the requested span is one contiguous run of bytes inside one
  // tracked Value.
  //
  // "Contiguous" is checked by pointer identity plus a *consecutive* byteOffset
  // run, and both halves are required. Same Value but non-consecutive offsets
  // means the value's bytes are being read out of order or with a gap -- an
  // extract over that range would silently include bytes the caller did not ask
  // for. Different Values is the non-contiguous case handled below.
  //
  // Strict: returns null rather than a partial answer, so the caller can fall
  // back to the general path instead of acting on a truncated value.
  llvm::Value* retrieveContiguousBufferedValue(
      const llvm::DenseMap<uint64_t, ValueByteReference>& sourceBuffer,
      uint64_t startAddress, uint8_t byteCount) {
    auto firstIt = sourceBuffer.find(startAddress);
    if (firstIt == sourceBuffer.end() || !firstIt->second.value) {
      return nullptr;
    }
    llvm::Value* sharedValue = firstIt->second.value;
    uint8_t firstByteOffset = firstIt->second.byteOffset;
    for (uint8_t i = 0; i < byteCount; ++i) {
      auto it = sourceBuffer.find(startAddress + i);
      if (it == sourceBuffer.end() ||
          static_cast<llvm::Value*>(it->second.value) != sharedValue ||
          it->second.byteOffset != firstByteOffset + i) {
        return nullptr;
      }
    }
    return this->extractBytes(sharedValue, firstByteOffset,
                              firstByteOffset + byteCount);
  }
  // The general path: assemble the span byte by byte, whether or not the bytes
  // share one Value.
  //
  // Tries the contiguous case first because it is a single extract rather than
  // byteCount shifts and ors, and the contiguous case is the common one -- a VM
  // that stored a qword in one instruction.
  //
  // The byte-by-byte assembly goes through the folders rather than IRBuilder so
  // that a run of known bytes folds to a constant here, before the path solver
  // sees the value. Emitting raw shifts and ors would defer the fold to the O2
  // fixpoint, which is after the solver has already had to decide what to do
  // with the result.
  llvm::Value* retrieveValueFromBufferSlice(
      const llvm::DenseMap<uint64_t, ValueByteReference>& sourceBuffer,
      uint64_t startAddress, uint8_t byteCount) {
    auto firstIt = sourceBuffer.find(startAddress);
    if (firstIt == sourceBuffer.end() || !firstIt->second.value) {
      return nullptr;
    }

    // Not a rejection, a downgrade: the loop below records whether the span
    // stayed contiguous rather than bailing on the first mismatch, because a
    // span can be partly contiguous and still be answerable byte by byte.
    bool contiguousSingleValue = true;
    llvm::Value* sharedValue = firstIt->second.value;
    uint8_t firstByteOffset = firstIt->second.byteOffset;
    for (uint8_t i = 0; i < byteCount; ++i) {
      auto it = sourceBuffer.find(startAddress + i);
      if (it == sourceBuffer.end() || !it->second.value) {
        return nullptr;
      }
      if (static_cast<llvm::Value*>(it->second.value) != sharedValue ||
          it->second.byteOffset != firstByteOffset + i) {
        contiguousSingleValue = false;
      }
    }
    if (contiguousSingleValue) {
      return this->extractBytes(sharedValue, firstByteOffset,
                                firstByteOffset + byteCount);
    }

    llvm::Value* result = llvm::ConstantInt::get(
        llvm::Type::getIntNTy(this->context, byteCount * 8), 0);
    for (uint8_t i = 0; i < byteCount; ++i) {
      auto it = sourceBuffer.find(startAddress + i);
      auto* byteValue = this->extractBytes(it->second.value, it->second.byteOffset,
                                           it->second.byteOffset + 1);
      if (!byteValue) {
        return nullptr;
      }
      auto* shiftedByteValue = this->createShlFolder(
          this->createZExtOrTruncFolder(
              byteValue, llvm::Type::getIntNTy(this->context, byteCount * 8)),
          llvm::APInt(byteCount * 8, i * 8));
      result = this->createOrFolder(result, shiftedByteValue,
                                    "generalized-local-byte");
    }
    return result;
  }
  // Three-tier lookup: tracked buffer, normalised buffer, then file.
  //
  // The tiers are ordered by trust. A byte the lifter itself tracked is what the
  // program actually stored, so it beats the file image. The file is the
  // fallback and is subject to shouldPromoteFileValue -- a file byte is only
  // promoted if the memory policy says that region is safe to constant-fold,
  // because folding an unrelocated image value produces a concrete answer that
  // is wrong for a relocated sample.
  //
  // The normalisation retry is not redundant with the file retry. An address
  // outside the PE's base lane may be tracked under its normalised form and
  // readable under it, or neither; each tier has to be tried at both spellings
  // before giving up.
  //
  // `usedAddress` records which spelling actually answered, because
  // shouldPromoteFileValue has to judge the address the bytes came from, not
  // the one that was asked for.
  llvm::Value* retrieveBufferedOrConcreteValue(
      const llvm::DenseMap<uint64_t, ValueByteReference>& sourceBuffer,
      uint64_t startAddress, uint8_t byteCount) {
    if (auto* buffered =
            retrieveValueFromBufferSlice(sourceBuffer, startAddress, byteCount)) {
      return buffered;
    }
    uint64_t normalizedAddress = this->normalizeRuntimeTargetAddress(startAddress);
    if (normalizedAddress != startAddress) {
      if (auto* normalizedBuffered =
              retrieveValueFromBufferSlice(sourceBuffer, normalizedAddress, byteCount)) {
        return normalizedBuffered;
      }
    }
    uint64_t concreteValue = 0;
    uint64_t usedAddress = startAddress;
    if (!this->file.readMemory(startAddress, byteCount, concreteValue)) {
      if (normalizedAddress == startAddress ||
          !this->file.readMemory(normalizedAddress, byteCount, concreteValue)) {
        return nullptr;
      }
      usedAddress = normalizedAddress;
    }
    if (!this->file.shouldPromoteFileValue(usedAddress, byteCount,
                                           concreteValue)) {
      return nullptr;
    }
    return this->builder->getIntN(byteCount * 8, concreteValue);
  }

  // Reset every field of the active generalized-loop state.
  //
  // Field-by-field rather than assigning a fresh struct so that a field added
  // later is visibly not cleared here -- a whole-struct assignment would
  // silently reset it, and the compiler would not point that out.
  //
  // Note `valid = false` rather than relying on any later check: this is the
  // single guard that tells the restore paths whether any of the other fields
  // mean anything.
  void clearGeneralizedLoopControlFieldState() {
    activeGeneralizedLoopEntrySourceBlock = nullptr;
    activeGeneralizedLoopControlFieldState.valid = false;
    activeGeneralizedLoopControlFieldState.headerBlock = nullptr;
    activeGeneralizedLoopControlFieldState.canonicalSource = nullptr;
    activeGeneralizedLoopControlFieldState.backedgeSources.clear();
    activeGeneralizedLoopControlFieldState.canonicalControl = 0;
    activeGeneralizedLoopControlFieldState.backedgeControls.clear();
    activeGeneralizedLoopControlFieldState.controlSlot = 0;
    activeGeneralizedLoopControlFieldState.targetSlot = 0;
    activeGeneralizedLoopControlFieldState.canonicalBuffer.clear();
    activeGeneralizedLoopControlFieldState.backedgeBuffers.clear();
    activeGeneralizedLoopControlFieldState.carriedSlots.clear();
  }
  // Constant-fold a loop-carried expression *for one specific incoming edge*.
  //
  // This is the key asymmetry with ordinary constant folding. A phi here is not
  // an unknown to be guarded against -- it is a known-multivalued value, and the
  // question "what is it?" has a different answer per incoming block. So the
  // phi case below selects the incoming value for `incomingBlock` and recurses,
  // rather than giving up the way a general folder would.
  //
  // That is what makes a generalized loop's control field concrete at all. The
  // phi built during generalization is the loop-carried variable, and evaluating
  // it edge-by-edge is what lets the dispatcher be resolved per iteration
  // instead of collapsing to a single wrong value.
  //
  // Deliberately a small whitelist -- constant, phi, trunc/zext/sext, and a few
  // binary ops. Not a general interpreter, and it should not become one: this
  // runs inside path solving, and a general evaluator would both be slower and
  // start answering for expression shapes whose edge-specific meaning has not
  // been reasoned about. An opcode not listed returns false, which makes the
  // caller fall back to a symbolic value -- the safe direction.
  //
  // No recursion depth cap. Every recursive step goes through a phi edge, a
  // cast, or a binary operator, and the IR DAG is acyclic, so the walk
  // terminates. A phi's incoming value cannot be the phi itself.
  bool evaluateConcreteGeneralizedLoopInt(llvm::Value* candidate,
                                          llvm::BasicBlock* incomingBlock,
                                          llvm::APInt& out) {
    if (!candidate || !incomingBlock) {
      return false;
    }
    if (auto* constantInt = llvm::dyn_cast<llvm::ConstantInt>(candidate)) {
      out = constantInt->getValue();
      return true;
    }
    if (auto* phi = llvm::dyn_cast<llvm::PHINode>(candidate)) {
      // Negative means this edge does not reach the phi at all, which is a real
      // answer: the value has no meaning on this incoming block, and returning
      // false here rather than picking another edge's value is what stops one
      // iteration's control from being used for another's.
      int incomingIndex = phi->getBasicBlockIndex(incomingBlock);
      if (incomingIndex < 0) {
        return false;
      }
      // Recurse with the *same* incomingBlock: nested phis in the chain belong
      // to the same edge, and substituting the phi's block would select values
      // from the wrong path.
      return evaluateConcreteGeneralizedLoopInt(phi->getIncomingValue(incomingIndex),
                                                incomingBlock, out);
    }
    if (auto* castInst = llvm::dyn_cast<llvm::CastInst>(candidate)) {
      llvm::APInt operandValue(1, 0);
      if (!evaluateConcreteGeneralizedLoopInt(castInst->getOperand(0), incomingBlock,
                                              operandValue)) {
        return false;
      }
      const unsigned width = castInst->getType()->getIntegerBitWidth();
      switch (castInst->getOpcode()) {
      case llvm::Instruction::Trunc:
        out = operandValue.trunc(width);
        return true;
      case llvm::Instruction::ZExt:
        out = operandValue.zext(width);
        return true;
      case llvm::Instruction::SExt:
        out = operandValue.sext(width);
        return true;
      default:
        return false;
      }
    }
    if (auto* binOp = llvm::dyn_cast<llvm::BinaryOperator>(candidate)) {
      llvm::APInt lhsValue(1, 0);
      llvm::APInt rhsValue(1, 0);
      if (!evaluateConcreteGeneralizedLoopInt(binOp->getOperand(0), incomingBlock,
                                              lhsValue) ||
          !evaluateConcreteGeneralizedLoopInt(binOp->getOperand(1), incomingBlock,
                                              rhsValue)) {
        return false;
      }
      const unsigned width = binOp->getType()->getIntegerBitWidth();
      auto lhs = lhsValue.zextOrTrunc(width);
      auto rhs = rhsValue.zextOrTrunc(width);
      switch (binOp->getOpcode()) {
      case llvm::Instruction::Add:
        out = lhs + rhs;
        return true;
      case llvm::Instruction::Sub:
        out = lhs - rhs;
        return true;
      case llvm::Instruction::And:
        out = lhs & rhs;
        return true;
      case llvm::Instruction::Or:
        out = lhs | rhs;
        return true;
      case llvm::Instruction::Xor:
        out = lhs ^ rhs;
        return true;
      case llvm::Instruction::Shl:
        out = lhs.shl(rhs.getLimitedValue(width));
        return true;
      case llvm::Instruction::LShr:
        out = lhs.lshr(rhs.getLimitedValue(width));
        return true;
      // AShr, the rotates, the divisions and the comparisons are all absent on
      // purpose. Each would need its own edge-specific reasoning to be safe
      // here, and none of them has been reasoned about -- an unreviewed case
      // that folds to a wrong constant is worse than one that declines and
      // leaves the value symbolic.
      //
      // getLimitedValue above is likewise not a general shift: LLVM requires the
      // shift amount to be strictly less than the width, and the value came
      // from a constant in this expression, so clamping rather than trapping is
      // the right failure.
      default:
        return false;
      }
    }
    // Unhandled node type. Falling out rather than returning true is the whole
    // contract: the caller treats false as "leave this symbolic", which is a
    // worse answer than a fold but a correct one.
    return false;
  }

  // uint64_t convenience overload.
  //
  // Widens the APInt result to 64 rather than asserting the width. A control
  // field narrower than 64 is normal -- the sample's offsets are 0x6/0xA/0xC,
  // which are byte offsets, and the field itself is a qword or less -- so the
  // caller gets a zero-extended value and decides for itself whether the narrow
  // width mattered. zextOrTrunc rather than sext is deliberate: these are
  // bytecode offsets and cursors, which are unsigned quantities.
  bool evaluateConcreteGeneralizedLoopInt(llvm::Value* candidate,
                                          llvm::BasicBlock* incomingBlock,
                                          uint64_t& out) {
    llvm::APInt value(1, 0);
    if (!evaluateConcreteGeneralizedLoopInt(candidate, incomingBlock, value)) {
      return false;
    }
    out = value.zextOrTrunc(64).getZExtValue();
    return true;
  }

  // Peel integer casts off a load operand, for address matching.
  //
  // Only integer-to-integer. A float or pointer cast in the chain stops the
  // peel: the remaining value is no longer an address expression this function
  // knows how to interpret, and stripping further would match a shape it has no
  // meaning for.
  //
  // The loop rather than a single strip because the lifter's own 32/64-bit
  // normalisation routinely stacks two casts on one operand.
  llvm::Value* stripIntegerCastsForGeneralizedLoad(llvm::Value* candidate) {
    while (auto* castInst = llvm::dyn_cast<llvm::CastInst>(candidate)) {
      auto* srcTy = castInst->getOperand(0)->getType();
      auto* dstTy = castInst->getType();
      if (!srcTy->isIntegerTy() || !dstTy->isIntegerTy()) {
        break;
      }
      candidate = castInst->getOperand(0);
    }
    return candidate;
  }
  bool matchGeneralizedLoopControlFieldAddress(llvm::Value* loadOffset,
                                               uint64_t& fieldOffsetOut) {
    llvm::Value* baseCandidate = nullptr;
    uint64_t constantOffset = 0;
    auto collectTerms = [&](auto&& self, llvm::Value* candidate) -> bool {
      candidate = stripIntegerCastsForGeneralizedLoad(candidate);
      if (auto* addInst = llvm::dyn_cast<llvm::BinaryOperator>(candidate);
          addInst && addInst->getOpcode() == llvm::Instruction::Add) {
        return self(self, addInst->getOperand(0)) &&
               self(self, addInst->getOperand(1));
      }
      if (auto* constantInt = llvm::dyn_cast<llvm::ConstantInt>(candidate)) {
        constantOffset += constantInt->getZExtValue();
        return true;
      }
      if (baseCandidate) {
        return false;
      }
      baseCandidate = candidate;
      return true;
    };
    // The address must have had at least one non-constant term. A pure-constant
    // offset has no base to match against and would otherwise pass every later
    // check vacuously.
    if (!collectTerms(collectTerms, loadOffset) || !baseCandidate) {
      return false;
    }
    // Whitelist, not a range. See the note at
    // kSupportedGeneralizedControlFieldOffsets -- these three offsets are what
    // this sample's control field used, and a fourth offset that happened to
    // work would not mean the layout is understood.
    const bool supportedOffset = llvm::is_contained(
        kSupportedGeneralizedControlFieldOffsets, constantOffset);
    if (!supportedOffset) {
      return false;
    }
    // Must be an i64 load. A narrower load of the same qword covers fewer bytes
    // than the control field, and building a phi over a partial read produces a
    // value that is right in its low bits and silently wrong above them.
    auto* loadInst = llvm::dyn_cast<llvm::LoadInst>(baseCandidate);
    if (!loadInst || !loadInst->getType()->isIntegerTy(64)) {
      return false;
    }
    // Tracked-buffer GEP specifically. A load through any other pointer is
    // reading something else -- image-backed, or another region -- and matching
    // it on address alone would bind the control field to unrelated memory.
    auto* gep =
        llvm::dyn_cast<llvm::GetElementPtrInst>(loadInst->getPointerOperand());
    if (!gep || gep->getPointerOperand() != this->memoryAlloc) {
      return false;
    }
    // The slot has to be the one this loop actually designated. Comparing
    // against the live state (rather than a constant) is what lets the same
    // matcher work once slot discovery replaces the Themida seed.
    auto* offsetCI = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1));
    if (!offsetCI ||
        offsetCI->getZExtValue() !=
            activeGeneralizedLoopControlFieldState.controlSlot) {
      return false;
    }
    fieldOffsetOut = constantOffset;
    return true;
  }


  // The stack portion of a buffer snapshot.
  //
  // Filtering rather than copying the whole map because the restore path only
  // ever needs the local stack: image-backed bytes come from the file and
  // bytecode bytes from the VMP model, so including them would let a stale
  // snapshot entry shadow the authoritative source.
  //
  // isTrackedLocalStackAddress rather than isTrackedStackAddress: only the
  // frame below the initial SP is real stack state. See the note there.
  llvm::DenseMap<uint64_t, ValueByteReference> extractLocalStackBuffer(
      const llvm::DenseMap<uint64_t, ValueByteReference>& sourceBuffer) {
    llvm::DenseMap<uint64_t, ValueByteReference> localBuffer;
    for (const auto& entry : sourceBuffer) {
      if (this->isTrackedLocalStackAddress(entry.first)) {
        localBuffer[entry.first] = entry.second;
      }
    }
    return localBuffer;
  }


  // Data-driven register preservation: a register is preserved (not widened
  // to undef on the first backedge) when its value differs between canonical
  // and any effective backedge — meaning the loop body carries state through
  // that register. RSP is always preserved regardless.
  //
  // For dispatcher-shaped loops (IndirectJump context), the Themida-tuned
  // hardcoded set {1,4,7,9,10,12,14} is used instead. Preserving ALL
  // differing registers in dispatchers prevents LLVM from optimizing away
  // scratch computations, which blocks import resolution.
  bool shouldPreserveGeneralizedBackedgeRegister(
      size_t index, const backup_point& canonical,
      llvm::ArrayRef<const backup_point*> effectiveSources,
      bool dispatcherShaped) const {
    // RSP is unconditionally preserved so the stack pointer is never
    // treated as "could be anything" inside the loop body.
    if (index == RSP_) return true;
    if (dispatcherShaped) {
      // Legacy Themida-tuned set: only these registers carry dispatcher
      // state that must survive widening. All others widen to undef so
      // LLVM can fold away scratch noise and resolve import targets.
      switch (index) {
      case 1:  // RCX
      case 7:  // RDI
      case 9:  // R9
      case 10: // R10
      case 12: // R12
      case 14: // R14
        return true;
      default:
        return false;
      }
    }
    // Data-driven: preserve when any backedge has a different SSA value
    // from canonical. ConstantInts with the same numeric value share a
    // pointer in LLVM, so pointer equality is a sound test for constants.
    for (const auto* src : effectiveSources) {
      if (src->vec[index] != canonical.vec[index]) {
        return true;
      }
    }
    return false;
  }

  // Build the snapshot that describes a generalized loop's entry state.
  //
  // `sources` are the backedges; `canonical` is the first (non-backedge)
  // arrival. The result is a single coherent view, because the restore path
  // takes one snapshot rather than reconstructing from several.
  //
  // NOTE on the buffer filter below: it KEEPS non-local-stack addresses and
  // DROPS local-stack ones -- the inverse of extractLocalStackBuffer, which
  // extracts exactly those. That is not an inconsistency. The generalized
  // snapshot models the VM's own memory (bytecode, control slots, tracked
  // slots); the local stack frame is restored separately by
  // load_generalized_backup_impl, and carrying it in both places would let the
  // two disagree. The two filters look like a bug side by side and are not;
  // worth knowing before "fixing" one to match the other.
  backup_point make_generalized_loop_backup(BasicBlock* bb,
                                            const backup_point& canonical,
                                            llvm::ArrayRef<backup_point> sources,
                                            bool dispatcherShaped = false) {
    // Use the first source as the base for the generalized snapshot shape
    // (buffer, counter, etc.). For 2-way loops this matches the original
    // single-source behavior exactly; for N-way we pick sources[0] as the
    // representative snapshot since the caller must restore a coherent view.
    //
    // The cache and assumptions are reset in BOTH branches below, and
    // identically. That is not redundancy -- it is the point. A generalized
    // snapshot represents a *merged* state that no single path ever held, so
    // carrying over one path's instruction cache would let the restored block
    // reuse IR built under the other path's assumptions. Same for branch
    // assumptions: they are per-edge facts and have no meaning for a merged
    // entry.
    //
    // No backedges: canonical-only path. Return canonical with local-stack
    // addresses filtered, matching the pre-N-way fallback where
    // make_generalized_loop_backup was called with canonical as both args.
    if (sources.empty()) {
      backup_point generalized = canonical;
      llvm::DenseMap<uint64_t, ValueByteReference> filteredBuffer;
      for (const auto& entry : canonical.buffer) {
        if (!this->isTrackedLocalStackAddress(entry.first)) {
          filteredBuffer[entry.first] = entry.second;
        }
      }
      generalized.buffer = std::move(filteredBuffer);
      generalized.cache = InstructionCache();
      generalized.assumptions.clear();
      return generalized;
    }
    backup_point generalized = sources.front();
    llvm::DenseMap<uint64_t, ValueByteReference> filteredBuffer;
    filteredBuffer.reserve(sources.front().buffer.size());
    for (const auto& entry : sources.front().buffer) {
      if (!this->isTrackedLocalStackAddress(entry.first)) {
        filteredBuffer[entry.first] = entry.second;
      }
    }
    generalized.buffer = std::move(filteredBuffer);
    generalized.cache = InstructionCache();
    generalized.assumptions.clear();

    auto* canonicalSource = canonical.sourceBlock;
    if (!bb || !canonicalSource) {
      return generalized;
    }
    // Filter backedges: drop any that duplicate canonicalSource. This
    // preserves the existing 2-way "canonicalSource == backedgeSource"
    // bailout for the trivial degenerate case.
    //
    // Without this filter a phi would get an incoming value from a block that
    // is also the canonical entry -- the same block twice, with the same value
    // -- which is legal IR but means the phi never varies, so the loop body
    // loses the variation it was generalized to represent.
    llvm::SmallVector<const backup_point*, 2> effectiveSources;
    effectiveSources.reserve(sources.size());
    for (const auto& src : sources) {
      if (src.sourceBlock && src.sourceBlock != canonicalSource) {
        effectiveSources.push_back(&src);
      }
    }
    if (effectiveSources.empty()) {
      return generalized;
    }

    // Phi arrays zero-initialised, so a null entry means "does not vary" and no
    // phi is built. Building phis for invariant registers would add nodes that
    // only forward, and would hide the register's loop-invariance from LLVM.
    std::array<llvm::PHINode*, REGISTER_COUNT> registerPhis{};
    std::array<llvm::PHINode*, FLAGS_END> flagPhis{};
    // Insertion at bb->begin(): phis must precede every non-phi instruction in
    // a block or LLVM rejects the module. Inserting at the builder's current
    // point would place them after whatever was already lifted into the header.
    llvm::IRBuilder<> phiBuilder(bb, bb->begin());
    auto mergeValue = [&](llvm::Value* canonicalValue,
                          llvm::ArrayRef<llvm::Value*> backedgeValues,
                          const char* name, llvm::PHINode*& phiOut,
                          bool widenFirstBackedge) -> llvm::Value* {
      // Require canonical + all backedges present and type-matched. Any
      // type mismatch or nullptr falls back to the first backedge value,
      // preserving the pre-N-way single-backedge semantics.
      //
      // The degradation is to ONE backedge's value, not to undef and not to a
      // phi. Picking a real value keeps the block concrete, which matters
      // because this is inside path solving -- a value that folds gives the
      // solver something to work with, while undef sends it down an unknown
      // path immediately. The cost is that the loop loses the variation for
      // this particular value, which is a coverage loss rather than a
      // correctness one.
      if (!canonicalValue || backedgeValues.empty()) {
        return backedgeValues.empty() ? nullptr : backedgeValues.front();
      }
      for (auto* beValue : backedgeValues) {
        if (!beValue || beValue->getType() != canonicalValue->getType() ||
            beValue == canonicalValue) {
          return backedgeValues.front();
        }
      }
      auto* phi = phiBuilder.CreatePHI(canonicalValue->getType(),
                                       1 + backedgeValues.size(), name);
      phi->addIncoming(canonicalValue, canonicalSource);
      for (size_t i = 0; i < backedgeValues.size(); ++i) {
        phi->addIncoming(widenFirstBackedge
                             ? llvm::UndefValue::get(backedgeValues[i]->getType())
                             : backedgeValues[i],
                         effectiveSources[i]->sourceBlock);
      }
      phiOut = phi;
      return phi;
    };
    constexpr std::array<Register, 16> gprOrder = {
        Register::RAX, Register::RCX, Register::RDX, Register::RBX,
        Register::RSP, Register::RBP, Register::RSI, Register::RDI,
        Register::R8,  Register::R9,  Register::R10, Register::R11,
        Register::R12, Register::R13, Register::R14, Register::R15,
    };

    llvm::SmallVector<llvm::Value*, 2> regValues;
    llvm::SmallVector<llvm::Value*, 2> flagValues;
    for (size_t i = 0; i < REGISTER_COUNT; ++i) {
      // "symbolizing everything except VIP" (Themida article, Virtualized
      // Control Flow / Tencent limitations): if this register carries a
      // module-backed address it is the VM's virtual instruction pointer.
      // Merging it into a loop phi turns it symbolic, and then every in-loop
      // bytecode read (load -> constant -> decrypt -> next handler) becomes
      // unresolvable. Freeze it instead so the chain survives the backedge.
      if (auto* ci =
              llvm::dyn_cast_or_null<llvm::ConstantInt>(canonical.vec[i])) {
        if (this->isModuleAddress(ci->getZExtValue()) &&
            !this->feedsCondition(canonical.vec[i])) {
          generalized.vec[i] = canonical.vec[i];
          continue;
        }
      }
      const bool widenFirstBackedge =
          !shouldPreserveGeneralizedBackedgeRegister(i, canonical,
                                                     effectiveSources,
                                                     dispatcherShaped);
      regValues.clear();
      for (auto* src : effectiveSources) {
        regValues.push_back(src->vec[i]);
      }
      generalized.vec[i] = mergeValue(canonical.vec[i], regValues,
                                      "loop_reg_phi", registerPhis[i],
                                      widenFirstBackedge);
    }
    for (size_t i = 0; i < FLAGS_END; ++i) {
      flagValues.clear();
      for (auto* src : effectiveSources) {
        flagValues.push_back(src->vecflag[i]);
      }
      generalized.vecflag[i] =
          mergeValue(canonical.vecflag[i], flagValues, "loop_flag_phi",
                     flagPhis[i], false);
    }
    generalizedLoopRegisterPhis[bb] = registerPhis;
    generalizedLoopFlagPhis[bb] = flagPhis;
    return generalized;
  }

  // Wholesale state restore.
  //
  // Every field is assigned, including cache and assumptions. Nothing is
  // merged and nothing is preserved: this is the "go back to where we were"
  // operation, and a partial restore would leave the current path's derived
  // artefacts attached to a different architectural state.
  //
  // `counter` is restored too. It is not architectural state, but it feeds
  // diagnostic labels and the instruction-stream trace, and letting it run
  // backwards would make a trace ambiguous -- two instructions with the same
  // counter at different points in the lift.
  //
  // Note this does NOT touch blockInfo, the worklist, or the current insert
  // block. Those describe where the lift is, not what the machine state is, and
  // the block-entry paths set them separately.
  void restore_backup_point(const backup_point& snapshot) {
    vec = snapshot.vec;
    vecflag = snapshot.vecflag;
    this->buffer = snapshot.buffer;
    this->cache = snapshot.cache;
    this->assumptions = snapshot.assumptions;
    this->counter = snapshot.ct;
  }

  // Take a snapshot for `bb`.
  //
  // Three cases, and the choice between them is the whole function:
  //
  //   doMove              the caller is abandoning this path entirely; steal
  //                       the state rather than copying it
  //   generalized + copy  the snapshot goes into TWO containers, so it has to
  //                       be a real copy
  //   plain               ordinary copy into BBbackup
  //
  // `generalized` therefore disables the move even when moveState is set. See
  // the note below -- that guard is correctness, not performance.
  //
  // sourceBlock is always the builder's current insert block, never the block
  // being backed up. Those are different things: the snapshot records where the
  // lift was when the backup was taken, which is what the restore path needs in
  // order to know which block a backedge came from.
  void branch_backup_impl(BasicBlock* bb, bool generalized,
                          bool moveState = false) {
    printvalue2("backing up");
    printvalue2(this->counter);

    // moveState: caller is abandoning the current path (run=0, single
    // successor). Steal buffer/cache/assumptions instead of deep-copying —
    // mix const-path: ~46k backups × DenseMap copy was ~3s.
    // Never move into generalized backups: that path may store the snapshot
    // twice (BBbackup + backedge vector).
    //
    // The move is only sound when the current path is genuinely finished with.
    // If the caller intends to keep lifting along this path, the state it
    // moved away is gone -- which is why this is opt-in per call site and not
    // a general optimisation.
    //
    // The `!generalized` guard is not merely a fast path. The generalized
    // branch below stores the snapshot in two places, so moving into it would
    // leave one of the two holding emptied maps, and restoring that copy would
    // silently lose the entire block state.
    const bool doMove = moveState && !generalized;
    LiftPerfDiag::ScopedTimer backupTimer(
        &this->perfDiag,
        doMove ? &this->perfDiag.backupMove : &this->perfDiag.backupCopy);
    if (doMove) {
      // Steal directly into the map slot — avoids a temporary backup_point
      // and a second InstructionCache move (now unique_ptr-sized anyway).
      //
      // Writing into the slot rather than constructing a temporary and moving
      // that matters: default-constructing a backup_point then moving into it
      // would allocate and release the DenseMaps an extra time, and this path
      // runs ~46k times per lift of a protected sample.
      //
      // ct and sourceBlock are copied rather than stolen because they are
      // scalars the caller still needs -- counter continues to be incremented,
      // and sourceBlock is the insert block that stays current.
      auto& slot = BBbackup[bb];
      slot.vec = std::move(vec);
      slot.vecflag = std::move(vecflag);
      slot.buffer = std::move(this->buffer);
      slot.cache = std::move(this->cache);
      slot.assumptions = std::move(this->assumptions);
      slot.ct = this->counter;
      slot.sourceBlock = this->builder->GetInsertBlock();
      return;
    }

    backup_point snapshot(vec, vecflag, this->buffer, this->cache,
                          this->assumptions, this->counter,
                          this->builder->GetInsertBlock());
    if (generalized) {
      // First-writer-wins for the plain entry. A second backup of the same
      // block must NOT overwrite it: the canonical entry is the non-backedge
      // arrival that every phi takes as its first incoming value, and a later
      // overwrite would silently substitute a backedge's state for it.
      if (!BBbackup.contains(bb)) {
        BBbackup[bb] = snapshot;
      }
      // Append per-source; a repeat call from the same sourceBlock replaces
      // that block's entry in place, preserving uniqueness without growing
      // the vector unboundedly on iterative lift passes.
      //
      // Replace-in-place rather than push-and-dedupe-later: on an iterative
      // lift the same backedge block is re-backed-up on every pass, so the
      // vector would grow without bound and the phi would gain duplicate
      // incoming edges that all carry the same block.
      auto& backedges = generalizedLoopBackedgeBackup[bb];
      for (auto& existing : backedges) {
        if (existing.sourceBlock == snapshot.sourceBlock) {
          existing = std::move(snapshot);
          return;
        }
      }
      backedges.push_back(std::move(snapshot));
      return;
    }

    BBbackup[bb] = std::move(snapshot);
  }

  // Recognise the VM dispatcher's mux shape: a select between two constants,
  // possibly behind casts.
  //
  // Both helpers peel casts first and only then test the shape, because the
  // lift's own width normalisation routinely puts a trunc/zext on the select
  // and a sext on each arm. Testing before peeling would miss every real mux.
  //
  // Constant arms are the requirement, not a convenience. A select with a
  // symbolic arm is an ordinary conditional, which the path solver already
  // handles; only the two-constant form is unambiguously a dispatcher choosing
  // between two bytecode addresses.
  static llvm::SelectInst* peelPcodeCursorSelect(llvm::Value* v) {
    return llvm::dyn_cast<llvm::SelectInst>(
        VmpPcodeCursor<Register>::peelCasts(v));
  }

  static bool isPcodeCursorSelectArms(llvm::SelectInst* sel,
                                      llvm::ConstantInt*& tArm,
                                      llvm::ConstantInt*& fArm) {
    tArm = llvm::dyn_cast<llvm::ConstantInt>(sel->getTrueValue());
    fArm = llvm::dyn_cast<llvm::ConstantInt>(sel->getFalseValue());
    return tArm && fArm;
  }

  // Fork a VM pcode-cursor multiplex: a select between two constant bytecode
  // addresses is the shape a VM dispatcher uses to choose its next handler,
  // and exploring both arms is how the lifter follows the VM rather than
  // giving up at the first symbolic dispatch.
  //
  // The cursorMuxForked set makes this idempotent per (condition, slot). On
  // the first call it creates the two blocks; on every later call with the same
  // key it *replays* the recorded assumption instead of forking again. Without
  // that, a loop containing the same mux would fork on every iteration and the
  // worklist would grow without bound.
  bool tryForkCursorSelectMux_impl(llvm::SelectInst* sel, uint64_t slot,
                                   llvm::ConstantInt* tArm,
                                   llvm::ConstantInt* fArm) {
    auto* condInst = llvm::dyn_cast<llvm::Instruction>(sel->getCondition());
    if (condInst == nullptr) {
      return false;
    }

    const CursorMuxForkKey key{condInst, slot};
    if (this->cursorMuxForked.contains(key)) {
      // Already forked for this condition. The assumption recorded on the
      // condition now *is* the answer: write the chosen arm back into the
      // slot and return, rather than creating another pair of blocks.
      //
      // A missing assumption here means the restore path did not carry it
      // across -- returning false lets the caller fall back to the generic
      // handling, which is the safe degradation.
      auto it = this->assumptions.find(condInst);
      if (it == this->assumptions.end()) {
        return false;
      }
      this->writeBufferQwordFromConstant(
          slot, it->second.isOne() ? tArm : fArm);
      return true;
    }
    this->cursorMuxForked.insert(key);

    const uint64_t contPC = this->current_address;
    llvm::BasicBlock* bbFalse =
        this->createBudgetedBasicBlock("cursor_mux_f", contPC);
    llvm::BasicBlock* bbTrue =
        this->createBudgetedBasicBlock("cursor_mux_t", contPC);
    if (bbFalse == this->liftAbortBlock || bbTrue == this->liftAbortBlock) {
      return false;
    }

    // The false arm is prepared as a *snapshot* before the true arm is taken.
    //
    // Order matters: branch_backup captures the current state, and only after
    // that does the false arm's slot get overwritten with fArm and its
    // assumption recorded. Doing it the other way round would back up state that
    // already contains the true arm's value, so restoring bbFalse would produce
    // the true arm's cursor with the false arm's assumption.
    //
    // The byte loop mirrors writeBufferQwordFromConstant rather than calling it,
    // because this writes into the *snapshot's* buffer, not the live one. That
    // is the whole reason the helper is not reusable here.
    this->branch_backup(bbFalse);
    auto& falseSnap = BBbackup[bbFalse];
    falseSnap.assumptions[condInst] = llvm::APInt(1, 0);
    const unsigned armBytes = fArm->getBitWidth() / 8;
    for (unsigned i = 0; i < armBytes; ++i) {
      falseSnap.buffer[slot + i] = ValueByteReference(fArm, i);
    }

    // The true arm is the one the lift *stays* on. Emitting it into the live
    // state means the current block continues down the true path while bbFalse
    // is queued, so the dispatcher is followed rather than abandoned at the
    // first fork.
    this->assumptions[condInst] = llvm::APInt(1, 1);
    this->writeBufferQwordFromConstant(slot, tArm);

    llvm::Value* cond = sel->getCondition();
    auto* br = this->builder->CreateCondBr(cond, bbTrue, bbFalse);
    this->RegisterBranch(br);
    // Only bbFalse is queued. bbTrue is entered immediately below via
    // SetInsertPoint, so queueing it too would lift the same continuation twice.
    this->addUnvisitedAddr(BBInfo(contPC, bbFalse));

    this->builder->SetInsertPoint(bbTrue);
    this->blockInfo = BBInfo(contPC, bbTrue);
    return true;
  }

  // Resolve a VM cursor pop to a single bytecode address, forking if needed.
  //
  // Four outcomes, in order of preference:
  //
  //   nullopt (no constant)      not resolvable at all; caller falls back
  //   nullopt (not bytecode)     a real constant that is not a handler address
  //   nullopt (mux, fork failed) the shape was right but the mux could not be
  //                              built -- budget, or a non-instruction condition
  //   a concrete address          either already concrete, or one arm of a mux
  //
  // The bytecode check on both mux arms is stricter than the single-value case
  // and deliberately so: a two-constant select where only one arm is bytecode
  // is far more likely to be ordinary arithmetic than a dispatcher choosing
  // between handlers. Forking on it would create a spurious path.
  std::optional<uint64_t> tryResolvePcodeCursorPop_impl(uint64_t slot,
                                                        LazyValue orgLoad) {
    LazyValue nested(orgLoad);
    llvm::Value* popped = this->retrieveCombinedValue(slot, 8, nested);
    if (popped == nullptr) {
      return std::nullopt;
    }
    if (auto* ci = llvm::dyn_cast<llvm::ConstantInt>(popped)) {
      const uint64_t addr = ci->getZExtValue();
      if (this->vmp.isBytecodeAddress(addr)) {
        return addr;
      }
      return std::nullopt;
    }

    llvm::SelectInst* sel = peelPcodeCursorSelect(popped);
    if (sel == nullptr) {
      return std::nullopt;
    }
    llvm::ConstantInt *tArm = nullptr, *fArm = nullptr;
    if (!isPcodeCursorSelectArms(sel, tArm, fArm) ||
        !this->vmp.isBytecodeAddress(tArm->getZExtValue()) ||
        !this->vmp.isBytecodeAddress(fArm->getZExtValue())) {
      return std::nullopt;
    }

    if (!tryForkCursorSelectMux_impl(sel, slot, tArm, fArm)) {
      return std::nullopt;
    }

    auto* condInst = llvm::dyn_cast<llvm::Instruction>(sel->getCondition());
    if (condInst == nullptr) {
      return std::nullopt;
    }
    // No recorded assumption means the fork was just created and this call is
    // the one that built it -- in which case the true arm is the one the lift is
    // currently on, and it is the right answer to return.
    auto it = this->assumptions.find(condInst);
    if (it == this->assumptions.end()) {
      return tArm->getZExtValue();
    }
    // Otherwise read the assumption and take the arm it names. This is the
    // replay path: the second time the same mux is reached, the assumption
    // recorded by the first fork says which side this lift is exploring.
    return (it->second.isOne() ? tArm : fArm)->getZExtValue();
  }

  // Restore the ordinary (non-generalized) snapshot for `bb`.
  //
  // A missing entry is a no-op, not an error. The block may never have been
  // backed up -- first arrival at an address, or a path that reached it without
  // a branch -- and in that case the current state is already correct and
  // restoring nothing is the right behaviour.
  void load_backup_impl(BasicBlock* bb) {
    activeGeneralizedLoopLocalBuffer.clear();
    if (BBbackup.contains(bb)) {
      printvalue2("loading backup");
      if (this->liftProgressDiagEnabled) {
        std::cout << "[diag] load_backup bb=" << bb->getName().str()
                  << " has14fca0=" << (BBbackup[bb].buffer.contains(1375392) ? 1 : 0)
                  << " has14fca8=" << (BBbackup[bb].buffer.contains(1375400) ? 1 : 0)
                  << " has14fcb0=" << (BBbackup[bb].buffer.contains(1375408) ? 1 : 0)
                  << "\n";
      }
      restore_backup_point(BBbackup[bb]);
      activeGeneralizedLoopEntrySourceBlock = BBbackup[bb].sourceBlock;
    }
  }

  // Result of generalized-loop slot discovery: control + target slot identity
  // and the canonical/backedge qword values + per-backedge buffers that
  // motivate the choice. backedgeSources/Controls/Buffers are filled with
  // exactly the backedges whose tracked qword at controlSlot differs from
  // canonical (the activation precondition for the loop-control helpers).
  //
  // `valid` guards the rest for the same reason as in
  // GeneralizedLoopControlFieldState: this is a plain value type that is always
  // default-constructed, so without it a discovery that failed and a discovery
  // that found slot 0 are indistinguishable.
  struct DiscoveredGeneralizedLoopSlots {
    bool valid = false;
    uint64_t controlSlot = 0;
    uint64_t targetSlot = 0;
    uint64_t canonicalControl = 0;
    // Parallel vectors, index-aligned. Each holds exactly the backedges that
    // activate the loop -- the ones whose control value differs -- so index i
    // of all three describes the same edge. Keeping them parallel rather than in
    // a struct-of-three is a readability tradeoff; the alternative would be a
    // vector of small structs and an extra indirection on the phi-building
    // path.
    llvm::SmallVector<llvm::BasicBlock*, 2> backedgeSources;
    llvm::SmallVector<uint64_t, 2> backedgeControls;
    llvm::SmallVector<llvm::DenseMap<uint64_t, ValueByteReference>, 2> backedgeBuffers;
    // All non-primary varying qwords discovered during scan.
    llvm::SmallVector<LoopCarriedSlot, 4> carriedSlots;
  };

  // Try to populate `dst` from a specific candidate `slot`. Returns true iff
  // canonical has a tracked qword at slot AND at least one backedge has a
  // differing tracked qword at slot. Caller uses this both for the legacy
  // Themida-slot priority path and for the fallback scan.
  //
  // "Differs from canonical" is the activation test, and it is stricter than
  // "differs from the previous backedge". A slot where every backedge agrees
  // with the canonical arrival carries no loop-carried value, so building a
  // phi for it would produce an invariant -- correct, but it would suppress the
  // discovery of slots that actually do vary, since the scan stops at the first
  // N hits.
  bool tryPopulateControlFromSlot(
      const backup_point& canonical,
      llvm::ArrayRef<backup_point> backedges, uint64_t slot,
      DiscoveredGeneralizedLoopSlots& dst) {
    uint64_t canonicalControl = 0;
    if (!readConstantTrackedQword(canonical.buffer, slot, canonicalControl)) {
      return false;
    }
    llvm::SmallVector<llvm::BasicBlock*, 2> sources;
    llvm::SmallVector<uint64_t, 2> controls;
    llvm::SmallVector<llvm::DenseMap<uint64_t, ValueByteReference>, 2> buffers;
    for (const auto& be : backedges) {
      if (!be.sourceBlock || be.sourceBlock == canonical.sourceBlock) {
        continue;
      }
      uint64_t beControl = 0;
      if (!readConstantTrackedQword(be.buffer, slot, beControl)) {
        continue;
      }
      if (beControl == canonicalControl) {
        continue;
      }
      sources.push_back(be.sourceBlock);
      controls.push_back(beControl);
      buffers.push_back(be.buffer);
    }
    if (sources.empty()) {
      return false;
    }
    dst.controlSlot = slot;
    dst.canonicalControl = canonicalControl;
    dst.backedgeSources = std::move(sources);
    dst.backedgeControls = std::move(controls);
    dst.backedgeBuffers = std::move(buffers);
    return true;
  }

  // Discover the loop's control + target memory slots from canonical and
  // backedge buffers. Order of preference for control slot:
  //   1. The legacy Themida cursor slot if it has a varying tracked qword
  //      (zero-regression guarantee on the reference Themida sample).
  //   2. Otherwise, the qword in the canonical buffer with the most-varying
  //      backedges. Tiebreak: lowest address.
  // Order of preference for target slot:
  //   1. The legacy Themida loop-carried slot if every selected backedge has
  //      a tracked qword there.
  //   2. Otherwise, the lowest-address candidate qword (excluding the chosen
  //      controlSlot) that is tracked across canonical and every selected
  //      backedge buffer. Values may match or differ; the target-slot helper
  //      handles both cases.
  // Returns a result with valid=false if no control slot can be identified.
  // Stack-local addresses are excluded from candidates; they are handled by
  // separate local-buffer machinery.
  DiscoveredGeneralizedLoopSlots discoverGeneralizedLoopSlots(
      const backup_point& canonical,
      llvm::ArrayRef<backup_point> backedges) {
    DiscoveredGeneralizedLoopSlots result;
    if (!canonical.sourceBlock || backedges.empty()) {
      return result;
    }

    // 1. Try the legacy Themida cursor slot first.
    if (!tryPopulateControlFromSlot(canonical, backedges,
                                    kThemidaControlCursorSlot, result)) {
      // 2. Fallback scan: enumerate qword-start addresses in canonical buffer
      //    and pick the most-varying. A "qword start" is an address A where
      //    canonical has 8 contiguous tracked bytes from A and has no key at
      //    A-1 (filters overlapping qwords from a single tracked region).
      //
      // The addr-1 test is what makes the candidate set non-overlapping. Without
      // it, a 16-byte tracked region yields 9 "qword starts" all describing the
      // same bytes, each scoring the same variance -- so the tiebreak would pick
      // by address rather than by anything meaningful, and could land on an
      // unaligned offset into the middle of a real slot.
      llvm::SmallVector<uint64_t, 16> candidates;
      for (const auto& entry : canonical.buffer) {
        const uint64_t addr = entry.first;
        // isTrackedStackAddress here, not isTrackedLocalStackAddress, even
        // though the exclusion is broader than necessary. The scan is looking
        // for VM memory, and being conservative about what counts as stack costs
        // nothing: stack addresses are restored by the local-buffer path and
        // would never have qualified anyway.
        if (this->isTrackedStackAddress(addr)) continue;
        if (canonical.buffer.contains(addr - 1)) continue;
        uint64_t dummy = 0;
        if (!readConstantTrackedQword(canonical.buffer, addr, dummy)) continue;
        candidates.push_back(addr);
      }
      // Sorted so the "lowest address wins" tiebreak below is a stable, stated
      // rule rather than an accident of DenseMap iteration order. Unsorted, the
      // same input could select a different slot across runs or across a
      // rebuild -- and the discovery result feeds straight into phi
      // construction, so a nondeterministic choice is a nondeterministic lift.
      std::sort(candidates.begin(), candidates.end());
      size_t bestVarianceCount = 0;
      for (uint64_t addr : candidates) {
        DiscoveredGeneralizedLoopSlots probe;
        if (!tryPopulateControlFromSlot(canonical, backedges, addr, probe)) {
          continue;
        }
        // Strict >, not >=. A tie keeps the earlier -- that is, the
        // lower-addressed -- candidate, which is the documented tiebreak and is
        // only a stable rule because the sort above ran.
        if (probe.backedgeSources.size() > bestVarianceCount) {
          bestVarianceCount = probe.backedgeSources.size();
          result.controlSlot = probe.controlSlot;
          result.canonicalControl = probe.canonicalControl;
          result.backedgeSources = std::move(probe.backedgeSources);
          result.backedgeControls = std::move(probe.backedgeControls);
          result.backedgeBuffers = std::move(probe.backedgeBuffers);
        }
      }
      if (bestVarianceCount == 0) {
        return result;  // no varying qword anywhere -> no control slot
      }
    }
    // `valid` set only here, after a control slot was actually found. Setting it
    // any earlier would mark a result whose backedge vectors are empty as a
    // valid discovery, and the phi construction would then build a zero-incoming
    // phi.
    result.valid = true;

    // Target slot: prefer legacy Themida carried slot if usable across all
    // selected backedges; otherwise scan for the lowest-addr alternative.
    auto targetUsableAt = [&](uint64_t slot) -> bool {
      if (slot == result.controlSlot) return false;
      uint64_t dummy = 0;
      if (!readConstantTrackedQword(canonical.buffer, slot, dummy)) return false;
      for (const auto& buf : result.backedgeBuffers) {
        if (!readConstantTrackedQword(buf, slot, dummy)) return false;
      }
      return true;
    };
    if (targetUsableAt(kThemidaLoopCarriedSlot)) {
      result.targetSlot = kThemidaLoopCarriedSlot;
    } else {
      // Same candidate enumeration as the control scan but WITHOUT the
      // readConstantTrackedQword filter. The control slot must be readable to be
      // a control; the target slot only has to be *tracked on every selected
      // backedge* (which targetUsableAt checks), and requiring it readable in
      // canonical too would reject a target whose canonical value happens not to
      // be a constant yet. The helper handles the matching-values case.
      llvm::SmallVector<uint64_t, 16> targetCandidates;
      for (const auto& entry : canonical.buffer) {
        const uint64_t addr = entry.first;
        if (this->isTrackedStackAddress(addr)) continue;
        if (canonical.buffer.contains(addr - 1)) continue;
        targetCandidates.push_back(addr);
      }
      // Sorted for the same reason as the control scan: "lowest address" is a
      // stated tiebreak only if the iteration order is one.
      std::sort(targetCandidates.begin(), targetCandidates.end());
      // First usable wins, which given the sort means lowest address.
      for (uint64_t addr : targetCandidates) {
        if (targetUsableAt(addr)) {
          result.targetSlot = addr;
          break;
        }
      }
      // targetSlot may remain 0 if nothing qualified. That is not an error: the
      // target-slot helper is optional, and the control slot alone is enough to
      // generalize a loop. A zero targetSlot is distinguishable from a real
      // slot at address 0 only by the surrounding validity checks, which is why
      // those checks exist.
    }

    // Collect ALL additional varying qwords beyond controlSlot/targetSlot.
    // Each gets a LoopCarriedSlot so retrieve helpers can build phis for
    // every loop-carried memory address, fixing the TEA-round class of bugs.
    {
      llvm::SmallVector<uint64_t, 16> allCandidates;
      for (const auto& entry : canonical.buffer) {
        const uint64_t addr = entry.first;
        if (this->isTrackedStackAddress(addr)) continue;
        if (canonical.buffer.contains(addr - 1)) continue;
        uint64_t dummy = 0;
        if (!readConstantTrackedQword(canonical.buffer, addr, dummy)) continue;
        allCandidates.push_back(addr);
      }
      std::sort(allCandidates.begin(), allCandidates.end());
      for (uint64_t addr : allCandidates) {
        if (addr == result.controlSlot || addr == result.targetSlot) continue;
        uint64_t canonVal = 0;
        if (!readConstantTrackedQword(canonical.buffer, addr, canonVal)) continue;
        // Collect per-backedge values at this address.
        // Unlike controlSlot, we include slots even when some backedges match
        // the canonical value — the helper will collapse to the shared value
        // when all match, and build a phi when any differ.
        //
        // This is the TEA-round fix: the earlier code required a slot to differ
        // from canonical on every backedge, so a slot that varied on two backedges
        // out of three was silently dropped and the loop body read the wrong
        // value on the third. Dropping a constant-valued slot costs a phi; it
        // does not cost correctness, so the permissive test is the right one.
        bool anyBackedgeHasSlot = false;
        LoopCarriedSlot slot;
        slot.address = addr;
        slot.canonicalValue = canonVal;
        for (const auto& buf : result.backedgeBuffers) {
          uint64_t beVal = 0;
          if (readConstantTrackedQword(buf, addr, beVal)) {
            slot.backedgeValues.push_back(beVal);
            anyBackedgeHasSlot = true;
          } else {
            // Backedge buffer lacks this slot — skip entire slot to avoid
            // mismatched backedge vector sizes.
            //
            // All-or-nothing, and the sizes really do have to match: the phi
            // built from this slot takes one incoming value per selected
            // backedge, in the same order as result.backedgeBuffers. A partial
            // vector would silently pair the wrong backedge with the wrong
            // value -- producing a phi that is well-formed and wrong, rather
            // than one that fails to build.
            //
            // Note this makes the slot set depend on every selected backedge
            // having it, so adding a backedge later can retroactively drop a
            // slot that was previously discovered.
            anyBackedgeHasSlot = false;
            break;
          }
        }
        if (anyBackedgeHasSlot && !slot.backedgeValues.empty()) {
          result.carriedSlots.push_back(std::move(slot));
        }
      }
    }

    return result;
  }

  // Restore a generalized loop's merged entry state.
  //
  // Both containers must be present. BBbackup alone means the block was backed
  // up but never reached through a backedge, so there is nothing to merge and
  // the ordinary restore is the right thing -- and it has already happened, so
  // falling through with cleared state is correct rather than a silent skip.
  //
  // The clear() calls come FIRST and unconditionally, including on the path
  // that does nothing. Leaving a previous loop's control-field state in place
  // would let this loop's helper calls read the previous loop's slots.
  void load_generalized_backup_impl(BasicBlock* bb) {
    activeGeneralizedLoopLocalBuffer.clear();
    clearGeneralizedLoopControlFieldState();
    if (generalizedLoopBackedgeBackup.contains(bb) && BBbackup.contains(bb)) {
      printvalue2("loading generalized backup");
      auto& backedges = generalizedLoopBackedgeBackup[bb];
      // Discover the per-loop control + target slots from canonical and
      // backedge buffers. Falls back to the legacy Themida slots when they
      // qualify (zero behavior change on the reference Themida sample).
      auto discovery = discoverGeneralizedLoopSlots(BBbackup[bb], backedges);
      // Dispatcher-shaped loops (Themida-style) use the hardcoded register
      // preserve set; simple guest loops use data-driven preservation.
      // Dispatcher detection: check if this is a Themida-style dispatcher
      // where the hardcoded register preserve set should be used.
      // When discovery IS valid and the control slot is the Themida cursor,
      // it's definitely a dispatcher. When discovery is invalid (no varying
      // slots), check if the canonical buffer contains the cursor slot —
      // if so, it's likely a dispatcher that hasn't diverged yet.
      // Otherwise (no cursor slot in buffer at all), it's a guest loop.
      //
      // Two probes rather than one, because the two situations need different
      // evidence. A valid discovery that landed on the Themida cursor is a
      // positive identification. An INVALID discovery is ambiguous -- the loop
      // may simply not have diverged yet -- so the weaker probe (is the cursor
      // present at all?) is used, which is a heuristic and will misclassify a
      // guest loop that happens to touch that address. That direction is the
      // mild one: the dispatcher set preserves more registers, which costs
      // folding opportunities rather than correctness.
      bool dispatcherShaped = false;
      if (discovery.valid) {
        dispatcherShaped = (discovery.controlSlot == kThemidaControlCursorSlot);
      } else {
        // No varying slots — check if the Themida cursor address is even
        // present in the canonical buffer (indicates a dispatcher that
        // hasn't fully diverged yet). Guest loops never write to the cursor.
        uint64_t cursorProbe = 0;
        dispatcherShaped = readConstantTrackedQword(
            BBbackup[bb].buffer, kThemidaControlCursorSlot, cursorProbe);
      }
      if (this->liftProgressDiagEnabled) {
        std::cout << "[diag] dispatcher_check valid=" << discovery.valid
                  << " controlSlot=0x" << std::hex << discovery.controlSlot
                  << " kThemida=0x" << kThemidaControlCursorSlot
                  << std::dec << " result=" << dispatcherShaped << "\n";
      }
      auto snapshot = make_generalized_loop_backup(bb, BBbackup[bb], backedges,
                                                   dispatcherShaped);
      if (this->liftProgressDiagEnabled) {
        auto formatHex = [](uint64_t value) {
          std::ostringstream os;
          os << "0x" << std::hex << std::uppercase << value;
          return os.str();
        };
        std::cout << "[diag] load_generalized_backup bb=" << bb->getName().str()
                  << " sourceCanonical="
                  << (BBbackup[bb].sourceBlock
                          ? BBbackup[bb].sourceBlock->getName().str()
                          : std::string("<null>"))
                  << " backedgeCount=" << backedges.size()
                  << " discovered="
                  << (discovery.valid ? "yes" : "no")
                  << " controlSlot="
                  << (discovery.valid ? formatHex(discovery.controlSlot)
                                      : std::string("na"))
                  << " targetSlot="
                  << (discovery.valid && discovery.targetSlot
                          ? formatHex(discovery.targetSlot)
                          : std::string("na"))
                  << " canonicalControl="
                  << (discovery.valid ? formatHex(discovery.canonicalControl)
                                      : std::string("na"));
        for (size_t i = 0; i < discovery.backedgeSources.size(); ++i) {
          std::cout << " backedge[" << i << "]source="
                    << (discovery.backedgeSources[i]
                            ? discovery.backedgeSources[i]->getName().str()
                            : std::string("<null>"))
                    << " backedge[" << i << "]control="
                    << formatHex(discovery.backedgeControls[i]);
        }
        std::cout << "\n";
      }
      restore_backup_point(snapshot);

      // Stored state wins over a fresh discovery.
      //
      // This is the single most important ordering in the function. A loop is
      // entered many times; on the second and later entries the phis already
      // exist and are keyed by header, so the loop's structure is fixed. If
      // discovery ran again and happened to pick a different slot -- which it
      // can, since the candidate set grows as more backedges are recorded -- the
      // restore would publish slots the existing phis were not built from, and
      // every control-field helper would read a slot no phi covers.
      //
      // So: look first, and only fall back to discovery when there is nothing
      // stored. That also makes the first entry cheap and every later one free.
      auto storedStateIt = generalizedLoopControlFieldStates.find(bb);
      if (storedStateIt != generalizedLoopControlFieldStates.end() &&
          storedStateIt->second.valid) {
        activeGeneralizedLoopControlFieldState = storedStateIt->second;
        // The entry source becomes the FIRST backedge, not the canonical source.
        // The loop is now past its first iteration, so the edge that led back in
        // is the one that explains the state being restored.
        activeGeneralizedLoopEntrySourceBlock =
            activeGeneralizedLoopControlFieldState.backedgeSources.empty()
                ? nullptr
                : activeGeneralizedLoopControlFieldState.backedgeSources.front();
        // Local stack comes from the same first backedge, for the same reason.
        if (!activeGeneralizedLoopControlFieldState.backedgeBuffers.empty()) {
          activeGeneralizedLoopLocalBuffer = extractLocalStackBuffer(
              activeGeneralizedLoopControlFieldState.backedgeBuffers.front());
        } else {
          activeGeneralizedLoopLocalBuffer.clear();
        }
      } else {
        // First entry (or a discovery that previously failed). The entry source
        // is the canonical source -- backedges.front() is only a fallback for the
        // case where no canonical source exists, which the branch below also
        // checks.
        activeGeneralizedLoopEntrySourceBlock =
            backedges.empty() ? nullptr : backedges.front().sourceBlock;
        activeGeneralizedLoopLocalBuffer =
            backedges.empty()
                ? llvm::DenseMap<uint64_t, ValueByteReference>{}
                : extractLocalStackBuffer(backedges.front().buffer);
        if (discovery.valid && BBbackup[bb].sourceBlock) {
          activeGeneralizedLoopControlFieldState.valid = true;
          activeGeneralizedLoopControlFieldState.headerBlock = bb;
          activeGeneralizedLoopControlFieldState.canonicalSource =
              BBbackup[bb].sourceBlock;
          activeGeneralizedLoopControlFieldState.canonicalControl =
              discovery.canonicalControl;
          activeGeneralizedLoopControlFieldState.canonicalBuffer =
              BBbackup[bb].buffer;
          activeGeneralizedLoopControlFieldState.backedgeSources =
              std::move(discovery.backedgeSources);
          activeGeneralizedLoopControlFieldState.backedgeControls =
              std::move(discovery.backedgeControls);
          activeGeneralizedLoopControlFieldState.backedgeBuffers =
              std::move(discovery.backedgeBuffers);
          activeGeneralizedLoopControlFieldState.controlSlot =
              discovery.controlSlot;
          activeGeneralizedLoopControlFieldState.targetSlot =
              discovery.targetSlot;
          activeGeneralizedLoopControlFieldState.carriedSlots =
              std::move(discovery.carriedSlots);
          generalizedLoopControlFieldStates[bb] =
              activeGeneralizedLoopControlFieldState;
        }
      }
      if (this->liftProgressDiagEnabled && bb && bb->getName() == "bb_solved_const282") {
        auto valueToString = [](llvm::Value* value) {
          if (!value) {
            return std::string("<null>");
          }
          std::string text;
          llvm::raw_string_ostream os(text);
          value->print(os);
          return os.str();
        };
        constexpr std::array<const char*, 12> tracedNames = {
            "RAX", "RCX", "RDX", "RBX", "R8",  "R9",
            "R10", "R11", "R12", "R13", "R14", "R15"};
        constexpr std::array<size_t, 12> tracedIndices = {
            0, 1, 2, 3, 8, 9, 10, 11, 12, 13, 14, 15};
        std::cout << "[diag] generalized regs bb=" << bb->getName().str();
        for (size_t i = 0; i < tracedIndices.size(); ++i) {
          size_t regIndex = tracedIndices[i];
          std::cout << " " << tracedNames[i] << " canonical="
                    << valueToString(BBbackup[bb].vec[regIndex]);
          for (size_t j = 0; j < backedges.size(); ++j) {
            std::cout << " backedge[" << j << "]="
                      << valueToString(backedges[j].vec[regIndex]);
          }
        }
        std::cout << "\n";
      }
      // Seed the local-stack qwords that every path agrees on, so the loop body
      // reads constants for them rather than phis.
      //
      // This is the complement of the carried-slot discovery: that finds slots
      // that VARY and gives them phis, this finds slots that do NOT vary and
      // pins them. Seeding is what lets LLVM fold the stack traffic inside the
      // loop, which is most of what makes a generalized loop readable.
      auto seedInvariantLocalQwords = [&](const backup_point& canonicalSnapshot,
                                          llvm::ArrayRef<backup_point> backedgeSnapshots) {
        // Set, not just a dedupe check: the tracked buffer is byte-keyed, so a
        // single qword appears as up to eight entries and without this it would
        // be seeded eight times.
        std::set<uint64_t> seededQwordStarts;
        for (const auto& entry : activeGeneralizedLoopLocalBuffer) {
          // Align down to the qword containing this byte, which is the unit the
          // seed writes and the unit the retrieve helpers read.
          uint64_t qwordStart = entry.first & ~0x7ULL;
          // The 0x100 exclusion band below STACKP_VALUE. This is NOT the same
          // as isTrackedLocalStackAddress: the intent is to leave the deepest
          // part of the frame alone, where return addresses and saved frames
          // live. Seeding one of those to a constant would pin the loop's exit
          // to a single address and make it unrollable.
          if (qwordStart > STACKP_VALUE - 0x100) {
            continue;
          }
          if (!seededQwordStarts.insert(qwordStart).second) {
            continue;
          }
          uint64_t canonicalValue = 0;
          if (!readConstantTrackedQword(canonicalSnapshot.buffer, qwordStart,
                                        canonicalValue)) {
            continue;
          }
          // All backedges must read the same concrete qword value for
          // the invariant to hold. Any mismatch disqualifies the qword.
          bool allMatch = true;
          for (const auto& be : backedgeSnapshots) {
            uint64_t beValue = 0;
            if (!readConstantTrackedQword(be.buffer, qwordStart, beValue) ||
                beValue != canonicalValue) {
              allMatch = false;
              break;
            }
          }
          if (!allMatch) {
            continue;
          }
          for (uint8_t i = 0; i < 8; ++i) {
            noteBufferWriteDiag("seedInvariantLocalQword", qwordStart + i, 1,
                                activeGeneralizedLoopLocalBuffer[qwordStart + i].value,
                                this->current_address - this->instruction.length);
            this->buffer[qwordStart + i] =
                activeGeneralizedLoopLocalBuffer[qwordStart + i];
          }
        }
      };
      seedInvariantLocalQwords(BBbackup[bb], backedges);
      return;
    }
    // No backedges: treat it as an ordinary restore.
    //
    // make_generalized_loop_backup is called with an empty ArrayRef rather than
    // being bypassed, so this path goes through the same buffer filtering and
    // cache/assumption reset as the generalized path. Calling restore_backup_point
    // directly with BBbackup[bb] would skip both and leave the restored state
    // carrying a cache built under the previous path's assumptions.
    if (BBbackup.contains(bb)) {
      printvalue2("loading generalized backup");
      auto snapshot = make_generalized_loop_backup(
          bb, BBbackup[bb], llvm::ArrayRef<backup_point>{});
      restore_backup_point(snapshot);
    }
  }



  // The active loop's state, falling back to any recorded one.
  //
  // The fallback is a guess: DenseMap iteration order is unspecified, so
  // begin()->second is whichever header was inserted first in bucket order, not
  // chronologically. It exists because a helper can legitimately be reached
  // before any loop has been entered -- in which case the caller wants *a* loop's
  // shape to reason about rather than nothing.
  //
  // Callers that care which loop they are in must use
  // getGeneralizedLoopStateForHeader instead. The active state is preferred when
  // valid, so within an entered loop this is exact.
  GeneralizedLoopControlFieldState* getMostRecentGeneralizedLoopState() {
    if (activeGeneralizedLoopControlFieldState.valid) {
      return &activeGeneralizedLoopControlFieldState;
    }
    if (generalizedLoopControlFieldStates.empty()) {
      return nullptr;
    }
    return &generalizedLoopControlFieldStates.begin()->second;
  }

  // The state for one specific header. This is the precise lookup; prefer it
  // whenever the header is known.
  GeneralizedLoopControlFieldState* getGeneralizedLoopStateForHeader(
      llvm::BasicBlock* headerBlock) {
    if (!headerBlock) {
      return nullptr;
    }
    auto it = generalizedLoopControlFieldStates.find(headerBlock);
    if (it == generalizedLoopControlFieldStates.end() || !it->second.valid) {
      return nullptr;
    }
    return &it->second;
  }

  // Read a stack slot inside a generalized loop, from the loop's own buffer.
  //
  // Only the *active* loop's local buffer, so this is only correct while a
  // generalized loop is entered. Outside one the buffer is empty and this
  // returns null, which is the right answer -- an ordinary stack read goes
  // through the normal path.
  llvm::Value* retrieve_generalized_loop_local_value_impl(uint64_t startAddress,
                                                          uint8_t byteCount) {
    if (activeGeneralizedLoopLocalBuffer.empty()) {
      return nullptr;
    }
    return retrieveValueFromBufferSlice(activeGeneralizedLoopLocalBuffer, startAddress,
                                        byteCount);
  }

  // Resolve a *stack address* that became a phi, to the value each edge loaded.
  //
  // Distinct from the function above, and the difference is the whole point:
  // this one is handed the ADDRESS rather than a known slot, and that address
  // varies per incoming edge. That happens when the code computes the stack
  // slot arithmetically and the lifter generalizes the resulting address
  // expression into a phi.
  //
  // Per-edge resolution rather than picking one edge: the phi's whole purpose is
  // that different edges named different slots, so answering with a single
  // edge's value would be wrong by construction.
  //
  // orgLoad is explicitly ignored ((void) above). There is no meaningful
  // fallback for an address that is itself uncertain: issuing the original load
  // would read whatever the current state's stack pointer happens to point at,
  // which is not what any edge did. Returning null and letting the caller leave
  // the value symbolic is the honest outcome.
  llvm::Value* retrieve_generalized_loop_local_phi_address_value_impl(
      llvm::Value* loadOffset, uint8_t byteCount, LazyValue orgLoad) {
    (void)orgLoad;
    if (byteCount == 0) {
      return nullptr;
    }
    // Peel casts to reach the phi -- same reason as
    // stripIntegerCastsForGeneralizedLoad: the lift's width normalisation stacks
    // them, and a phi behind a trunc is still a phi.
    while (auto* castInst = llvm::dyn_cast<llvm::CastInst>(loadOffset)) {
      if (!castInst->getOperand(0)->getType()->isIntegerTy() ||
          !castInst->getType()->isIntegerTy()) {
        break;
      }
      loadOffset = castInst->getOperand(0);
    }
    // Fewer than two incoming values means there is nothing to choose between --
    // a single-incoming phi is not a generalization artifact and is handled
    // elsewhere.
    auto* phi = llvm::dyn_cast<llvm::PHINode>(loadOffset);
    if (!phi || phi->getNumIncomingValues() < 2) {
      return nullptr;
    }
    // The state must come from the phi's OWN parent, not the active loop. This
    // helper can be reached while a different loop is the active one, and using
    // the active state would resolve this phi's edges against the wrong loop's
    // buffers.
    auto* state = getGeneralizedLoopStateForHeader(phi->getParent());
    if (!state) {
      return nullptr;
    }

    // Resolve one edge. Three rejections, each for a distinct reason:
    // a non-constant address means the edge computed a slot we cannot name; a
    // non-stack address is not this helper's business; and an edge belonging to
    // neither the canonical source nor a recorded backedge belongs to a path
    // whose state was never snapshotted.
    auto resolveIncomingLocalValue = [&](llvm::Value* incomingAddress,
                                         llvm::BasicBlock* incomingBlock)
        -> llvm::Value* {
      auto* incomingCI = llvm::dyn_cast<llvm::ConstantInt>(incomingAddress);
      if (!incomingCI) {
        return nullptr;
      }
      const uint64_t address = incomingCI->getZExtValue();
      if (!this->isTrackedLocalStackAddress(address)) {
        return nullptr;
      }
      if (incomingBlock == state->canonicalSource) {
        return retrieveBufferedOrConcreteValue(state->canonicalBuffer, address,
                                              byteCount);
      }
      for (size_t i = 0; i < state->backedgeSources.size(); ++i) {
        if (incomingBlock == state->backedgeSources[i]) {
          return retrieveBufferedOrConcreteValue(state->backedgeBuffers[i],
                                                 address, byteCount);
        }
      }
      return nullptr;
    };


    llvm::SmallVector<std::pair<llvm::Value*, llvm::BasicBlock*>, 2> incomingLoads;
    llvm::Value* firstValue = nullptr;
    bool allSameValue = true;
    for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
      auto* resolvedValue = resolveIncomingLocalValue(phi->getIncomingValue(i),
                                                      phi->getIncomingBlock(i));
      if (!resolvedValue) {
        return nullptr;
      }
      if (!firstValue) {
        firstValue = resolvedValue;
      } else if (resolvedValue != firstValue) {
        allSameValue = false;
      }
      incomingLoads.push_back({resolvedValue, phi->getIncomingBlock(i)});
    }
    if (incomingLoads.empty()) {
      return nullptr;
    }
    if (this->liftProgressDiagEnabled) {
      std::cout << "[diag] generalized local-phi match block="

                << state->headerBlock->getName().str()
                << " byteCount=" << static_cast<unsigned>(byteCount);
      for (const auto& incoming : incomingLoads) {
        std::string valueText;
        llvm::raw_string_ostream valueStream(valueText);
        incoming.first->print(valueStream);
        std::cout << " incoming="
                  << (incoming.second ? incoming.second->getName().str()
                                      : std::string("<null>"))
                  << ":" << valueStream.str();
      }
      std::cout << "\n";
    }
    // All edges agreed: return the value rather than a phi that forwards it.
    // A phi with N identical incoming values is correct but opaque -- it hides
    // the fact that nothing varies, which is exactly the fact that makes the
    // loop simpler to read.
    if (allSameValue) {
      return firstValue;
    }
    // Inserted at the header's begin(), same requirement as
    // make_generalized_loop_backup: phis must precede non-phi instructions.
    llvm::IRBuilder<> phiBuilder(state->headerBlock, state->headerBlock->begin());
    // The type comes from the first incoming value rather than from byteCount,
    // because the values were resolved from each edge's own buffer and they may
    // not all be the same width. If they are not, CreatePHI would assert on the
    // mismatched incoming; the resolve step above is what has already
    // established they agree.
    auto* phiLoad =
        phiBuilder.CreatePHI(incomingLoads.front().first->getType(),
                             incomingLoads.size(),
                             "generalized_local_phi_load");
    // Pairs, not two parallel vectors -- addIncoming takes them together and
    // getting them out of step would attach a value to the wrong edge.
    for (const auto& incoming : incomingLoads) {
      phiLoad->addIncoming(incoming.first, incoming.second);
    }
    return phiLoad;
  }

  // Resolve a phi'd address that is NOT stack -- the VM's own memory.
  //
  // Same idea as the local variant above but for tracked slots, so the first
  // thing it does is peel a constant displacement off the address. A VM slot is
  // commonly reached as `base + constant`, and the base is what becomes the phi;
  // the constant is what identifies *which* field within it.
  //
  // Sign handling below is the subtle part and is why Sub is handled explicitly
  // rather than folded into the Add case.
  llvm::Value* retrieve_generalized_loop_phi_address_value_impl(
      llvm::Value* loadOffset, uint8_t byteCount, LazyValue orgLoad) {
    (void)orgLoad;
    if (byteCount == 0) {
      return nullptr;
    }
    while (auto* castInst = llvm::dyn_cast<llvm::CastInst>(loadOffset)) {
      if (!castInst->getOperand(0)->getType()->isIntegerTy() ||
          !castInst->getType()->isIntegerTy()) {
        break;
      }
      loadOffset = castInst->getOperand(0);
    }
    int64_t displacement = 0;
    if (auto* binOp = llvm::dyn_cast<llvm::BinaryOperator>(loadOffset)) {
      auto* lhs = binOp->getOperand(0);
      auto* rhs = binOp->getOperand(1);
      auto* rhsCI = llvm::dyn_cast<llvm::ConstantInt>(rhs);
      auto* lhsCI = llvm::dyn_cast<llvm::ConstantInt>(lhs);
      if (rhsCI && (binOp->getOpcode() == llvm::Instruction::Add ||
                    binOp->getOpcode() == llvm::Instruction::Sub)) {
        loadOffset = lhs;
        displacement = rhsCI->getSExtValue();
        // Negate for Sub so downstream address arithmetic is uniformly
        // `phiValue + displacement`. Without this the two opcodes would need
        // parallel handling everywhere the displacement is used, and the
        // omission is silent -- it reads the right bytes of the wrong slot.
        if (binOp->getOpcode() == llvm::Instruction::Sub) {
          displacement = -displacement;
        }
      } else if (lhsCI && binOp->getOpcode() == llvm::Instruction::Add) {
        // Constant on the left. Only Add -- `const - phi` cannot be expressed as
        // phi + displacement, and pretending otherwise would invert the
        // meaning of the address.
        loadOffset = rhs;
        displacement = lhsCI->getSExtValue();
      }
      // Anything else (a Mul, a symbolic displacement, a non-binop) leaves
      // loadOffset as it was, with displacement 0. Falling through to the phi
      // check then fails and this returns null, which is the correct outcome for
      // an address expression whose constant part could not be identified.
    }
    auto* phi = llvm::dyn_cast<llvm::PHINode>(loadOffset);
    if (!phi || phi->getNumIncomingValues() < 2) {
      return nullptr;
    }
    // The phi's own parent, not the active loop -- this helper can be reached
    // while a different loop is active. See the local variant above.
    auto* state = getGeneralizedLoopStateForHeader(phi->getParent());
    if (!state) {
      return nullptr;
    }
    if (this->liftProgressDiagEnabled) {
      std::cout << "[diag] generalized_phi_address current=0x" << std::hex
                << this->current_address << std::dec << " parent="
                << phi->getParent()->getName().str() << " activeSource="
                << (activeGeneralizedLoopEntrySourceBlock
                        ? activeGeneralizedLoopEntrySourceBlock->getName().str()
                        : std::string("<null>")) << "\n";
    }

    auto resolveIncomingValue = [&](llvm::Value* incomingAddress,
                                    llvm::BasicBlock* incomingBlock)
        -> llvm::Value* {
      auto* incomingCI = llvm::dyn_cast<llvm::ConstantInt>(incomingAddress);
      if (!incomingCI) {
        return nullptr;
      }
      // Sign-extend then add then wrap. A VM slot address is a signed 64-bit
      // value that may legitimately sit above 2^63 once the displacement is
      // applied -- the addresses here are runtime addresses, not quantities with
      // a sign. The cast back to uint64_t is what makes the wrap explicit
      // rather than relying on the addition's own behaviour.
      const uint64_t address =
          static_cast<uint64_t>(incomingCI->getSExtValue() + displacement);
      if (incomingBlock == state->canonicalSource) {
        return retrieveBufferedOrConcreteValue(state->canonicalBuffer, address,
                                              byteCount);
      }
      for (size_t i = 0; i < state->backedgeSources.size(); ++i) {
        if (incomingBlock == state->backedgeSources[i]) {
          return retrieveBufferedOrConcreteValue(state->backedgeBuffers[i],
                                                 address, byteCount);
        }
      }
      return nullptr;
    };

    llvm::SmallVector<std::pair<llvm::Value*, llvm::BasicBlock*>, 2> incomingLoads;
    llvm::Value* firstValue = nullptr;
    bool allSameValue = true;
    for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
      auto* resolvedValue =
          resolveIncomingValue(phi->getIncomingValue(i), phi->getIncomingBlock(i));
      if (!resolvedValue) {
        return nullptr;
      }
      if (!firstValue) {
        firstValue = resolvedValue;
      } else if (resolvedValue != firstValue) {
        allSameValue = false;
      }
      incomingLoads.push_back({resolvedValue, phi->getIncomingBlock(i)});
    }
    if (incomingLoads.empty()) {
      return nullptr;
    }
    if (allSameValue) {
      return firstValue;
    }
    llvm::IRBuilder<> phiBuilder(state->headerBlock, state->headerBlock->begin());
    auto* phiLoad =
        phiBuilder.CreatePHI(incomingLoads.front().first->getType(),
                             incomingLoads.size(),
                             "generalized_phi_load");
    for (const auto& incoming : incomingLoads) {
      phiLoad->addIncoming(incoming.first, incoming.second);
    }
    return phiLoad;
  }

  // Read the loop's control slot, building a phi when the edges disagree.
  //
  // Three gates, each rejecting a distinct mismatch:
  //
  //   !state.valid          not inside a generalized loop
  //   startAddress mismatch the caller asked about a different slot
  //   byteCount out of range  0 would produce a zero-width type; >8 cannot be
  //                         masked out of a uint64_t, so the truncation below
  //                         would silently wrap rather than narrow
  //
  // All three return null rather than a partial answer, because the caller's
  // fallback is to issue the original load, and issuing that load at the wrong
  // width would produce a plausible value from the wrong bytes.
  llvm::Value* retrieve_generalized_loop_control_slot_value_impl(
      uint64_t startAddress, uint8_t byteCount) {
    auto& state = activeGeneralizedLoopControlFieldState;
    if (!state.valid || startAddress != state.controlSlot ||
        byteCount == 0 || byteCount > 8) {
      return nullptr;
    }
    // maskTrailingOnes narrows the stored qword to the requested width rather
    // than truncating the ConstantInt, so the value is right for a 4-byte read
    // of an 8-byte slot. Without the mask, getIntN would take the low bits
    // anyway -- but doing it here makes the narrowing explicit and keeps the
    // same expression on the backedge side below.
    auto* canonicalValue = this->builder->getIntN(
        byteCount * 8, state.canonicalControl & llvm::maskTrailingOnes<uint64_t>(byteCount * 8));
    if (this->liftProgressDiagEnabled) {
      std::cout << "[diag] control_slot current=0x" << std::hex
                << this->current_address << " start=0x" << startAddress
                << " canonical=0x" << state.canonicalControl << std::dec
                << " backedgeCount=" << state.backedgeControls.size()
                << " bytes=" << static_cast<unsigned>(byteCount) << "\n";
    }
    if (state.backedgeSources.empty()) {
      return canonicalValue;
    }
    // Build the canonical + N backedge values. If everything collapses to
    // a single value, skip phi construction.
    llvm::SmallVector<llvm::Value*, 2> backedgeValues;
    backedgeValues.reserve(state.backedgeControls.size());
    bool allSameAsCanonical = true;
    for (uint64_t be : state.backedgeControls) {
      auto* v = this->builder->getIntN(
          byteCount * 8, be & llvm::maskTrailingOnes<uint64_t>(byteCount * 8));
      if (v != canonicalValue) allSameAsCanonical = false;
      backedgeValues.push_back(v);
    }
    if (allSameAsCanonical) {
      return canonicalValue;
    }
    llvm::IRBuilder<> phiBuilder(state.headerBlock, state.headerBlock->begin());
    auto* phi = phiBuilder.CreatePHI(canonicalValue->getType(),
                                     1 + backedgeValues.size(),
                                     "generalized_control_slot_phi");
    phi->addIncoming(canonicalValue, state.canonicalSource);
    for (size_t i = 0; i < backedgeValues.size(); ++i) {
      phi->addIncoming(backedgeValues[i], state.backedgeSources[i]);
    }
    return phi;
  }


  // Read the loop's output slot: the value this iteration hands to the next.
  //
  // Two-tier, and the order is the compatibility story. The legacy targetSlot is
  // checked first so the reference Themida sample behaves exactly as before;
  // the carriedSlots extension only fires when the legacy slot does not match.
  // Reordering would change which slot wins on the reference sample, which is
  // what the zero-regression guarantee forbids.
  llvm::Value* retrieve_generalized_loop_target_slot_value_impl(
      uint64_t startAddress, uint8_t byteCount) {
    if (!activeGeneralizedLoopControlFieldState.valid || byteCount == 0) {
      return nullptr;
    }
    auto& state = activeGeneralizedLoopControlFieldState;

    // Check the legacy targetSlot first.
    if (startAddress == state.targetSlot) {
      auto* canonicalValue = retrieveBufferedOrConcreteValue(state.canonicalBuffer,
                                                             startAddress, byteCount);
      if (!canonicalValue) return nullptr;
      if (this->liftProgressDiagEnabled) {
        std::cout << "[diag] target_slot current=0x" << std::hex
                  << this->current_address << " start=0x" << startAddress
                  << std::dec << " bytes=" << static_cast<unsigned>(byteCount)
                  << " backedgeCount=" << state.backedgeBuffers.size() << "\n";
      }
      llvm::SmallVector<llvm::Value*, 2> backedgeValues;
      backedgeValues.reserve(state.backedgeBuffers.size());
      bool allSame = true;
      for (const auto& beBuf : state.backedgeBuffers) {
        auto* v = retrieveBufferedOrConcreteValue(beBuf, startAddress, byteCount);
        if (!v || v->getType() != canonicalValue->getType()) {
          return nullptr;
        }
        if (v != canonicalValue) allSame = false;
        backedgeValues.push_back(v);
      }
      if (state.backedgeSources.empty() || allSame) {
        return canonicalValue;
      }
      llvm::IRBuilder<> phiBuilder(state.headerBlock, state.headerBlock->begin());
      auto* phi = phiBuilder.CreatePHI(canonicalValue->getType(),
                                       1 + backedgeValues.size(),
                                       "generalized_local_slot_phi");
      phi->addIncoming(canonicalValue, state.canonicalSource);
      for (size_t i = 0; i < backedgeValues.size(); ++i) {
        phi->addIncoming(backedgeValues[i], state.backedgeSources[i]);
      }
      return phi;
    }

    // Check additional carried slots (multi-slot extension).
    for (const auto& slot : state.carriedSlots) {
      if (slot.address != startAddress) continue;
      // Sizes must agree for the same reason as the discovery-time
      // all-or-nothing rule: the phi below pairs backedgeValues[i] with
      // backedgeSources[i], so a short vector silently mis-attributes values to
      // edges. Skipping the slot here is the runtime counterpart of the
      // discovery rule that drops a slot when any backedge lacks it.
      if (slot.backedgeValues.size() != state.backedgeSources.size()) continue;

      const uint64_t mask = llvm::maskTrailingOnes<uint64_t>(byteCount * 8);
      auto* canonicalValue = this->builder->getIntN(
          byteCount * 8, slot.canonicalValue & mask);

      llvm::SmallVector<llvm::Value*, 2> backedgeValues;
      bool allSame = true;
      for (uint64_t be : slot.backedgeValues) {
        auto* v = this->builder->getIntN(byteCount * 8, be & mask);
        if (v != canonicalValue) allSame = false;
        backedgeValues.push_back(v);
      }
      if (state.backedgeSources.empty() || allSame) {
        return canonicalValue;
      }
      llvm::IRBuilder<> phiBuilder(state.headerBlock, state.headerBlock->begin());
      auto* phi = phiBuilder.CreatePHI(canonicalValue->getType(),
                                       1 + backedgeValues.size(),
                                       "generalized_carried_slot_phi");
      phi->addIncoming(canonicalValue, state.canonicalSource);
      for (size_t i = 0; i < backedgeValues.size(); ++i) {
        phi->addIncoming(backedgeValues[i], state.backedgeSources[i]);
      }
      return phi;
    }

    return nullptr;
  }

  // Read a *field* inside the control slot: control value + constant offset.
  //
  // The insert-block check is the part that looks redundant and is not. This
  // helper answers from the loop's merged state, which is only meaningful while
  // lifting the header itself. Called from inside the body, the same loadOffset
  // would resolve against buffers that describe the loop entry rather than the
  // current iteration -- producing the entry's control value mid-loop, which is
  // stale by definition.
  //
  // orgLoad ignored for the same reason as the phi-address helpers: an
  // uncertain address has no honest fallback load.
  llvm::Value* retrieve_generalized_loop_control_field_value_impl(
      llvm::Value* loadOffset, uint8_t byteCount, LazyValue orgLoad) {
    (void)orgLoad;
    if (!activeGeneralizedLoopControlFieldState.valid || byteCount == 0 ||
        this->builder->GetInsertBlock() !=
            activeGeneralizedLoopControlFieldState.headerBlock) {
      return nullptr;
    }
    uint64_t fieldOffset = 0;
    if (!matchGeneralizedLoopControlFieldAddress(loadOffset, fieldOffset)) {
      return nullptr;
    }
    auto& state = activeGeneralizedLoopControlFieldState;
    auto* canonicalValue = retrieveBufferedOrConcreteValue(
        state.canonicalBuffer, state.canonicalControl + fieldOffset, byteCount);
    if (!canonicalValue) return nullptr;
    if (this->liftProgressDiagEnabled) {
      std::cout << "[diag] generalized control-field match block="
                << state.headerBlock->getName().str()
                << " fieldOffset=0x" << std::hex << fieldOffset
                << " canonical=0x" << (state.canonicalControl + fieldOffset)
                << std::dec << " bytes=" << static_cast<unsigned>(byteCount)
                << " backedgeCount=" << state.backedgeControls.size() << "\n";
    }
    llvm::SmallVector<llvm::Value*, 2> backedgeValues;
    backedgeValues.reserve(state.backedgeControls.size());
    bool allSame = true;
    for (size_t i = 0; i < state.backedgeControls.size(); ++i) {
      auto* v = retrieveBufferedOrConcreteValue(
          state.backedgeBuffers[i],
          state.backedgeControls[i] + fieldOffset, byteCount);
      if (!v || v->getType() != canonicalValue->getType()) {
        return nullptr;
      }
      if (v != canonicalValue) allSame = false;
      backedgeValues.push_back(v);
    }
    if (state.backedgeSources.empty() || allSame) {
      return canonicalValue;
    }
    llvm::IRBuilder<> phiBuilder(state.headerBlock, state.headerBlock->begin());
    auto* phi = phiBuilder.CreatePHI(canonicalValue->getType(),
                                     1 + backedgeValues.size(),
                                     "loop_control_field_phi");
    phi->addIncoming(canonicalValue, state.canonicalSource);
    for (size_t i = 0; i < backedgeValues.size(); ++i) {
      phi->addIncoming(backedgeValues[i], state.backedgeSources[i]);
    }
    return phi;
  }
  // Re-home all per-header state when a generalized block is replaced.
  //
  // Called from replaceWithGeneralizedLoopBlock. Every one of the five maps is
  // keyed by header block, so a replacement that left them behind would orphan
  // the loop: the new header would re-discover (or worse, find no state) while
  // the old maps still pointed at a block nothing branches to anymore.
  //
  // Copy, not move: the old block may still be referenced by queued path-solver
  // predecessors, and replaceAllUsesWith repoints those -- but the maps are
  // consulted by address-keyed lookups that outlive the replacement. Deleting
  // the old entries would break a restore that is still in flight for the old
  // block.
  //
  // The `!contains(newBlock)` guards make the migration first-writer-wins. A
  // new block that already has its own entry was generalized independently, and
  // overwriting it with the old block's phis would substitute one loop's
  // variables for another's.
  //
  // headerBlock is re-pointed only in the control-field map because it is the
  // only one that stores the header redundantly inside the value. The other
  // four are keyed by it, so the key move is the whole update.
  void migrate_generalized_loop_block_impl(BasicBlock* oldBlock,
                                           BasicBlock* newBlock) {
    if (oldBlock == newBlock) {
      return;
    }
    if (generalizedLoopRegisterPhis.contains(oldBlock) &&
        !generalizedLoopRegisterPhis.contains(newBlock)) {
      generalizedLoopRegisterPhis[newBlock] = generalizedLoopRegisterPhis[oldBlock];
    }
    if (generalizedLoopFlagPhis.contains(oldBlock) &&
        !generalizedLoopFlagPhis.contains(newBlock)) {
      generalizedLoopFlagPhis[newBlock] = generalizedLoopFlagPhis[oldBlock];
    }
    if (BBbackup.contains(oldBlock) && !BBbackup.contains(newBlock)) {
      BBbackup[newBlock] = BBbackup[oldBlock];
    }
    if (generalizedLoopBackedgeBackup.contains(oldBlock) &&
        !generalizedLoopBackedgeBackup.contains(newBlock)) {
      generalizedLoopBackedgeBackup[newBlock] =
          generalizedLoopBackedgeBackup[oldBlock];
    }
    if (generalizedLoopControlFieldStates.contains(oldBlock) &&
        !generalizedLoopControlFieldStates.contains(newBlock)) {
      generalizedLoopControlFieldStates[newBlock] =
          generalizedLoopControlFieldStates[oldBlock];
      generalizedLoopControlFieldStates[newBlock].headerBlock = newBlock;
    }
  }

  // Record that the current block flows back into generalized header `bb`.
  //
  // sourceBlock is the builder's insert block -- the block control is leaving --
  // not `bb`. The backedge is the edge (source -> header), and recording the
  // wrong end would make the phi's incoming blocks name the header itself.
  void record_generalized_loop_backedge_impl(BasicBlock* bb) {
    auto* sourceBlock = this->builder->GetInsertBlock();
    if (!bb || !sourceBlock) {
      return;
    }

    auto regIt = generalizedLoopRegisterPhis.find(bb);
    if (regIt != generalizedLoopRegisterPhis.end()) {
      for (size_t i = 0; i < REGISTER_COUNT; ++i) {
        auto* phi = regIt->second[i];
        if (!phi || !vec[i] || phi->getType() != vec[i]->getType() ||
            phi->getParent() != bb ||
            phi->getBasicBlockIndex(sourceBlock) >= 0) {
          continue;
        }
        phi->addIncoming(vec[i], sourceBlock);
      }
    }


    auto flagIt = generalizedLoopFlagPhis.find(bb);
    if (flagIt != generalizedLoopFlagPhis.end()) {
      for (size_t i = 0; i < FLAGS_END; ++i) {
        auto* phi = flagIt->second[i];
        if (!phi || !vecflag[i] || phi->getType() != vecflag[i]->getType() ||
            phi->getParent() != bb ||
            phi->getBasicBlockIndex(sourceBlock) >= 0) {
          continue;
        }
        phi->addIncoming(vecflag[i], sourceBlock);
      }
    }
    auto stateIt = generalizedLoopControlFieldStates.find(bb);
    if (stateIt == generalizedLoopControlFieldStates.end() ||
        !stateIt->second.valid) {
      return;
    }
    auto& sources = stateIt->second.backedgeSources;
    auto& controls = stateIt->second.backedgeControls;
    auto& buffers = stateIt->second.backedgeBuffers;

    if (sources.size() == 1) {
      // 2-way loop: preserve the original rotation semantics - move the
      // current backedge into canonical and install the new body source
      // as the single backedge. This matches the reference Themida flow
      // where body exploration rolls the control cursor forward.
      //
      // Rotation rather than append, because a 2-way loop has exactly two
      // arrivals and keeping both would turn it into a 3-way one. The old
      // backedge becomes the new canonical: it is the arrival the loop most
      // recently came through, so it is the right "first" value for the phis.
      auto* existingBackedgeSource = sources.front();
      // Same source re-recorded: not a new backedge, just the same edge being
      // walked again. Recording it would rotate the state onto itself --
      // canonical and backedge swapping without any new value.
      if (!existingBackedgeSource || sourceBlock == existingBackedgeSource) {
        return;
      }
      auto* currentControlValue =
          retrieveContiguousBufferedValue(this->buffer, stateIt->second.controlSlot, 8);
      uint64_t rolledBackedgeControl = 0;
      // Three ways to decline, and declining is the point: rotation is only
      // valid when the cursor actually advanced. A missing value, an
      // unresolvable expression, or an unchanged value all mean "the loop did
      // not move forward", and rotating on any of them would install a backedge
      // identical to the canonical -- a phi that claims to vary but does not.
      if (!currentControlValue ||
          !evaluateConcreteGeneralizedLoopInt(currentControlValue,
                                              existingBackedgeSource,
                                              rolledBackedgeControl) ||
          rolledBackedgeControl == controls.front()) {
        return;
      }
      auto previousBackedgeSource = existingBackedgeSource;
      auto previousBackedgeControl = controls.front();
      auto previousBackedgeBuffer = buffers.front();
      stateIt->second.canonicalSource = previousBackedgeSource;
      stateIt->second.canonicalControl = previousBackedgeControl;
      stateIt->second.canonicalBuffer = previousBackedgeBuffer;
      sources.front() = sourceBlock;
      controls.front() = rolledBackedgeControl;
      buffers.front() = this->buffer;
      // Rotate carried slots alongside the primary control slot.
      for (auto& carried : stateIt->second.carriedSlots) {
        if (carried.backedgeValues.size() != 1) continue;
        uint64_t newCarriedValue = 0;
        if (readConstantTrackedQword(this->buffer, carried.address, newCarriedValue)) {
          carried.canonicalValue = carried.backedgeValues.front();
          carried.backedgeValues.front() = newCarriedValue;
        }
      }
      if (bb == activeGeneralizedLoopControlFieldState.headerBlock) {
        activeGeneralizedLoopControlFieldState = stateIt->second;
        activeGeneralizedLoopEntrySourceBlock = sourceBlock;
        activeGeneralizedLoopLocalBuffer = extractLocalStackBuffer(
            activeGeneralizedLoopControlFieldState.backedgeBuffers.front());
      }
      if (this->liftProgressDiagEnabled) {
        std::cout << "[diag] roll_generalized_backedge bb=" << bb->getName().str()
                  << " canonical=0x" << std::hex
                  << stateIt->second.canonicalControl << " backedge=0x"
                  << controls.front() << std::dec
                  << " source=" << sourceBlock->getName().str() << "\n";
      }
      return;
    }

    // Multi-way loop (size > 1): append-or-update the body source to the
    // backedge list. Each distinct body block contributes at most one
    // entry (dedup by sourceBlock). This preserves the original N
    // backedges and records the body's rolled state alongside them;
    // unbounded growth is prevented by the per-sourceBlock dedup.
    // Rotation (promoting a backedge to canonical) is undefined for
    // multi-way - no single backedge is "the" one to promote.
    if (sourceBlock == stateIt->second.canonicalSource) {
      return;
    }
    auto* currentControlValue =
        retrieveContiguousBufferedValue(this->buffer, stateIt->second.controlSlot, 8);
    uint64_t newControl = 0;
    if (!currentControlValue ||
        !evaluateConcreteGeneralizedLoopInt(currentControlValue, sourceBlock,
                                            newControl)) {
      return;
    }
    bool mutated = false;
    bool isNew = true;
    for (size_t i = 0; i < sources.size(); ++i) {
      if (sources[i] == sourceBlock) {
        isNew = false;
        if (controls[i] == newControl) {
          return;  // no progress; nothing to record
        }
        controls[i] = newControl;
        buffers[i] = this->buffer;
        // Update carried slots for this backedge index.
        for (auto& carried : stateIt->second.carriedSlots) {
          if (i < carried.backedgeValues.size()) {
            uint64_t newVal = 0;
            if (readConstantTrackedQword(this->buffer, carried.address, newVal)) {
              carried.backedgeValues[i] = newVal;
            }
            // Unreadable slot left as-is: the previous value is a better answer
            // than the canonical fallback used for NEW backedges below, because
            // this edge previously produced a real value here.
          }
        }
        mutated = true;
        break;
      }
    }
    if (isNew) {
      sources.push_back(sourceBlock);
      controls.push_back(newControl);
      buffers.push_back(this->buffer);
      // Append carried slot values for the new backedge.
      for (auto& carried : stateIt->second.carriedSlots) {
        uint64_t newVal = 0;
        if (readConstantTrackedQword(this->buffer, carried.address, newVal)) {
          carried.backedgeValues.push_back(newVal);
        } else {
          // Keep vectors aligned: push canonical as fallback.
          //
          // The fallback is canonical, not zero, so the new edge initially
          // claims to agree with the first arrival -- which keeps the phi
          // correct (one more identical incoming) rather than introducing a
          // value no edge ever held. Alignment matters more than precision
          // here: see the discovery all-or-nothing rule.
          carried.backedgeValues.push_back(carried.canonicalValue);
        }
      }
      mutated = true;
    }
    if (mutated && bb == activeGeneralizedLoopControlFieldState.headerBlock) {
      activeGeneralizedLoopControlFieldState = stateIt->second;
    }
    if (mutated && this->liftProgressDiagEnabled) {
      std::cout << "[diag] roll_generalized_backedge_multiway bb="
                << bb->getName().str()
                << " backedgeCount=" << sources.size()
                << " source=" << sourceBlock->getName().str() << std::dec
                << "\n";
    }
  }

  // The lifted function's signature: 16 GPRs, EIP, memory, 16 XMMs.
  //
  // Fixed rather than derived from the binary because every consumer -- the ABI
  // layer, InitRegisters_impl below, the test harness -- indexes arguments
  // positionally. Changing the arity here silently renumbers all of those, so
  // this is a cross-file contract, not a local choice.
  //
  // The two middle pointers are EIP-then-memory, in that order. InitRegisters
  // consumes them positionally (eipArg, then memoryArg), so swapping the pushes
  // binds the memory base to RIP and the entry address to the memory model --
  // which verifies and mis-lifts everything.
  //
  // 16 XMMs as i128: the widest the lifter models. A narrower type would need a
  // cast on every vector write; i128 holds any XMM value without one.
  void createFunction_impl() {
    std::vector<llvm::Type*> argTypes;
    for (size_t i = 0; i < 16; ++i) {
      argTypes.push_back(llvm::Type::getInt64Ty(this->context));
    }

    argTypes.push_back(llvm::PointerType::get(this->context, 0));
    argTypes.push_back(llvm::PointerType::get(this->context, 0)); // memory

    for (size_t i = 0; i < 16; ++i) {
      argTypes.push_back(llvm::Type::getInt128Ty(this->context));
    }

    auto functionType = llvm::FunctionType::get(
        llvm::Type::getInt64Ty(this->context), argTypes, 0);

    const std::string function_name = "main";
    this->fnc =
        llvm::Function::Create(functionType, llvm::Function::ExternalLinkage,
                               function_name.c_str(), this->M);
  }

  // Bind the function arguments to the register file, positionally.
  //
  // gprOrder must match createFunction_impl's push order exactly: the i-th GPR
  // argument becomes the i-th register here. A mismatch binds the wrong argument
  // to a register, which verifies, runs, and produces a lift where every
  // register holds its neighbour's value.
  //
  // RSP is bound to whatever the caller passed, NOT to STACKP_VALUE. The
  // emulated stack base is a lifter-side constant; the argument is the entry
  // stack pointer the ABI promises. Conflating them would make the lifted
  // function's first push write to a fixed address regardless of its caller.
  void InitRegisters_impl() {
    constexpr std::array<Register, 16> gprOrder = {
        Register::RAX, Register::RCX, Register::RDX, Register::RBX,
        Register::RSP, Register::RBP, Register::RSI, Register::RDI,
        Register::R8,  Register::R9,  Register::R10, Register::R11,
        Register::R12, Register::R13, Register::R14, Register::R15,
    };

    auto argIt = this->fnc->arg_begin();
    for (auto reg : gprOrder) {
      auto* arg = &*argIt++;
      arg->setName(magic_enum::enum_name(reg));
      this->SetRegisterValue(reg, arg);
    }

    auto* eipArg = &*argIt++;
    eipArg->setName("EIP");
    auto* ripValue = eipArg->getType()->isPointerTy()
                         ? this->builder->CreatePtrToInt(
                               eipArg, llvm::Type::getInt64Ty(this->context), "rip.arg")
                         : this->builder->CreateZExtOrTrunc(
                               eipArg, llvm::Type::getInt64Ty(this->context), "rip.arg");
    this->SetRegisterValue(Register::RIP, ripValue);
    auto* memoryArg = &*argIt++;
    memoryArg->setName("memory");
    // The pseudo-memory base. Every GEP the lifter builds is rooted here, so
    // this single assignment is what makes PromotePseudoMemory able to find
    // them: a load through any other base is invisible to that pass and is
    // never promoted.
    this->memoryAlloc = memoryArg;

    for (uint8_t i = 0; i < 16; ++i) {
      auto xmmReg =
          static_cast<Register>(static_cast<int>(Register::XMM0) + i);
      auto* xmmArg = &*argIt++;
      xmmArg->setName(magic_enum::enum_name(xmmReg));
      this->SetRegisterValue(xmmReg, xmmArg);
    }
    // printvalue(GetRegisterValue(Register::RAX));

    LLVMContext& context = this->builder->getContext();
    auto zero = ConstantInt::getSigned(Type::getInt1Ty(context), 0);
    auto one = ConstantInt::getSigned(Type::getInt1Ty(context), 1);
    auto two = ConstantInt::getSigned(Type::getInt1Ty(context), 2);

    // All flags start cleared except the two the architecture defines as 1.
    // FLAG_RESERVED1 is always 1 on real hardware; FLAG_IF (interrupts enabled)
    // is the power-on state a user-mode program observes. Starting from any
    // other combination makes the first conditional branch depend on a flag
    // value no real execution could have produced.
    for (int flag = FLAG_CF; flag < FLAGS_END; ++flag)
      this->setFlag(static_cast<Flag>(flag), zero);
    this->setFlag(FLAG_RESERVED1, one);
    this->setFlag(FLAG_IF, one);
    // RFLAGS as a whole reads 2: bit 1 set, everything else clear. That is the
    // same state as the per-flag writes above expressed as one value, for
    // consumers that read the register rather than individual flags.
    this->SetRegisterValue(Register::RFLAGS, two);

    // auto value =
    //     cast<Value>(ConstantInt::getSigned(Type::getInt64Ty(context),
    //     rip));

    // auto new_rip = createAddFolder(zero, value);

    // SetRegisterValue(Register::RIP, new_rip);

    // RSP starts at the emulated stack base. This OVERWRITES the entry-stack
    // argument bound above: the lifted function always runs on the lifter's own
    // pseudo-stack, never on the caller's. That is what makes the stack window
    // (isTrackedStackAddress) and the pseudo-stack promotion sound -- they both
    // assume every stack access is within [STACKP_VALUE - reserve,
    // STACKP_VALUE + reserve], which is only true because the entry value is
    // discarded here.
    auto stackvalue = cast<Value>(
        ConstantInt::getSigned(Type::getInt64Ty(context), STACKP_VALUE));

    this->SetRegisterValue(Register::RSP, stackvalue);

    return;
  }
};
#endif