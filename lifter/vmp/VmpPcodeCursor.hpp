#ifndef VMP_PCODE_CURSOR_H
#define VMP_PCODE_CURSOR_H

// Stateful tracker for where a VM's bytecode program counter currently points.
//
// Vocabulary used throughout lifter/vmp/:
//
//   pcode    the protected bytecode stream the protector's handlers interpret
//   VIP      "virtual instruction pointer" -- the protector's own PC over that
//            stream, modelled here as the (pcodeReg, offset) pair
//   fetch    the moment the VM reads the next pcode from bytecode memory
//
// The cursor is deliberately the *smallest* piece of state in the VMP model: it
// records which register holds a bytecode address and what that address was.
// It does not interpret the bytecode and does not attempt to prove the VM is
// well-formed. Every test below is a cheap syntactic check whose failure mode
// is "no opinion" rather than "wrong answer", because a false positive at
// this layer makes the lifter pin a bytecode pointer to a handler address and
// produce confidently wrong devirtualisation.

#include "CommonRegisters.h"
#include "Includes.h"

#include <cstdint>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Value.h>

template <Registers Register>
class VmpPcodeCursor {
public:
  // Register holding a bytecode address. Register::None means "not bound", and
  // every mutator below is a no-op until a bytecode load establishes one.
  // Binding is sticky on purpose: a handler reuses one register as the VIP for
  // the whole dispatch loop.
  Register pcodeReg = Register::None;
  uint64_t offset = 0;
  llvm::Value* lastStackQwordLoad = nullptr;
  uint64_t lastStackQwordSlot = 0;

  bool bound() const { return pcodeReg != Register::None; }

  // Reduce an address to its image-relative form, so two observations of the
  // same bytecode compare equal.
  //
  // The same pcode is observed at different absolute addresses depending on
  // the base the protector linked at: 0x140000000 for a 64-bit image,
  // 0x40000000 for a 32-bit one. Comparing raw values would miss every
  // cross-module dispatch on a sample whose handler and bytecode live at
  // different bases. Anything outside both known bases is already
  // image-relative (or is not module memory at all) and passes through.
  static uint64_t fetchRva(uint64_t addr) {
    if (addr >= 0x140000000ULL) {
      return addr - 0x140000000ULL;
    }
    if ((addr & 0xFF000000ULL) == 0x40000000ULL) {
      return addr & 0x00FFFFFFULL;
    }
    return addr;
  }

  // Look through bitcast/zext/sext chains down to the underlying value.
  //
  // The hop limit is a guard against malformed IR, not a heuristic: a
  // cyclic or self-referential cast chain would otherwise spin forever.
  // Eight is far above any real cast depth this lifter produces, so hitting
  // the limit means something is already wrong and the non-cast value is a
  // safe value to return.
  static llvm::Value* peelCasts(llvm::Value* v) {
    unsigned hops = 0;
    while (v && hops++ < 8) {
      if (auto* cast = llvm::dyn_cast<llvm::CastInst>(v)) {
        v = cast->getOperand(0);
        continue;
      }
      break;
    }
    return v;
  }

  // Whether an address lies in the emulated stack region.
  //
  // This is the VM's own stack window: a *fixed* 1MB reserve around
  // STACKP_VALUE, deliberately independent of the configurable stackReserve
  // that MemoryPolicySetup clamps to [0x1000, 0x100000]. The VM pushes its
  // own bookkeeping here and does not honour the host program's declared stack
  // size, so deriving this from that value would miss the stack entirely for
  // samples declaring a small one. Keep the two windows distinct when changing
  // either.
  static bool isVmStackAddress(uint64_t address) {
    constexpr uint64_t kReserve = 0x100000;
    return address >= STACKP_VALUE - kReserve &&
           address <= STACKP_VALUE + kReserve;
  }

  // Match "a load from a constant offset inside the VM stack" and return that
  // offset. Returns 0 for anything that is not exactly that shape.
  //
  // outLoad receives the LoadInst so callers can re-read the value later; the
  // address on its own is not always enough to recover what was popped.
  static uint64_t stackLoadAddress(llvm::Value* v,
                                   llvm::LoadInst** outLoad = nullptr) {
    if (outLoad) {
      *outLoad = nullptr;
    }
    v = peelCasts(v);
    auto* li = llvm::dyn_cast_or_null<llvm::LoadInst>(v);
    if (!li) {
      return 0;
    }
    // stripPointerCasts before the GEP dyn_cast: lifter output routinely routes
    // the base through an inttoptr/bitcast, and matching the GEP directly would
    // miss every access whose base had been promoted out of pseudo-memory.
    llvm::Value* ptr = li->getPointerOperand()->stripPointerCasts();
    auto* gep = llvm::dyn_cast<llvm::GetElementPtrInst>(ptr);
    if (!gep || gep->getNumOperands() < 2) {
      return 0;
    }
    auto* off = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1));
    if (!off) {
      return 0;
    }
    const uint64_t addr = off->getZExtValue();
    if (!isVmStackAddress(addr)) {
      return 0;
    }
    if (outLoad) {
      *outLoad = li;
    }
    return addr;
  }

  // A fetch is the cursor being used as a memory base for a bytecode read. All
  // four conditions must hold; `simple` excludes address arithmetic on the
  // base, since a computed address is not a cursor position.
  bool isFetch(Register memBase, bool simple, bool offsetIsBytecode) const {
    return bound() && simple && memBase == pcodeReg && offset != 0 &&
           offsetIsBytecode;
  }

  // Attach the cursor to a register, but only when the address really is
  // bytecode. Refusing to bind otherwise is what stops an unrelated data load
  // that happens to reuse the same register from hijacking the VIP.
  void bind(Register memBase, bool simple, bool addrIsBytecode) {
    if (!addrIsBytecode || !simple) {
      return;
    }
    pcodeReg = memBase;
  }

  void noteModule(uint64_t addr) { offset = addr; }

  // Move the VIP by a pointer-step delta. Negative deltas are expected: the
  // dispatch loop walks the pcode stream both forwards (sequential handlers)
  // and backwards (revisiting an already-consumed dispatch).
  void advance(int64_t delta) {
    if (!bound() || offset == 0 || delta == 0) {
      return;
    }
    offset += static_cast<uint64_t>(delta);
  }

  // Re-target the cursor when a mov relocates a bytecode address into a
  // different register.
  //
  // The third disjunct (`srcIsMemory && memBase != pcodeReg`) is the one that
  // does most of the work: a mov that *loads* a bytecode address into a fresh
  // register is the VM fetching its next handler. When pcodeReg already names
  // a different base, the loaded value is the VIP and the destination register
  // takes over as the base for subsequent pointer steps.
  void onMovToReg(Register dest, Register srcReg, Register memBase,
                  bool srcIsMemory, llvm::Value* v, bool valueIsBytecode) {
    if (valueIsBytecode && (dest == pcodeReg || srcReg == pcodeReg ||
                            (srcIsMemory && memBase != pcodeReg))) {
      pcodeReg = dest;
      if (auto* ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(v)) {
        offset = ci->getZExtValue();
      }
    }
  }

  // Remember the most recent 64-bit VM-stack load.
  //
  // Gated on width as well as address: a narrower load from the same slot is a
  // different value, and treating it as the same pop is how the fetch planner
  // ends up reading a qword that was only ever written as a dword.
  void noteStackQword(llvm::Value* result, uint8_t sizeBits, uint64_t addr) {
    if (result && sizeBits == 64 && addr != 0 && isVmStackAddress(addr)) {
      lastStackQwordLoad = result;
      lastStackQwordSlot = addr;
    }
  }

  // Drop all state. Called when a fetch resolves to something that is not
  // bytecode: staying bound would leave the cursor on a stale address and let
  // later unrelated loads look like fetches.
  void unbind() {
    pcodeReg = Register::None;
    offset = 0;
  }

  // Whether a dispatch arm refers to the pcode the cursor currently sits on.
  //
  // Exact equality is the common case. The trailing range check is the
  // tolerance that makes this useful in practice: by the time a handler's
  // dispatch select is examined, the VIP has typically already stepped past
  // the dispatch it is selecting on, so the arm lands just behind the cursor.
  // Bounding that gap to 8 bytes stops this matching an arbitrary earlier
  // pcode that merely happens to sit nearby.
  bool matchesCurrentPcode(uint64_t arm) const {
    if (arm == 0 || offset == 0) {
      return false;
    }
    if (arm == offset || fetchRva(arm) == fetchRva(offset)) {
      return true;
    }
    const uint64_t ar = fetchRva(arm);
    const uint64_t pr = fetchRva(offset);
    return pr >= ar && (pr - ar) <= 8;
  }

  // Outcome of deciding how a fetch's base address should be obtained.
  //
  //   cursor    the address to use as the new VIP
  //   freshPop  the address came from a stack pop rather than from the
  //             current cursor, so it must be read back out of the VM stack
  //   popSlot   the VM-stack slot holding the popped value
  //   popOrg    the IR value the slot was loaded from, for re-reading
  struct FetchPlan {
    uint64_t cursor = 0;
    bool freshPop = false;
    uint64_t popSlot = 0;
    llvm::Value* popOrg = nullptr;
  };

  // Classify a fetch's base value into a FetchPlan.
  //
  // Three cases, in order:
  //   1. a constant that is bytecode -- use it directly, nothing to pop
  //   2. a VM-stack load             -- a fresh pop; the caller must read
  //                                     the slot to learn the new VIP
  //   3. anything else               -- keep the current cursor
  //
  // Case 2 also accepts a re-use of the exact IR value seen in the previous
  // noteStackQword call, not only a recognisable stack-shaped load. That
  // covers the common case where the value reached the use-site via an
  // optimisation that rewrote the load away, leaving only the earlier SSA
  // value to identify it by.
  template <typename IsBytecode>
  FetchPlan planFetch(llvm::Value* baseVal, IsBytecode&& isBytecode) const {
    FetchPlan plan;
    if (auto* ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(baseVal)) {
      if (isBytecode(ci->getZExtValue())) {
        plan.cursor = ci->getZExtValue();
        return plan;
      }
    }
    llvm::LoadInst* li = nullptr;
    uint64_t slot = stackLoadAddress(baseVal, &li);
    const bool freshPop =
        slot != 0 || (lastStackQwordLoad &&
                      peelCasts(baseVal) == peelCasts(lastStackQwordLoad));
    if (!freshPop) {
      plan.cursor = offset;
      return plan;
    }
    plan.freshPop = true;
    if (slot == 0) {
      slot = lastStackQwordSlot;
    }
    plan.popSlot = slot;
    plan.popOrg = li ? static_cast<llvm::Value*>(li) : lastStackQwordLoad;
    return plan;
  }
};

#endif
