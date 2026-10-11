#ifndef VMP_MODEL_H
#define VMP_MODEL_H

// Top-level entry point for VMP devirtualisation, and the only piece of this
// subsystem the semantics layer needs to know about.
//
// The layering is: semantics handlers observe instructions and forward them
// here as events (onMov, onBytecodeLoad, onPointerStep, ...); VmpModel owns
// the bytecode-range table and the cursor, and forwards the dispatch questions
// to VmpDispatch. Handlers never talk to the cursor directly.
//
// The event API is fire-and-forget by design. A handler cannot ask "where is
// the VIP" and get a useful answer, because the answer depends on instructions
// the handler has not lowered yet. So the model accumulates state across
// events and only answers at the points where the lifter has enough
// information to ask a real question.

#include "VmpDispatch.hpp"
#include "VmpPcodeCursor.hpp"

#include <cstdint>
#include <utility>
#include <vector>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Value.h>

template <Registers Register>
class VmpModel {
  VmpPcodeCursor<Register> cursor;
  // Known extents of the pcode stream. Separate from the PE section map: this
  // is whatever the protector actually stores bytecode in, which is often not
  // a section boundary.
  std::vector<std::pair<uint64_t, uint64_t>> bytecodeRanges;

public:
  using FetchPlan = typename VmpPcodeCursor<Register>::FetchPlan;
  using TransferScan = typename VmpDispatch<Register>::TransferScan;

  VmpDispatch<Register> dispatch;

  // All copy and move operations are deleted on purpose. `dispatch` holds a
  // *reference* to `cursor`, so a defaulted copy would produce a copy whose
  // dispatch points back at the original's cursor -- a model that appears to
  // work and silently never observes the new object's events. Deleting is the
  // only option that makes that mistake a compile error.
  VmpModel() : dispatch(cursor) {}
  VmpModel(const VmpModel&) = delete;
  VmpModel& operator=(const VmpModel&) = delete;
  VmpModel(VmpModel&&) = delete;
  VmpModel& operator=(VmpModel&&) = delete;

  bool bound() const { return cursor.bound(); }
  Register pcodeRegister() const { return cursor.pcodeReg; }
  uint64_t vipOffset() const { return cursor.offset; }

  void addBytecodeRange(uint64_t start, uint64_t end) {
    bytecodeRanges.emplace_back(start, end);
  }

  // Half-open interval test: [first, second). Ranges are merged by the caller,
  // and the range list is expected to be short (one or two entries in
  // practice), so a linear scan beats maintaining a sorted structure.
  bool isBytecodeAddress(uint64_t address) const {
    for (const auto& range : bytecodeRanges) {
      if (address >= range.first && address < range.second) {
        return true;
      }
    }
    return false;
  }

  bool isFetch(Register memBase, bool simple) const {
    return cursor.isFetch(memBase, simple, isBytecodeAddress(cursor.offset));
  }

  // Pick which side of a two-operand decryption-shaped instruction carries the
// real dependency chain.
  //
  // The protector's per-handler key derivation puts one operand through a chain
  // of pointer steps; the other is a plain constant or a direct value. Folding
  // the wrong operand leaves the key unevaluated and the dispatch symbolic.
  //
  //   both chained   -> the constant side is the base, the chained side the key
  //   one chained     -> that side, unambiguously
  //   neither         -> nullptr, no opinion; caller falls back to generic
  static llvm::Value* pickDecryptOperand(llvm::Value* lhs, llvm::Value* rhs,
                                         bool lhsIsModuleConst,
                                         bool lhsHasChain, bool rhsHasChain) {
    if (lhsHasChain && rhsHasChain) {
      return lhsIsModuleConst ? rhs : lhs;
    }
    if (lhsHasChain) {
      return lhs;
    }
    if (rhsHasChain) {
      return rhs;
    }
    return nullptr;
  }

  // Execute a fetch plan produced by the cursor.
  //
  // The interesting branch is the fresh-pop case: the VIP came off the VM
  // stack rather than from the current cursor, so it has to be read back out
  // of the slot the pop named. Two guards apply to that read:
  //
  //   popSlot / popOrg must both be known. A fresh pop with no identified
  //   origin means the plan was built from the previous noteStackQword value
  //   rather than from this instruction; re-reading would pick up whatever the
  //   stack holds now, which is not necessarily what was popped.
  //
  //   the read-back must itself land in bytecode. If it does not, the pop was
  //   not a VIP after all, so the cursor is unbound rather than pointed at the
  //   value. Unbinding is the important part: leaving the cursor bound with
  // offset 0 makes every later unrelated load look like a fetch.
  //
  // wroteRegister reports whether this fetch resolved to a real address, so
  // callers can tell "the VM advanced" from "we lost the thread".
  template <typename Retrieve>
  uint64_t resolveFetch(llvm::Value* baseVal, Retrieve&& retrieve,
                        bool& wroteRegister) {
    wroteRegister = false;
    auto plan = cursor.planFetch(
        baseVal, [&](uint64_t addr) { return isBytecodeAddress(addr); });
    uint64_t addr = plan.cursor;
    if (addr == 0 && plan.freshPop) {
      if (plan.popSlot != 0 && plan.popOrg) {
        addr = retrieve(plan.popSlot, plan.popOrg);
        if (!isBytecodeAddress(addr)) {
          addr = 0;
        }
      }
      if (addr == 0) {
        cursor.unbind();
        return 0;
      }
      wroteRegister = true;
    }
    if (addr != 0) {
      cursor.offset = addr;
    }
    return addr;
  }

  void onModuleLoad(uint64_t addr) {
    // Last bytecode fetch is the VIP (AddEndHandlerCommands). Ultra handlers
    // also load native RX / tables afterwards; those must not replace a live
    // bytecode cursor or transfer keys loops on a handler VA.
    //
    // The guard is directional: a module load only displaces the cursor when
    // the cursor currently sits on bytecode and the new address does not. A
    // load while the cursor is already off bytecode (not yet bound, or
    // already unbound) is allowed through, because that is the initial
    // binding. Without the direction check, the first native load after a
    // dispatch would clobber the cursor before the next bytecode fetch.
    if (addr == 0) {
      return;
    }
    if (isBytecodeAddress(cursor.offset) && !isBytecodeAddress(addr)) {
      return;
    }
    cursor.noteModule(addr);
  }
  void onBytecodeLoad(Register memBase, bool simple, uint64_t addr) {
    cursor.bind(memBase, simple, isBytecodeAddress(addr));
  }

  // Track a pointer step on the VIP register.
  //
  // Only 1/2/4/8 are accepted: those are the natural instruction granularities
  // for walking a pcode stream, and allowing arbitrary steps would let a
  // scaling multiply or an unrelated add move the cursor by an amount that
  // has nothing to do with sequential dispatch.
  //
  // The dest register must be the one currently holding the cursor; a step on
  // any other register is ordinary arithmetic.
  void onPointerStep(Register dest, bool isAdd, uint64_t step) {
    if (step != 1 && step != 2 && step != 4 && step != 8) {
      return;
    }
    if (!cursor.bound() || dest != cursor.pcodeReg) {
      return;
    }
    cursor.advance(isAdd ? static_cast<int64_t>(step)
                         : -static_cast<int64_t>(step));
  }

  void onMov(Register dest, Register srcReg, Register memBase, bool srcIsMemory,
             llvm::Value* v, bool valueIsBytecode) {
    cursor.onMovToReg(dest, srcReg, memBase, srcIsMemory, v, valueIsBytecode);
  }

  void noteStackQword(llvm::Value* result, uint8_t sizeBits, uint64_t addr) {
    cursor.noteStackQword(result, sizeBits, addr);
  }
};

#endif
