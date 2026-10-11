#ifndef VMP_DISPATCH_H
#define VMP_DISPATCH_H

// Transfer-level analysis for VM dispatch: deciding whether an indirect jump
// can be resolved to a single handler, pinned to one, or must be left as a
// runtime select.
//
// The problem this solves: by the time a VM dispatch reaches the lifter, the
// destination has usually been computed through several handlers and is no
// longer a constant. Recovering it means recognising the *shape* of the
// transfer (selects between constants, a phi carrying an instance base) and
// deciding which parts of that shape carry information about the next
// handler rather than about ordinary data.
//
// The rule throughout is conservative: when the shape is ambiguous, decline
// to pin and fall back to the unspecialised path. A wrong pin produces IR
// that looks clean and computes the wrong thing; declining produces IR that
// is merely less optimal.

#include "VmpPcodeCursor.hpp"

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <set>

template <Registers Register>
class VmpDispatch {
public:
  explicit VmpDispatch(VmpPcodeCursor<Register>& cursor) : cursor(cursor) {}

  // Accumulates evidence about one dispatch transfer as the lift loop walks
  // it. Filled by the semantics handlers, then queried once the transfer is
  // complete.
  struct TransferScan {
    // Addresses observed flowing into the VIP.
    std::set<uint64_t> vipLoadAddrs;
    // The selects that mux between two such addresses. Kept as pointers
    // because keepDestSelect has to exclude these specific instructions, and
    // an address set cannot express "all selects except these".
    std::set<llvm::SelectInst*> vipLoadSelects;
    llvm::PHINode* basePhi = nullptr;
    llvm::ConstantInt* baseConst = nullptr;

    // Record a `select cond, <addrA>, <addrB>` as a VIP address mux.
    //
    // Both arms must be constants. A select with a symbolic arm is not a
    // dispatch transfer, it is ordinary control flow, and recording it would
    // suppress forking for the whole transfer on the strength of a shape that
    // carries no address information at all.
    void noteAddressMux(llvm::SelectInst* sel) {
      auto* t = llvm::dyn_cast<llvm::ConstantInt>(sel->getTrueValue());
      auto* f = llvm::dyn_cast<llvm::ConstantInt>(sel->getFalseValue());
      if (!t || !f) {
        return;
      }
      vipLoadSelects.insert(sel);
      // Record each arm under both its raw form and its image-relative form.
      // Later lookups (isVipLoadAddr) try both, because a select built before
      // image-base normalisation and one built after will not compare equal.
      auto add = [&](uint64_t addr) {
        vipLoadAddrs.insert(addr);
        vipLoadAddrs.insert(VmpPcodeCursor<Register>::fetchRva(addr));
      };
      add(t->getZExtValue());
      add(f->getZExtValue());
    }

    // Capture the phi that carries the VM instance base, if any.
    //
    // First phi with at least one constant incoming wins, and the scan stops
    // at the first match (note the early `return`). Taking the first rather
    // than the last is intentional: it is the loop-header phi, and later
    // phis in the same block are typically derived from it, so the earliest
    // one is the root and gives the same answer with less reasoning.
    void noteInstanceBase(llvm::PHINode* ph) {
      if (basePhi || !ph) {
        return;
      }
      for (unsigned k = 0; k < ph->getNumIncomingValues(); ++k) {
        if (auto* kc =
                llvm::dyn_cast<llvm::ConstantInt>(ph->getIncomingValue(k))) {
          basePhi = ph;
          baseConst = kc;
          return;
        }
      }
    }

    // Once the transfer has been seen muxing VIP addresses, it is the address
    // computation rather than a branch decision, so forking the destination
    // on top of it would produce a select over selects.
    bool suppressDestFork() const { return !vipLoadSelects.empty(); }

    // Whether a constant-armed select should survive into the emitted IR
    // rather than being folded away. Excludes the VIP muxes (those are
    // address plumbing this pass is replacing) and requires both arms to be
    // constants so there is a real choice to preserve.
    bool keepDestSelect(llvm::SelectInst* sel) const {
      return vipLoadSelects.count(sel) == 0 &&
             llvm::isa<llvm::ConstantInt>(sel->getTrueValue()) &&
             llvm::isa<llvm::ConstantInt>(sel->getFalseValue());
    }

    // Whether an address was one of the VIP muxes, tested in both raw and
    // image-relative form for the reason given in noteAddressMux.
    bool isVipLoadAddr(uint64_t addr) const {
      return vipLoadAddrs.count(addr) != 0 ||
             vipLoadAddrs.count(VmpPcodeCursor<Register>::fetchRva(addr)) != 0;
    }
  };

  // Whether the destination can be pinned to a single handler address.
  //
  // offset == 0 means the cursor never bound, and is checked explicitly
  // rather than relying on the caller's bound() because pinning to address 0
  // is never meaningful and would otherwise look like a successful pin.
  bool canPinDest(bool offsetIsMappedCode) const {
    return cursor.bound() && cursor.offset != 0 && offsetIsMappedCode;
  }

  // Choose the arm of a load-select that corresponds to the pcode the cursor
  // is on, collapsing the select to that constant.
  //
  // Returns nullptr when neither or both arms match. Both-matching means the
  // select is not actually discriminating on pcode and folding it would pick
  // arbitrarily; neither means the cursor has moved somewhere the select
  // cannot explain. Either way the caller keeps the select.
  llvm::ConstantInt* pinLoadSelectArm(llvm::ConstantInt* tArm,
                                      llvm::ConstantInt* fArm) const {
    const bool tHit =
        tArm && cursor.matchesCurrentPcode(tArm->getZExtValue());
    const bool fHit =
        fArm && cursor.matchesCurrentPcode(fArm->getZExtValue());
    if (tHit == fHit) {
      return nullptr;
    }
    return tHit ? tArm : fArm;
  }

  // A bytecode address is never a valid handler destination. Handlers live in
  // native code, bytecode lives in the pcode stream, and confusing the two is
  // the characteristic failure of trying to follow a dispatch statically.
  //
  // Either input disqualifying is enough: `addr` being bytecode means we
  // followed the pointer into the pcode stream rather than to a handler, and
  // `normIsBytecode` says the normalised form landed there, which catches the
  // case where the raw address was a relocated pointer that only looked like
  // code.
  static bool excludeBytecodeDest(bool addrIsBytecode, bool normIsBytecode) {
    return addrIsBytecode || normIsBytecode;
  }

  // Whether the destination is in fact the VIP rather than a handler. Guards
  // against "resolving" a dispatch to the bytecode address itself.
  static bool isVipAsDest(uint64_t dest, uint64_t pcode) {
    return VmpPcodeCursor<Register>::fetchRva(dest) ==
           VmpPcodeCursor<Register>::fetchRva(pcode);
  }

  // Final gate on treating `dest` as a live handler.
  //
  // Three ways to fail, each catching a different way of being wrong:
  //   handlerOk false        -- the handler itself failed structural checks
  //   isVipLoadAddr(dest)    -- the "destination" is a VIP load target, so we
  //                              followed the address computation one hop too
  //                              far and landed on pcode, not a handler
  //   isVipAsDest(dest,pcode)-- destination equals the current pcode
  //
  // The pcode==0 disjunct is skipped rather than tested: fetchRva(0) == 0 for
  // every input, so an unset pcode would make this return true unconditionally
  // and reject every candidate.
  static bool isLiveHandler(const TransferScan& scan, uint64_t dest,
                            bool handlerOk, uint64_t pcode = 0) {
    if (!handlerOk || scan.isVipLoadAddr(dest)) {
      return false;
    }
    if (pcode != 0 && isVipAsDest(dest, pcode)) {
      return false;
    }
    return true;
  }

private:
  // Held by reference: the cursor is the mutable state this class queries,
  // and copying it would silently fork the VIP tracking.
  VmpPcodeCursor<Register>& cursor;
};

#endif
