#ifndef VMP_DISPATCH_H
#define VMP_DISPATCH_H

#include "VmpPcodeCursor.hpp"

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <set>

template <Registers Register>
class VmpDispatch {
public:
  explicit VmpDispatch(VmpPcodeCursor<Register>& cursor) : cursor(cursor) {}

  struct TransferScan {
    std::set<uint64_t> vipLoadAddrs;
    std::set<llvm::SelectInst*> vipLoadSelects;
    llvm::PHINode* basePhi = nullptr;
    llvm::ConstantInt* baseConst = nullptr;

    void noteAddressMux(llvm::SelectInst* sel) {
      auto* t = llvm::dyn_cast<llvm::ConstantInt>(sel->getTrueValue());
      auto* f = llvm::dyn_cast<llvm::ConstantInt>(sel->getFalseValue());
      if (!t || !f) {
        return;
      }
      vipLoadSelects.insert(sel);
      auto add = [&](uint64_t addr) {
        vipLoadAddrs.insert(addr);
        vipLoadAddrs.insert(VmpPcodeCursor<Register>::fetchRva(addr));
      };
      add(t->getZExtValue());
      add(f->getZExtValue());
    }

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

    bool suppressDestFork() const { return !vipLoadSelects.empty(); }

    bool keepDestSelect(llvm::SelectInst* sel) const {
      return vipLoadSelects.count(sel) == 0 &&
             llvm::isa<llvm::ConstantInt>(sel->getTrueValue()) &&
             llvm::isa<llvm::ConstantInt>(sel->getFalseValue());
    }

    bool isVipLoadAddr(uint64_t addr) const {
      return vipLoadAddrs.count(addr) != 0 ||
             vipLoadAddrs.count(VmpPcodeCursor<Register>::fetchRva(addr)) != 0;
    }
  };

  bool canPinDest(bool offsetIsMappedCode) const {
    return cursor.bound() && cursor.offset != 0 && offsetIsMappedCode;
  }

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

  static bool excludeBytecodeDest(bool addrIsBytecode, bool normIsBytecode) {
    return addrIsBytecode || normIsBytecode;
  }

  static bool isVipAsDest(uint64_t dest, uint64_t pcode) {
    return VmpPcodeCursor<Register>::fetchRva(dest) ==
           VmpPcodeCursor<Register>::fetchRva(pcode);
  }

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
  VmpPcodeCursor<Register>& cursor;
};

#endif
