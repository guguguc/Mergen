#ifndef VMP_PCODE_CURSOR_H
#define VMP_PCODE_CURSOR_H

#include "CommonRegisters.h"
#include "Includes.h"

#include <cstdint>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Value.h>

template <Registers Register>
class VmpPcodeCursor {
public:
  Register pcodeReg = Register::None;
  uint64_t offset = 0;
  llvm::Value* lastStackQwordLoad = nullptr;
  uint64_t lastStackQwordSlot = 0;

  bool bound() const { return pcodeReg != Register::None; }

  static uint64_t fetchRva(uint64_t addr) {
    if (addr >= 0x140000000ULL) {
      return addr - 0x140000000ULL;
    }
    if ((addr & 0xFF000000ULL) == 0x40000000ULL) {
      return addr & 0x00FFFFFFULL;
    }
    return addr;
  }

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

  static bool isVmStackAddress(uint64_t address) {
    constexpr uint64_t kReserve = 0x100000;
    return address >= STACKP_VALUE - kReserve &&
           address <= STACKP_VALUE + kReserve;
  }

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

  bool isFetch(Register memBase, bool simple, bool offsetIsBytecode) const {
    return bound() && simple && memBase == pcodeReg && offset != 0 &&
           offsetIsBytecode;
  }

  void bind(Register memBase, bool simple, bool addrIsBytecode) {
    if (!addrIsBytecode || !simple) {
      return;
    }
    pcodeReg = memBase;
  }

  void noteModule(uint64_t addr) { offset = addr; }

  void advance(int64_t delta) {
    if (!bound() || offset == 0 || delta == 0) {
      return;
    }
    offset += static_cast<uint64_t>(delta);
  }

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

  void noteStackQword(llvm::Value* result, uint8_t sizeBits, uint64_t addr) {
    if (result && sizeBits == 64 && addr != 0 && isVmStackAddress(addr)) {
      lastStackQwordLoad = result;
      lastStackQwordSlot = addr;
    }
  }

  void unbind() {
    pcodeReg = Register::None;
    offset = 0;
  }

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

  struct FetchPlan {
    uint64_t cursor = 0;
    bool freshPop = false;
    uint64_t popSlot = 0;
    llvm::Value* popOrg = nullptr;
  };

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
