#ifndef VMP_MODEL_H
#define VMP_MODEL_H

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
  std::vector<std::pair<uint64_t, uint64_t>> bytecodeRanges;

public:
  using FetchPlan = typename VmpPcodeCursor<Register>::FetchPlan;
  using TransferScan = typename VmpDispatch<Register>::TransferScan;

  VmpDispatch<Register> dispatch;

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
