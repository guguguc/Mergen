
#pragma once

#include "CommonDisassembler.hpp"
#include "GEPTracker.ipp"
#include "LifterDiagHelpers.hpp"
#include "ZydisDisassembler.hpp"
#include "LifterClass.hpp"
#include "Utils.h"
#include <cstdio>
#include <iostream>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Analysis/ConstantFolding.h>
#include <llvm/Analysis/DomConditionCache.h>
#include <llvm/Analysis/InstructionSimplify.h>
#include <llvm/Analysis/SimplifyQuery.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Analysis/ValueLattice.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/Support/KnownBits.h>
#include <llvm/TargetParser/Triple.h>
#include <magic_enum/magic_enum.hpp>
#include <optional>

using namespace llvm;

#ifndef TESTFOLDER
#define TESTFOLDER
#define TESTFOLDER3
#define TESTFOLDER4
#define TESTFOLDER5
#define TESTFOLDER6
#define TESTFOLDER7
#define TESTFOLDER8
#define TESTFOLDERshl
#define TESTFOLDERshr
#endif

using namespace PatternMatch;

static void findAffectedValues(Value* Cond, SmallVectorImpl<Value*>& Affected) {
  auto AddAffected = [&Affected](Value* V) {
    if (isa<Argument>(V) || isa<GlobalValue>(V)) {
      Affected.push_back(V);
    } else if (auto* I = dyn_cast<Instruction>(V)) {
      Affected.push_back(I);

      // Peek through unary operators to find the source of the condition.

      Value* Op;
      if (match(I, m_PtrToInt(m_Value(Op)))) {
        if ((isa<Instruction>(Op) || isa<Argument>(Op)) &&
            Op->hasNUsesOrMore(1))
          Affected.push_back(Op);
      }
    }
  };

  llvm::ICmpInst::Predicate Pred = {};
  Value* A;
#if LLVM_VERSION_MAJOR > 18
  llvm::CmpPredicate CmpPred{Pred};
  if (match(Cond, m_ICmp(CmpPred, m_Value(A), m_Constant()))) {
#else
  if (match(Cond, m_ICmp(Pred, m_Value(A), m_Constant()))) {
#endif
    AddAffected(A);

    if (llvm::ICmpInst::isEquality(Pred)) {
      Value* X;
      // (X & C) or (X | C) or (X ^ C).
      // (X << C) or (X >>_s C) or (X >>_u C).
      if (match(A, m_BitwiseLogic(m_Value(X), m_ConstantInt())) ||
          match(A, m_Shift(m_Value(X), m_ConstantInt())))
        AddAffected(X);
    } else {
      Value* X;
      // Handle (A + C1) u< C2, which is the canonical form of A > C3 && A < C4.
      if (match(A, m_Add(m_Value(X), m_ConstantInt())))
        AddAffected(X);
    }
  }
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(llvm::SimplifyQuery)::createSimplifyQuery(
    Instruction* Inst) {
  // updateDomTree(*fnc);
  // auto DT = getDomTree();
  auto DL = fnc->getParent()->getDataLayout();
  static llvm::TargetLibraryInfoImpl TLIImpl(
      llvm::Triple(fnc->getParent()->getTargetTriple()));
  static llvm::TargetLibraryInfo TLI(TLIImpl);

  llvm::SimplifyQuery SQ(DL, &TLI, DT, nullptr, Inst, true, true, nullptr);

  return SQ;
}

using namespace llvm::PatternMatch;

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::doPatternMatching(
    Instruction::BinaryOps const I, Value* const op0, Value* const op1) {

  switch (I) {
  case Instruction::Add: {
    auto and_by_power = [&](Value* op, ConstantInt*& power) {
      Value* LHS;
      return match(op, m_And(m_Value(LHS), m_ConstantInt(power))) &&
             power->getValue().isPowerOf2();
    };

    auto shifted_by_power = [&](Value* op, ConstantInt*& ShiftAmount,
                                Value*& LHS) {
      return match(op, m_LShr(m_Value(LHS), m_ConstantInt(ShiftAmount)));
    };

    auto negative_constant_singlebit = [](Value* op, ConstantInt*& ci) {
      return match(op, m_ConstantInt(ci)) && ci->getValue().isNegative() &&
             ci->getValue().abs().isPowerOf2();
    };

    auto matchPattern = [&](Value* op0, Value* op1) -> Value* {
      ConstantInt *power = nullptr, *ShiftAmount = nullptr, *ci = nullptr;
      Value* LHS = nullptr;

      if (negative_constant_singlebit(op0, ci)) {
        if (shifted_by_power(op1, ShiftAmount, LHS)) {
          if (and_by_power(LHS, power)) {
            auto diff = power->getValue().logBase2() - ShiftAmount->getValue();
            printvalue2(power->getValue());
            printvalue2(ShiftAmount->getValue());
            printvalue2(ci->getValue());
            auto math_is_hard =
                diff.getBoolValue() ? APInt(64, 2) << diff : APInt(64, 1);
            printvalue2(math_is_hard);
            printvalue2(ci->getValue() == -(math_is_hard));
            if (ci->getValue() == -(math_is_hard)) {
              auto zero =
                  builder->getIntN(op1->getType()->getIntegerBitWidth(), 0);
              auto cond = createICMPFolder(llvm::CmpInst::ICMP_EQ, op1, zero);
              return createSelectFolder(cond, ci, zero);
            }
          }
        }
      }
      return nullptr;
    };

    /*
    %not-PConsRegister-9425 = and i64 %realnot-5369619277-, 64 ( 2 ** 6 = 64)
        %shr-lshr-5368775124- = lshr i64 %not-PConsRegister-9425, 6
        %realadd-5369433110- = add i64 -1, %shr-lshr-5368775124- ( - (2 ** 6-6)
        ;  ( (a & (2**power) ) >> (power-lula) ) - (2**(lula))
        ;  result = select trunc( (a & (2**power) ) >> (power-lula) ),  0 or
        -(2**(lula))
    */

    // Check if the pattern matches with op0 and op1 in both configurations
    if (auto aaaaa = matchPattern(op0, op1)) {
      return aaaaa;
    }

    break;
  }
  case Instruction::Or: {
    Value *A = nullptr, *B = nullptr, *C = nullptr;

    // Match (~A & B) | (A & C)
    auto handleAndNotPattern = [&](Value* op0, Value* op1) -> bool {
      return (match(op0, m_And(m_Not(m_Value(A)), m_Value(B))) &&
              match(op1, m_And(m_Value(A), m_Value(C))));
    };

    if (handleAndNotPattern(op0, op1) || handleAndNotPattern(op1, op0)) {
      // This matches (~A & B) | (A & C)
      // Simplify to A ? C : B

      // if a is 0, select B
      // if a is -1, select C
      // then... ?
      if (auto X_inst = dyn_cast<Instruction>(A)) {

        auto possible_condition = analyzeValueKnownBits(X_inst, X_inst);
        if (possible_condition.getMaxValue().isAllOnes() &&
            possible_condition.getMinValue().isZero()) {
          auto zero = ConstantInt::get(A->getType(), 0);
          auto cond = createICMPFolder(llvm::CmpInst::ICMP_EQ, A, zero);
          return createSelectFolder(cond, B, C, "selectEZ");
        }
      }
    }
    break;
  }
  case Instruction::And: {
    // X & ~X
    Value* X = nullptr;
    static auto isXAndNotX = [](Value* op0, Value* op1, Value* X) {
      return (match(op0, m_ZExtOrSelf(m_Not(m_Value(X)))) &&
              match(op1, m_ZExtOrSelf(m_Specific(X)))) ||
             (match(op0, m_Trunc(m_Not(m_Value(X)))) &&
              match(op1, m_Trunc(m_Specific(X))));
    };

    if (isXAndNotX(op0, op1, X) || isXAndNotX(op1, op0, X)) {
      auto possibleSimplifyand = ConstantInt::get(op1->getType(), 0);
      return possibleSimplifyand;
    }
    // ~X & ~X

    if (match(op0, m_Not(m_Value(X))) && X == op1)
      return op0;

    break;
  }
  case Instruction::Xor: {
    // ~~X -> X
    Value* X = nullptr;
    if (match(op1, m_SpecificInt(-1)) && match(op0, m_Not(m_Value(X))))
      return X;
    if (match(op0, m_SpecificInt(-1)) && match(op1, m_Not(m_Value(X))))
      return X;

    // X ^ ~X
    static auto isXorNotX = [](Value* op0, Value* op1, Value* X) {
      return (match(op0, m_ZExtOrSelf(m_Not(m_Value(X)))) &&
              match(op1, m_ZExtOrSelf(m_Specific(X)))) ||
             (match(op0, m_Trunc(m_Not(m_Value(X)))) &&
              match(op1, m_Trunc(m_Specific(X))));
    };

    if (isXorNotX(op0, op1, X) || isXorNotX(op1, op0, X)) {
      auto possibleSimplify = ConstantInt::get(op1->getType(), -1);
      return possibleSimplify;
    }

    if (match(op0, m_Specific(op1))) {
      auto possibleSimplify = ConstantInt::get(op1->getType(), 0);
      return possibleSimplify;
    }

    Value* A = nullptr;
    Value* B = nullptr;
    Value* C = nullptr;
    Value* D = nullptr;
    // not
    auto handleNegXorOr = [&](Value* op0, Value* op1) -> Value* {
      if (match(op1, m_SpecificInt(-1)) &&
          match(op0, m_Or(m_Value(A), m_Value(B)))) {
        Constant* constant_v = nullptr;

        auto createAndNot = [&](Value* C, Constant* constant_v,
                                const char* suffix) -> Value* {
          return createAndFolder(
              C,
              createXorFolder(constant_v,
                              Constant::getAllOnesValue(constant_v->getType())),
              suffix);
        };

        auto handleNotAOrB = [&](Value* A, Value* B) -> Value* {
          if (match(A, m_Not(m_Value(C))) && match(B, m_Constant(constant_v))) {
            // ~(~a | b) -> a & ~b
            return createAndNot(C, constant_v, "not-PConst-");
          }
          return nullptr;
        };

        auto handleAOrBci = [&](Value* A, Value* B) -> Value* {
          if (match(A, m_Value(C)) && match(B, m_Constant(constant_v))) {
            // ~(a | b(ci)) -> ~a & ~b
            return createAndFolder(

                createXorFolder(C, Constant::getAllOnesValue(C->getType()),
                                "not_v"),
                createXorFolder(constant_v, Constant::getAllOnesValue(
                                                constant_v->getType())),
                "not-PConsRegister-");
          }
          return nullptr;
        };

        auto handleNotAOrNotB = [&](Value* A, Value* B) -> Value* {
          if (match(A, m_Not(m_Value(C))) && match(B, m_Not(m_Value(D)))) {
            // ~(~a | ~b) -> a & b
            return createAndFolder(C, D, "not-P1-");
          }
          return nullptr;
        };

        auto matchAndSimplify = [&](Value* A, Value* B) -> Value* {
          if (Value* result = handleNotAOrB(A, B))
            return result;
          if (Value* result = handleAOrBci(A, B))
            return result;
          if (Value* result = handleAOrBci(B, A))
            return result;
          if (Value* result = handleNotAOrNotB(A, B))
            return result;
          if (Value* result = handleNotAOrB(A, B))
            return result;
          if (Value* result = handleNotAOrB(B, A))
            return result;
          return nullptr;
        };

        if (Value* result = matchAndSimplify(A, B)) {
          return result;
        } else if (Value* result_swap = matchAndSimplify(B, A)) {
          return result_swap;
        }
      }

      return nullptr;
    };

    if (auto result = handleNegXorOr(op0, op1))
      return result;

    break;
  }

  default: {
    return nullptr;
  }
  }

  return nullptr;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(KnownBits)::analyzeValueKnownBits(
    Value* value, Instruction* ctxI) {
  KnownBits knownBits(64);
  knownBits.resetAll();
  if (value->getType()->getIntegerBitWidth() > 64 || isa<UndefValue>(value))
    return knownBits;

  if (auto v_inst = dyn_cast<Instruction>(value)) {
    // Use find() to check if v_inst exists in the map
    auto it = assumptions.find(v_inst);
    if (it != assumptions.end()) {
      auto a = it->second; // Retrieve the value associated with the instruction
      return KnownBits::makeConstant(a);
    }
  }

  if (value->getType() == Type::getInt128Ty(value->getContext()))
    return knownBits;

  if (auto CIv = dyn_cast<ConstantInt>(value)) {
    return KnownBits::makeConstant(APInt(value->getType()->getIntegerBitWidth(),
                                         CIv->getZExtValue(), false));
  }
  auto SQ = createSimplifyQuery(ctxI);

  computeKnownBits(value, knownBits, 0, SQ);
  return knownBits.trunc(value->getType()->getIntegerBitWidth());
}


inline bool isCast(uint8_t opcode) {
  return Instruction::Trunc <= opcode && opcode <= Instruction::AddrSpaceCast;
};

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::getOrCreate(
    const InstructionKey& key, uint8_t opcode, const Twine& Name) {

  auto it = cache.lookup(opcode, key);
  if (it) {
    return it;
  }
  Value* newInstruction = nullptr;
  if (isCast(opcode) == 0) {
    // Binary instruction. Distribute over select through folderBinOps so
    // identities (-1/0/~~) and constant folding run on each arm; CreateBinOp
    // alone skips Mergen's folder and leaves VIP masks symbolic.
    const auto binOp = static_cast<Instruction::BinaryOps>(opcode);
    if (auto select_inst = dyn_cast<llvm::SelectInst>(key.operand1)) {
      printvalue2(
          analyzeValueKnownBits(select_inst->getCondition(), select_inst));
      if (isa<ConstantInt>(key.operand2))
        return createSelectFolder(
            select_inst->getCondition(),
            folderBinOps(select_inst->getTrueValue(), key.operand2, Name,
                         binOp),
            folderBinOps(select_inst->getFalseValue(), key.operand2, Name,
                         binOp),
            "lola-");
    }
    if (auto select_inst = dyn_cast<llvm::SelectInst>(key.operand2)) {
      printvalue2(
          analyzeValueKnownBits(select_inst->getCondition(), select_inst));
      if (isa<ConstantInt>(key.operand1))
        return createSelectFolder(
            select_inst->getCondition(),
            folderBinOps(key.operand1, select_inst->getTrueValue(), Name,
                         binOp),
            folderBinOps(key.operand1, select_inst->getFalseValue(), Name,
                         binOp),
            "lolb-");
    }

    Value *cnd1, *lhs1, *rhs1;
    if (match(key.operand1, m_TruncOrSelf(m_Select(m_Value(cnd1), m_Value(lhs1),
                                                   m_Value(rhs1))))) {
      if (auto select_inst = dyn_cast<llvm::SelectInst>(key.operand2))
        if (select_inst && cnd1 == select_inst->getCondition()) // also check
                                                                // if inversed
          return createSelectFolder(
              select_inst->getCondition(),
              folderBinOps(lhs1, select_inst->getTrueValue(), Name, binOp),
              folderBinOps(rhs1, select_inst->getFalseValue(), Name, binOp),
              "lol2-");
    } else if (match(key.operand1,
                     m_ZExtOrSExtOrSelf(m_Select(m_Value(cnd1), m_Value(lhs1),
                                                 m_Value(rhs1))))) {
      if (auto select_inst = dyn_cast<llvm::SelectInst>(key.operand2))
        if (select_inst && cnd1 == select_inst->getCondition()) // also check
                                                                // if inversed
          return createSelectFolder(
              select_inst->getCondition(),
              folderBinOps(lhs1, select_inst->getTrueValue(), Name, binOp),
              folderBinOps(rhs1, select_inst->getFalseValue(), Name, binOp),
              "lol2-");
    }
    Value *cnd, *lhs, *rhs;
    if (match(key.operand2, m_TruncOrSelf(m_Select(m_Value(cnd), m_Value(lhs),
                                                   m_Value(rhs))))) {
      if (auto select_inst = dyn_cast<llvm::SelectInst>(key.operand1))
        if (select_inst && cnd == select_inst->getCondition()) // also check
                                                               // if inversed
          return createSelectFolder(
              select_inst->getCondition(),
              folderBinOps(select_inst->getTrueValue(), lhs, Name, binOp),
              folderBinOps(select_inst->getFalseValue(), rhs, Name, binOp),
              "lol2-");
    } else if (match(key.operand2,
                     m_ZExtOrSExtOrSelf(
                         m_Select(m_Value(cnd), m_Value(lhs), m_Value(rhs))))) {
      if (auto select_inst = dyn_cast<llvm::SelectInst>(key.operand1))
        if (select_inst && cnd == select_inst->getCondition()) // also check
                                                               // if inversed
          return createSelectFolder(
              select_inst->getCondition(),
              folderBinOps(select_inst->getTrueValue(), lhs, Name, binOp),
              folderBinOps(select_inst->getFalseValue(), rhs, Name, binOp),
              "lol2-");
    }
    newInstruction =
        builder->CreateBinOp(binOp, key.operand1, key.operand2, Name);
  } else if (isCast(opcode)) {
    // Cast instruction
    switch (opcode) {

    case Instruction::Trunc:
    case Instruction::ZExt:
    case Instruction::SExt:
      printvalue(key.operand1);
      if (auto select_inst = dyn_cast<llvm::SelectInst>(key.operand1)) {
        return createSelectFolder(
            select_inst->getCondition(),
            builder->CreateCast(static_cast<Instruction::CastOps>(opcode),
                                select_inst->getTrueValue(), key.destType),
            builder->CreateCast(static_cast<Instruction::CastOps>(opcode),
                                select_inst->getFalseValue(), key.destType),
            "lol-");
      }
      newInstruction =
          builder->CreateCast(static_cast<Instruction::CastOps>(opcode),
                              key.operand1, key.destType);
      break;
    // Add other cast operations as needed
    default:
      UNREACHABLE("Unsupported cast opcode");
    }
  }
  cache.insert(opcode, key, newInstruction);
  return newInstruction;
}

static unsigned getComplexity(const Value* V) {

  if (isa<ConstantInt>(V))
    return isa<UndefValue>(V) ? 0 : 1;

  if (isa<CastInst>(V) || match(V, m_Neg(PatternMatch::m_Value())) ||
      match(V, m_Not(PatternMatch::m_Value())) ||
      match(V, m_FNeg(PatternMatch::m_Value())))
    return 2;

  return 3;
}

static bool isCommutative(const unsigned Opcode) {
  switch (Opcode) {
  case Instruction::Add:
  case Instruction::FAdd:
  case Instruction::Mul:
  case Instruction::FMul:
  case Instruction::And:
  case Instruction::Or:
  case Instruction::Xor:
    return true;
  default:
    return false;
  }
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createInstruction(
    unsigned opcode, Value* operand1, Value* operand2, Type* destType,
    const Twine& Name) {
  if (isCommutative(opcode)) {
    if (getComplexity(operand1) < getComplexity(operand2)) {
      // if operand1 is less complex, move it to RHS
      std::swap(operand2, operand1);
    }
  }

  InstructionKey key;
  if (destType)
    key = InstructionKey(operand1, destType);
  else
    key = InstructionKey(operand1, operand2);

  Value* newValue = getOrCreate(key, opcode, Name);

  recordFoldOrigin(newValue, opcode, operand1, operand2);

  return newValue; //
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createSelectFolder(
    Value* C, Value* True, Value* False, const Twine& Name) {
  assert(True->getType() == False->getType() &&
         "Both values must have same type in select");
  if (auto* CConst = dyn_cast<Constant>(C)) {

    if (CConst->isOneValue()) {
      return True;
    } else if (CConst->isZeroValue()) {
      return False;
    }
  }

  if (True == False)
    return True;

  auto inst = builder->CreateSelect(C, True, False, Name);

  auto RHSKBSELECT_C = analyzeValueKnownBits(C, dyn_cast<Instruction>(inst));

  printvalue2(RHSKBSELECT_C);
  if (!(RHSKBSELECT_C.isUnknown())) {
    auto constant_cond = RHSKBSELECT_C.getConstant();
    if (constant_cond.isOne())
      return True;
    if (constant_cond.isZero())
      return False;
  }

  return inst;
}

KnownBits computeKnownBitsFromOperation(KnownBits& vv1, KnownBits& vv2,
                                        Instruction::BinaryOps opcode) {
  if (vv1.getBitWidth() > vv2.getBitWidth()) {
    vv2 = vv2.zext(vv1.getBitWidth());
  }
  if (vv2.getBitWidth() > vv1.getBitWidth()) {
    vv1 = vv1.zext(vv2.getBitWidth());
  }
  if (opcode >= Instruction::Shl &&
      opcode <= Instruction::LShr) { // AShr might not make it 0, it also could
                                     // make it -1
    auto ugt_result = KnownBits::ugt(
        vv2,
        KnownBits::makeConstant(APInt(vv1.getBitWidth(), vv1.getBitWidth())));
    if (ugt_result.has_value() &&
        ugt_result.value()) { // has value and value == 1
      printvalue2(ugt_result.value());
      return KnownBits::makeConstant(APInt(vv1.getBitWidth(), 0));
    }
  }

  switch (opcode) {
  case Instruction::Add: {
#if LLVM_VERSION_MAJOR > 18
    return KnownBits::computeForAddSub(true, false, false, vv1, vv2);
#else
    return KnownBits::computeForAddSub(true, false, vv1, vv2);
#endif
    break;
  }
  case Instruction::Sub: {
#if LLVM_VERSION_MAJOR > 18
    return KnownBits::computeForAddSub(false, false, false, vv1, vv2);
#else
    return KnownBits::computeForAddSub(false, false, vv1, vv2);
#endif
    break;
  }
  case Instruction::Mul: {
    return KnownBits::mul(vv1, vv2);
    break;
  }
  case Instruction::LShr: {
    return KnownBits::lshr(vv1, vv2);
    break;
  }
  case Instruction::AShr: {
    return KnownBits::ashr(vv1, vv2);
    break;
  }
  case Instruction::Shl: {
    return KnownBits::shl(vv1, vv2);
    break;
  }
  case Instruction::UDiv: {
    if (!vv2.isZero()) {
      return (KnownBits::udiv(vv1, vv2));
    }
    break;
  }
  case Instruction::URem: {
    return KnownBits::urem(vv1, vv2);
    break;
  }
  case Instruction::SDiv: {
    if (!vv2.isZero()) {
      return KnownBits::sdiv(vv1, vv2);
    }
    break;
  }
  case Instruction::SRem: {
    return KnownBits::srem(vv1, vv2);
    break;
  }
  case Instruction::And: {
    return (vv1 & vv2);
    break;
  }
  case Instruction::Or: {
    return (vv1 | vv2);
    break;
  }
  case Instruction::Xor: {
    return (vv1 ^ vv2);
    break;
  }

  default:
    std::cout << "\n : " << opcode;
    UNREACHABLE("Unsupported operation in calculatePossibleValues.\n");
    break;
  }
  /*
  case Instruction::ICmp: {
     KnownBits kb(64);
     kb.setAllOnes();
     kb.setAllZero();
     kb.One ^= 1;
     kb.Zero ^= 1;
     switch (cast<llvm::ICmpInst>(inst)->getPredicate()) {
     case llvm::CmpInst::ICMP_EQ: {
       auto idk = KnownBits::eq(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     case llvm::CmpInst::ICMP_NE: {
       auto idk = KnownBits::eq(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     case llvm::CmpInst::ICMP_SLE: {
       auto idk = KnownBits::sle(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     case llvm::CmpInst::ICMP_SLT: {
       auto idk = KnownBits::slt(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     case llvm::CmpInst::ICMP_ULE: {
       auto idk = KnownBits::ule(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     case llvm::CmpInst::ICMP_ULT: {
       auto idk = KnownBits::ult(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     case llvm::CmpInst::ICMP_SGE: {
       auto idk = KnownBits::sge(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     case llvm::CmpInst::ICMP_SGT: {
       auto idk = KnownBits::sgt(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     case llvm::CmpInst::ICMP_UGE: {
       auto idk = KnownBits::uge(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     case llvm::CmpInst::ICMP_UGT: {
       auto idk = KnownBits::uge(vv1, vv2);
       if (idk.has_value()) {
         return KnownBits::makeConstant(APInt(64, idk.value()));
       }
       return kb;
       break;
     }
     default: {
       outs() << "\n : " << cast<llvm::ICmpInst>(inst)->getPredicate();
       outs().flush();
       llvm_unreachable_internal(
           "Unsupported operation in calculatePossibleValues ICMP.\n");
       break;
     }
     }
     break;
   }
  */
  return KnownBits(0); // never reach
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::folderBinOps(
    Value* LHS, Value* RHS, const Twine& Name, Instruction::BinaryOps opcode) {
  Value* result = folderBinOpsImpl(LHS, RHS, Name, opcode);
  recordFoldOrigin(result, static_cast<unsigned>(opcode), LHS, RHS);
  // Propagate memory provenance through arithmetic so a computed transfer
  // target (VMProtect dispatch: jmp_reg + loaded_bytecode, intel.cc:27845)
  // keeps the identity of the bytecode load that produced it - that load is
  // the VIP. Only values that feed the transfer ever carry it, so mutated
  // junk loads (intel.cc:16039) never contribute.
  {
    LiftPerfDiag::ScopedTimer provenanceTimer(
        &perfDiag, &perfDiag.folderProvenance);
    if (result) {
      auto it = loadProvenance.find(LHS);
      if (it == loadProvenance.end()) {
        it = loadProvenance.find(RHS);
      }
      if (it != loadProvenance.end()) {
        loadProvenance[result] = it->second;
      }
    }
  }
  return result;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::folderBinOpsImpl(
    Value* LHS, Value* RHS, const Twine& Name, Instruction::BinaryOps opcode) {
  auto folderSample = profiler.sample("sem_folder_binops");
  const bool perf = perfDiag.enabled;
  if (perf) {
    ++perfDiag.folderCalls;
  }
  auto earlyExit = [&](Value* v) -> Value* {
    if (perf) {
      ++perfDiag.folderExitEarly;
    }
    return v;
  };
  if (LHS->getType() != RHS->getType()) {
    // A mismatch here means the fold below combines constants of different bit
    // widths and takes the result type from the left operand. printvalue* write
    // to the debug stream, which stays off unless a debug log was requested, so
    // this condition used to pass silently. Report a bounded number instead.
    static int mismatches = 0;
    if (mismatches < 40) {
      ++mismatches;
      std::string ls;
      std::string rs;
      llvm::raw_string_ostream lo(ls);
      llvm::raw_string_ostream ro(rs);
      LHS->print(lo);
      RHS->print(ro);
      std::cout << "[typemismatch] @" << std::hex
                << (current_address - instruction.length) << std::dec
                << " lhs=" << ls.substr(0, 90) << " rhs=" << rs.substr(0, 90)
                << "\n"
                << std::flush;
    }
  }

  if (LHS == RHS) {
    switch (opcode) {
    case Instruction::Xor:
    case Instruction::Sub:
      return earlyExit(
          builder->getIntN(LHS->getType()->getIntegerBitWidth(), 0));
    case Instruction::And:
    case Instruction::Or:
      return earlyExit(LHS);
    default:
      break;
    }
  }

  if (auto* LHSConst = dyn_cast<ConstantInt>(LHS)) {
    if (auto* RHSConst = dyn_cast<ConstantInt>(RHS)) {
      const llvm::APInt& lhsValue = LHSConst->getValue();
      const llvm::APInt& rhsValue = RHSConst->getValue();
      switch (opcode) {
      case Instruction::Add:
        return earlyExit(
            ConstantInt::get(LHSConst->getType(), lhsValue + rhsValue));
      case Instruction::Sub:
        return earlyExit(
            ConstantInt::get(LHSConst->getType(), lhsValue - rhsValue));
      case Instruction::And:
        return earlyExit(
            ConstantInt::get(LHSConst->getType(), lhsValue & rhsValue));
      case Instruction::Or:
        return earlyExit(
            ConstantInt::get(LHSConst->getType(), lhsValue | rhsValue));
      case Instruction::Xor:
        return earlyExit(
            ConstantInt::get(LHSConst->getType(), lhsValue ^ rhsValue));
      default:
        break;
      }
    }
  }

  // ideally we go cheaper to more expensive

  // this part will eliminate unneccesary operations
  switch (opcode) {
    // shifts also should return 0 if shift is bigger than x's bitwidth

  case Instruction::Shl:  // x >> 0 = x , 0 >> x = 0
  case Instruction::LShr: // x << 0 = x , 0 << x = 0
  {

    if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
      if (RHSConst->isZero())
        return earlyExit(LHS);
      if (RHSConst->getZExtValue() >= LHS->getType()->getIntegerBitWidth()) {
        return earlyExit(
            builder->getIntN(LHS->getType()->getIntegerBitWidth(), 0));
      }
    }
    [[fallthrough]];
  }
  case Instruction::AShr: {

    if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
      if (LHSConst->isZero())
        return earlyExit(LHS);
    }
    break;
  }
  case Instruction::Xor: { // x ^ 0 = x ; ~~x = x
    if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
      if (LHSConst->isZero())
        return earlyExit(RHS);
    }
    if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
      if (RHSConst->isZero())
        return earlyExit(LHS);
    }
    Value* X = nullptr;
    if (match(RHS, m_SpecificInt(-1)) && match(LHS, m_Not(m_Value(X))))
      return earlyExit(X);
    if (match(LHS, m_SpecificInt(-1)) && match(RHS, m_Not(m_Value(X))))
      return earlyExit(X);
    break;
  }
  case Instruction::Add: { // x + 0 = x , 0 + x = 0

    if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
      if (LHSConst->isZero())
        return earlyExit(RHS);
    }

    if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
      if (RHSConst->isZero())
        return earlyExit(LHS);
    }

    break;
  }
  case Instruction::Sub: {

    if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
      if (RHSConst->isZero())
        return earlyExit(LHS);
    }
    break;
  }
  case Instruction::Or: {
    if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
      if (LHSConst->isZero())
        return earlyExit(RHS);
      if (LHSConst->isMinusOne())
        return earlyExit(LHS);
    }
    if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
      if (RHSConst->isZero())
        return earlyExit(LHS);
      if (RHSConst->isMinusOne())
        return earlyExit(RHS);
    }
    break;
  }
  case Instruction::And: {
    // ~~X & Y -> X & Y (VMP NAND masks often arrive double-complemented).
    Value* peeled = nullptr;
    if (match(LHS, m_Not(m_Not(m_Value(peeled))))) {
      if (perf) {
        --perfDiag.folderCalls;
      }
      return folderBinOps(peeled, RHS, Name, opcode);
    }
    if (match(RHS, m_Not(m_Not(m_Value(peeled))))) {
      if (perf) {
        --perfDiag.folderCalls;
      }
      return folderBinOps(LHS, peeled, Name, opcode);
    }
    if (ConstantInt* LHSConst = dyn_cast<ConstantInt>(LHS)) {
      if (LHSConst->isZero())
        return earlyExit(builder->getIntN(LHSConst->getBitWidth(), 0));
      if (LHSConst->isMinusOne())
        return earlyExit(RHS);
    }
    if (ConstantInt* RHSConst = dyn_cast<ConstantInt>(RHS)) {
      if (RHSConst->isZero())
        return earlyExit(builder->getIntN(RHSConst->getBitWidth(), 0));
      if (RHSConst->isMinusOne())
        return earlyExit(LHS);
    }
    break;
  }
  default: {
    break;
  }
  }
  // this part analyses if we can simplify the instruction
  Value* inst = nullptr;
  {
    LiftPerfDiag::ScopedTimer patternTimer(&perfDiag, &perfDiag.folderPattern);
    inst = doPatternMatching(opcode, LHS, RHS);
  }
  if (inst) {
    if (perf) {
      ++perfDiag.folderPatternHit;
    }
  } else {
    LiftPerfDiag::ScopedTimer createTimer(&perfDiag, &perfDiag.folderCreate);
    inst = createInstruction(opcode, LHS, RHS, nullptr, Name);
    if (perf) {
      ++perfDiag.folderCreateUsed;
    }
  }

  // knownbits is recursive, and goes back 5 instructions, ideally it would be
  // not recursive and store the info for all values
  // until then, we just calculate it ourselves

  // we can just swap analyzeValueKnownBits with something else later down the
  // road
  {
    LiftPerfDiag::ScopedTimer knownBitsTimer(&perfDiag,
                                             &perfDiag.folderKnownBits);
    auto LHSKB = analyzeValueKnownBits(LHS, dyn_cast<Instruction>(inst));
    auto RHSKB = analyzeValueKnownBits(RHS, dyn_cast<Instruction>(inst));

    auto computedBits = computeKnownBitsFromOperation(LHSKB, RHSKB, opcode);
    if (computedBits.isConstant() && !computedBits.hasConflict()) {
      if (perf) {
        ++perfDiag.folderExitKnownConst;
      }
      return builder->getIntN(LHS->getType()->getIntegerBitWidth(),
                              computedBits.getConstant().getZExtValue());
    }
  }
  if (perf) {
    ++perfDiag.folderExitKeepInst;
  }
  return inst;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createGEPFolder(Type* Type,
                                                            Value* Base,
                                                            Value* Address,
                                                            const Twine& Name) {
  GEPinfo key = {Address, (uint8_t)(Type->getScalarSizeInBits()), 1};
  auto it = GEPcache.lookup(key);
  if (it) {
    return it;
  }

  std::vector<Value*> indices;
  indices.push_back(Address);
  auto v = builder->CreateGEP(Type, Base, indices);
  printvalue(v);
  GEPcache.insert({key, v});
  return v;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createAddFolder(Value* LHS,
                                                            Value* RHS,
                                                            const Twine& Name) {

  return folderBinOps(LHS, RHS, Name, Instruction::Add);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createSubFolder(Value* LHS,
                                                            Value* RHS,
                                                            const Twine& Name) {

  return folderBinOps(LHS, RHS, Name, Instruction::Sub);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createOrFolder(Value* LHS,
                                                           Value* RHS,
                                                           const Twine& Name) {

  return folderBinOps(LHS, RHS, Name, Instruction::Or);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createXorFolder(Value* LHS,
                                                            Value* RHS,
                                                            const Twine& Name) {

  return folderBinOps(LHS, RHS, Name, Instruction::Xor);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createNotFolder(Value* LHS,
                                                            const Twine& Name) {

  return createXorFolder(LHS, Constant::getAllOnesValue(LHS->getType()), Name);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createAndFolder(Value* LHS,
                                                            Value* RHS,
                                                            const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::And);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createMulFolder(Value* LHS,
                                                            Value* RHS,
                                                            const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::Mul);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createSDivFolder(
    Value* LHS, Value* RHS, const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::SDiv);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createUDivFolder(
    Value* LHS, Value* RHS, const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::UDiv);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createSRemFolder(
    Value* LHS, Value* RHS, const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::SRem);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createURemFolder(
    Value* LHS, Value* RHS, const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::URem);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createShlFolder(Value* LHS,
                                                            Value* RHS,
                                                            const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::Shl);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createLShrFolder(
    Value* LHS, Value* RHS, const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::LShr);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createAShrFolder(
    Value* LHS, Value* RHS, const Twine& Name) {
  return folderBinOps(LHS, RHS, Name, Instruction::AShr);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createShlFolder(Value* LHS,
                                                            uint64_t RHS,
                                                            const Twine& Name) {
  return createShlFolder(LHS, ConstantInt::get(LHS->getType(), RHS), Name);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createShlFolder(Value* LHS,
                                                            APInt RHS,
                                                            const Twine& Name) {
  return createShlFolder(LHS, ConstantInt::get(LHS->getType(), RHS), Name);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createLShrFolder(
    Value* LHS, uint64_t RHS, const Twine& Name) {
  return createLShrFolder(LHS, ConstantInt::get(LHS->getType(), RHS), Name);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createLShrFolder(
    Value* LHS, APInt RHS, const Twine& Name) {
  return createLShrFolder(LHS, ConstantInt::get(LHS->getType(), RHS), Name);
}
std::optional<bool> foldKnownBits(CmpInst::Predicate P, const KnownBits& LHS,
                                  KnownBits RHS) {

  switch (P) {
  case CmpInst::ICMP_EQ:
    return KnownBits::eq(LHS, RHS);
  case CmpInst::ICMP_NE:
    return KnownBits::ne(LHS, RHS);
  case CmpInst::ICMP_UGT:
    return KnownBits::ugt(LHS, RHS);
  case CmpInst::ICMP_UGE:
    return KnownBits::uge(LHS, RHS);
  case CmpInst::ICMP_ULT:
    return KnownBits::ult(LHS, RHS);
  case CmpInst::ICMP_ULE:
    return KnownBits::ule(LHS, RHS);
  case CmpInst::ICMP_SGT:
    return KnownBits::sgt(LHS, RHS);
  case CmpInst::ICMP_SGE:
    return KnownBits::sge(LHS, RHS);
  case CmpInst::ICMP_SLT:
    return KnownBits::slt(LHS, RHS);
  case CmpInst::ICMP_SLE:
    return KnownBits::sle(LHS, RHS);
  default:
    return std::nullopt;
  }

  return std::nullopt;
}

Value* ICMPPatternMatcher(IRBuilder<>* builder,
                          CmpInst::Predicate P, Value* LHS, Value* RHS,
                          const Twine& Name) {
  if (auto SI = dyn_cast<SelectInst>(LHS)) {
    if (P == CmpInst::ICMP_EQ && RHS == SI->getTrueValue())
      return SI->getCondition();
  }
  // c = add a, b
  // cmp x, c, 0
  // =>
  // cmp x, a, -b

  // lhs is a bin op

  return nullptr;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createICMPFolder(
    CmpInst::Predicate P, Value* LHS, Value* RHS, const Twine& Name) {
  auto folderSample = profiler.sample("sem_folder_icmp");
  Value* patternCheck = nullptr;
  {
    LiftPerfDiag::ScopedTimer patternTimer(&perfDiag, &perfDiag.icmpPattern);
    patternCheck = ICMPPatternMatcher(builder.get(), P, LHS, RHS, Name);
  }
  if (patternCheck) {
    printvalue(patternCheck);
    return patternCheck;
  }

  auto result = builder->CreateICmp(P, LHS, RHS, Name);

  if (auto ctxI = dyn_cast<Instruction>(result)) {
    LiftPerfDiag::ScopedTimer knownBitsTimer(&perfDiag,
                                             &perfDiag.icmpKnownBits);
    KnownBits KnownLHS = analyzeValueKnownBits(LHS, ctxI);
    KnownBits KnownRHS = analyzeValueKnownBits(RHS, ctxI);

    if (std::optional<bool> v = foldKnownBits(P, KnownLHS, KnownRHS)) {
      return ConstantInt::get(Type::getInt1Ty(builder->getContext()),
                              v.value());
    }
    printvalue2(KnownLHS) printvalue2(KnownRHS);
  }

  return result;
}

// - probably not needed anymore

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createTruncFolder(
    Value* V, Type* DestTy, const Twine& Name) {

  if (V->getType()->getIntegerBitWidth() <= DestTy->getIntegerBitWidth())
    return V;

  Value* result =
      createInstruction(Instruction::Trunc, V, nullptr, DestTy, Name);

  if (auto ctxI = dyn_cast<Instruction>(result)) {
    LiftPerfDiag::ScopedTimer knownBitsTimer(&perfDiag,
                                             &perfDiag.truncKnownBits);
    KnownBits KnownTruncResult = analyzeValueKnownBits(result, ctxI);
    printvalue2(KnownTruncResult);
    if (!KnownTruncResult.hasConflict() && KnownTruncResult.getBitWidth() > 1 &&
        KnownTruncResult.isConstant())
      return ConstantInt::get(DestTy, KnownTruncResult.getConstant());
  }
  // TODO: CREATE A MAP FOR AVAILABLE TRUNCs/ZEXTs/SEXTs
  // WHY?
  // IF %y = trunc %x exists
  // we dont want to create %y2 = trunc %x
  // just use %y
  // so xor %y, %y2 => %y, %y => 0

  return result;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createZExtFolder(
    Value* V, Type* DestTy, const Twine& Name) {
  auto result = createInstruction(Instruction::ZExt, V, nullptr, DestTy, Name);
#ifdef TESTFOLDER8
  if (auto ctxI = dyn_cast<Instruction>(result)) {
    KnownBits KnownRHS = analyzeValueKnownBits(result, ctxI);
    if (!KnownRHS.hasConflict() && KnownRHS.getBitWidth() > 1 &&
        KnownRHS.isConstant())
      return ConstantInt::get(DestTy, KnownRHS.getConstant());
  }
#endif
  return result;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createZExtOrTruncFolder(
    Value* V, Type* DestTy, const Twine& Name) {
  auto folderSample = profiler.sample("sem_folder_zext_or_trunc");
  Type* VTy = V->getType();
  if (VTy->getScalarSizeInBits() < DestTy->getScalarSizeInBits())
    return createZExtFolder(V, DestTy, Name);
  if (VTy->getScalarSizeInBits() > DestTy->getScalarSizeInBits())
    return createTruncFolder(V, DestTy, Name);
  return V;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createSExtFolder(
    Value* V, Type* DestTy, const Twine& Name) {
  auto result = createInstruction(Instruction::SExt, V, nullptr, DestTy, Name);

#ifdef TESTFOLDER8
  if (auto ctxI = dyn_cast<Instruction>(result)) {
    KnownBits KnownRHS = analyzeValueKnownBits(result, ctxI);
    if (!KnownRHS.hasConflict() && KnownRHS.getBitWidth() > 1 &&
        KnownRHS.isConstant())
      return ConstantInt::get(DestTy, KnownRHS.getConstant());
  }
#endif
  return result;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::createSExtOrTruncFolder(
    Value* V, Type* DestTy, const Twine& Name) {
  auto folderSample = profiler.sample("sem_folder_sext_or_trunc");
  Type* VTy = V->getType();
  if (VTy->getScalarSizeInBits() < DestTy->getScalarSizeInBits())
    return createSExtFolder(V, DestTy, Name);
  if (VTy->getScalarSizeInBits() > DestTy->getScalarSizeInBits())
    return createTruncFolder(V, DestTy, Name);
  return V;
}


MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::setFlag(const Flag flag,
                                                  Value* newValue) {
  auto flagSample = profiler.sample("sem_flags");
  LiftPerfDiag::ScopedTimer flagTimer(&perfDiag, &perfDiag.flagSet);
  if (perfDiag.enabled) {
    ++perfDiag.flagSetCalls;
  }
  return setFlagValue(flag, newValue);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::setFlag(
    const Flag flag, std::function<Value*()> calculation) {
  auto flagSample = profiler.sample("sem_flags");
  LiftPerfDiag::ScopedTimer flagTimer(&perfDiag, &perfDiag.flagSet);
  if (perfDiag.enabled) {
    ++perfDiag.flagSetCalls;
    ++perfDiag.flagSetLazyCalls;
  }
  return setFlagValue(flag, calculation());
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(LazyValue)::getLazyFlag(const Flag flag) {
  //
  return LazyValue(getFlagValue(flag));
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::getFlag(const Flag flag) {
  auto flagSample = profiler.sample("sem_flags");
  LiftPerfDiag::ScopedTimer flagTimer(&perfDiag, &perfDiag.flagGet);
  if (perfDiag.enabled) {
    ++perfDiag.flagGetCalls;
  }
  return getFlagValue(flag);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::GetValueFromHighByteRegister(
    const Register reg) {

  Value* fullRegisterValue = GetRegisterValue_internal(getBiggestEncoding(reg));

  Value* shiftedValue = createLShrFolder(fullRegisterValue, 8, "highreg");

  Value* FF = ConstantInt::get(shiftedValue->getType(), 0xff);
  Value* highByteValue = createAndFolder(shiftedValue, FF, "highByte");

  return createTruncFolder(highByteValue, builder->getIntNTy(8));
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::privilegeAllowsIF() {
  LLVMContext& context = builder->getContext();
  Value* iopl = createOrFolder(
      createZExtFolder(getFlag(FLAG_IOPL), Type::getInt64Ty(context)),
      createShlFolder(
          createZExtFolder(getFlag(FLAG_IOPL2), Type::getInt64Ty(context)),
          ConstantInt::get(Type::getInt64Ty(context), 1)));
  return createICMPFolder(
      llvm::CmpInst::ICMP_ULE,
      ConstantInt::get(Type::getInt64Ty(context), 3), iopl);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::SetRFLAGSValue(Value* value) {
  LLVMContext& context = builder->getContext();
  Value* allowIF = privilegeAllowsIF();
  for (int flag = FLAG_CF; flag < FLAGS_END; flag++) {
    int shiftAmount = flag;
    Value* shiftedFlagValue = createLShrFolder(
        value, ConstantInt::get(value->getType(), shiftAmount), "setflag");
    auto flagValue = createTruncFolder(shiftedFlagValue,
                                       Type::getInt1Ty(context), "flagtrunc");
    if (flag == FLAG_RESERVED1) {
      setFlag(FLAG_RESERVED1,
              ConstantInt::getSigned(Type::getInt1Ty(context), 1));
      continue;
    }
    if (flag == FLAG_RESERVED3 || flag == FLAG_RESERVED5 || flag == FLAG_IOPL ||
        flag == FLAG_IOPL2 || flag == FLAG_VM || flag == FLAG_VIP ||
        flag == FLAG_VIF) {
      continue;
    }
    if (flag == FLAG_IF) {
      setFlag(FLAG_IF, createSelectFolder(allowIF, flagValue, getFlag(FLAG_IF)));
      continue;
    }
    setFlag((Flag)flag, flagValue);
  }
  return;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::GetRFLAGSByte(unsigned byteIndex) {
  LLVMContext& context = builder->getContext();
  auto* i8Ty = Type::getInt8Ty(context);
  Value* packed = ConstantInt::get(i8Ty, 0);
  if (byteIndex >= 8) {
    return packed;
  }
  const int lo = static_cast<int>(byteIndex) * 8;
  const int hi = lo + 8;
  for (int flag = FLAG_CF; flag < FLAGS_END; flag++) {
    if (flag < lo || flag >= hi) {
      continue;
    }
    printvalue2(magic_enum::enum_name((Flag)flag));
    Value* flagValue = getFlag((Flag)flag);
    printvalue(flagValue);
    Value* shiftedFlagValue = createShlFolder(
        createZExtFolder(flagValue, i8Ty, "createrflag1-"),
        ConstantInt::get(i8Ty, flag - lo), "createrflag2-");
    packed = createOrFolder(packed, shiftedFlagValue, "creatingrflagbyte");
  }
  return packed;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::GetRFLAGSValue() {
  LLVMContext& context = builder->getContext();
  Value* rflags = ConstantInt::get(Type::getInt64Ty(context), 0);
  for (int flag = FLAG_CF; flag < FLAGS_END; flag++) {
    printvalue2(magic_enum::enum_name((Flag)flag));
    Value* flagValue = getFlag((Flag)flag);
    printvalue(flagValue);
    int shiftAmount = flag;
    Value* shiftedFlagValue = createShlFolder(

        createZExtFolder(flagValue, Type::getInt64Ty(context), "createrflag1-"),
        ConstantInt::get(Type::getInt64Ty(context), shiftAmount),
        "createrflag2-");
    rflags = createOrFolder(rflags, shiftedFlagValue, "creatingrflag");
  }
  return rflags;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::dumpRflagsDiag(const char* tag,
                                                         uint64_t rva,
                                                         llvm::Value* rflagsIr,
                                                         uint64_t extraAddr) {
  const char** names = flagBitNames();
  std::cout << "[" << tag << "] rva=0x" << std::hex << rva;
  if (extraAddr) {
    std::cout << " addr=0x" << extraAddr;
  }
  auto emitReg = [&](const char* name, Register reg) {
    std::cout << " " << name << "=";
    llvm::Value* v = GetRegisterValue(reg);
    if (auto* ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(v)) {
      std::cout << "0x" << ci->getZExtValue();
    } else {
      std::cout << "-";
    }
  };
  emitReg("r9", Register::R9);
  emitReg("rsp", Register::RSP);
  std::cout << " bits=[";
  bool first = true;
  std::cout << std::dec;
  for (int f = FLAG_CF; f < FLAGS_END; ++f) {
    llvm::Value* fv = getFlag((Flag)f);
    if (!first) {
      std::cout << " ";
    }
    first = false;
    std::cout << names[f] << "=";
    if (auto* ci = llvm::dyn_cast<llvm::ConstantInt>(fv)) {
      std::cout << ci->getZExtValue();
    } else {
      std::cout << irText(fv);
    }
  }
  std::cout << "] symbolic=[";
  bool firstSym = true;
  for (int f = FLAG_CF; f < FLAGS_END; ++f) {
    llvm::Value* fv = getFlag((Flag)f);
    if (llvm::isa<llvm::ConstantInt>(fv)) {
      continue;
    }
    if (!firstSym) {
      std::cout << ",";
    }
    firstSym = false;
    std::cout << names[f] << "=" << irText(fv);
  }
  std::cout << "]";
  if (rflagsIr) {
    std::cout << " rflags_ir=" << irText(rflagsIr, 160);
  }
  std::cout << std::endl;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::GetRegisterValue(
    const Register key) {
  auto registerSample = profiler.sample("sem_registers");
  LiftPerfDiag::ScopedTimer regTimer(&perfDiag, &perfDiag.regGet);
  if (perfDiag.enabled) {
    ++perfDiag.regGetCalls;
  }
  // printvalue2(magic_enum::enum_name(key));

  if (key == Register::RIP || key == Register::EIP) {
    return ConstantInt::getSigned(file.getMode() == X64
                                      ? Type::getInt64Ty(builder->getContext())
                                      : Type::getInt32Ty(builder->getContext()),
                                  current_address);
  }

  if (key == Register::AH || key == Register::CH || key == Register::DH ||
      key == Register::BH) {
    if (perfDiag.enabled) {
      ++perfDiag.regGetHighByte;
    }
    return GetValueFromHighByteRegister(key);
  }

  if (key == Register::RFLAGS || key == Register::EFLAGS) {
    if (perfDiag.enabled) {
      ++perfDiag.regGetRflags;
    }
    return GetRFLAGSValue();
  }

  if (key == Register::GS) {
    typename funcsignatures<Register>::functioninfo funcInfo("loadGS", {});
    return callFunctionIR("loadGS", &funcInfo);
  }
  if (key == Register::DS) {
    typename funcsignatures<Register>::functioninfo funcInfo("loadDS", {});
    return callFunctionIR("loadDS", &funcInfo);
  }
  /*
  if (Registers.find(newKey) == Registers.end()) {
          UNREACHABLE("register not found"); exit(-1);
  }
  */

  Register largestKey = getBiggestEncoding(key);
  // it is safe to zext&truncate here, because if size doesnt match, we DO need
  // to make it fit, we start caring about signedness once we are in the
  // semantics

  printvalue2(magic_enum::enum_name(largestKey));
  auto reg = GetRegisterValue_internal(largestKey);
  if (!reg) {
    std::cout << "[nullreg] key=" << magic_enum::enum_name(key)
              << " largestKey=" << magic_enum::enum_name(largestKey)
              << " at=0x" << std::hex << (current_address - instruction.length)
              << std::dec << "\n"
              << std::flush;
  }
  printvalue(reg);
  return createZExtOrTruncFolder(reg, builder->getIntNTy(getRegisterSize(key)));
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::SetValueToHighByteRegister(
    const Register reg, Value* value) {
  LLVMContext& context = builder->getContext();
  int shiftValue = 8;

  Register fullRegKey = getBiggestEncoding(reg);
  Value* fullRegisterValue = GetRegisterValue_internal(fullRegKey);

  Value* eightBitValue = createAndFolder(
      value, ConstantInt::get(value->getType(), 0xFF), "eight-bit");
  Value* shiftedValue = createShlFolder(
      eightBitValue, ConstantInt::get(value->getType(), shiftValue), "shl");

  Value* mask =
      ConstantInt::get(Type::getInt64Ty(context), ~(0xFF << shiftValue));
  Value* clearedRegister =
      createAndFolder(fullRegisterValue, mask, "clear-reg");

  shiftedValue = createZExtFolder(shiftedValue, fullRegisterValue->getType());

  Value* newRegisterValue =
      createOrFolder(clearedRegister, shiftedValue, "high_byte");

  return newRegisterValue;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::SetValueToSubRegister_8b(
    const Register reg, Value* value) {
  LLVMContext& context = builder->getContext();
  Register fullRegKey = getBiggestEncoding(reg);
  Value* fullRegisterValue = GetRegisterValue_internal(fullRegKey);
  fullRegisterValue =
      createZExtOrTruncFolder(fullRegisterValue, Type::getInt64Ty(context));

  Value* extendedValue =
      createZExtFolder(value, Type::getInt64Ty(context), "extendedValue");

  bool isHighByteReg = (reg == Register::AH || reg == Register::CH ||
                        reg == Register::DH || reg == Register::BH);

  uint64_t mask = isHighByteReg ? 0xFFFFFFFFFFFF00FFULL : 0xFFFFFFFFFFFFFF00ULL;

  Value* maskValue = ConstantInt::get(Type::getInt64Ty(context), mask);
  Value* maskedFullReg =
      createAndFolder(fullRegisterValue, maskValue, "maskedreg");

  if (isHighByteReg) {
    extendedValue = createShlFolder(extendedValue, 8, "shiftedValue");
  }

  Value* updatedReg = createOrFolder(maskedFullReg, extendedValue, "newreg");

  // Sub-register writes of R8 are how the VM's byte-rotate chain (rol r8b, 1)
  // lands in the register. If the merge produces a constant, R8 has collapsed
  // from a 64-bit runtime value to a small integer; report a bounded number of
  // the R8 cases with both sides so the collapse is visible.
  if (fullRegKey == Register::R8) {
    static int sub8bR8 = 0;
    if (sub8bR8 < 30) {
      ++sub8bR8;
      auto txt = [&](llvm::Value* v) {
        std::string s;
        llvm::raw_string_ostream os(s);
        if (v) {
          v->print(os);
        } else {
          os << "<null>";
        }
        return os.str().substr(0, 70);
      };
      std::cout << "[sub8b] @" << std::hex
                << (current_address - instruction.length) << std::dec
                << " val=" << txt(value) << " old=" << txt(fullRegisterValue)
                << " new=" << txt(updatedReg) << "\n"
                << std::flush;
    }
  }

  SetRegisterValue_internal(fullRegKey, updatedReg);

  return updatedReg;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::SetValueToSubRegister_16b(
    const Register reg, Value* value) {

  Register fullRegKey = getBiggestEncoding(reg);
  Value* fullRegisterValue = GetRegisterValue_internal(fullRegKey);
  printvalue(fullRegisterValue);
  Value* last4cleared =
      ConstantInt::get(fullRegisterValue->getType(), 0xFFFFFFFFFFFF0000);
  Value* maskedFullReg =
      createAndFolder(fullRegisterValue, last4cleared, "maskedreg");
  value = createZExtFolder(value, fullRegisterValue->getType());

  Value* updatedReg = createOrFolder(maskedFullReg, value, "newreg");
  printvalue(updatedReg);
  return updatedReg;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::SetRegisterValue(const Register key,
                                                           Value* value) {
  auto registerSample = profiler.sample("sem_registers");
  LiftPerfDiag::ScopedTimer regTimer(&perfDiag, &perfDiag.regSet);
  if (perfDiag.enabled) {
    ++perfDiag.regSetCalls;
  }
  if (key == Register::EIP || key == Register::RIP)
    return;

  if ((key >= Register::AL) && (key <= Register::R15B)) {
    if (perfDiag.enabled) {
      ++perfDiag.regSetSub8;
    }
    value = SetValueToSubRegister_8b(key, value);
  }

  if (((key >= Register::AX) && (key <= Register::R15W))) {
    if (perfDiag.enabled) {
      ++perfDiag.regSetSub16;
    }
    printvalue2("subreg_16");
    value = SetValueToSubRegister_16b(key, value);
  }

  if ((key >= Register::EAX) && (key <= Register::R15D)) {
    if (perfDiag.enabled) {
      ++perfDiag.regSetZext32;
    }
    value = createZExtFolder(value, Type::getInt64Ty(this->context),
                             "zeroextend-32bit-write");
  }

  if (key == Register::RFLAGS) {
    if (perfDiag.enabled) {
      ++perfDiag.regSetRflags;
    }
    SetRFLAGSValue(value);
    return;
  }
  printvalue2(magic_enum::enum_name(key));
  printvalue(value);
  Register newKey = getBiggestEncoding(key);
  SetRegisterValue_internal(newKey, value);
  // Any write invalidates a stale import-provenance binding on this
  // register; a later `call reg` must not emit a named external call
  // unless a fresh `mov reg, [rip+iat]` re-tagged it.
  registerImportSource.erase(newKey);

}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::GetEffectiveAddress() {
  auto memorySample = profiler.sample("sem_memory_effective_address");
  LLVMContext& context = builder->getContext();

  Value* effectiveAddress = nullptr;

  Value* baseValue = nullptr;

  if (instruction.mem_base != Register::None) {
    baseValue = GetRegisterValue(instruction.mem_base);
    baseValue = createZExtFolder(baseValue, Type::getInt64Ty(context));
    printvalue(baseValue);
  }
  Value* indexValue = nullptr;

  if (instruction.mem_index != Register::None) {
    indexValue = GetRegisterValue(instruction.mem_index);

    indexValue = createZExtFolder(indexValue, Type::getInt64Ty(context));
    printvalue(indexValue);
    Value* scaleValue =
        ConstantInt::get(Type::getInt64Ty(context), instruction.mem_scale);
    indexValue = createMulFolder(indexValue, scaleValue, "mul_ea");
  }

  if (baseValue && indexValue) {
    effectiveAddress =
        createAddFolder(baseValue, indexValue, "bvalue_indexvalue_set");
  } else if (baseValue) {
    effectiveAddress = baseValue;
  } else if (indexValue) {
    effectiveAddress = indexValue;
  } else {
    effectiveAddress = ConstantInt::get(Type::getInt64Ty(context), 0);
  }

  printvalue2(instruction.mem_disp);
  if (instruction.mem_disp) {

    Value* dispValue =
        ConstantInt::get(Type::getInt64Ty(context), instruction.mem_disp);

    effectiveAddress = createAddFolder(effectiveAddress, dispValue, "disp_set");
  }
  printvalue(effectiveAddress);

  // gs:/fs: addressing is TEB-relative. Model the TEB at tebBase instead of
  // resolving the offset against the flat address space (the disassembler now
  // surfaces the segment override; see modelProcessEnvironment).
  if (instruction.mem_segment == Register::GS ||
      instruction.mem_segment == Register::FS) {
    effectiveAddress = createAddFolder(
        effectiveAddress,
        ConstantInt::get(Type::getInt64Ty(context), tebBase), "seg-base");
  }
  return effectiveAddress;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::getPointer(Value* address) {

  LLVMContext& context = builder->getContext();
  std::vector<Value*> indices;
  indices.push_back(address);

  auto memoryOperand = memoryAlloc;
  //
  // if (segment == Register::GS)
  //     memoryOperand = TEB;

  // A small constant address reaching here means the effective address collapsed
  // to a bare offset (the base register value is gone), so the access reads from
  // address 0xN instead of the intended VM slot. Report the first few with the
  // source instruction's memory-operand shape, which attributes the collapse to a
  // specific addressing path.
  if (auto* addressConst = llvm::dyn_cast<llvm::ConstantInt>(address)) {
    const uint64_t addr = addressConst->getZExtValue();
    if (addr >= 0x40 && addr <= 0x80) {
      static int smallAddrHits = 0;
      if (smallAddrHits < 20) {
        ++smallAddrHits;
        std::cout << "[smalladdr] @" << std::hex
                  << (current_address - instruction.length) << " addr=0x" << addr
                  << " mem_base=" << magic_enum::enum_name(instruction.mem_base)
                  << " mem_index=" << magic_enum::enum_name(instruction.mem_index)
                  << " mem_disp=0x" << instruction.mem_disp << std::dec
                  << " scale=" << (unsigned)instruction.mem_scale << " ops=";
        for (uint8_t k = 0; k < instruction.operand_count_visible; ++k) {
          std::cout << " [" << (unsigned)k << "]"
                    << magic_enum::enum_name(instruction.types[k]) << "/"
                    << magic_enum::enum_name(instruction.regs[k]);
        }
        std::cout << "\n" << std::flush;
      }
    }
  }

  Value* pointer =
      builder->CreateGEP(Type::getInt8Ty(context), memoryOperand, indices);
  return pointer;
}

// takes address, not pointers

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::GetMemoryValue(Value* address,
                                                           uint8_t size) {
  auto memorySample = profiler.sample("sem_memory_load");

  // convert to pointer first
  auto pointer = getPointer(address);
  LazyValue retval([this, pointer, size]() {
    auto ret = builder->CreateLoad(builder->getIntNTy(size),
                                   pointer /*, "Loadxd-" + address + "-"*/);
    printvalue(ret);
    return ret;
  });

  loadMemoryOp(pointer);

  // Determine the load address first: the bytecode range decides whether this
  // read may keep its LoadInst (see below).
  uint64_t loadAddress = 0;
  if (auto* addressConst = llvm::dyn_cast<llvm::ConstantInt>(address)) {
    loadAddress = addressConst->getZExtValue();
  } else if (auto* gep = llvm::dyn_cast<llvm::GetElementPtrInst>(pointer)) {
    if (auto* offset = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1))) {
      loadAddress = offset->getZExtValue();
    }
  }
  if (loadAddress == 0 &&
      vmp.isFetch(getBiggestEncoding(instruction.mem_base),
                  isSimpleRegMemOp()) &&
      currentPathSolveContext != PathSolveContext::Ret) {
    bool wroteRegister = false;
    const uint64_t cursor = vmp.resolveFetch(
        GetRegisterValue(vmp.pcodeRegister()),
        [&](uint64_t slot, llvm::Value* org) -> uint64_t {
          LazyValue nested(org);
          if (auto resolved = tryResolvePcodeCursorPop(slot, nested)) {
            return *resolved;
          }
          return 0;
        },
        wroteRegister);
    if (wroteRegister) {
      SetRegisterValue(vmp.pcodeRegister(), builder->getInt64(cursor));
    }
    if (cursor != 0) {
      loadAddress = cursor;
      address = builder->getInt64(loadAddress);
      pointer = getPointer(address);
      retval.setCalculation([this, pointer, size]() {
        auto ret = builder->CreateLoad(builder->getIntNTy(size), pointer);
        printvalue(ret);
        return ret;
      });
      loadMemoryOp(pointer);
    }
  }

  Value* result = nullptr;

  // Bytecode-read stream. The VM decrypts each handler's next target from a
  // read inside the protector's bytecode section, so the first read whose
  // address differs from the machine's is the first point where the VM's
  // virtual instruction pointer has drifted. Recorded as
  //   R,<reader insn VA>,<read address>,<width>
  // and aligned against vmpdrtrace's -trackmem stream by reader RVA.
  if (const char* path = std::getenv("MERGEN_READ_STREAM_FILE")) {
    if (current_address >= 0x140000000ULL && current_address < 0x150000000ULL) {
      FILE* f = std::fopen(path, "a");
      if (f) {
        std::fprintf(f, "R,0x%llx,0x%llx,%u\n",
                     (unsigned long long)(current_address - instruction.length),
                     (unsigned long long)loadAddress, (unsigned)size);
        std::fclose(f);
      }
    }
  }
  // FINAL: the single byte that becomes 0x58. Both sides read the same byte
  // (file byte 0xE2 at rva 0x12CD57) with the same key, yet the lifter ends up
  // with 0x58. Print what this one read actually produced, its provenance, and
  // the registers of the decrypt expression, so the arithmetic can be compared
  // against the machine's 0x3e957e chain:
  //   r8d = [r11] ^ r10d ^ 0x3AFD456B ; r8d += 0x05DA2F20 ; movsxd
  if (std::getenv("MERGEN_DIAG_BYTE") &&
      (current_address - instruction.length) == 0x14033578EULL) {
    auto txt = [&](llvm::Value* v) {
      std::string s;
      llvm::raw_string_ostream os(s);
      if (v) {
        v->print(os);
      } else {
        os << "<null>";
      }
      return os.str().substr(0, 130);
    };
    std::cout << "[byte] @0x14033578E addr=0x" << std::hex << loadAddress
              << std::dec << " size_bits=" << (unsigned)size
              << " mnem=" << magic_enum::enum_name(instruction.mnemonic) << "\n"
              << "[byte]   raw=" << txt(result)
              << "\n[byte]   R10=" << txt(GetRegisterValue(Register::R10))
              << "\n[byte]   R11=" << txt(GetRegisterValue(Register::R11))
              << "\n[byte]   R8=" << txt(GetRegisterValue(Register::R8))
              << "\n" << std::flush;
  }
  if (Value* solvedLoad = solveLoad(retval, pointer, size)) {
    result = solvedLoad;
  } else {
    result = retval.get();
  }
  vmp.noteStackQword(result, size, loadAddress);
  {
    const uint64_t insnVA = current_address - instruction.length;
    if (insnVA == 0x1403D50FEULL || loadAddress == 0x1400EF850ULL) {
      static int gmvHits = 0;
      if (gmvHits < 20) {
        ++gmvHits;
        auto* ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(result);
        std::string s;
        llvm::raw_string_ostream os(s);
        if (result) {
          result->print(os);
        } else {
          os << "<null>";
        }
        std::cout << "[ef850-gmv] insn=0x" << std::hex << insnVA << " addr=0x"
                  << loadAddress << std::dec << " bits=" << (unsigned)size
                  << " isCI=" << (ci ? 1 : 0) << " ci=0x" << std::hex
                  << (ci ? ci->getZExtValue() : 0) << std::dec << " ir="
                  << os.str().substr(0, 120) << "\n"
                  << std::flush;
      }
    }
  }
  // Which flag bit was still symbolic when a flag-bearing op rewrote RFLAGS into
  // VM data. work.md 7.12.6: `pushfq` at rva 0x396b77 wrote to an unaligned
  // (r9+6) slot, so the later qword load at rva 0x410840 could not fold to the
  // machine's 0x202 even though both sides entered `pushfq` with rdx=0x282.
  // Naming the symbolic bit turns "FLAGS is symbolic" into an actionable site.
  if (std::getenv("MERGEN_DIAG_RFLAGS")) {
    const uint64_t insnRVA = maskedRVA(current_address - instruction.length);
    const bool flagBearing =
        (loadAddress == 0x14FE66ULL || loadAddress == 0x14FE68ULL ||
         loadAddress == 0x14FE60ULL || loadAddress == 0x14FE62ULL) ||
        insnRVA == 0x396B77ULL || insnRVA == 0x396B80ULL ||
        insnRVA == 0x410840ULL || insnRVA == 0x2F528EULL ||
        insnRVA == 0x2F5299ULL || insnRVA == 0x2F9E73ULL;
    if (flagBearing) {
      dumpRflagsDiag("rflags", insnRVA, nullptr, loadAddress);
    }
  }
  // VIP candidates are bytecode-range reads only. VMProtect's dispatch does the
  // next-pcode read last in every handler (AddEndHandlerCommands, intel.cc:27842),
  // so the last bytecode load since the previous transfer is the current VIP.
  // Other module reads (VM tables/context) would otherwise masquerade as the VIP
  // and fabricate loop backedges. (Themida article, "Constant Promotion & Memory
  // Modeling" - configurable range policy.)
  if (loadAddress != 0 && isModuleAddress(loadAddress) &&
      currentPathSolveContext != PathSolveContext::Ret) {
    loadProvenance[result] = loadAddress;
    // Verbose (=2): every module load. Default (=1): only non-bytecode loads
    // that can clobber a live bytecode cursor (the Ultra failure mode).
    const char* vipDiag = std::getenv("MERGEN_DIAG_VIP");
    if (vipDiag && vipDiag[0] != '\0' && vipDiag[0] != '0') {
      const bool verbose = vipDiag[0] == '2';
      const bool loadBc = isBytecodeAddress(loadAddress);
      const uint64_t cur = vmp.vipOffset();
      if (verbose || (!loadBc && isBytecodeAddress(cur))) {
        const Register memBase = getBiggestEncoding(instruction.mem_base);
        const bool simple = isSimpleRegMemOp();
        std::cout << "[vipload] insn=0x" << std::hex
                  << (current_address - instruction.length) << " addr=0x"
                  << loadAddress << std::dec << " bc=" << (loadBc ? 1 : 0)
                  << " fetch=" << (vmp.isFetch(memBase, simple) ? 1 : 0)
                  << " bound=" << (vmp.bound() ? 1 : 0) << " cursor=0x"
                  << std::hex << cur << std::dec << "\n"
                  << std::flush;
      }
    }
    noteModuleLoad(loadAddress);
    vmp.onBytecodeLoad(getBiggestEncoding(instruction.mem_base),
                       isSimpleRegMemOp(), loadAddress);
  }

  return result;
}

// takes address, not pointers

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::SetMemoryValue(llvm::Value* address,
                                                         llvm::Value* value) {
  if (liftProgressDiagEnabled && std::getenv("MERGEN_DIAG_SSA58") &&
      (current_address - instruction.length) == 0x1403E9AF2ULL) {
    // Walk the *real* SSA use-def chain of the stored value. Every earlier
    // attempt read foldOrigin, a bookkeeping table whose operands never matched
    // the disassembly. This walks actual operands and names the defining
    // instruction, hard capped (depth 8, 200 nodes) so it cannot blow up the log.
    if (auto* ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(value)) {
      if (ci->getBitWidth() == 64 && ci->getZExtValue() == 0x58) {
        auto txt = [&](llvm::Value* v) {
          std::string s;
          llvm::raw_string_ostream os(s);
          if (v) {
            v->print(os);
          } else {
            os << "<null>";
          }
          return os.str().substr(0, 110);
        };
        std::cout << "[ssa58] store of 0x58; R8=" << txt(GetRegisterValue(Register::R8))
                  << " R10=" << txt(GetRegisterValue(Register::R10))
                  << "\n[ssa58] use-def chain of the stored value:\n";
        std::set<llvm::Value*> seen;
        std::vector<std::pair<llvm::Value*, int>> work{{value, 0}};
        int printed = 0;
        while (!work.empty() && printed < 200) {
          auto entry = work.back();
          work.pop_back();
          llvm::Value* v = entry.first;
          const int d = entry.second;
          if (!v || !seen.insert(v).second) continue;
          auto* inst = llvm::dyn_cast<llvm::Instruction>(v);
          if (!inst) {
            std::cout << "[ssa58]   " << std::string(d * 2, ' ')
                      << "NON-INSTR " << txt(v) << "\n";
            ++printed;
            continue;
          }
          std::cout << "[ssa58]   " << std::string(d * 2, ' ') << txt(inst);
          if (auto* li = llvm::dyn_cast<llvm::LoadInst>(inst)) {
            std::cout << "   [LOAD ptr=" << txt(li->getPointerOperand()) << "]";
          }
          std::cout << "\n";
          ++printed;
          if (d >= 8) continue;
          for (auto& op : inst->operands()) {
            work.push_back({op.get(), d + 1});
          }
        }
        std::cout << "[ssa58] end (printed " << printed << ")\n" << std::flush;
      }
    }
  }
  if (liftProgressDiagEnabled && std::getenv("MERGEN_DIAG_ST9AF2") &&
      (current_address - instruction.length) == 0x1403E9AF2ULL) {
    static bool reported = false;
    if (!reported) {
      reported = true;
      auto txt = [&](llvm::Value* v) {
        std::string s;
        llvm::raw_string_ostream os(s);
        if (v) {
          v->print(os);
        } else {
          os << "<null>";
        }
        return os.str().substr(0, 160);
      };
      std::cout << "[stb] store=0x58 R8=" << txt(GetRegisterValue(Register::R8))
                << " R10=" << txt(GetRegisterValue(Register::R10))
                << "\n" << std::flush;
    }
  }
  auto memorySample = profiler.sample("sem_memory_store");

  auto pointer = getPointer(address);

  auto store = builder->CreateStore(value, pointer);

  insertMemoryOp(cast<StoreInst>(store));
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::GetIndexValue(uint8_t index) {

  auto type = instruction.types[index];
  printvalue2(index);
  printvalue2(magic_enum::enum_name(type));

  switch (type) {
  case OperandType::Register8:
  case OperandType::Register16:
  case OperandType::Register32:
  case OperandType::Register64:
  case OperandType::Register128: {
    auto reg = instruction.regs[index];
    printvalue2(magic_enum::enum_name(reg));
    return createZExtOrTruncFolder(GetRegisterValue(reg),
                                   builder->getIntNTy(GetTypeSize(type)));
  }

  case OperandType::Immediate8:
  case OperandType::Immediate16:
  case OperandType::Immediate32:
  case OperandType::Immediate64: {
    int size = 0;

    switch (type) {
    case OperandType::Immediate8:
      size = 8;
      break;
    case OperandType::Immediate16:
      size = 16;
      break;
    case OperandType::Immediate32:
      size = 32;
      break;
    case OperandType::Immediate64:
      size = 64;
      break;
    default:
      UNREACHABLE("??");
    }

    return builder->getIntN(size, instruction.immediate);
  }

  case OperandType::Immediate8_2nd: {
    return builder->getIntN(8, instruction.immediate2);
  }

  case OperandType::Memory8:
  case OperandType::Memory16:
  case OperandType::Memory32:
  case OperandType::Memory64:
  case OperandType::Memory128: {
    int size = 0;

    switch (type) {

    case OperandType::Memory8:
      size = 8;
      break;
    case OperandType::Memory16:
      size = 16;
      break;
    case OperandType::Memory32:
      size = 32;
      break;
    case OperandType::Memory64:
      size = 64;
      break;
    case OperandType::Memory128:
      size = 128;
      break;

    default:
      UNREACHABLE("??");
    }
    auto addr = GetEffectiveAddress();
    auto ret = GetMemoryValue(addr, size);
    printvalue(ret);
    return ret;
  }
  default: {
    printvalueforce2(magic_enum::enum_name(type));
    printvalueforce2((uint32_t)index);
    printvalueforce2(current_address);
    UNREACHABLE("idk");
  }
  }
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::SetIndexValue(uint8_t index,
                                                        Value* value) {

  auto type = instruction.types[index];

  switch (type) {
  case OperandType::Register8:
  case OperandType::Register16:
  case OperandType::Register32:
  case OperandType::Register64:
  case OperandType::Register128: {
    auto reg = instruction.regs[index];

    // TODO: do we need to remove this sext from here?
    // value =
    //    createSExtOrTruncFolder(value,
    //    builder->getIntNTy(getRegisterSize(reg)));

    SetRegisterValue(reg, value);
    return;
  }

  case OperandType::Immediate8:
  case OperandType::Immediate16:
  case OperandType::Immediate32:
  case OperandType::Immediate64: {
    UNREACHABLE("Cant set imm operands");
  }

  case OperandType::Memory8:
  case OperandType::Memory16:
  case OperandType::Memory32:
  case OperandType::Memory64:
  case OperandType::Memory128: {
    int size = 0;

    switch (type) {

    case OperandType::Memory8:
      size = 8;
      break;
    case OperandType::Memory16:
      size = 16;
      break;
    case OperandType::Memory32:
      size = 32;
      break;
    case OperandType::Memory64:
      size = 64;
      break;
    case OperandType::Memory128:
      size = 128;
      break;

    default:
      UNREACHABLE("??");
    }

    // TODO: do we need to remove this sext from here?
    value = createSExtOrTruncFolder(value, builder->getIntNTy(size));
    auto addr = GetEffectiveAddress();
    SetMemoryValue(addr, value);

    return;
  }
  default: {
    UNREACHABLE("idk");
  }
  }
}


MERGEN_LIFTER_DEFINITION_TEMPLATES(std::vector<Value*>)::GetRFLAGS() {
  std::vector<Value*> rflags;
  for (int flag = FLAG_CF; flag < FLAGS_END; flag++) {
    rflags.push_back(getFlag((Flag)flag));
  }
  return rflags;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::pushFlags(
    const std::vector<Value*>& value, const std::string& address) {
  LLVMContext& context = builder->getContext();

  auto rsp = GetRegisterValue(Register::RSP);

  for (size_t i = 0; i < value.size(); i += 8) {
    Value* byteVal = ConstantInt::get(Type::getInt8Ty(context), 0);
    for (size_t j = 0; j < 8 && (i + j) < value.size(); ++j) {
      Value* flag = value[i + j];
      Value* extendedFlag =
          createZExtFolder(flag, Type::getInt8Ty(context), "pushflag1");
      Value* shiftedFlag = createShlFolder(extendedFlag, j, "pushflag2");
      byteVal = createOrFolder(byteVal, shiftedFlag, "pushflagbyteval");
    }

    Value* pointer = createGEPFolder(Type::getInt8Ty(context), memoryAlloc, rsp,
                                     "GEPSTORE-" + address + "-");

    auto store = builder->CreateStore(byteVal, pointer, "storebyte");

    insertMemoryOp(cast<StoreInst>(store));
    rsp = createAddFolder(rsp, ConstantInt::get(rsp->getType(), 1));
  }
}

// return [rsp], rsp+=8

MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::popStack(int size) {
  LLVMContext& context = builder->getContext();
  auto rsp = GetRegisterValue(Register::RSP);
  // should we get a address calculator function, do we need that?

  Value* pointer = createGEPFolder(Type::getInt8Ty(context), memoryAlloc, rsp,
                                   "GEPLoadPOPStack--");

  auto loadType = Type::getInt64Ty(context);
  LazyValue returnValue([this, loadType, pointer]() {
    auto ret = builder->CreateLoad(loadType, pointer /*, "PopStack-"*/);
    printvalue(ret);
    return ret;
  });

  auto CI = ConstantInt::get(rsp->getType(), size);
  SetRegisterValue_internal(Register::RSP, createAddFolder(rsp, CI));

  Value* solvedLoad =
      solveLoad(returnValue, pointer, loadType->getIntegerBitWidth());
  if (solvedLoad) {
    return solvedLoad;
  }

  return returnValue.get();
}