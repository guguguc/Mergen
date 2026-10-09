
#include "PathSolver.h"
#include "LiftPerfDiag.hpp"
#include "CustomPasses.hpp"
#include "Utils.h"
#include <llvm/ADT/DenseMap.h>
#include <llvm/Analysis/InstructionSimplify.h>
#include <llvm/Analysis/ConstantFolding.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Casting.h>

using namespace llvm;

// Try to resolve a symbolic branch target to a concrete address by:
// 1. Attempting LLVM ConstantFoldInstruction on the value
// 2. Attempting LLVM simplifyInstruction on the value
// Returns PATH_solved with dest set if the value folds to a constant,
// PATH_unsolved otherwise. This is intentionally conservative — it only
// succeeds when LLVM can prove the value is a single constant.
PATH_info getConstraintVal(llvm::Function* function, Value* constraint,
                           uint64_t& dest, LiftPerfDiag* perf) {
  printvalue(constraint);

  if (perf != nullptr && perf->enabled) {
    ++perf->gcvCalls;
  }

  // Already a constant — should have been caught by caller, but handle anyway.
  if (auto* CI = dyn_cast<ConstantInt>(constraint)) {
    dest = CI->getZExtValue();
    if (perf != nullptr && perf->enabled) {
      ++perf->gcvSolvedConst;
    }
    return PATH_solved;
  }

  auto* inst = dyn_cast<Instruction>(constraint);
  if (!inst) {
    if (perf != nullptr && perf->enabled) {
      ++perf->gcvUnsolved;
    }
    return PATH_unsolved;
  }

  const DataLayout& DL = function->getParent()->getDataLayout();

  // Try constant folding first (cheaper, handles pure-constant operand cases).
  if (auto* folded = ConstantFoldInstruction(inst, DL)) {
    if (auto* CI = dyn_cast<ConstantInt>(folded)) {
      dest = CI->getZExtValue();
      printvalue(CI);
      if (perf != nullptr && perf->enabled) {
        ++perf->gcvSolvedFold;
      }
      return PATH_solved;
    }
  }

  // Try instruction simplification (handles identities, known-bits, etc).
  SimplifyQuery SQ(DL, inst);
  if (auto* simplified = simplifyInstruction(inst, SQ)) {
    if (auto* CI = dyn_cast<ConstantInt>(simplified)) {
      dest = CI->getZExtValue();
      printvalue(CI);
      if (perf != nullptr && perf->enabled) {
        ++perf->gcvSolvedSimplify;
      }
      return PATH_solved;
    }
  }

  if (perf != nullptr && perf->enabled) {
    ++perf->gcvUnsolved;
  }
  return PATH_unsolved;
}
