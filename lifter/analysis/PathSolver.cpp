
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
//
// This is the cheap, last-resort tier of the path solver: it handles the case
// where the target is genuinely provable from LLVM's own view of the IR, and
// declines everything else. It does not attempt the lifter's own analyses --
// those live in solvePath (PathSolver.ipp), which calls into here. Keeping
// the tiers separate is what lets this one stay a small, obviously-correct
// fallback: a wrong answer here is a wrong jump, so it answers only when LLVM
// itself proves the value.
//
// Single target only. Multi-target resolution (a switch fan-out) is a
// PATH_multi_solved outcome produced by the caller, never by this function.
//
// Every perf increment is gated on `perf != nullptr && perf->enabled` rather
// than on enabled alone, so a caller with no diagnostic sink pays nothing. The
// four outcome counters are what make the profile actionable: a rising
// `simplify` share means answers are coming from LLVM's general simplifier
// rather than direct folding, which usually means the lifter is emitting IR
// it could have folded itself.
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

  // Not an instruction and not a constant: there is nothing to fold or
  // simplify. A global, an argument, or a poison value would land here, and
  // none of those can be proven to a single address.
  auto* inst = dyn_cast<Instruction>(constraint);
  if (!inst) {
    if (perf != nullptr && perf->enabled) {
      ++perf->gcvUnsolved;
    }
    return PATH_unsolved;
  }

  const DataLayout& DL = function->getParent()->getDataLayout();

  // Try constant folding first (cheaper, handles pure-constant operand cases).
  // Constant folding first, simplification second. The order is by cost, not by
  // power: ConstantFoldInstruction is a local, operand-only rewrite and handles
  // the common case where both operands are already constant. Simplification
  // is strictly more expensive and strictly more powerful, so it only runs for
  // what folding could not answer.
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
