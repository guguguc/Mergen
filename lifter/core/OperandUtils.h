#pragma once

#include <llvm/Analysis/InstSimplifyFolder.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Value.h>

// Small shared helpers for reasoning about instruction order.

// Whether `a` is guaranteed to execute before `b`.
//
// This is a *dominance* question, not a textual one. Two instructions in the
// same block have a definite order; two in different blocks only have an order
// if one block dominates the other. Incomparable blocks (siblings under a
// diamond, or on separate paths) mean the answer is "no" -- and the lifter
// must then treat the pair as unordered rather than assuming either order.
//
// The function returns false rather than throwing for the incomparable case,
// because "no ordering" is a normal answer here, not an error.
inline bool comesBefore(llvm::Instruction* a, llvm::Instruction* b,
                        llvm::DominatorTree& DT) {

  bool sameBlock =
      a->getParent() == b->getParent(); // if same block, use ->comesBefore,

  if (sameBlock) {
    return a->comesBefore(b); // if a comes before b, return true
  }
  // if "a"'s block dominates "b"'s block, "a" comes first.
  //
  // properlyDominates rather than dominates: a block does not dominate itself,
  // and asking about a block reaching itself is a degenerate query that should
  // answer "no" rather than trip the "reflexive domination" assertion
  // properlyDominates exists to catch.
  bool dominate = DT.properlyDominates(a->getParent(), b->getParent());
  return dominate;
}
