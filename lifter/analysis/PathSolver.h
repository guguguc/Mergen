#pragma once

// Public surface of the path solver: the two entry points the lift loop uses
// to turn an address-valued expression into a concrete jump destination.
//
// Implementations live in PathSolver.ipp. The split is deliberate -- this
// header stays free of the LLVM analysis includes that the .ipp pulls in, so
// the ~40 call sites across the semantics files do not each drag in the
// solver's dependency graph.
//
// Both functions return PATH_info rather than a bool because "I resolved this
// to exactly one target" and "I resolved this to several targets" are
// meaningfully different outcomes for the caller: the first can be inlined,
// the second has to be lowered into a switch. Collapsing them to bool is what
// previously forced multi-target resolution to degrade into a linear scan
// against just the first successor.

#include "MemoryPolicy.hpp"
#include <llvm/IR/Function.h>
#include <llvm/IR/Value.h>

struct LiftPerfDiag;

enum PATH_info {
  PATH_unsolved = 0,
  PATH_solved = 1,
  // >2 targets resolved via SwitchInst. More than two because a two-way
  // diamond is still unambiguously resolvable at the call site without a
  // switch; only genuine n-way fan-out needs the switch lowering.
  PATH_multi_solved = 2,
};

// Resolve `constraint`, an address-valued SSA value, to a single target
// address written to `dest`.
//
// `perf` is optional so the many callers that do not want per-query timing do
// not have to construct a diagnostic sink; passing nullptr disables the
// accounting entirely rather than paying for it and discarding the result.
PATH_info getConstraintVal(llvm::Function* function, llvm::Value* constraint,
                           uint64_t& dest, LiftPerfDiag* perf = nullptr);


// Main entry point used by the control-flow semantics. Wraps getConstraintVal
// with the target simplification the lift loop expects, including the
// disambiguation between a constant target and a switch fan-out.
//
// `simplifyValue` is the raw pre-simplification value; solving against the
// simplified form would discard exactly the alias information that lets the
// solver see through a GEP or a load chain.
PATH_info solvePath(llvm::Function* function, uint64_t& dest,
                    llvm::Value* simplifyValue);