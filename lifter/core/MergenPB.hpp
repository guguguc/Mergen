#pragma once

// The optimisation pipeline: what gets run, in what order, and why the order
// is load-bearing.
//
// ARCHITECTURE.md documents the shape. What is easy to get wrong is that the
// custom passes are *not* interchangeable and reordering them is silent
// breakage, not a compile error. The two orders that matter:
//
//   GEPLoadPass before PromotePseudoMemory
//       GEPLoadPass folds constant loads out of the PE image. If
//       PromotePseudoMemory runs first it converts every remaining
//       memory-base GEP into an inttoptr, and GEPLoadPass then has nothing
//       it recognises. The folded constants are simply gone -- no error, just
//       worse IR.
//
//   PromotePseudoStackPass before PromotePseudoMemory
//       The stack is a distinguished sub-range of pseudo-memory. Once the
//       general pass has inttoptr'd stack accesses, the window test
//       PromotePseudoStackPass relies on can no longer find them, and the
//       stack stops being promoted to a real alloca.
//
// Both failures are silent. Treat this order as fixed unless you have a
// golden-IR diff showing the alternative is better.

#include "CustomPasses.hpp"
#include "LifterClass.hpp"
#include "Utils.h"
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Analysis/ConstantFolding.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Transforms/IPO/DeadArgumentElimination.h>

using namespace llvm;

// Fold every module-backed load to a constant, then constant-fold whatever
// arithmetic consumed those loads.
//
// This runs outside the lift loop, which is why it collects loads into a
// vector first: erasing an instruction while iterating its basic block
// invalidates the iterator. Same reason the fold loop uses `it++` in the
// increment so the iterator already points past the current instruction
// before eraseFromParent runs.
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::concretizeBytecodeLoads() {
  llvm::SmallVector<llvm::LoadInst*, 32> loads;
  for (llvm::BasicBlock& BB : *this->fnc) {
    for (llvm::Instruction& I : BB) {
      if (auto* li = llvm::dyn_cast<llvm::LoadInst>(&I)) {
        loads.push_back(li);
      }
    }
  }
  for (llvm::LoadInst* li : loads) {
    auto* gep =
        llvm::dyn_cast<llvm::GetElementPtrInst>(li->getPointerOperand());
    if (!gep || gep->getPointerOperand() != this->memoryAlloc) {
      continue;
    }
    if (!li->getType()->isIntegerTy()) {
      continue;
    }
    unsigned bits = li->getType()->getIntegerBitWidth();
    if (bits % 8) {
      continue;
    }
    auto* off = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1));
    if (!off) {
      continue;
    }
    // retrieveCombinedValue reads the image / concolic buffer and emits no IR,
    // so it is safe to run outside the lift loop. Every module-backed load is
    // folded (bytecode and VM tables alike): leaving a table read symbolic keeps
    // the dispatcher state symbolic, which is what stalled the lift at 15 blocks.
    LazyValue nestedLoad([li]() -> llvm::Value* { return li; });
    if (auto* c = this->retrieveCombinedValue(off->getZExtValue(), bits / 8,
                                              nestedLoad)) {
      if (llvm::isa<llvm::Constant>(c) && static_cast<llvm::Value*>(c) !=
                                             static_cast<llvm::Value*>(li)) {
        li->replaceAllUsesWith(c);
        li->eraseFromParent();
      }
    }
  }
  // Fold arithmetic that consumed the loads above, to a fixpoint.
  //
  // One ConstantFoldInstruction sweep is not enough: folding a load can expose
  // a new foldable binary operator whose other operand was already constant,
  // which in turn can expose another. The loop keeps going while it is still
  // changing anything.
  //
  // Terminators are skipped because ConstantFoldInstruction on a branch would
  // either do nothing useful or fold the condition into a constant without
  // collapsing the branch itself, leaving dead blocks behind.
  //
  // TLI is passed because ConstantFoldInstruction needs target information to
  // fold width-correctly; without it the folding is wrong for types whose
  // layout depends on the target.
  //
  // Constant-fold to a fixpoint, so the VM state stays concrete for the next block.
  const llvm::DataLayout& DL = this->M->getDataLayout();
  bool changed = true;
  while (changed) {
    changed = false;
    for (llvm::BasicBlock& BB : *this->fnc) {
      for (auto it = BB.begin(); it != BB.end();) {
        llvm::Instruction* I = &*it++;
        if (I->isTerminator()) {
          continue;
        }
        if (auto* c = llvm::ConstantFoldInstruction(I, DL, this->TLI)) {
          if (static_cast<llvm::Value*>(c) !=
              static_cast<llvm::Value*>(I)) {
            I->replaceAllUsesWith(c);
            I->eraseFromParent();
            changed = true;
          }
        }
      }
    }
  }
}

// Run GEPLoadPass alone, mid-lift.
  //
  // This is the one optimisation that is safe to run while the lift loop is
  // still going. See the note in promoteModuleLoads about why InstCombine is
  // absent: blocks that have been created and queued but not yet lifted are
  // empty and have no terminator, and stock LLVM passes reject them.
  //
  // Run here rather than inside the lift loop so a whole batch of concretised
  // loads can be folded at once instead of one instruction at a time.
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::promoteModuleLoads() {
  if (!this->memoryAlloc) {
    return;
  }
  llvm::PassBuilder passBuilder;
  llvm::LoopAnalysisManager loopAnalysisManager;
  llvm::FunctionAnalysisManager functionAnalysisManager;
  llvm::CGSCCAnalysisManager cGSCCAnalysisManager;
  llvm::ModuleAnalysisManager moduleAnalysisManager;
  passBuilder.registerModuleAnalyses(moduleAnalysisManager);
  passBuilder.registerCGSCCAnalyses(cGSCCAnalysisManager);
  passBuilder.registerFunctionAnalyses(functionAnalysisManager);
  passBuilder.registerLoopAnalyses(loopAnalysisManager);
  passBuilder.crossRegisterProxies(loopAnalysisManager, functionAnalysisManager,
                                   cGSCCAnalysisManager, moduleAnalysisManager);

  llvm::Module* module = this->fnc->getParent();
  llvm::ModulePassManager modulePassManager;
  modulePassManager.addPass(
      GEPLoadPass(this->memoryAlloc, this->fileBase, memoryPolicy,
                  this->stackReserve));
  // No InstCombine here: the function still contains blocks that were created
  // and queued but not yet lifted (empty, no terminator), which stock passes
  // reject. GEPLoadPass is the Mergen pass that tolerates mid-lift IR.
  modulePassManager.run(*module, moduleAnalysisManager);
}

// The full optimisation pipeline, run once at the end of the lift.
//
// Three phases, in this order:
//
//   1. Fixpoint loop at O1 plus the four custom promotion passes. Iterated
//      until the module's instruction count stops changing, because each pass
//      can expose work for an earlier one -- promoting the stack can make a
//      previously-blocked GEPLoadPass fold succeed, and the fold can expose
//      another promotion.
//
//   2. A single O2 run. Not part of the fixpoint: O2 is expensive and its
//      output depends on the input being settled, so running it inside a loop
//      would multiply cost without improving convergence.
//
//   3. Post-O2 cleanup: structural normalisation, then reroll, then dead-arg
//      elimination and canonical naming.
//
// The analysis managers are deliberately rebuilt before phase 2 -- see the
// comment there.
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::run_opts() {
  llvm::PassBuilder passBuilder;

  llvm::LoopAnalysisManager loopAnalysisManager;
  llvm::FunctionAnalysisManager functionAnalysisManager;
  llvm::CGSCCAnalysisManager cGSCCAnalysisManager;
  llvm::ModuleAnalysisManager moduleAnalysisManager;

  passBuilder.registerModuleAnalyses(moduleAnalysisManager);
  passBuilder.registerCGSCCAnalyses(cGSCCAnalysisManager);
  passBuilder.registerFunctionAnalyses(functionAnalysisManager);
  passBuilder.registerLoopAnalyses(loopAnalysisManager);
  passBuilder.crossRegisterProxies(loopAnalysisManager, functionAnalysisManager,
                                   cGSCCAnalysisManager, moduleAnalysisManager);

  llvm::ModulePassManager modulePassManager =
      passBuilder.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O0);

  llvm::Module* module = this->fnc->getParent();
  /*
  modulePassManager.addPass(BasicBlockDotGraphPass());

  modulePassManager.run(*module, moduleAnalysisManager);
  */
  // Fixpoint on instruction count, not on a pass manager's own "changed" flag.
  //
  // getInstructionCount is a cheap, global, monotone-ish measure that does not
  // require trusting any individual pass to report correctly. Using it means
  // the loop terminates as soon as the module is genuinely stable rather than
  // when some pass decided it had nothing left to do -- which is the safer
  // failure mode, since a pass that under-reports would otherwise cut the loop
  // short and leave promotions unfinished.
  //
  // Note `changed` is assigned, not OR-ed: it is recomputed from the counts
  // each iteration, so there is no accumulation across iterations to reason
  // about.
  bool changed = 0;
  //   const char* a = "-jump-threading-across-loop-headers=1";
  //   llvm::cl::ParseCommandLineOptions(1, &a);

  do {
    changed = false;

    const size_t beforeSize = module->getInstructionCount();

    modulePassManager =
        passBuilder.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O1);

    // Fatal rather than returning: the pipeline cannot do anything useful
    // without memoryAlloc, and silently skipping the promotion passes would
    // produce output.ll full of pseudo-memory GEPs that look plausible and
    // are wrong. Failing loudly at pipeline setup is far cheaper to diagnose
    // than a regression in the emitted IR.
    llvm::Value* memoryArg = this->memoryAlloc;
    if (!memoryArg) {
      llvm::report_fatal_error(
          "run_opts: memoryAlloc is null; lifter setup did not initialize it");
    }

    // ORDER IS LOAD-BEARING. See the file header.
    modulePassManager.addPass(
        GEPLoadPass(memoryArg, this->fileBase, memoryPolicy, this->stackReserve));
    modulePassManager.addPass(ReplaceTruncWithLoadPass());
    modulePassManager.addPass(PromotePseudoStackPass(memoryArg, this->stackReserve));
    modulePassManager.addPass(PromotePseudoMemory(memoryArg));

    modulePassManager.run(*module, moduleAnalysisManager);

    const size_t afterSize = module->getInstructionCount();

    changed = beforeSize != afterSize;
  } while (changed);

  // Rebuild analysis state before the final O2 pipeline. The fixpoint loop above
  // mutates the module repeatedly with custom passes; fresh managers keep the
  // final optimization run aligned with standalone `opt -O2` on output_no_opts.ll.
  llvm::LoopAnalysisManager finalLoopAnalysisManager;
  llvm::FunctionAnalysisManager finalFunctionAnalysisManager;
  llvm::CGSCCAnalysisManager finalCGSCCAnalysisManager;
  llvm::ModuleAnalysisManager finalModuleAnalysisManager;

  passBuilder.registerModuleAnalyses(finalModuleAnalysisManager);
  passBuilder.registerCGSCCAnalyses(finalCGSCCAnalysisManager);
  passBuilder.registerFunctionAnalyses(finalFunctionAnalysisManager);
  passBuilder.registerLoopAnalyses(finalLoopAnalysisManager);
  passBuilder.crossRegisterProxies(finalLoopAnalysisManager,
                                   finalFunctionAnalysisManager,
                                   finalCGSCCAnalysisManager,
                                   finalModuleAnalysisManager);

  modulePassManager =
      passBuilder.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O2);

  modulePassManager.run(*module, finalModuleAnalysisManager);

  // Post-optimization passes: normalize IR, drop dead parameters, canonicalize names.
  //
  // Order matters here too, and the pairs are not arbitrary:
  //
  //   SelectChainToSwitch then SwitchNormalization
  //       The first turns a linear chain of selects into a switch; the second
  //       makes that switch canonical. Running them apart leaves chains that
  //       InstCombine would otherwise have merged.
  //
  //   InstCombine, StraightLineReroll, InstCombine
  //       Reroll has to run on cleaned-up arithmetic -- it keys on structural
  //       fingerprints, and leftover select chains change the fingerprint. The
  //       trailing InstCombine cleans up the phi the emitted loop introduces.
  //
  //   CanonicalNaming last
  //       So the names reflect the final IR. Running it earlier means the
  //       golden hashes key off names that later passes renamed anyway.
  llvm::ModulePassManager postPassManager;
  postPassManager.addPass(StripTrailingScratchStoresPass());
  postPassManager.addPass(SelectChainToSwitchPass());
  postPassManager.addPass(SwitchNormalizationPass());
  postPassManager.addPass(SignedCompareFromFlagsPass());
  postPassManager.addPass(
      llvm::createModuleToFunctionPassAdaptor(llvm::InstCombinePass()));
  // After O2 + cleanup InstCombine: fold repeated straight-line iterative
  // reductions (identical pure seed→out rounds) back into a counted loop.
  postPassManager.addPass(StraightLineRerollPass());
  postPassManager.addPass(
      llvm::createModuleToFunctionPassAdaptor(llvm::InstCombinePass()));
  postPassManager.addPass(llvm::DeadArgumentEliminationPass());
  postPassManager.addPass(CanonicalNamingPass());
  postPassManager.run(*module, finalModuleAnalysisManager);
}
