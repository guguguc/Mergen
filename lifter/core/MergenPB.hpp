#pragma once

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

// not pathsolver, & probably put this in lifter class, & we would utilize
// templates since geploadpass
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
  // Constant-fold the arithmetic that consumed those loads, to a fixpoint, so
  // the VM state stays concrete for the next block.
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
  bool changed = 0;
  //   const char* a = "-jump-threading-across-loop-headers=1";
  //   llvm::cl::ParseCommandLineOptions(1, &a);

  do {
    changed = false;

    const size_t beforeSize = module->getInstructionCount();

    modulePassManager =
        passBuilder.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O1);

    llvm::Value* memoryArg = this->memoryAlloc;
    if (!memoryArg) {
      llvm::report_fatal_error(
          "run_opts: memoryAlloc is null; lifter setup did not initialize it");
    }

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
