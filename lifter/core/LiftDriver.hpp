#pragma once

// Stage 6 of the pipeline: the lift loop.
//
// The loop is worklist-driven rather than address-order-driven. Blocks are
// created and queued as control flow is discovered, so the set of blocks to
// lift grows while the loop runs; getUnvisitedAddr hands back the next
// queued block and the loop keeps going until the queue drains.
//
// Per-block state has to be re-established on every iteration because the
// lifter's builder, backup, and restore-mode are all mutable cursors that the
// previous block left pointing somewhere else. That setup is the first thing
// in the body, before anything is emitted.

#include "LifterClass_Concolic.hpp"
#include "MergenPB.hpp"
#include <iostream>
#include <sstream>

inline void runLiftWorklist(lifterConcolic<>* lifter) {
  BBInfo bbinfo;
  // `filter` gates whether a block that already has instructions may be
  // lifted again. It starts false so the *first* block handed back is always
  // taken regardless of its state -- that block is the entry, and the entry is
  // the one block whose emptiness cannot be assumed. From the second
  // iteration on, a non-empty block is skipped, because re-lifting it would
  // append duplicate instructions to a block someone else already populated.
  bool filter = false;

  while (lifter->getUnvisitedAddr(bbinfo, filter)) {
    if (!(bbinfo.block->empty()) && filter) {
      printvalue2("not empty");
      continue;
    }

    filter = true;
    // Restore the register/flag state this block was created with.
    //
    // Two restore paths because loop-carried memory state is tracked two
    // ways. The generalized one handles variable-width backedge state; the
    // ordinary one handles the fixed control/target slots. A block that was
    // created inside a loop carrying generalized state must not get the
    // narrow restore, or the phi it expects never materialises.
    if (lifter->currentBlockUsesGeneralizedLoopState()) {
      lifter->load_generalized_backup(bbinfo.block);
    } else {
      lifter->load_backup(bbinfo.block);
    }
    lifter->currentBlockRestoreMode =
        lifterConcolic<>::BlockRestoreMode::Normal;
    lifter->finished = 0;

    // Speculative call bail-out: the callee exceeded the inline budget.
    // This BB is the return continuation with pre-call state restored.
    // Emit CreateCall + ABI effects, then continue lifting normally.
    //
    // The lifter tries to inline a call target before committing to it. If the
    // callee turns out to be too large, the attempt is abandoned and this
    // block -- the continuation, already created and queued during the aborted
    // attempt -- is lifted normally with the call replaced by an opaque
    // call node. The work already done is not wasted: the continuation block,
    // the queue entries, and the restored pre-call state are all still valid.
    //
    // Matching on the return address rather than a flag alone is what makes
    // this safe: a bailedOut flag could be stale by the time some unrelated
    // block is lifted, and acting on it would emit a phantom call.
    if (lifter->speculativeCall.bailedOut &&
        bbinfo.block_address == lifter->speculativeCall.returnAddr) {
      lifter->speculativeCall.bailedOut = false;

      lifter->builder->SetInsertPoint(bbinfo.block);

      // Emit an opaque call representing the outlined callee.
      auto& context = lifter->builder->getContext();
      auto fx = lifter->buildUnknownCallFx();
      fx.target = CallTargetClass::UnknownDirect;

      // The call target is unknown (we bailed out of inlining it).
      // Use a poison-ish constant so the IR shows what happened.
      //
      // 0xBA11ED is not a valid address; it is a deliberate marker. A real
      // call target here would be a lie -- we do not know it -- so the IR
      // carries an obviously-fake pointer that a reader (or a grep in a
      // regression diff) can spot rather than mistaking for a resolved
      // target.
      auto* callTarget = llvm::ConstantInt::get(
          llvm::Type::getInt64Ty(context), 0xBA11ED);  // "bailed"
      auto* callPtr = lifter->builder->CreateIntToPtr(
          callTarget, llvm::PointerType::get(context, 0));

      auto* callResult = lifter->builder->CreateCall(
          lifter->parseArgsType(nullptr, context), callPtr,
          lifter->parseArgs(nullptr));

      lifter->applyPostCallEffects(callResult, fx);

      abi::printCallEffectsDiag(fx, bbinfo.block_address);
      std::cout << "[call-abi] outlined via speculative bail-out\n"
                << std::flush;

      // Now continue lifting from the return address normally.
    } else {
      lifter->builder->SetInsertPoint(bbinfo.block);
    }

    auto nextBlockName = bbinfo.block->getName();
    printvalue2(nextBlockName);

    lifter->liftBasicBlockFromAddress(bbinfo.block_address);
  }

  // Lifting summary remains in structured diagnostics; keep stdout quiet unless debugging.
  //
  // Two channels on purpose. The human-readable line is debug-gated so it does
  // not pollute stdout for scripted runs; the DiagCode::LiftComplete entry is
  // unconditional so the counts always reach output_diagnostics.json, which is
  // what the regression gate reads to notice that a sample suddenly lifts
  // fewer blocks or more unsupported instructions.
  debugging::doIfDebug([&]() {
    std::cout << "Lift summary: "
              << lifter->liftStats.blocks_attempted << " blocks attempted, "
              << lifter->liftStats.blocks_completed << " completed, "
              << lifter->liftStats.blocks_unreachable << " unreachable, "
              << lifter->liftStats.instructions_lifted << " instructions, "
              << lifter->liftStats.instructions_unsupported << " unsupported"
              << std::endl;
  });
  {
    std::ostringstream ss;
    ss << lifter->liftStats.blocks_attempted << " blocks ("
       << lifter->liftStats.blocks_completed << " completed, "
       << lifter->liftStats.blocks_unreachable << " unreachable), "
       << lifter->liftStats.instructions_lifted << " instructions ("
       << lifter->liftStats.instructions_unsupported << " unsupported)";
    lifter->diagnostics.info(DiagCode::LiftComplete, 0, ss.str());
  }
  lifter->dumpLiftProgressReport(std::cout);
}
