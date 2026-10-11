#pragma once

// Stage 4-6 of the pipeline: everything between "the lifter object exists" and
// "optimized IR has been written".
//
// ARCHITECTURE.md lists seven steps; only three of them are visible here. The
// rest happen inside the callees and this function is deliberately kept as a
// flat, readable summary of the ordering rather than a decomposition:
//
//   stage 4  prepareRuntimePagedMemory   mark pageMap intervals
//   stage 5  runSignatureStage          signature/offset analysis
//   stage 6  runLiftWorklist            the lift loop proper
//   stage 7  run_opts                   (inside emitLiftOutputs)
//
// Stages 1-3 (createRuntimeImageContext, createConfiguredLifterForRuntime,
// configureDefaultMemoryPolicy) have already completed by the time the
// lifter pointer and RuntimeImageContext are handed in.
//
// Ordering is load-bearing in two places, both noted at their call sites
// below. The short version: paged memory must exist before anything reads it,
// and the pre-optimization IR must be written before the optimizer runs,
// because optimization mutates the module in place and the original is then
// unrecoverable.

#include "LiftDriver.hpp"
#include "LifterPipelineStages.hpp"
#include "Utils.h"
#include <iostream>
#include <vector>

inline void runLifterPipeline(lifterConcolic<>* lifter,
                              const RuntimeImageContext& runtimeContext,
                              const uint8_t* fileBase,
                              std::vector<uint8_t>& fileData) {
  // Stage 4. Must precede the lift loop: every memory access the loop lowers
  // consults pageMap to decide concrete-vs-symbolic, and an unmarked region
  // silently degrades to symbolic instead of reading real PE bytes. Printing
  // the context first is diagnostic only -- if the bounds below look wrong in
  // a debug run, this line is where you confirm the input was interpreted
  // correctly before blaming the page map.
  lifter->profiler.begin("pe_setup");
  printRuntimeImageContext(runtimeContext, fileBase);
  prepareRuntimePagedMemory(lifter, runtimeContext);
  lifter->profiler.end();

  // Stage 5. Signature search walks the raw file bytes, so it needs fileData
  // rather than the paged view -- it is looking for byte patterns in the
  // on-disk image, not for values the emulated process would read.
  lifter->profiler.begin("signature_search");
  runSignatureStage(lifter, fileData);
  lifter->profiler.end();

  auto ms = captureElapsedMilliseconds();
  reportSignatureStageTiming(ms);

  // Stage 6. The lift loop. Profiled separately from the stages above because
  // it dominates wall time on VM-protected inputs and is the only stage whose
  // cost scales with the size of the protected region rather than the file.
  lifter->profiler.begin("lift");
  runLiftWorklist(lifter);
  lifter->profiler.end();

  ms = captureElapsedMilliseconds();
  reportLiftCompletionTiming(ms);

  // Stage 7 plus output emission. Also writes output_no_opts.ll, which is why
  // this call is not simply "run the optimizer and write output.ll".
  emitLiftOutputs(lifter, ms);
}
