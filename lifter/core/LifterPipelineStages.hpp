#pragma once

// Individual pipeline steps, split out of LifterPipeline.hpp so the ordering
// reads as a list of named stages instead of one long function body.
//
// These are all `inline` and header-only because every one of them is called
// exactly once per run. Making them out-of-line would buy nothing and would
// force the includes of this header onto every translation unit that wants
// only one of them.

#include "RuntimeImageContext.hpp"
#include "LifterClass_Concolic.hpp"
#include "Utils.h"
#include <llvm/Support/raw_ostream.h>
#include <cstdint>
#include <iostream>
#include <vector>

inline void printRuntimeImageContext(const RuntimeImageContext& runtimeContext,
                                     const uint8_t* fileBase) {
  // Debug-only, and it prints even when the run subsequently fails. This is
  // the first thing worth looking at when a lift produces nothing: it shows
  // how the entry address was decoded into image base / RVA / file offset, so
  // a wrong startAddr is visible here rather than surfacing much later as an
  // empty worklist.
  debugging::doIfDebug([&]() {
    std::cout << std::hex << "0x" << static_cast<int>(runtimeContext.firstOpcodeByte)
              << std::endl;

    std::cout << "address: " << runtimeContext.imageBase
              << " imageSize: " << runtimeContext.imageSize
              << " filebase: " << reinterpret_cast<uint64_t>(fileBase)
              << " fOffset: " << runtimeContext.fileOffset
              << " RVA: " << runtimeContext.rva
              << " stackSize: " << runtimeContext.stackReserve << std::endl;
  });
}


inline void prepareRuntimePagedMemory(lifterConcolic<>* lifter,
                                      const RuntimeImageContext& runtimeContext) {
  // Use the clamped stack reserve (set by configureDefaultMemoryPolicy) so that
  // pageMap and memoryPolicy agree on stack bounds. The raw PE header value
  // (runtimeContext.stackReserve) can be very large (e.g. 16MB) and would
  // create an unreasonably wide paged region.
  //
  // That agreement is the whole point. pageMap answers "is this address
  // backed?", memoryPolicy answers "backed concretely or symbolically?". If
  // the two used different bounds then a stack address outside the clamped
  // window would read as paged-but-symbolic, which is the worst of both: it
  // takes the slow symbolic path while still claiming the read is valid.
  const uint64_t reserve = lifter->stackReserve;
  lifter->markMemPaged(STACKP_VALUE - reserve, STACKP_VALUE + reserve);
  printvalue2(reserve);
  // The PE image itself, [imageBase, imageBase + imageSize). This is what
  // makes GEPLoadPass able to fold concrete instruction bytes later on.
  lifter->markMemPaged(runtimeContext.imageBase,
                       runtimeContext.imageBase + runtimeContext.imageSize);
}

inline void runSignatureStage(lifterConcolic<>* lifter,
                              std::vector<uint8_t>& fileData) {
  // search_signatures does the matching; createOffsetMap turns the raw matches
  // into the offset table the rest of the lift consults. Both must run -- an
  // offset map built from an empty match set would look valid and silently
  // disable every signature-derived improvement.
  lifter->signatures.search_signatures(fileData);
  lifter->signatures.createOffsetMap();
  debugging::doIfDebug([&]() {
    lifter->signatures.displayMatches();
  });
}

// Trivial accessor kept so the pipeline does not reach into the timer
// namespace directly; makes the timing capture points easy to find and change.
inline double captureElapsedMilliseconds() { return timer::getTimer(); }

inline void reportSignatureStageTiming(double elapsedMilliseconds) {
  debugging::doIfDebug([&]() {
    std::cout << "\n" << std::dec << elapsedMilliseconds
              << " milliseconds has past" << std::endl;
  });
}

inline void reportLiftCompletionTiming(double elapsedMilliseconds) {
  debugging::doIfDebug([&]() {
    std::cout << "\nlifting complete, " << std::dec << elapsedMilliseconds
              << " milliseconds has past" << std::endl;
  });
}
// Final step: seal the IR, write both the pre- and post-optimization dumps,
// run the fixpoint optimizer, and persist diagnostics.
//
// The output_no_opts.txt ordering below is not cosmetic. run_opts() mutates
// the LLVM module in place, so once it has run the pre-optimization IR is
// gone for good. That dump is the only way to tell "the lift loop produced
// bad IR" apart from "a pass mangled good IR" after the fact, which is the
// single most common way regression triage goes wrong on this project.
inline void emitLiftOutputs(lifterConcolic<>* lifter, double elapsedMilliseconds) {
  // Blocks the lift loop never finished must be closed before the module can
  // be printed at all -- a function with a dangling predecessor reference is
  // rejected by the LLVM printer. This is why it runs before any write, not
  // just before optimization.
  lifter->finalizeIncompleteBlocks();
  lifter->profiler.begin("write_unopt_ir");
  lifter->writeFunctionToFile("output_no_opts.ll");
  lifter->profiler.end();

  debugging::doIfDebug([&]() {
    std::cout << "\nwriting complete, " << std::dec << elapsedMilliseconds
              << " milliseconds has past" << std::endl;
  });

  // Stage 7. Fixpoint O1+promotion loop, then a single O2, then the post-O2
  // passes. Pass order is documented in ARCHITECTURE.md and is not to be
  // reshuffled casually -- GEPLoadPass in particular must precede
  // PromotePseudoMemory or concrete PE loads get inttoptr'd away.
  lifter->profiler.begin("optimization");
  lifter->run_opts();
  lifter->profiler.end();

  lifter->profiler.begin("write_opt_ir");
  lifter->writeFunctionToFile("output.ll");
  lifter->profiler.end();

  // Write structured diagnostics + profile + stats to JSON.
  //
  // This is a best-effort artifact, not a gate: a lifter that produced valid
  // IR should not fail its run because the diagnostics file could not be
  // written. So both the open and the write are error-checked and reported to
  // stderr, then execution continues. Note clear_error() after reporting --
  // raw_fd_ostream latches its error state, and leaving it set makes the
  // destructor complain again during stack unwinding, producing a second,
  // misleading diagnostic for the same underlying failure.
  {
    auto& profile = lifter->profiler.getStages();
    auto json = lifter->diagnostics.toJson(&profile, &lifter->liftStats);
    std::string diagPath = "output_diagnostics.json";
    std::error_code EC;
    llvm::raw_fd_ostream diagFile(diagPath, EC);
    if (!EC) {
      diagFile << json;
      diagFile.close();
      if (diagFile.has_error()) {
        std::cerr << "[diagnostics] write error for " << diagPath << "\n";
        diagFile.clear_error();
      }
    } else {
      std::cerr << "[diagnostics] failed to open " << diagPath
                << ": " << EC.message() << "\n";
    }
    // Human-readable counterpart to the JSON, on stdout under the same debug
    // gate as the rest of the stage chatter.
    lifter->diagnostics.printSummary();
  }
  lifter->dumpPerfDiagReport(std::cout);
}
