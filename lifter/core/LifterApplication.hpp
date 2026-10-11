#pragma once

// CLI argument handling shared by the lifter binary and the test harnesses.
//
// The template parameter is the actual lift entry point, so the same
// argument-validation and file-loading path is exercised whether the caller
// is the production binary or a test that wants to lift an in-memory image.
// Keeping it a template rather than a function pointer avoids the indirect
// call on a path that runs once per process, and lets the compiler inline the
// entry point into this frame.
//
// Everything here returns a status code rather than calling exit(): the test
// harness reuses these helpers and must survive a bad argument to report a
// failure instead of taking the whole runner down with it.

#include "CommandLineHelpers.hpp"
#include "Utils.h"
#include <cstdint>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

template <typename LiftEntryFn>
inline int runLifterApplication(const std::vector<std::string>& args,
                                LiftEntryFn&& liftEntry) {
  // args.front() is argv[0] when the caller forwards a real argv, but the
  // harnesses pass a synthetic vector that may be empty. Falling back to a
  // fixed name keeps the usage message readable instead of dereferencing an
  // empty container.
  const char* programName = args.empty() ? "mergen-lifter" : args.front().c_str();
  if (args.size() < 3) {
    printLifterUsage(programName);
    return 1;
  }

  uint64_t startAddr = 0;
  // Validate before touching the filesystem. A malformed address is a usage
  // error and should report as one, not as a confusing read failure after the
  // file is already mapped.
  if (!parseStartAddressArg(args[2], startAddr)) {
    std::cerr << "Invalid startAddr value: " << args[2] << std::endl;
    printLifterUsage(programName);
    return 1;
  }

  std::vector<uint8_t> fileData;
  if (!readBinaryFile(args[1], fileData)) {
    return 1;
  }

  // Move the file bytes into the entry point rather than copying or borrowing.
  // The PE image is typically megabytes and nothing else needs the buffer
  // afterwards; a copy here would double peak RSS for no benefit. The entry
  // point takes ownership precisely so this can be a move.
  const bool liftSucceeded =
      std::forward<LiftEntryFn>(liftEntry)(startAddr, std::move(fileData));
  if (!liftSucceeded) {
    return 1;
  }

  // Process-wide timer, not scoped to the lift: stopTimer returns total
  // elapsed since startTimer, which the caller started during CLI parsing.
  // Debug-only output -- timing on the success path is a development
  // affordance, and the structured timings that matter for regression work
  // come from the per-stage profiler instead.
  auto milliseconds = timer::stopTimer();
  debugging::doIfDebug([&]() {
    std::cout << "\n"
              << std::dec << milliseconds << " milliseconds have passed"
              << std::endl;
    std::cout << "Lift and optimization pipeline completed" << std::endl;
  });
  return 0;
}
