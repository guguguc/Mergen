#pragma once

// Decides, once, which addresses the lifter is willing to read concretely.
//
// This is the trust boundary. Everywhere else in the lifter, "is this address
// concrete?" is answered by this policy, so a wrong decision here propagates
// into every load the lifter promotes. The default is maximally cautious
// (SYMBOLIC) and it is opened up one region at a time, with the reason for
// each recorded at its call site below.
//
// Order matters: configureDefaultMemoryPolicy must run before
// applyRuntimeDumpMemoryPolicy, because the dump's spans are a refinement of
// this policy rather than a replacement for it.

#include "LifterClass_Concolic.hpp"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>

// SYMBOLIC first, then open up specific regions. Anything not explicitly
  // added stays symbolic forever, so forgetting a region degrades to a slower
  // but correct lift rather than to a wrong one.
inline void configureDefaultMemoryPolicy(lifterConcolic<>* lifter,
                                         uint64_t stackReserve = 0x1000) {
  lifter->memoryPolicy.setDefaultMode(MemoryAccessMode::SYMBOLIC);

  for (auto& section : lifter->file.sections_v) {
    const auto sectionStart = lifter->file.imageBase + section.virtual_address;
    const auto sectionEnd = sectionStart + section.virtual_size;

    char sectionName[9] = {0};
    std::memcpy(sectionName, &section.name.short_name, 8);

    // Two disjoint cases earn CONCRETE, and they earn it for different reasons:
    //
    //   Linker-stable known sections
    //       The compiler and linker produced these; their on-disk bytes are
    //       final. isFileImmutableSection is an allowlist rather than a
    //       "not executable" test because it has to exclude protector-invented
    //       sections that happen to carry a standard name.
    //
    //   Unknown executable sections
    //       Deliberately promoted even though nothing guarantees their
    //       stability. This is the packer case: a packer's RX/RWX section
    //       holds bytecode that is *already decrypted* in the file at the
    //       point the analyst lifted it. Refusing to promote it is what makes
    //       protected samples stall, so this trades strictness for coverage.
    //
    // Non-executable unknown sections stay SYMBOLIC -- those are runtime
    // data the loader or the program will rewrite.
    MemoryAccessMode mode = MemoryAccessMode::SYMBOLIC;
    if (isFileImmutableSection(sectionName) ||
        section.characteristics.mem_execute) {
      mode = MemoryAccessMode::CONCRETE;
    }
    lifter->memoryPolicy.addRange(sectionStart, sectionEnd, mode);

    // Executable-but-not-.text sections are bytecode for the VMP model, and
    // they are recorded separately from the memory policy because the two
    // answer different questions: policy says "can I read this", bytecode
    // ranges say "is this the VM's instruction stream".
    if (section.characteristics.mem_execute &&
        std::strncmp(sectionName, ".text", 5) != 0) {
      lifter->addBytecodeRange(sectionStart, sectionEnd);
    }
  }

  // PE headers sit below the first section and are equally file-backed. If
  // they stay SYMBOLIC, header reads never promote and any value derived from
  // the header area (e.g. a VM context pointer) stays symbolic. The range
  // policy is what decides which loads are safe to promote (Themida article,
  // "Constant Promotion & Memory Modeling").
  {
    uint32_t firstSectionRva = UINT32_MAX;
    for (auto& section : lifter->file.sections_v) {
      firstSectionRva = std::min(firstSectionRva,
                                 static_cast<uint32_t>(section.virtual_address));
    }
    if (firstSectionRva != 0 && firstSectionRva != UINT32_MAX) {
      lifter->memoryPolicy.addRange(lifter->file.imageBase,
                                    lifter->file.imageBase + firstSectionRva,
                                    MemoryAccessMode::CONCRETE);
    }
  }

  // Use actual stack reserve from PE header instead of hardcoded 0x1000.
  // Clamp to reasonable bounds: at least 0x1000, at most 0x100000 (1MB).
  //
  // Both bounds are load-bearing and neither is arbitrary:
  //
  //   floor 0x1000  A reserve below one page would leave legitimate stack
  //                 accesses outside the paged window, and they would degrade
  //                 to symbolic mid-lift.
  //
  //   ceiling 0x100000  A malformed or extreme PE header can claim a reserve
  //                 of tens of megabytes. Marking that whole span paged makes
  //                 every address in it look file-backed and wrecks the
  //                 memory policy's discrimination for no benefit.
  //
  // The clamp lives here rather than at the use site so that pageMap and
  // memoryPolicy -- which prepareRuntimePagedMemory and PromotePseudoStackPass
  // both read from lifter->stackReserve -- agree by construction. They must
  // use the same window; if they disagreed, a stack address could be paged
  // but symbolic, which is the worst of both.
  uint64_t clampedReserve = std::max(stackReserve, uint64_t(0x1000));
  clampedReserve = std::min(clampedReserve, uint64_t(0x100000));
  lifter->stackReserve = clampedReserve;
  lifter->memoryPolicy.addRange(STACKP_VALUE - clampedReserve,
                                STACKP_VALUE + clampedReserve,
                                MemoryAccessMode::CONCRETE);
}

// Refine the policy with a runtime dump, if one was loaded.
//
// Runs after configureDefaultMemoryPolicy and only ever *adds* CONCRETE
// ranges. It is a refinement, not a replacement: a region the base policy
// rejected stays rejected unless a dump actually covers it, which keeps the
// trust decision traceable to one of two stated reasons rather than to
// whatever the dump happened to contain.
//
// Each kept span is marked paged as well as concrete. markMemPaged is what
// stops the address from being treated as unmapped, and skipping it produces
// a region that reads correctly but is invisible to the page map -- which then
// mislabels it during diagnostics.
//
// The summary line goes to stderr unconditionally, not under the debug gate:
// this count is the first thing to check when a dump-backed lift produces
// less concrete IR than expected, and it is cheap enough to always emit.
inline void applyRuntimeDumpMemoryPolicy(lifterConcolic<>* lifter) {
  const auto& overlay = lifter->file.memoryOverlay();
  const auto keep = selectDumpConcreteSpans(overlay);
  const auto& spans = overlay.getSpans();
  uint64_t concreteBytes = 0;
  size_t concreteSpans = 0;
  for (size_t i = 0; i < spans.size(); ++i) {
    if (!keep[i] || spans[i].bytes.empty()) {
      continue;
    }
    const uint64_t start = spans[i].va;
    const uint64_t end = start + spans[i].bytes.size();
    lifter->memoryPolicy.addRange(start, end, MemoryAccessMode::CONCRETE);
    lifter->markMemPaged(start, end);
    concreteBytes += spans[i].bytes.size();
    ++concreteSpans;
  }
  std::cerr << "[mem-dump] concrete spans " << concreteSpans << "/"
            << spans.size() << " bytes " << concreteBytes << "\n";
}
