#pragma once

#include "LifterClass_Concolic.hpp"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>

inline void configureDefaultMemoryPolicy(lifterConcolic<>* lifter,
                                         uint64_t stackReserve = 0x1000) {
  lifter->memoryPolicy.setDefaultMode(MemoryAccessMode::SYMBOLIC);

  for (auto& section : lifter->file.sections_v) {
    const auto sectionStart = lifter->file.imageBase + section.virtual_address;
    const auto sectionEnd = sectionStart + section.virtual_size;

    char sectionName[9] = {0};
    std::memcpy(sectionName, &section.name.short_name, 8);

    // Linker-stable sections keep file bytes. Executable unknown sections
    // (packer RX/RWX) stay CONCRETE so encrypted bytecode still promotes.
    // Non-executable unknown sections are SYMBOLIC (runtime-rewritten data).
    MemoryAccessMode mode = MemoryAccessMode::SYMBOLIC;
    if (isFileImmutableSection(sectionName) ||
        section.characteristics.mem_execute) {
      mode = MemoryAccessMode::CONCRETE;
    }
    lifter->memoryPolicy.addRange(sectionStart, sectionEnd, mode);

    if (section.characteristics.mem_execute &&
        std::strncmp(sectionName, ".text", 5) != 0) {
      lifter->bytecodeRanges.emplace_back(sectionStart, sectionEnd);
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
  uint64_t clampedReserve = std::max(stackReserve, uint64_t(0x1000));
  clampedReserve = std::min(clampedReserve, uint64_t(0x100000));
  lifter->stackReserve = clampedReserve;
  lifter->memoryPolicy.addRange(STACKP_VALUE - clampedReserve,
                                STACKP_VALUE + clampedReserve,
                                MemoryAccessMode::CONCRETE);
}

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
