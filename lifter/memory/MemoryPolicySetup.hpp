#pragma once

#include "LifterClass_Concolic.hpp"
#include <algorithm>
#include <cstdint>
#include <cstring>

// Sections whose on-disk bytes remain valid after the image is mapped.
// Anything else (protector-invented names, packer stubs, etc.) is SYMBOLIC:
// promoting file bytes there reinjects stale values the process no longer has.
inline bool isFileImmutableSection(const char* name) {
  static constexpr const char* kImmutable[] = {
      ".text",  ".rdata", ".pdata", ".idata", ".edata", ".reloc",
      ".rsrc",  ".00cfg", ".xdata", ".data",  ".bss",   ".tls",
      ".CRT",   ".didat", ".gfids", ".gehcont", ".retplne", ".fptable",
  };
  for (const char* known : kImmutable) {
    if (std::strcmp(name, known) == 0) {
      return true;
    }
  }
  return false;
}

inline void configureDefaultMemoryPolicy(lifterConcolic<>* lifter,
                                         uint64_t stackReserve = 0x1000) {
  lifter->memoryPolicy.setDefaultMode(MemoryAccessMode::SYMBOLIC);

  for (auto& section : lifter->file.sections_v) {
    const auto sectionStart = lifter->file.imageBase + section.virtual_address;
    const auto sectionEnd = sectionStart + section.virtual_size;

    char sectionName[9] = {0};
    std::memcpy(sectionName, &section.name.short_name, 8);

    const MemoryAccessMode mode = isFileImmutableSection(sectionName)
                                      ? MemoryAccessMode::CONCRETE
                                      : MemoryAccessMode::SYMBOLIC;
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
