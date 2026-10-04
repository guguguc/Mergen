#ifndef FILEREADER_HPP
#define FILEREADER_HPP

#include "nt/nt_headers.hpp"
#include "RuntimeMemDump.hpp"
#include <algorithm>
#include <assert.h>
#include <coff/section_header.hpp>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

enum arch_mode : uint8_t { X86 = 0, X64 = 1 };
enum class characteristics : uint8_t {
  NONE = 1 << 0,
  R = 1 << 1,
  W = 1 << 2,
  X = 1 << 3,
  RW = R | W,
  RX = R | X,
  WX = W | X,
  RWX = R | W | X
};

inline characteristics operator|(characteristics lhs, characteristics rhs) {
  return static_cast<characteristics>(
      static_cast<std::underlying_type_t<characteristics>>(lhs) |
      static_cast<std::underlying_type_t<characteristics>>(rhs));
}

inline characteristics& operator|=(characteristics& lhs, characteristics rhs) {
  lhs = lhs | rhs;
  return lhs;
}

// On-disk bytes that stay valid after mapping. Protector-invented sections
// are not in this set even when marked RX: they mix encrypted bytecode with
// slots rewritten at runtime.
inline bool isFileImmutableSection(const char* name) {
  static constexpr const char* kImmutable[] = {
      ".text",    ".rdata", ".pdata", ".idata",   ".edata",  ".reloc",
      ".rsrc",    ".00cfg", ".xdata", ".data",    ".bss",    ".tls",
      ".CRT",     ".didat", ".gfids", ".gehcont", ".retplne", ".fptable",
  };
  for (const char* known : kImmutable) {
    if (std::strcmp(name, known) == 0) {
      return true;
    }
  }
  return false;
}

template <typename SectionRange>
inline bool isImmutableImageAddressIn(uint64_t imageBase,
                                      const SectionRange& sections,
                                      uint64_t va) {
  if (va < imageBase || sections.empty()) {
    return false;
  }
  const uint64_t rva64 = va - imageBase;
  if (rva64 > UINT32_MAX) {
    return false;
  }
  const uint32_t rva = static_cast<uint32_t>(rva64);
  auto it = std::upper_bound(sections.begin(), sections.end(), rva,
                             [](uint32_t val, const win::section_header_t& s) {
                               return val < s.virtual_address;
                             });
  if (it == sections.begin()) {
    return true;
  }
  --it;
  if (rva >= it->virtual_address + it->virtual_size) {
    return false;
  }
  char name[9] = {};
  std::memcpy(name, &it->name.short_name, 8);
  return isFileImmutableSection(name);
}

template <typename T>
concept FileRead = requires(T t) {
  { t.init_impl(std::declval<uint8_t*>()) } -> std::same_as<bool>;
  {
    t.address_to_mapped_address_impl(std::declval<uint64_t>())
  } -> std::same_as<uint64_t>;
};

template <typename Derived> class FileReader {
protected:
  uint8_t* FileBase;
  RuntimeMemoryOverlay runtimeOverlay;

public:
  FileReader() {
    static_assert(FileRead<Derived> && std::derived_from<Derived, FileReader>);
  };
  bool init(uint8_t* fileBase) {
    return static_cast<Derived*>(this)->init_impl(fileBase);
  }
  bool getMode() { return static_cast<Derived*>(this)->getMode_impl(); }
  uint64_t address_to_mapped_address(uint64_t rva) {
    return static_cast<Derived*>(this)->address_to_mapped_address_impl(rva);
  }
  bool readMemory(uint64_t rva, unsigned count, uint64_t& out) {
    if (runtimeOverlay.read(rva, count, out)) {
      return true;
    }
    return static_cast<Derived*>(this)->readMemory_impl(rva, count, out);
  }
  RuntimeMemoryOverlay& memoryOverlay() { return runtimeOverlay; }
  const RuntimeMemoryOverlay& memoryOverlay() const { return runtimeOverlay; }
  const char* getName(uint64_t offset) {
    return static_cast<Derived*>(this)->getName_impl(offset);
  }
  bool isImmutableImageAddress(uint64_t va) {
    return static_cast<Derived*>(this)->isImmutableImageAddress_impl(va);
  }
  // Non-immutable file zeros are indistinguishable from slots rewritten after
  // mapping. Refuse the whole load, including 1-4 byte slices of an 8-byte
  // zero qword. Bytecode zeros that sit inside a nonzero qword still promote.
  // Dump-backed bytes are process memory at the lift RVA, including valid zeros.
  bool shouldPromoteFileValue(uint64_t va, unsigned byteSize, uint64_t value) {
    if (runtimeOverlay.covers(va, byteSize)) {
      return true;
    }
    if (isImmutableImageAddress(va)) {
      return true;
    }
    if (value != 0) {
      return true;
    }
    if (byteSize >= 8) {
      return false;
    }
    uint64_t qword = 0;
    const uint64_t aligned = va & ~uint64_t(7);
    if (!readMemory(aligned, 8, qword)) {
      return true;
    }
    return qword != 0;
  }
  inline void filebase_exists() {

    assert(FileBase != nullptr && "fileBase is NULL");
  }
};

class x86FileReader : public FileReader<x86FileReader> {
public:
private:
  win::section_header_t* sectionHeader;
  int numSections;
  win::dos_header_t* dosHeader;
  uint8_t* ntHeadersBase;
  win::nt_headers_t<X86>* ntHeaders;
  uint64_t imageBase;
  std::vector<win::section_header_t> sections;

public:
  bool init_impl(uint8_t* fileBase) {

    dosHeader = reinterpret_cast<win::dos_header_t*>(fileBase);
    ntHeadersBase = reinterpret_cast<uint8_t*>(fileBase) + dosHeader->e_lfanew;
    ntHeaders = reinterpret_cast<win::nt_headers_t<X86>*>(ntHeadersBase);
    imageBase = ntHeaders->optional_header.image_base;
    sectionHeader = reinterpret_cast<win::nt_headers_t<X86>*>(ntHeadersBase)
                        ->get_sections();
    numSections = reinterpret_cast<const win::nt_headers_t<X86>*>(ntHeadersBase)
                      ->file_header.num_sections;
    auto rawSecs = reinterpret_cast<win::nt_headers_t<X86>*>(ntHeadersBase)
                       ->get_sections();
    numSections = ntHeaders->file_header.num_sections;

    sections.assign(rawSecs, rawSecs + numSections);

    std::sort(sections.begin(), sections.end(), [](auto& a, auto& b) {
      return a.virtual_address < b.virtual_address;
    });

    return 1;
  }
  arch_mode getMode_impl() { return X86; }
  x86FileReader(uint8_t* fileBase) {

    dosHeader = reinterpret_cast<win::dos_header_t*>(fileBase);
    ntHeadersBase = reinterpret_cast<uint8_t*>(fileBase) + dosHeader->e_lfanew;
    ntHeaders = reinterpret_cast<win::nt_headers_t<X86>*>(ntHeadersBase);
    imageBase = ntHeaders->optional_header.image_base;
    sectionHeader = reinterpret_cast<win::nt_headers_t<X86>*>(ntHeadersBase)
                        ->get_sections();
    numSections = reinterpret_cast<const win::nt_headers_t<X86>*>(ntHeadersBase)
                      ->file_header.num_sections;
    auto rawSecs = reinterpret_cast<win::nt_headers_t<X86>*>(ntHeadersBase)
                       ->get_sections();
    numSections = ntHeaders->file_header.num_sections;

    sections.assign(rawSecs, rawSecs + numSections);

    std::sort(sections.begin(), sections.end(), [](auto& a, auto& b) {
      return a.virtual_address < b.virtual_address;
    });
  };

  uint64_t RvaToFileOffset(uint32_t rva) {

    auto it =
        std::upper_bound(sections.begin(), sections.end(), rva,
                         [](uint32_t val, const win::section_header_t& s) {
                           return val < s.virtual_address;
                         });
    if (it == sections.begin()) {
      // rva is before the first section. PE headers are not covered by any
      // section, but they are file-backed at the same raw offset as their RVA.
      // Leaving them unmapped makes header reads un-promotable, which poisons
      // every value derived from the image's header area.
      if (rva < sections.front().virtual_address) {
        return rva;
      }
      return 0;
    }
    --it; // now *it is the candidate section
    if (rva < it->virtual_address + it->virtual_size) {
      uint32_t offset_in_section = rva - it->virtual_address;
      if (offset_in_section >= it->size_raw_data)
        return 0; // BSS region (beyond raw data), zero-filled
      return offset_in_section + it->ptr_raw_data;
    }
    return 0;
  }

  uint64_t address_to_mapped_address_impl(uint64_t rva) {
    uint64_t address = rva - imageBase;
    auto fileOffset = RvaToFileOffset(address);
    if (fileOffset == 0)
      return 0;
    return (uint64_t)FileBase + fileOffset;
  }

  bool readMemory_impl(uint64_t addr, unsigned byteSize, uint64_t& value) {
    // Guard against buffer overflow: memcpy into uint64_t is only safe for
    // reads up to 8 bytes. Wider loads (SSE/AVX 128/256/512-bit) must not
    // reach this path — they require vector-aware memory handling.
    if (byteSize > sizeof(uint64_t)) {
      fprintf(stderr, "readMemory: wide load rejected (byteSize=%u > 8)\n", byteSize);
      return 0;
    }
    uint64_t mappedAddr = address_to_mapped_address(addr);
    if (mappedAddr > 0) {
      uint64_t tempValue = 0;
      std::memcpy(&tempValue, reinterpret_cast<const void*>(mappedAddr),
                  byteSize);
      value = tempValue;
      return 1;
    }

    // Handle zero-initialized virtual tails (BSS) and raw->BSS boundary reads.
    uint64_t rva64 = addr - imageBase;
    if (rva64 > UINT32_MAX)
      return 0;
    uint32_t rva = static_cast<uint32_t>(rva64);

    auto it =
        std::upper_bound(sections.begin(), sections.end(), rva,
                         [](uint32_t val, const win::section_header_t& s) {
                           return val < s.virtual_address;
                         });
    if (it == sections.begin())
      return 0;
    --it;

    if (rva >= it->virtual_address + it->virtual_size)
      return 0;

    uint32_t offset_in_section = rva - it->virtual_address;
    if (offset_in_section + byteSize > it->virtual_size)
      return 0;

    uint64_t tempValue = 0;
    if (offset_in_section < it->size_raw_data) {
      uint32_t rawAvailable =
          std::min<uint32_t>(byteSize, it->size_raw_data - offset_in_section);
      std::memcpy(&tempValue,
                  reinterpret_cast<const void*>(FileBase + it->ptr_raw_data +
                                               offset_in_section),
                  rawAvailable);
    }

    value = tempValue;
    return 1;
  }

  const char* getName_impl(uint64_t offset) {
    auto rvaOffset = RvaToFileOffset(offset);
    return (const char*)FileBase + rvaOffset;
  }

  bool isImmutableImageAddress_impl(uint64_t va) {
    return isImmutableImageAddressIn(imageBase, sections, va);
  }
};

class x86_64FileReader : public FileReader<x86_64FileReader> {
public: // pain
  win::section_header_t* sectionHeader;
  int numSections;
  win::dos_header_t* dosHeader;
  uint8_t* ntHeadersBase;
  win::nt_headers_t<X64>* ntHeaders;
  uint64_t imageBase;
  std::vector<win::section_header_t> sections_v;
  std::vector<win::section_header_t> sections_r;

public:
  bool init_impl(uint8_t* fileBase) {
    FileBase = fileBase;
    dosHeader = reinterpret_cast<win::dos_header_t*>(fileBase);
    ntHeadersBase = reinterpret_cast<uint8_t*>(fileBase) + dosHeader->e_lfanew;
    ntHeaders = reinterpret_cast<win::nt_headers_t<X64>*>(ntHeadersBase);
    imageBase = ntHeaders->optional_header.image_base;
    sectionHeader = reinterpret_cast<win::nt_headers_t<X64>*>(ntHeadersBase)
                        ->get_sections();
    numSections = reinterpret_cast<const win::nt_headers_t<X64>*>(ntHeadersBase)
                      ->file_header.num_sections;
    auto rawSecs = reinterpret_cast<win::nt_headers_t<X64>*>(ntHeadersBase)
                       ->get_sections();
    numSections = ntHeaders->file_header.num_sections;

    sections_v.assign(rawSecs, rawSecs + numSections);

    std::sort(sections_v.begin(), sections_v.end(), [](auto& a, auto& b) {
      return a.virtual_address < b.virtual_address;
    });

    sections_r.assign(rawSecs, rawSecs + numSections);

    std::sort(sections_r.begin(), sections_r.end(),
              [](auto& a, auto& b) { return a.ptr_raw_data < b.ptr_raw_data; });

    return 1;
  }

  arch_mode getMode_impl() { return X64; }
  x86_64FileReader(){};

  x86_64FileReader(uint8_t* fileBase) { init(fileBase); };

  characteristics
  parseSectionCharacteristics(win::section_characteristics_t c) {
    characteristics res = characteristics::NONE;
    if (c.mem_read) {
      res |= characteristics::R;
    }
    if (c.mem_write) {
      res |= characteristics::W;
    }
    if (c.mem_execute) {
      res |= characteristics::X;
    }
    return res;
  }

  uint64_t RvaToFileOffset(uint32_t rva) {

    auto it =
        std::upper_bound(sections_v.begin(), sections_v.end(), rva,
                         [](uint32_t val, const win::section_header_t& s) {
                           return val < s.virtual_address;
                         });
    if (it == sections_v.begin())
      return 0;

    --it;
    if (rva < it->virtual_address + it->virtual_size) {
      uint32_t offset_in_section = rva - it->virtual_address;
      if (offset_in_section >= it->size_raw_data)
        return 0; // BSS region (beyond raw data), zero-filled
      return offset_in_section + it->ptr_raw_data;
    }
    return 0;
  }

  uint64_t fileOffsetToRVA(uint64_t offset) {
    auto it =
        std::upper_bound(sections_v.begin(), sections_v.end(), offset,
                         [](uint64_t val, const win::section_header_t& s) {
                           return val < s.virtual_address;
                         });
    if (it == sections_v.begin()) {
      // rva is before the first section
      return 0;
    }
    --it; // now *it is the candidate section
    if (offset < it->ptr_raw_data + it->size_raw_data) {
      return (offset - it->virtual_address) + it->ptr_raw_data;
    }
    return 0;
  }

  uint64_t address_to_mapped_address_impl(uint64_t rva) {
    uint64_t address = rva - imageBase;
    auto fileOffset = RvaToFileOffset(address);
    if (fileOffset == 0)
      return 0;
    return (uint64_t)FileBase + fileOffset;
  }

  bool readMemory_impl(uint64_t addr, unsigned byteSize, uint64_t& value) {
    // Guard against buffer overflow: memcpy into uint64_t is only safe for
    // reads up to 8 bytes. Wider loads (SSE/AVX 128/256/512-bit) must not
    // reach this path — they require vector-aware memory handling.
    if (byteSize > sizeof(uint64_t)) {
      fprintf(stderr, "readMemory: wide load rejected (byteSize=%u > 8)\n", byteSize);
      return 0;
    }
    uint64_t mappedAddr = address_to_mapped_address(addr);
    if (mappedAddr > 0) {
      uint64_t tempValue = 0;
      std::memcpy(&tempValue, reinterpret_cast<const void*>(mappedAddr),
                  byteSize);
      value = tempValue;
      return 1;
    }

    // Handle zero-initialized virtual tails (BSS) and raw->BSS boundary reads.
    uint64_t rva64 = addr - imageBase;
    if (rva64 > UINT32_MAX)
      return 0;
    uint32_t rva = static_cast<uint32_t>(rva64);

    auto it =
        std::upper_bound(sections_v.begin(), sections_v.end(), rva,
                         [](uint32_t val, const win::section_header_t& s) {
                           return val < s.virtual_address;
                         });
    if (it == sections_v.begin())
      return 0;
    --it;

    if (rva >= it->virtual_address + it->virtual_size)
      return 0;

    uint32_t offset_in_section = rva - it->virtual_address;
    if (offset_in_section + byteSize > it->virtual_size)
      return 0;

    uint64_t tempValue = 0;
    if (offset_in_section < it->size_raw_data) {
      uint32_t rawAvailable =
          std::min<uint32_t>(byteSize, it->size_raw_data - offset_in_section);
      std::memcpy(&tempValue,
                  reinterpret_cast<const void*>(FileBase + it->ptr_raw_data +
                                               offset_in_section),
                  rawAvailable);
    }

    value = tempValue;
    return 1;
  }

  const char* getName_impl(uint64_t offset) {
    auto rvaOffset = RvaToFileOffset(offset);
    return (const char*)FileBase + rvaOffset;
  }

  bool isImmutableImageAddress_impl(uint64_t va) {
    return isImmutableImageAddressIn(imageBase, sections_v, va);
  }
};

#endif // FILEREADER_HPP