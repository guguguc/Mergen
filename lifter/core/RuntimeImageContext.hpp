#pragma once

// Step 1 of the pipeline: translate a runtime start address into everything
// downstream needs, and refuse the input loudly if it does not make sense.
//
// The problem this solves is that the lifter has two address spaces in play:
//   - the caller's start address is a *runtime* VA (imageBase + RVA), because
//     that is what an analyst reads off a debugger
//   - the disassembler and the PE readers work in *file* offsets
// This module is the only place the two are reconciled.
//
// It is also the untrusted-input boundary. Everything read here comes from the
// file's own headers, including the offsets used to find the next header, so
// each field is validated against the buffer bounds before it is dereferenced.
// On a truncated or deliberately malformed PE the answer is a specific error
// code, never a read past the end of the buffer and never a silently wrong
// context. `python test.py negative` asserts on these codes.

#include "FileReader.hpp"
#include "nt/nt_headers.hpp"
#include <cstddef>
#include <cstdint>
#include <optional>

// The resolved entry context, handed to the rest of the pipeline.
//
// stackReserve is deliberately the *raw* PE value here. It is not clamped at
// this point; configureDefaultMemoryPolicy does that later, and
// prepareRuntimePagedMemory deliberately reads the clamped `lifter->stackReserve`
// rather than this field, because the raw value can be 16MB or more.
struct RuntimeImageContext {
  arch_mode mode;          // X64 or X86, from the optional header magic
  uint64_t imageBase;      // OptionalHeader.ImageBase
  uint64_t imageSize;      // OptionalHeader.SizeOfImage -- bounds the valid RVA range
  uint64_t stackReserve;   // OptionalHeader.SizeOfStackReserve (raw, see above)
  uint64_t rva;            // start address - imageBase
  uint64_t fileOffset;     // where that RVA's bytes actually live in the file
  uint8_t firstOpcodeByte; // sanity value, echoed by printRuntimeImageContext
};

// Failure reasons, kept specific rather than collapsed into a bool.
//
// The granularity exists so a bad sample can be diagnosed without a debugger:
// "RuntimeRvaUnmapped" and "FileOffsetOutOfRange" mean very different things
// about the PE, and both are reachable. Note the ordering matches the order
// the checks run in createRuntimeImageContext -- the enum is effectively a
// diagnostic trace of the validation sequence.
enum class RuntimeImageContextError : uint8_t {
  None = 0,
  InvalidInputBuffer,
  InvalidDosMagic,
  InvalidNtHeaderOffset,
  NtHeadersOutOfRange,
  InvalidNtSignature,
  InvalidOptionalHeaderMagic,
  SectionTableOutOfRange,
  RuntimeAddressBelowImageBase,
  RuntimeAddressOutsideImage,
  RuntimeRvaTooLarge,
  RuntimeRvaUnmapped,
  FileOffsetOutOfRange,
};

inline const char*
runtimeImageContextErrorMessage(RuntimeImageContextError error) {
  switch (error) {
  case RuntimeImageContextError::None:
    return "no error";
  case RuntimeImageContextError::InvalidInputBuffer:
    return "input buffer is null or too small for a DOS header";
  case RuntimeImageContextError::InvalidDosMagic:
    return "input is not a PE file (missing MZ DOS magic)";
  case RuntimeImageContextError::InvalidNtHeaderOffset:
    return "PE DOS header contains an invalid NT header offset";
  case RuntimeImageContextError::NtHeadersOutOfRange:
    return "PE NT headers are truncated or out of file bounds";
  case RuntimeImageContextError::InvalidNtSignature:
    return "PE NT signature is invalid (expected PE\\0\\0)";
  case RuntimeImageContextError::InvalidOptionalHeaderMagic:
    return "PE optional header magic is neither PE32 nor PE32+";
  case RuntimeImageContextError::SectionTableOutOfRange:
    return "PE section table is truncated or out of file bounds";
  case RuntimeImageContextError::RuntimeAddressBelowImageBase:
    return "start address is below image base";
  case RuntimeImageContextError::RuntimeAddressOutsideImage:
    return "start address RVA is outside image size";
  case RuntimeImageContextError::RuntimeRvaTooLarge:
    return "start address RVA does not fit in 32 bits";
  case RuntimeImageContextError::RuntimeRvaUnmapped:
    return "start address RVA is not mapped to file-backed bytes";
  case RuntimeImageContextError::FileOffsetOutOfRange:
    return "resolved file offset is outside input file bounds";
  }
  return "unknown runtime context error";
}

// Outcome type: context plus error. `context` is optional rather than a
// separate `ok` flag so the two cannot disagree -- there is no state in which
// ok() is true and the context is empty.
struct RuntimeImageContextResult {
  std::optional<RuntimeImageContext> context{};
  RuntimeImageContextError error = RuntimeImageContextError::None;

  [[nodiscard]] bool ok() const { return context.has_value(); }
};

// Check that the section table lies fully inside the file.
//
// The section table's location is *computed*, not stored: it sits after the
// NT headers, at an offset built from ntOffset plus the size of the signature,
// the file header, and the optional header length. Every one of those is a
// value read out of the file, so a hostile or truncated PE can point the
// table anywhere -- including past the end of the buffer, where the loop in
// mapRvaToFileOffset would then read section headers out of bounds.
//
// Templated on the header type because the optional header length -- and
// therefore the table's offset -- differs between PE32 and PE32+.
template <typename NtHeadersT>
inline bool validateSectionTableBounds(const uint8_t* fileBase, size_t fileSize,
                                       size_t ntOffset,
                                       RuntimeImageContextError& outError) {
  const auto* ntHeaders =
      reinterpret_cast<const NtHeadersT*>(fileBase + ntOffset);
  const uint64_t sectionHeaderOffset =
      static_cast<uint64_t>(ntOffset) + sizeof(uint32_t) +
      sizeof(win::file_header_t) + ntHeaders->file_header.size_optional_header;
  const uint64_t sectionTableBytes =
      static_cast<uint64_t>(ntHeaders->file_header.num_sections) *
      sizeof(win::section_header_t);

  // The comparison order matters and is not incidental. `sectionHeaderOffset`
  // is attacker-influenced, so it is compared against fileSize *first*; only
  // once it is known to be in range is the subtraction below computed. Reversing
  // these two clauses would underflow the unsigned subtraction and pass the
  // bounds check for any offset past the end of the file.
  if (sectionHeaderOffset > fileSize ||
      sectionTableBytes > (fileSize - sectionHeaderOffset)) {
    outError = RuntimeImageContextError::SectionTableOutOfRange;
    return false;
  }

  return true;
}

// Map an RVA to a file offset, or nullopt if it is not file-backed.
//
// Returns nullopt in two distinct situations that are deliberately not merged:
// the RVA falls in a gap between sections, and the RVA falls inside a
// section's *virtual* extent but past its *raw* data. The second is a
// zero-filled tail (uninitialised / BSS-like memory) that exists at runtime
// but has no bytes in the file, so there is nothing to disassemble.
//
// Templated so the same logic serves both PE32 and PE32+ header layouts.
template <typename NtHeadersT>
inline std::optional<uint64_t> mapRvaToFileOffset(const NtHeadersT* ntHeaders,
                                                  uint32_t rva) {
  const auto* sections = ntHeaders->get_sections();
  const auto sectionCount = ntHeaders->file_header.num_sections;

  // Anything below SizeOfHeaders is the PE header block itself, which is
  // mapped one-to-one at file offset == RVA. Sections start after it.
  const auto headerSize =
      static_cast<uint64_t>(ntHeaders->optional_header.size_headers);
  if (static_cast<uint64_t>(rva) < headerSize) {
    return static_cast<uint64_t>(rva);
  }

  // `continue` rather than `break` on a below-VA section: the PE spec requires
  // sections sorted ascending by VirtualAddress, but a malformed or crafted
  // file may not be, and skipping keeps later sections reachable instead of
  // giving up at the first out-of-order entry.
  for (uint16_t index = 0; index < sectionCount; ++index) {
    const auto& section = sections[index];
    if (rva < section.virtual_address) {
      continue;
    }

    const auto offsetInSection = static_cast<uint64_t>(rva) -
                                 static_cast<uint64_t>(section.virtual_address);
    // A zero VirtualSize is legal and means "use SizeOfRawData". This matters
    // for the next two comparisons, which are bounds in different spaces.
    const auto mappedVirtualSize =
        section.virtual_size != 0 ? static_cast<uint64_t>(section.virtual_size)
                                  : static_cast<uint64_t>(section.size_raw_data);
    // Past the section's virtual extent: either a gap or the next section.
    if (offsetInSection >= mappedVirtualSize) {
      continue;
    }

    // Inside the virtual extent but past the raw data. This is the
    // zero-filled tail -- mapped at runtime, absent from the file. nullopt,
    // not an offset past EOF, because the bytes genuinely do not exist.
    if (offsetInSection >= section.size_raw_data) {
      return std::nullopt;
    }

    return static_cast<uint64_t>(section.ptr_raw_data) + offsetInSection;
  }

  return std::nullopt;
}

// Validate the input and build the entry context.
//
// The checks run in a fixed order -- buffer size, DOS magic, NT offset, NT
// signature, optional header magic, section table bounds, start address, RVA
// mapping, file offset -- and each failure returns a distinct error code. The
// order is not arbitrary: every check must complete before the one after it
// can assume its inputs are sane. Do not reorder without re-reading which
// pointer each subsequent check dereferences.
inline RuntimeImageContextResult
createRuntimeImageContext(const uint8_t* fileBase, size_t fileSize,
                         uint64_t runtimeAddress) {
  if (fileBase == nullptr || fileSize < sizeof(win::dos_header_t)) {
    return {.context = std::nullopt,
            .error = RuntimeImageContextError::InvalidInputBuffer};
  }

  if (*reinterpret_cast<const uint16_t*>(fileBase) != win::DOS_HDR_MAGIC) {
    return {.context = std::nullopt,
            .error = RuntimeImageContextError::InvalidDosMagic};
  }

  const auto* dosHeader = reinterpret_cast<const win::dos_header_t*>(fileBase);
  // e_lfanew is a *signed* 32-bit field in the DOS header. Casting it straight
  // to size_t would turn a negative value into an enormous unsigned offset
  // that happens to fail the next check for the wrong reason, so the sign is
  // checked before the conversion.
  const auto ntOffsetSigned = static_cast<int64_t>(dosHeader->e_lfanew);
  if (ntOffsetSigned < 0) {
    return {.context = std::nullopt,
            .error = RuntimeImageContextError::InvalidNtHeaderOffset};
  }

  // Subtraction-safe bounds test: `ntOffset > fileSize` is checked before
  // `fileSize - ntOffset`, for the same reason as in
  // validateSectionTableBounds.
  const auto ntOffset = static_cast<size_t>(ntOffsetSigned);
  if (ntOffset > fileSize ||
      fileSize - ntOffset < sizeof(win::nt_headers_t<false>)) {
    return {.context = std::nullopt,
            .error = RuntimeImageContextError::NtHeadersOutOfRange};
  }

  const auto* ntHeadersBase = fileBase + ntOffset;
  const auto* ntHeaders32 =
      reinterpret_cast<const win::nt_headers_t<false>*>(ntHeadersBase);
  if (ntHeaders32->signature != win::NT_HDR_MAGIC) {
    return {.context = std::nullopt,
            .error = RuntimeImageContextError::InvalidNtSignature};
  }

  // The optional header magic is what distinguishes PE32 from PE32+, and it has
  // to be validated before either header type can be dereferenced -- the two
  // layouts have different sizes and different field offsets. The magic is
  // read through the 32-bit view first because it sits at the same offset in
  // both.
  constexpr auto IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
  constexpr auto IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

  const auto optionalHeaderMagic = ntHeaders32->optional_header.magic;
  if (optionalHeaderMagic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
      optionalHeaderMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    return {.context = std::nullopt,
            .error = RuntimeImageContextError::InvalidOptionalHeaderMagic};
  }

  // Only now is it safe to re-read through the 64-bit view, and only after
  // confirming the buffer is actually large enough to hold those headers.
  const bool is64Bit = optionalHeaderMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  if (is64Bit && fileSize - ntOffset < sizeof(win::nt_headers_t<true>)) {
    return {.context = std::nullopt,
            .error = RuntimeImageContextError::NtHeadersOutOfRange};
  }

  RuntimeImageContextError sectionError = RuntimeImageContextError::None;
  if (is64Bit) {
    if (!validateSectionTableBounds<win::nt_headers_t<true>>(fileBase, fileSize,
                                                             ntOffset, sectionError)) {
      return {.context = std::nullopt, .error = sectionError};
    }
  } else {
    if (!validateSectionTableBounds<win::nt_headers_t<false>>(fileBase, fileSize,
                                                              ntOffset, sectionError)) {
      return {.context = std::nullopt, .error = sectionError};
    }
  }

  RuntimeImageContext context{};
  context.mode = is64Bit ? X64 : X86;

  // The PE32 and PE32+ bodies below are near-duplicates on purpose. Factoring
  // them into one generic helper would require either reinterpreting the
  // headers back to a common type (losing the type safety that makes these
  // accesses safe) or a second virtual dispatch. At ~20 duplicated lines each,
  // spelled-out beats clever: this code runs once per lift, not in a loop.
  std::optional<uint64_t> fileOffset;
  if (is64Bit) {
    const auto* ntHeaders64 =
        reinterpret_cast<const win::nt_headers_t<true>*>(ntHeadersBase);
    context.imageBase = ntHeaders64->optional_header.image_base;
    context.imageSize = ntHeaders64->optional_header.size_image;
    context.stackReserve = ntHeaders64->optional_header.size_stack_reserve;

    if (runtimeAddress < context.imageBase) {
      return {.context = std::nullopt,
              .error = RuntimeImageContextError::RuntimeAddressBelowImageBase};
    }

    context.rva = runtimeAddress - context.imageBase;
    if (context.rva >= context.imageSize) {
      return {.context = std::nullopt,
              .error = RuntimeImageContextError::RuntimeAddressOutsideImage};
    }
    // Bounds the RVA against SizeOfImage before narrowing it to 32 bits for
    // mapRvaToFileOffset. RuntimeRvaTooLarge is only reachable if SizeOfImage
    // itself exceeds 4GB, which a malformed file can claim; the check is
    // retained rather than assumed redundant.
    if (context.rva > 0xFFFFFFFFull) {
      return {.context = std::nullopt,
              .error = RuntimeImageContextError::RuntimeRvaTooLarge};
    }

    fileOffset = mapRvaToFileOffset(ntHeaders64, static_cast<uint32_t>(context.rva));
  } else {
    context.imageBase = ntHeaders32->optional_header.image_base;
    context.imageSize = ntHeaders32->optional_header.size_image;
    context.stackReserve = ntHeaders32->optional_header.size_stack_reserve;

    if (runtimeAddress < context.imageBase) {
      return {.context = std::nullopt,
              .error = RuntimeImageContextError::RuntimeAddressBelowImageBase};
    }

    context.rva = runtimeAddress - context.imageBase;
    if (context.rva >= context.imageSize) {
      return {.context = std::nullopt,
              .error = RuntimeImageContextError::RuntimeAddressOutsideImage};
    }
    if (context.rva > 0xFFFFFFFFull) {
      return {.context = std::nullopt,
              .error = RuntimeImageContextError::RuntimeRvaTooLarge};
    }

    fileOffset = mapRvaToFileOffset(ntHeaders32, static_cast<uint32_t>(context.rva));
  }

  if (!fileOffset.has_value()) {
    return {.context = std::nullopt,
            .error = RuntimeImageContextError::RuntimeRvaUnmapped};
  }

  // Final belt-and-braces check. mapRvaToFileOffset derives the offset from
  // section headers, which are file-controlled, so the result is re-validated
  // against the real buffer size before it is used to index the buffer below.
  context.fileOffset = *fileOffset;
  if (context.fileOffset >= fileSize) {
    return {.context = std::nullopt,
            .error = RuntimeImageContextError::FileOffsetOutOfRange};
  }

  // Read one byte so printRuntimeImageContext can show what the start address
  // actually resolved to. If this looks wrong, the address or the RVA
  // calculation is wrong -- it is the cheapest possible sanity check on the
  // whole resolution.
  context.firstOpcodeByte = fileBase[context.fileOffset];
  return {.context = context, .error = RuntimeImageContextError::None};
}