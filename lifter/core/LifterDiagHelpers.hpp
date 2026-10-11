#pragma once

#include <cstdint>
#include <string>

#include "llvm/IR/Value.h"
#include "llvm/Support/raw_ostream.h"

// Lifting rebases the image to 0x40000000, so a code site is observable under
// either the original 0x140000000 base or the rebased one. Diagnostics that pin
// a specific instruction must compare a masked RVA, not a raw address, or the
// same probe silently never fires in one of the two lanes (work.md 7.12.8).
// These live in their own header because OperandUtils.ipp and GEPTracker.ipp
// include each other, so neither can be the first to define them.
//
// NOTE: maskedRva duplicates VmpPcodeCursor::fetchRva exactly -- same two
// bases, same mask, same pass-through. The duplication predates this header.
// They are kept separate because the VMP cursor must not depend on the
// diagnostics header, but if you change one, change both; a divergence would
// make a code site match under one lane and not the other, which is precisely
// the failure mode the comment above warns about.
inline uint64_t maskedRVA(uint64_t va) {
  if (va >= 0x140000000ULL) {
    return va - 0x140000000ULL;
  }
  if ((va & 0xFF000000ULL) == 0x40000000ULL) {
    return va & 0x00FFFFFFULL;
  }
  return va;
}

// RFLAGS bit names, indexed by bit position (bit 0 = CF, bit 1 = RESERVED1,
// ... bit 21 = ID).
//
// The RESERVED entries are named rather than left blank because the array is
// indexed by bit number: a placeholder keeps the indices aligned, and a
// diagnostic that prints a reserved bit shows "RESERVED3" instead of silently
// reading a neighbouring flag's name off a shifted array.
//
// IF and DF appear here even though the lifter does not model them
// semantically -- they show up in flag dumps and it is better to print their
// real names than to claim they are reserved.
inline const char** flagBitNames() {
  static const char* kNames[] = {
      "CF",   "RESERVED1", "PF",     "RESERVED3", "AF",   "RESERVED5",
      "ZF",   "SF",        "TF",     "IF",        "DF",   "OF",
      "IOPL", "IOPL2",     "NT",     "MD",        "RF",   "VM",
      "AC",   "VIF",       "VIP",    "ID"};
  return kNames;
}

// Render a value as IR text for a diagnostic message.
//
// Two deliberate limits. `limit` truncates, because these strings go into
// diagnostics JSON where a whole basic block's worth of IR would be unreadable
// and unhelpful. And a null renders as "<null>" rather than dereferencing --
// this is called on values that failed to resolve, which is exactly when they
// may be null, and a diagnostic helper that crashes while describing a crash
// is worse than useless.
//
// Not escaped for JSON here; the caller runs the result through
// LiftDiagnostics' escapeJson.
inline std::string irText(llvm::Value* v, size_t limit = 110) {
  std::string s;
  llvm::raw_string_ostream os(s);
  if (v) {
    v->print(os);
  } else {
    os << "<null>";
  }
  return os.str().substr(0, limit);
}
