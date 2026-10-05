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
inline uint64_t maskedRVA(uint64_t va) {
  if (va >= 0x140000000ULL) {
    return va - 0x140000000ULL;
  }
  if ((va & 0xFF000000ULL) == 0x40000000ULL) {
    return va & 0x00FFFFFFULL;
  }
  return va;
}

inline const char** flagBitNames() {
  static const char* kNames[] = {
      "CF",   "RESERVED1", "PF",     "RESERVED3", "AF",   "RESERVED5",
      "ZF",   "SF",        "TF",     "IF",        "DF",   "OF",
      "IOPL", "IOPL2",     "NT",     "MD",        "RF",   "VM",
      "AC",   "VIF",       "VIP",    "ID"};
  return kNames;
}

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
