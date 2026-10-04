#ifndef GEPTracker_H
#define GEPTracker_H

#include "MemoryPolicy.hpp"
#include <llvm/ADT/APInt.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/IR/Value.h>


enum Assumption { Real, Assumed }; // add None

enum isPaged { MEMORY_PAGED, MEMORY_MIGHT_BE_PAGED, MEMORY_NOT_PAGED };

struct APIntComparator {
  bool operator()(const llvm::APInt& lhs, const llvm::APInt& rhs) const {
    return lhs.ult(rhs); // unsigned less-than comparison
  }
};

class ValueByteReference {
public:
  // A WeakTrackingVH (rather than a raw Value*) so the reference follows the
  // value across RAUW: when a constant-promotion pass replaces a record load
  // with its constant, the concolic state sees the constant instead of a
  // dangling pointer.
  llvm::WeakTrackingVH value;
  uint8_t byteOffset;
  ValueByteReference() : value(nullptr), byteOffset(0) {}
  ValueByteReference(llvm::Value* val, short offset)
      : value(val), byteOffset(offset) {}
};

class ValueByteReferenceRange {
public:
  ValueByteReference ref;
  uint64_t memoryAddress;

  uint8_t start;
  uint8_t end;

  bool isRef;
  ValueByteReferenceRange(ValueByteReference vref, uint8_t startv, uint8_t endv)
      : ref(vref), memoryAddress(0), start(startv), end(endv), isRef(true) {}

  // Constructor for ValueByteReferenceRange using memoryAddress
  ValueByteReferenceRange(uint64_t addr, uint8_t startv, uint8_t endv)
      : ref(), memoryAddress(addr), start(startv), end(endv), isRef(false) {}
};

// Diagnostic: every write that lands in the watched pseudo-stack slot interval
// is reported with the label of the code path that performed it. Three distinct
// paths populate the concolic buffer (addValueReference, createMemcpy, and the
// generalized-loop retrieve helpers), so a plain probe on one of them cannot
// prove where a byte came from.
void noteBufferWriteDiag(const char* site, uint64_t start, uint64_t size,
                         llvm::Value* value, uint64_t insnAddr);

/*
namespace SCCPSimplifier {
    void init(Function* function);
    SCCPSolver* get();

    void cleanup();
} // namespace SCCPSimplifier
*/

#endif