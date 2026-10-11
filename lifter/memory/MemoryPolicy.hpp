#pragma once

// Per-address decision of whether a memory access is concrete (read the real
// byte) or symbolic (introduce an unknown). This is the switch that decides
// how much of the program the lifter actually knows, so it is the single
// highest-leverage knob in the whole pipeline.
//
// Three implementations are provided behind one interface:
//   MemoryPolicyDynamic       real interval map, the default
//   MemoryPolicyFullySymbolic everything symbolic; addRange is a no-op
//   MemoryPolicyFullyConcrete everything concrete; addRange is a no-op
// The two degenerate ones exist so a fully-symbolic or emulator-backed run
// pays *nothing* for the bookkeeping, rather than maintaining an interval map
// whose answers it already knows a priori.
//
// Ranges are INCLUSIVE on both ends throughout. Half-open would be the
// modern preference, but this arithmetic is full of `start - 1` / `end + 1`
// splitting, and inclusive bounds make those splits exact instead of
// requiring ±1 corrections at each step.

#include <assert.h>
#include <concepts>
#include <llvm/IR/Value.h>
#include <set>
#include <vector>

namespace llvm {
  class Module;
  class Function;
} // namespace llvm

enum class MemoryAccessMode : uint8_t { SYMBOLIC, CONCRETE };

struct MemoryRange {
  uint64_t start, end;
  MemoryAccessMode mode;

  // Orders by `start` ONLY. This is load-bearing, not a shortcut: it makes
  // `start` the set's key, which buys O(log n) lookup and forces the
  // non-overlapping invariant -- std::set treats two elements with equal
  // `start` as the same element, so overlapping ranges could not coexist
  // even if the algorithms tried. addRange_impl's split-then-reinsert dance
  // exists precisely to maintain that.
  bool operator<(MemoryRange const& o) const { return start < o.start; }
};

// Compile-time contract for a policy. Stated as a concept rather than
// enforced by the CRTP base calling into a non-existent member, so a bad
// policy fails at its own definition with a readable error rather than deep
// inside a template instantiation.
template <typename T>
concept MemoryPolicyConcept = requires(T t) {
  {
    t.setDefaultMode_impl(std::declval<MemoryAccessMode>())
  } -> std::same_as<void>;
  {
    t.addRange_impl(std::declval<uint64_t>(), std::declval<uint64_t>(),
                    std::declval<MemoryAccessMode>())
  } -> std::same_as<void>;
  {
    t.getAccessMode_impl(std::declval<uint64_t>())
  } -> std::same_as<MemoryAccessMode>;
  {
    t.isRangeFullyCovered_impl(std::declval<uint64_t>(),
                               std::declval<uint64_t>(),
                               std::declval<MemoryAccessMode>())
  } -> std::same_as<bool>;
};

// CRTP base. Static dispatch rather than virtual because getAccessMode is
// called on essentially every memory operand the lifter lowers -- a vtable
// indirection there is measurable, and there is no polymorphic object graph to
// justify it.
template <typename Derived> class MemoryPolicyBase {
public:
  MemoryPolicyBase() {
    static_assert(MemoryPolicyConcept<Derived>,
                  "Derived should satisfy MemoryPolicyConcept");
  }
  void setDefaultMode(MemoryAccessMode mode) {
    static_cast<Derived*>(this)->setDefaultMode_impl(mode);
  }

  // inclusive range
  void addRange(uint64_t start, uint64_t end, MemoryAccessMode mode) {
    static_cast<Derived*>(this)->addRange_impl(start, end, mode);
  }

  MemoryAccessMode getAccessMode(uint64_t address) const {
    return static_cast<const Derived*>(this)->getAccessMode_impl(address);
  }

  // inclusive range
  bool isRangeFullyCovered(uint64_t start, uint64_t end,
                           MemoryAccessMode mode) const {
    return static_cast<const Derived*>(this)->isRangeFullyCovered_impl(
        start, end, mode);
  }

  bool isSymbolic(uint64_t address) {
    return getAccessMode(address) == MemoryAccessMode::SYMBOLIC;
  }

  bool isConcrete(uint64_t address) {
    return getAccessMode(address) == MemoryAccessMode::CONCRETE;
  }
};

// Dynamic mode, for when we need concolic execution
class MemoryPolicyDynamic : public MemoryPolicyBase<MemoryPolicyDynamic> {
public:
  // Interval map holding the *exceptions* to the default mode. Addresses absent
  // from `range` take defaultMode, so configureDefaultMemoryPolicy only has to
  // record the PE sections and the stack rather than the whole address space.
  std::set<MemoryRange> range;
  MemoryAccessMode defaultMode;

  MemoryPolicyDynamic() { defaultMode = MemoryAccessMode::SYMBOLIC; }

  MemoryPolicyDynamic(MemoryPolicyDynamic& other) {
    range = other.range;
    defaultMode = other.defaultMode;
  };

  MemoryPolicyDynamic(MemoryPolicyDynamic&& other) {
    range = std::move(other.range);
    defaultMode = std::move(other.defaultMode);
  };

  void setDefaultMode_impl(MemoryAccessMode mode) { defaultMode = mode; }

  // Declare that [start, end] uses `mode`, overriding whatever the range
  // currently says.
  //
  // Non-overlap is an invariant of the set, so an existing range that straddles
  // the new one must be trimmed to the parts outside it before the new range
  // goes in. Per overlapping existing range:
  //
  //     existing:  [----old----]
  //     new:            [---new---]
  //     result:   [old-left] [---new---] [old-right]
  //
  // The two toAdd.push_back calls produce those surviving fragments. They are
  // queued rather than inserted immediately because inserting into the set
  // mid-scan would invalidate the iterator being walked.
  //
  // Adjacent equal-mode regions are deliberately NOT merged. That costs a
  // little memory and locality but keeps the cost proportional to the overlap
  // count; merging would need a second pass with its own invalidation hazards.
  // Bounded in practice because callers add a few large regions (PE sections,
  // the stack), not many small adjacent ones.
  //
  // inclusive range
  void addRange_impl(uint64_t start, uint64_t end, MemoryAccessMode mode) {
    // make sure start is smoller than end
    if (start > end)
      std::swap(start, end);

    // 1- remove overlapping ranges
    auto it = range.lower_bound({start, start, mode});
    if (it != range.begin())
      --it;

    std::vector<MemoryRange> toAdd;
    while (it != range.end() && it->start <= end) {
      if (it->end < start) {
        ++it;
        continue;
      }

      // track splitted ranges, (( should we also merge the ranges? ))
      if (it->start < start)
        toAdd.push_back({it->start, start - 1, it->mode});
      if (it->end > end)
        toAdd.push_back({end + 1, it->end, it->mode});

      it = range.erase(it);
    }

    // 2 - Add new range
    toAdd.push_back({start, end, mode});
    for (auto& r : toAdd) {
      range.insert(r);
    }
  }

  // Look up one address.
  //
  // upper_bound finds the first range starting strictly after `address`;
  // stepping back one lands on the only candidate that could contain it. The
  // containment test is still required because that neighbour may start earlier
  // and end before `address`, i.e. a gap.
  //
  // The `mode` field of the probe key is irrelevant -- MemoryRange orders on
  // `start` alone -- but the type requires one, so the default is passed.
  MemoryAccessMode getAccessMode_impl(uint64_t address) const {
    auto it = range.upper_bound({address, address, defaultMode});
    if (it != range.begin()) {
      --it;
      if (address >= it->start && address <= it->end)
        return it->mode;
    }
    return defaultMode;
  }

  // inclusive range
  // Whether every address in [start, end] resolves to `mode`.
  //
  // This is the question the lift loop asks before committing to a concrete
  // walk of a region, and the answer has to account for gaps: an address
  // covered by no range takes defaultMode. So a gap *passes* when
  // defaultMode == mode and *fails* when it differs -- which is why the gap arm
  // checks defaultMode instead of just skipping.
  //
  // The walk is a forward linear scan from the first range that might contain
  // `start`, jumping cursor to each range's end+1. Worst case is O(ranges
  // spanned), fine because callers ask about contiguous regions that span few
  // boundaries.
  //
  // inclusive range
  bool isRangeFullyCovered_impl(uint64_t start, uint64_t end,
                                MemoryAccessMode mode) const {
    if (start > end)
      std::swap(start, end);

    uint64_t cursor = start;

    // 1- find the first range that might contain "start"
    auto it = this->range.upper_bound({start, start, mode});
    if (it != this->range.begin())
      --it;

    while (cursor <= end) {
      // 2 - if we're out of ranges, rely on default mode
      if (it == this->range.end() || it->start > cursor) {
        uint64_t gapEnd =
            (it != this->range.end()) ? std::min(end, it->start - 1) : end;

        if (this->defaultMode != mode)
          return false;

        cursor = gapEnd + 1;
        continue;
      }

      // region in range, match node
      if (it->mode != mode)
        return false;

      if (it->start > cursor)
        return false;

      cursor = it->end + 1;
      ++it;
    }

    return true;
  }
};

// Fully symbolic, for when we go fully symbolic with everything.
//
// Every operation is a no-op and every query answers from a constant. The
// empty copy/move constructors are *not* an oversight -- they exist so this
// type stays assignable in the same places MemoryPolicyDynamic is, which is
// what lets the two be swapped without touching call sites.
//
// isRangeFullyCovered answers `true` for SYMBOLIC regardless of the range:
// everything is symbolic, so any symbolic query is trivially satisfied.
class MemoryPolicyFullySymbolic
    : public MemoryPolicyBase<MemoryPolicyFullySymbolic> {
public:
  MemoryPolicyFullySymbolic() {}

  MemoryPolicyFullySymbolic(MemoryPolicyFullySymbolic& other){

  };

  MemoryPolicyFullySymbolic(MemoryPolicyFullySymbolic&& other){

  };

  void setDefaultMode_impl(MemoryAccessMode mode) { return; }

  // inclusive range
  void addRange_impl(uint64_t start, uint64_t end, MemoryAccessMode mode) {
    return;
  }

  MemoryAccessMode getAccessMode_impl(uint64_t address) const {
    return MemoryAccessMode::SYMBOLIC;
  }

  // inclusive range
  bool isRangeFullyCovered_impl(uint64_t start, uint64_t end,
                                MemoryAccessMode mode) const {
    return MemoryAccessMode::SYMBOLIC == mode;
  }
};

// Fully concrete, could use it with emu
//
// Mirror of FullySymbolic: the range map is never built because every query
// has a constant answer. For an emulator-backed run, where all memory really
// is concrete, maintaining intervals would be pure overhead.
class MemoryPolicyFullyConcrete
    : public MemoryPolicyBase<MemoryPolicyFullyConcrete> {
public:
  MemoryPolicyFullyConcrete() {}

  MemoryPolicyFullyConcrete(MemoryPolicyFullyConcrete& other){

  };

  MemoryPolicyFullyConcrete(MemoryPolicyFullyConcrete&& other){

  };

  void setDefaultMode_impl(MemoryAccessMode mode) { return; }

  // inclusive range
  void addRange_impl(uint64_t start, uint64_t end, MemoryAccessMode mode) {
    return;
  }

  MemoryAccessMode getAccessMode_impl(uint64_t address) const {
    return MemoryAccessMode::CONCRETE;
  }

  // inclusive range
  bool isRangeFullyCovered_impl(uint64_t start, uint64_t end,
                                MemoryAccessMode mode) const {
    return MemoryAccessMode::CONCRETE == mode;
  }
};

// The policy the lifter actually uses. configureDefaultMemoryPolicy sets this
// to SYMBOLIC by default with CONCRETE overrides for the PE sections and the
// stack, so a fresh policy starts maximally cautious and gets opened up only
// for memory the lifter can vouch for.
using MemoryPolicy = MemoryPolicyDynamic;