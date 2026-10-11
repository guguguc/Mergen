#pragma once

// Decides whether a resolved call target gets inlined into the IR or left as a
// call.
//
// Inlining is how the lifter makes a callee's behaviour visible to the path
// solver. An outlined call is opaque: the solver has to assume anything about
// what it does to memory and flags. So the default is to inline everything,
// and the outline set is the exception list -- addresses the lifter must NOT
// descend into.
//
// Two reasons an address lands on that list:
//   - it is an import thunk, which has no meaningful body to inline
//   - inlining it exceeded the inline budget (the speculative bail-out in
//     LiftDriver)
//
// Structured like MemoryPolicy -- a CRTP base over a dynamic set plus two
// degenerate always/never implementations -- so the two subsystems read alike
// and can be swapped the same way.

#include <assert.h>
#include <concepts>
#include <llvm/IR/Value.h>
#include <set>

namespace llvm {
  class Module;
  class Function;
} // namespace llvm

enum class FunctionInlineMode : uint8_t { INLINE, OUTLINE };

// setDefaultMode_impl is deliberately absent, and the commented-out requirement
// in the concept below records why: the default is fixed at INLINE for every
// policy here. Letting a caller flip it would make "not in the outline set"
// mean different things in different configurations, and the interesting case
// (outline everything) is already FunctionInlinePolicyOutlineAll.
template <typename T>
concept FunctionInlineConcept = requires(T t) {
  /*
  {
     t.setDefaultMode_impl(std::declval<FunctionInlineMode>())
   } -> std::same_as<void>;
  */
  { t.addAddress_impl(std::declval<uint64_t>()) } -> std::same_as<void>;
  {
    t.getAccessMode_impl(std::declval<uint64_t>())
  } -> std::same_as<FunctionInlineMode>;
};

template <typename Derived> class FunctionInlinePolicyBase {
public:
  FunctionInlinePolicyBase() {
    static_assert(FunctionInlineConcept<Derived>,
                  "Derived should satisfy FunctionInlineConcept");
  }

  // address to outline
  void addAddress(uint64_t address) {
    static_cast<Derived*>(this)->addAddress_impl(address);
  }

  FunctionInlineMode getAccessMode(uint64_t address) const {
    return static_cast<const Derived*>(this)->getAccessMode_impl(address);
  }

  bool isInline(uint64_t address) {
    return getAccessMode(address) == FunctionInlineMode::INLINE;
  }

  bool isOutline(uint64_t address) {
    return getAccessMode(address) == FunctionInlineMode::OUTLINE;
  }
};

// Dynamic mode, for when we need concolic execution
// inline by default
//
// The outline set holds exact addresses, not ranges -- an address is either on
// the list or it is not. That is why getAccessMode_impl is exact-match rather
// than the containment test MemoryPolicy uses.
class FunctionInlinePolicyDynamicInlineDefault
    : public FunctionInlinePolicyBase<
          FunctionInlinePolicyDynamicInlineDefault> {
public:
  // inline by default
  // keep track of outlines, everything else is inline?
  std::set<uint64_t> range;
  FunctionInlineMode defaultMode;

  FunctionInlinePolicyDynamicInlineDefault() {
    defaultMode = FunctionInlineMode::INLINE;
  }

  FunctionInlinePolicyDynamicInlineDefault(
      FunctionInlinePolicyDynamicInlineDefault& other) {
    range = other.range;
    defaultMode = other.defaultMode;
  };

  FunctionInlinePolicyDynamicInlineDefault(
      FunctionInlinePolicyDynamicInlineDefault&& other) {
    range = std::move(other.range);
    defaultMode = std::move(other.defaultMode);
  };

  // void setDefaultMode_impl(FunctionInlineMode mode) { defaultMode = mode; }

  void addAddress_impl(uint64_t address) { range.insert(address); }

  // Exact membership. The upper_bound-then-decrement dance and the
  // `address >= *it && address <= *it` test are carried over from
  // MemoryPolicy's interval lookup, where they are needed; for a set of exact
  // addresses `range.count(address)` expresses the same thing directly. Both
  // forms are correct, this one is just doing unnecessary work.
  FunctionInlineMode getAccessMode_impl(uint64_t address) const {
    auto it = range.upper_bound(address);
    if (it != range.begin()) {
      --it;
      if (address >= *it && address <= *it)
        return FunctionInlineMode::OUTLINE;
    }
    return this->defaultMode;
  }
};

// Dynamic mode, for when we need concolic execution
// outline by default
//
// WARNING: this class does not do what its name says. Its constructor sets
// defaultMode to INLINE, and its getAccessMode_impl is byte-for-byte the same
// as FunctionInlinePolicyDynamicInlineDefault's -- so the two are currently
// indistinguishable in behaviour. The name promises "outline everything not
// explicitly listed", which is what FunctionInlinePolicyOutlineAll does.
//
// It is harmless today only because the alias at the bottom of this file picks
// the InlineDefault variant. If you are reaching for a policy that outlines by
// default, use FunctionInlinePolicyOutlineAll, not this.
class FunctionInlinePolicyDynamicOutlineDefault
    : public FunctionInlinePolicyBase<
          FunctionInlinePolicyDynamicOutlineDefault> {
public:
  // inline by default
  // keep track of outlines, everything else is inline?
  std::set<uint64_t> range;
  FunctionInlineMode defaultMode;

  FunctionInlinePolicyDynamicOutlineDefault() {
    defaultMode = FunctionInlineMode::INLINE;
  }

  FunctionInlinePolicyDynamicOutlineDefault(
      FunctionInlinePolicyDynamicOutlineDefault& other) {
    range = other.range;
    defaultMode = other.defaultMode;
  };

  FunctionInlinePolicyDynamicOutlineDefault(
      FunctionInlinePolicyDynamicOutlineDefault&& other) {
    range = std::move(other.range);
    defaultMode = std::move(other.defaultMode);
  };

  // void setDefaultMode_impl(FunctionInlineMode mode) { defaultMode = mode; }

  void addAddress_impl(uint64_t address) { range.insert(address); }

  FunctionInlineMode getAccessMode_impl(uint64_t address) const {
    auto it = range.upper_bound(address);
    if (it != range.begin()) {
      --it;
      if (address >= *it && address <= *it)
        return FunctionInlineMode::OUTLINE;
    }
    return this->defaultMode;
  }
};

// Fully symbolic, for when we go fully symbolic with everything
//
// Degenerate policy: addAddress is ignored and every address inlines. Use this
// when you want maximal coverage and do not care about IR size. The empty
// copy/move constructors are deliberate, matching MemoryPolicy's degenerate
// types -- they exist so this type stays assignable wherever the dynamic
// policies are.
class FunctionInlinePolicyInlineAll
    : public FunctionInlinePolicyBase<FunctionInlinePolicyInlineAll> {
public:
  FunctionInlinePolicyInlineAll() {}

  FunctionInlinePolicyInlineAll(FunctionInlinePolicyInlineAll& other){

  };

  FunctionInlinePolicyInlineAll(FunctionInlinePolicyInlineAll&& other){

  };

  void addAddress_impl(uint64_t start) { return; }

  FunctionInlineMode getAccessMode_impl(uint64_t address) const {
    return FunctionInlineMode::INLINE;
  }
};

// Fully concrete, could use it with emu
//
// The opposite degenerate policy: nothing inlines, every resolved target stays
// a call. Useful when the point is to look at call structure rather than at
// inlined bodies, or to keep the lift tractable on a very large image.
class FunctionInlinePolicyOutlineAll
    : public FunctionInlinePolicyBase<FunctionInlinePolicyOutlineAll> {
public:
  FunctionInlinePolicyOutlineAll() {}

  FunctionInlinePolicyOutlineAll(FunctionInlinePolicyOutlineAll& other){

  };

  FunctionInlinePolicyOutlineAll(FunctionInlinePolicyOutlineAll&& other){

  };

  void addAddress_impl(uint64_t start) { return; }

  FunctionInlineMode getAccessMode_impl(uint64_t address) const {
    return FunctionInlineMode::OUTLINE;
  }
};

// What the lifter uses: inline everything except the explicit outline set,
// which is populated from --outline and from PE export auto-outlining.
using FunctionInlinePolicy = FunctionInlinePolicyDynamicInlineDefault;