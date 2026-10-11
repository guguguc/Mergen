#pragma once

// Optional overlay of runtime process memory on top of the static PE image.
//
// When a dump is supplied (--mem-dump / MERGEN_MEM_DUMP), the lifter can read
// memory as it existed in the live process rather than as it sits in the file.
// That matters for VM-protected samples, where the protector has already
// unpacked and relocated things by the time the analyst dumps them.
//
// The hard part is that the two disagree about addresses. The file has one
// image base; the live process had whatever base it was actually loaded at.
// Everything below exists to reconcile that, and to do it without letting dump
// data silently corrupt the lifter's own emulated environment.
//
// Pipeline position: this is consumed when the memory policy is configured --
// selectDumpConcreteSpans decides which overlay spans become CONCRETE.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

// Same anchor as STACKP_VALUE in Includes.h — dump pages must not occupy it.
constexpr uint64_t kDumpStackAnchor = 0x00000000014FEA0ULL;

// Snapshot of process memory at the lift RVA (not a trace). Image pages are
// reloc-undone to PE ImageBase, then only bytes that still differ from the
// file are stored. Non-image pages keep dump VAs. Heap pointer qwords are
// not slid.
//
// Three invariants worth stating up front, because the rest of the file
// exists to maintain them:
//
//  1. Stored VAs are always PE-space VAs, never dump-space. installDumpBytes
//     rewrites image-region addresses on the way in, so nothing downstream
//     has to know the dump base existed.
//  2. Only *differences* from the file are stored. The PE remains the source
//     of truth for unchanged bytes, which keeps dumps small and keeps a stale
//     dump from freezing bytes that the file actually changed.
//  3. Overrides are qword-aligned and qword-sized (see installDumpBytes).
//     Partial-qword overrides would let a pointer read pick up half of a dump
//     value and half of a file value.
struct RuntimeOverlaySpan {
  uint64_t va = 0;
  std::vector<uint8_t> bytes;
};

class RuntimeMemoryOverlay {
public:
  uint64_t peImageBase = 0;
  uint64_t dumpImageBase = 0;
  uint64_t imageSize = 0;

  void clear() {
    spans.clear();
    peImageBase = 0;
    dumpImageBase = 0;
    imageSize = 0;
  }

  bool empty() const { return spans.empty(); }

  // Insert a span at `va`, then coalesce it with its neighbours.
  //
  // Every lookup in this class assumes `spans` is sorted by va, so the
  // insertion point has to be computed rather than appended. The
  // upper_bound comparator is the standard "first span starting after va"
  // search.
  //
  // mergeFrom starts one slot *earlier* than the insertion point when there is
  // one: a new span can touch the span immediately before it as well as the
  // one after, and starting at the insert point would leave that pair
  // unmerged. Missed merges would not corrupt reads (find() would still locate
  // the right span) but would leave adjacent spans that read() cannot serve,
  // since covers() requires the whole access to fit in one span.
  void write(uint64_t va, const uint8_t* data, size_t n) {
    if (n == 0 || data == nullptr) {
      return;
    }
    auto it = std::upper_bound(
        spans.begin(), spans.end(), va,
        [](uint64_t addr, const RuntimeOverlaySpan& s) { return addr < s.va; });
    const size_t idx = static_cast<size_t>(it - spans.begin());
    RuntimeOverlaySpan span;
    span.va = va;
    span.bytes.assign(data, data + n);
    spans.insert(spans.begin() + static_cast<std::ptrdiff_t>(idx),
                 std::move(span));
    mergeFrom(idx > 0 ? idx - 1 : 0);
  }

  // Whether the overlay has a byte differing from the file at this VA.
  //
  // Non-image dump pages are stored verbatim at their dump VA, so this only
  // reports true for image-region overrides.
  bool isMappedImageVa(uint64_t va) const {
    va = canonicalVa(va);
    return imageSize != 0 && peImageBase != 0 && va >= peImageBase &&
           va < peImageBase + imageSize;
  }

  // Rewrite a dump-space image VA into the equivalent PE-space VA.
  //
  // This is the reloc-undo. A dump taken from a running process records
  // pointers as the process saw them, i.e. relative to the base it was
  // actually loaded at, which under ASLR is not the base in the file.
  //
  // Guarded on all three fields being non-zero *and* the bases differing:
  // with no relocation, canonicalVa is the identity function, and short-
  // circuiting here avoids doing arithmetic on every single lookup. The
  // range check keeps the rewrite from touching non-image addresses, which
  // must keep their dump-space VAs.
  uint64_t canonicalVa(uint64_t va) const {
    if (imageSize != 0 && dumpImageBase != 0 && peImageBase != 0 &&
        dumpImageBase != peImageBase && va >= dumpImageBase &&
        va < dumpImageBase + imageSize) {
      return peImageBase + (va - dumpImageBase);
    }
    return va;
  }

  // Whether one span wholly contains [va, va+n).
  //
  // Whole-span containment, not per-byte. An access straddling two adjacent
  // spans that failed to merge is reported as uncovered rather than stitched
  // together from two sources, so a missing merge shows up as a coverage
  // miss rather than as a silently wrong value.
  bool covers(uint64_t va, unsigned n) const {
    if (n == 0) {
      return false;
    }
    va = canonicalVa(va);
    const RuntimeOverlaySpan* s = find(va);
    return s && va >= s->va && va + n <= s->va + s->bytes.size();
  }

  // Read up to a qword out of the overlay.
  //
  // n is capped at sizeof(uint64_t) because this feeds register-sized loads,
  // not arbitrary reads. Little-endian memcpy into a zeroed uint64_t is how
  // the partial-width case is handled: the upper bytes stay zero, which is
  // what a zero-extending load should produce.
  bool read(uint64_t va, unsigned n, uint64_t& out) const {
    va = canonicalVa(va);
    if (n == 0 || n > sizeof(uint64_t) || !covers(va, n)) {
      return false;
    }
    const RuntimeOverlaySpan* s = find(va);
    uint64_t value = 0;
    std::memcpy(&value, s->bytes.data() + (va - s->va), n);
    out = value;
    return true;
  }

  std::ptrdiff_t spanIndexContaining(uint64_t va) const {
    va = canonicalVa(va);
    auto it = std::upper_bound(
        spans.begin(), spans.end(), va,
        [](uint64_t addr, const RuntimeOverlaySpan& s) { return addr < s.va; });
    if (it == spans.begin()) {
      return -1;
    }
    --it;
    if (va < it->va || va >= it->va + it->bytes.size()) {
      return -1;
    }
    return it - spans.begin();
  }

  const std::vector<RuntimeOverlaySpan>& getSpans() const { return spans; }

private:
  std::vector<RuntimeOverlaySpan> spans;

  const RuntimeOverlaySpan* find(uint64_t va) const {
    auto it = std::upper_bound(
        spans.begin(), spans.end(), va,
        [](uint64_t addr, const RuntimeOverlaySpan& s) { return addr < s.va; });
    if (it == spans.begin()) {
      return nullptr;
    }
    --it;
    if (va < it->va || va >= it->va + it->bytes.size()) {
      return nullptr;
    }
    return &*it;
  }

  void mergeFrom(size_t start) {
    size_t i = start;
    while (i + 1 < spans.size()) {
      auto& a = spans[i];
      auto& b = spans[i + 1];
      const uint64_t aEnd = a.va + a.bytes.size();
      if (aEnd < b.va) {
        ++i;
        continue;
      }
      if (aEnd < b.va + b.bytes.size()) {
        a.bytes.resize(static_cast<size_t>(b.va + b.bytes.size() - a.va));
        std::memcpy(a.bytes.data() + (b.va - a.va), b.bytes.data(),
                    b.bytes.size());
      }
      spans.erase(spans.begin() + static_cast<std::ptrdiff_t>(i + 1));
    }
  }
};

// Dump data must never land on the addresses the lifter emulates itself.
//
// Two regions are off limits:
//
//   0x7FFD0000-0x7FFD2000   the TEB/PEB model. modelProcessEnvironment seeds
//                           TEB.Self, PEB.BeingDebugged and the OS build number
//                           here; a dump page overlapping that window would
//                           replace seeded values with whatever the dumped
//                           process happened to hold, and the VM key derivation
//                           would silently stop reproducing.
//
//   STACKP +/- 1MB           the emulated stack. The VMP model has its own
//                           fixed 1MB window here (see VmpPcodeCursor's
//                           isVmStackAddress); a dump page on top of it would
//                           make stack reads non-deterministic.
//
// Half-open overlap test on both bounds, so adjacent-but-not-overlapping
// regions are allowed.
inline bool overlayIntersectsForbidden(uint64_t va, size_t n) {
  const uint64_t end = va + n;
  const uint64_t tebLo = 0x7FFD0000ULL;
  const uint64_t tebHi = 0x7FFD2000ULL;
  const uint64_t stackLo = kDumpStackAnchor - 0x100000ULL;
  const uint64_t stackHi = kDumpStackAnchor + 0x100000ULL;
  auto hits = [](uint64_t a, uint64_t b, uint64_t lo, uint64_t hi) {
    return a < hi && b > lo;
  };
  return hits(va, end, tebLo, tebHi) || hits(va, end, stackLo, stackHi);
}

// Rewrite image pointers inside a dump page from dump-space to PE-space.
//
// Scans in 8-byte strides, so it only rewrites qword-aligned values. That is a
// deliberate limitation: real relocation entries can point at unaligned
// addresses, but scanning every byte offset would rewrite any coincidental
// 8-byte run that merely looked like an image pointer -- corrupting ordinary
// data. Accepting the missed case is much cheaper than paying for the false
// positives.
//
// `n < 8` is a no-op because there is no complete qword to examine; that is
// why the loop bound is `i + 8 <= n` and not `i < n`.
//
// Heap pointers are intentionally not rewritten. Heap addresses were not
// relocated by the loader, so they are already correct; sliding them would
// corrupt them.
inline void slideDumpImagePointers(uint8_t* p, size_t n, uint64_t dumpImageBase,
                                   uint64_t peImageBase, uint64_t imageSize) {
  if (p == nullptr || n < 8 || dumpImageBase == peImageBase || imageSize == 0) {
    return;
  }
  const uint64_t dumpEnd = dumpImageBase + imageSize;
  for (size_t i = 0; i + 8 <= n; i += 8) {
    uint64_t q = 0;
    std::memcpy(&q, p + i, 8);
    if (q >= dumpImageBase && q < dumpEnd) {
      q = peImageBase + (q - dumpImageBase);
      std::memcpy(p + i, &q, 8);
    }
  }
}

// Install one dumped region into the overlay, splitting it into image and
// non-image parts and reducing the image part to the bytes that actually
// differ from the file.
//
// The outer loop walks the region in chunks, never crossing the dump image
// boundary: image bytes need relocation and delta-filtering, non-image bytes
// need neither and are stored verbatim at their dump VA.
//
// On the image path the filter is the interesting part. A byte is kept only if
// it differs from the PE, and when it does, its ENTIRE containing qword is
// kept -- see the q0/q1 computation. Keeping whole qwords is what stops a
// pointer read from straddling a dump/file boundary and picking up a value
// assembled from both. The cost is that a single changed byte drags in its
// seven neighbours; for unpacked VM code that is still a large net saving.
//
// peRead is injected as a callable rather than reached through the overlay so
// this stays a free function and can be unit-tested against a stub.
template <typename PeRead>
inline void installDumpBytes(RuntimeMemoryOverlay& overlay, uint64_t peImageBase,
                             uint64_t dumpImageBase, uint64_t imageSize,
                             uint64_t dumpVa, const uint8_t* data, size_t n,
                             PeRead&& peRead) {
  if (n == 0 || data == nullptr) {
    return;
  }
  const uint64_t dumpImgEnd = dumpImageBase + imageSize;
  size_t off = 0;
  while (off < n) {
    const uint64_t va = dumpVa + off;
    const size_t left = n - off;
    const bool inImage =
        imageSize != 0 && va >= dumpImageBase && va < dumpImgEnd;
    size_t chunk = left;
    if (inImage) {
      chunk = static_cast<size_t>(
          std::min<uint64_t>(left, dumpImgEnd - va));
      const uint64_t rva = va - dumpImageBase;
      const uint64_t peVa = peImageBase + rva;
      if (overlayIntersectsForbidden(peVa, chunk)) {
        off += chunk;
        continue;
      }
      std::vector<uint8_t> slid(data + off, data + off + chunk);
      slideDumpImagePointers(slid.data(), slid.size(), dumpImageBase,
                             peImageBase, imageSize);
      std::vector<char> keep(chunk, 0);
      // Expand a kept byte to its whole qword. The lo/hi clamp to the current chunk
      // matters because a qword can straddle both the chunk boundary and the
      // start of the region; clamping keeps the fill inside `keep`.
      for (size_t i = 0; i < chunk; ++i) {
        uint64_t peWord = 0;
        const bool peOk = peRead(peVa + i, 1, peWord);
        const uint8_t peByte = peOk ? static_cast<uint8_t>(peWord) : 0;
        if (peOk && peByte == slid[i]) {
          continue;
        }
        const uint64_t q0 = (peVa + i) & ~uint64_t(7);
        const uint64_t q1 = q0 + 8;
        const size_t lo = static_cast<size_t>(
            q0 > peVa ? q0 - peVa : 0);
        const size_t hi = static_cast<size_t>(
            std::min<uint64_t>(q1 - peVa, chunk));
        std::fill(keep.begin() + static_cast<std::ptrdiff_t>(lo),
                  keep.begin() + static_cast<std::ptrdiff_t>(hi), 1);
      }
      // Emit maximal runs of kept bytes as single overlay spans, so the span list
      // stays proportional to the number of *changed regions* rather than to
      // the byte count.
      size_t run = 0;
      auto flush = [&](size_t end) {
        if (end > run) {
          overlay.write(peVa + run, slid.data() + run, end - run);
        }
      };
      for (size_t i = 0; i < chunk; ++i) {
        if (!keep[i]) {
          flush(i);
          run = i + 1;
        }
      }
      flush(chunk);
    } else {
      if (va < dumpImageBase && dumpImageBase > va) {
        chunk = static_cast<size_t>(
            std::min<uint64_t>(left, dumpImageBase - va));
      }
      if (!overlayIntersectsForbidden(va, chunk)) {
        overlay.write(va, data + off, chunk);
      }
    }
    off += chunk;
  }
}

// Load a runtime dump file and install it as the overlay.
//
// The on-disk format is deliberately trivial, little-endian, header-first:
//
//   "MRGNDMP1"        8 bytes magic
//   dumpImageBase    u64   image base the dump was taken at
//   imageSize        u64
//   nregions         u32
//   flags            u32   reserved, currently ignored
//   then nregions times:
//     va             u64
//     size           u32
//     prot           u32   reserved, currently ignored
//     bytes          size
//
// Every field read is checked against the stream state, and a truncated dump
// is a hard error rather than a short overlay -- a partial overlay would
// silently mix dump and file bytes with no indication of which is which.
template <typename File>
inline bool loadRuntimeMemDump(File& file, const std::string& path,
                               std::string& err) {
  auto& overlay = file.memoryOverlay();
  const uint64_t peImageBase = file.imageBase;
  overlay.clear();
  overlay.peImageBase = peImageBase;
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    err = "Failed to open mem dump: " + path;
    return false;
  }
  char magic[8] = {};
  in.read(magic, 8);
  if (!in || std::memcmp(magic, "MRGNDMP1", 8) != 0) {
    err = "Mem dump has bad magic (want MRGNDMP1): " + path;
    return false;
  }
  uint64_t dumpImageBase = 0;
  uint64_t imageSize = 0;
  uint32_t nregions = 0;
  uint32_t flags = 0;
  in.read(reinterpret_cast<char*>(&dumpImageBase), sizeof(dumpImageBase));
  in.read(reinterpret_cast<char*>(&imageSize), sizeof(imageSize));
  in.read(reinterpret_cast<char*>(&nregions), sizeof(nregions));
  in.read(reinterpret_cast<char*>(&flags), sizeof(flags));
  if (!in) {
    err = "Mem dump header truncated: " + path;
    return false;
  }
  (void)flags;
  overlay.dumpImageBase = dumpImageBase;
  overlay.imageSize = imageSize;
  auto peRead = [&](uint64_t va, unsigned n, uint64_t& out) -> bool {
    return file.readMemory_impl(va, n, out);
  };
  for (uint32_t i = 0; i < nregions; ++i) {
    uint64_t va = 0;
    uint32_t size = 0;
    uint32_t prot = 0;
    in.read(reinterpret_cast<char*>(&va), sizeof(va));
    in.read(reinterpret_cast<char*>(&size), sizeof(size));
    in.read(reinterpret_cast<char*>(&prot), sizeof(prot));
    if (!in) {
      err = "Mem dump region header truncated";
      return false;
    }
    if (size == 0) {
      continue;
    }
    // Sanity bound on a single region. A dump file is an input like any other;
    // without this, a corrupt or hostile size field would drive a multi-GB
    // allocation before the read failed.
    if (size > 64u * 1024u * 1024u) {
      err = "Mem dump region too large";
      return false;
    }
    std::vector<uint8_t> bytes(size);
    in.read(reinterpret_cast<char*>(bytes.data()), size);
    if (!in) {
      err = "Mem dump region bytes truncated";
      return false;
    }
    installDumpBytes(overlay, peImageBase, dumpImageBase, imageSize, va,
                     bytes.data(), bytes.size(), peRead);
  }
  return true;
}

// Image overlay spans plus heap spans reached by qword pointers in those
// pages (one extra hop for the [heap+0x58] object). Other dump heaps/stacks
// stay SYMBOLIC so path-solve does not fork through the allocator.
//
// The two-hop limit is the whole design. A dump contains far more memory than
// the program under analysis actually uses, and making all of it CONCRETE
// would put every allocator artefact into the path solver's search space --
// the solver would fork across plausible-but-wrong destinations through
// allocator metadata and the concrete walk would never converge.
//
// So only spans reachable from the image through at most two pointer hops are
// promoted. One hop gets the objects the unpacked code points at; the second
// gets the object those objects point at (the [heap+0x58] link that VM
// handlers typically use to reach their state). Two is where the reachable
// set stops being predictable and starts being allocator structure again.
//
// Everything else stays SYMBOLIC, which is the safe default: the lift
// degrades to symbolic rather than forking.
//
// `keep` is indexed parallel to spans and is seeded from isMappedImageVa, so
// the image is always reachable regardless of what the dump contains.
inline std::vector<char>
selectDumpConcreteSpans(const RuntimeMemoryOverlay& overlay) {
  const auto& spans = overlay.getSpans();
  std::vector<char> keep(spans.size(), 0);
  if (spans.empty()) {
    return keep;
  }
  for (size_t i = 0; i < spans.size(); ++i) {
    if (overlay.isMappedImageVa(spans[i].va)) {
      keep[i] = 1;
    }
  }
  auto scan = [&](const RuntimeOverlaySpan& span, std::vector<char>& into) {
    if (span.bytes.size() < 8) {
      return;
    }
    for (size_t off = 0; off + 8 <= span.bytes.size(); off += 8) {
      uint64_t q = 0;
      std::memcpy(&q, span.bytes.data() + off, 8);
      if (q == 0 || overlay.isMappedImageVa(q)) {
        continue;
      }
      const std::ptrdiff_t idx = overlay.spanIndexContaining(q);
      if (idx >= 0) {
        into[static_cast<size_t>(idx)] = 1;
      }
    }
  };
  // Fixed-point: each hop only scans spans that were already reachable in the
  // PREVIOUS round. Writing into `next` (initialised from `keep`) rather than
  // `keep` in place is what makes this breadth-limited instead of
  // unbounded-transitive.
  for (int hop = 0; hop < 2; ++hop) {
    std::vector<char> next = keep;
    for (size_t i = 0; i < spans.size(); ++i) {
      if (keep[i]) {
        scan(spans[i], next);
      }
    }
    keep.swap(next);
  }
  return keep;
}
