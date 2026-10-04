#pragma once

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

  bool isMappedImageVa(uint64_t va) const {
    va = canonicalVa(va);
    return imageSize != 0 && peImageBase != 0 && va >= peImageBase &&
           va < peImageBase + imageSize;
  }

  uint64_t canonicalVa(uint64_t va) const {
    if (imageSize != 0 && dumpImageBase != 0 && peImageBase != 0 &&
        dumpImageBase != peImageBase && va >= dumpImageBase &&
        va < dumpImageBase + imageSize) {
      return peImageBase + (va - dumpImageBase);
    }
    return va;
  }

  bool covers(uint64_t va, unsigned n) const {
    if (n == 0) {
      return false;
    }
    va = canonicalVa(va);
    const RuntimeOverlaySpan* s = find(va);
    return s && va >= s->va && va + n <= s->va + s->bytes.size();
  }

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
