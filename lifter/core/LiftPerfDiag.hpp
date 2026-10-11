#pragma once

// Optional lift-time performance instrumentation.
//
// Off unless MERGEN_DIAG_PERF is set to 1/true/TRUE (see envEnabled). Every
// accounting path below checks `enabled` before touching anything, so the
// default cost is one predictable branch per probe site, not a data race and
// not a lock.
//
// Intended use: find out *where* a slow lift is spending its time, and more
// usefully, which of the lifter's internal strategies is dominating. The
// counters that matter most for that are not the timers but the histograms:
// `cpvResult*` (how wide the possible-value set is at each constant-propagation
// query) and `solvePathSiteCalls` (which call sites enter the path solver)
// together identify the specific instruction that is making the solver
// expensive, which a total-ms figure cannot.
//
// Naming shorthand used throughout:
//   cpv   computePossibleValues
//   gcv   getConstraintVal
//   RVA   the site counters are keyed by call-site address

#include <algorithm>
#include <array>
#include <cstdlib>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <string_view>
#include <vector>

struct LiftPerfDiag {
  bool enabled = false;

  // A timing bucket: call count plus accumulated milliseconds.
  //
  // count and totalMs are kept separately rather than only an average, because
  // a single pathological call and a broad cheap cost can produce the same
  // average and need completely different fixes.
  struct Acc {
    uint64_t count = 0;
    double totalMs = 0.0;

    void add(double ms) {
      ++count;
      totalMs += ms;
    }

    // Guards the division rather than returning NaN, so an unprobed bucket
    // prints as 0.0 in the dump instead of poisoning a column of averages.
    double avgMs() const { return count ? totalMs / static_cast<double>(count) : 0.0; }
  };

  // --- solvePath breakdown -----------------------------------------------
  //
  // solvePath is the total; the rest are nested inside it, not siblings. The
  // constant-backup timers are separate from the constant-resolve timer
  // because a backup can be taken without a resolve happening.
  Acc solvePath;
  Acc solvePathCpv;
  Acc solvePathGcv;
  Acc solvePathConstResolve;
  Acc solvePathConstBackup;
  Acc solvePathConstBr;
  Acc cpvTotal;
  // Move-vs-copy split for the constant backup. Taken/skipped below records
  // how often a backup happened at all.
  Acc backupMove;
  Acc backupCopy;

  // --- folding / known-bits ----------------------------------------------
  //
  // folderPattern and folderCreate are mutually exclusive outcomes of one
  // folder attempt: match an existing instruction pattern, or build a fresh
  // instruction. folderKnownBits is the known-bits reasoning underneath both.
  Acc folderPattern;
  Acc folderCreate;
  Acc folderKnownBits;
  Acc folderProvenance;
  Acc icmpPattern;
  Acc icmpKnownBits;
  Acc truncKnownBits;

  // --- instruction construction ------------------------------------------
  //
  // createCacheInsert is the cost of recording a newly built instruction for
  // pattern reuse; createComplexity is the complexity estimate that decides
  // whether folding is worth attempting at all. If the latter dominates, the
  // expensive part is deciding not to fold.
  Acc createLookup;
  Acc createSelectDist;
  Acc createBinOp;
  Acc createCast;
  Acc createCacheInsert;
  Acc createComplexity;
  Acc createFoldOrigin;

  // --- register and flag access ------------------------------------------
  Acc regGet;
  Acc regSet;
  Acc flagGet;
  Acc flagSet;
  Acc flagSetLazyCalc;
  Acc flagSetStore;
  Acc decode;

  // --- outcome counters ---------------------------------------------------
  uint64_t constBackupSkipped = 0;
  uint64_t constBackupTaken = 0;

  uint64_t folderCalls = 0;
  uint64_t folderExitEarly = 0;
  uint64_t folderPatternHit = 0;
  uint64_t folderCreateUsed = 0;
  uint64_t folderExitKnownConst = 0;
  uint64_t folderExitKeepInst = 0;

  // The reg/flag subtallies split the calls by the path taken. These exist
  // because the totals alone cannot distinguish "one expensive high-byte
  // access" from "many cheap ones", and those have different fixes.
  uint64_t regGetCalls = 0;
  uint64_t regSetCalls = 0;
  uint64_t regGetHighByte = 0;
  uint64_t regGetRflags = 0;
  uint64_t regSetSub8 = 0;
  uint64_t regSetSub16 = 0;
  uint64_t regSetZext32 = 0;
  uint64_t regSetRflags = 0;

  uint64_t flagGetCalls = 0;
  uint64_t flagSetCalls = 0;
  uint64_t flagSetLazyCalls = 0;
  uint64_t flagSetEagerCalls = 0;
  // Indexed by flag id; sized 32 to cover the x86 flag identifiers the
  // semantics layer uses. Callers must bounds-check before indexing.
  std::array<uint64_t, 32> flagSetById{};

  uint64_t createCalls = 0;
  uint64_t createCacheHits = 0;
  uint64_t createCacheMisses = 0;
  uint64_t createSelectDistEntered = 0;
  uint64_t createSelectDistHit = 0;
  uint64_t createPlainBinOp = 0;
  uint64_t createCastPath = 0;
  // Indexed by opcode; 256 covers the x86 opcode space the lifter dispatches
  // on. Wider indices are dropped by noteCpvRootOpcode's bounds check rather
  // than wrapped, so the histogram stays a valid count.
  std::array<uint64_t, 256> createOpcode{};

  // cpvResult* is a width histogram: how many possible values came back from
  // a constant-propagation query. A run dominated by cpvResultMany is where
  // the path solver is spending its time on sets too wide to act on.
  uint64_t cpvCacheHits = 0;
  uint64_t cpvDepthCut = 0;
  uint64_t cpvResultEmpty = 0;
  uint64_t cpvResultOne = 0;
  uint64_t cpvResultTwo = 0;
  uint64_t cpvResultFew = 0;
  uint64_t cpvResultMany = 0;
  double cpvMaxMs = 0.0;

  std::array<uint64_t, 256> cpvRootOpcode{};

  // Indexed by call-site context: unknown/cond/direct/indirect-jump/ret,
  // matching the labels printed in dump().
  std::array<uint64_t, 5> solvePathContext{};

  std::map<std::string, uint64_t> solvePathOutcomes;

  // getConstraintVal resolution provenance: how often each strategy produced
  // the answer. A rising `simplify` count relative to `const` and `fold` means
  // the solver is increasingly relying on LLVM simplification rather than on
  // its own analysis.
  uint64_t gcvCalls = 0;
  uint64_t gcvSolvedConst = 0;
  uint64_t gcvSolvedFold = 0;
  uint64_t gcvSolvedSimplify = 0;
  uint64_t gcvUnsolved = 0;

  // Per-call-site solvePath entry counts. Keyed by VA so the top offenders can
  // be mapped straight back to the instruction that caused them.
  std::map<uint64_t, uint64_t> solvePathSiteCalls;

  // RAII timer for a timing bucket.
  //
  // The construction trick is the point: when diagnostics are off, `diag` and
  // `bucket` are both nulled out and `start` is left default-constructed. The
  // destructor then takes a single branch and returns without ever reading the
  // clock. Call sites stay unconditional ("always construct a ScopedTimer")
  // rather than being wrapped in `if (perf.enabled)` at every probe site,
  // which keeps the instrumentation from drifting out of sync with the code it
  // measures -- the usual way these decay.
  class ScopedTimer {
    LiftPerfDiag* diag;
    Acc* bucket;
    std::chrono::high_resolution_clock::time_point start;

  public:
    ScopedTimer(LiftPerfDiag* d, Acc* b)
        : diag(d != nullptr && d->enabled ? d : nullptr),
          bucket(diag != nullptr ? b : nullptr),
          start(bucket != nullptr ? std::chrono::high_resolution_clock::now()
                                  : std::chrono::high_resolution_clock::time_point{}) {}

    ~ScopedTimer() {
      if (diag == nullptr || bucket == nullptr) {
        return;
      }
      const double ms = std::chrono::duration<double, std::milli>(
                            std::chrono::high_resolution_clock::now() - start)
                            .count();
      bucket->add(ms);
    }
  };

  // Bounds-checked histogram updates. The `>= size()` guards are not defensive
  // padding: an out-of-range index silently truncating to a nearby bucket would
  // make the profile point at the wrong opcode, which is worse than losing the
  // sample.

  void noteSolvePathContext(unsigned ctx) {
    if (!enabled || ctx >= solvePathContext.size()) {
      return;
    }
    ++solvePathContext[ctx];
  }

  void noteSolvePathOutcome(const char* name) {
    if (!enabled || name == nullptr) {
      return;
    }
    ++solvePathOutcomes[name];
  }

  void noteSolvePathSite(uint64_t site) {
    if (!enabled) {
      return;
    }
    ++solvePathSiteCalls[site];
  }

  // Bucket a cpv result set by width. The breakpoints are 0/1/2/3-8/9+ because
  // those are the cases with different remedies: 1 is the fast path, 2 is a
  // diamond the solver can still resolve, and 9+ is where the set is too wide
  // to act on and the work is largely wasted.
  void noteCpvResult(size_t n) {
    if (!enabled) {
      return;
    }
    if (n == 0) {
      ++cpvResultEmpty;
    } else if (n == 1) {
      ++cpvResultOne;
    } else if (n == 2) {
      ++cpvResultTwo;
    } else if (n <= 8) {
      ++cpvResultFew;
    } else {
      ++cpvResultMany;
    }
  }

  void noteCpvRootOpcode(unsigned opcode) {
    if (!enabled || opcode >= cpvRootOpcode.size()) {
      return;
    }
    ++cpvRootOpcode[opcode];
  }

  void noteCpvElapsed(double ms) {
    if (!enabled) {
      return;
    }
    if (ms > cpvMaxMs) {
      cpvMaxMs = ms;
    }
  }

  // Strict allowlist rather than "any value except 0/false/off". Being liberal
  // here would mean a typo like MERGEN_DIAG_PERF=yes silently enabling
  // instrumentation on every run, and the resulting slowdown would look like a
  // regression in the lifter rather than in the environment.
  static bool envEnabled() {
    const char* env = std::getenv("MERGEN_DIAG_PERF");
    if (env == nullptr) {
      return false;
    }
    const std::string_view value(env);
    return value == "1" || value == "true" || value == "TRUE";
  }

  // Render the whole report to a stream. No-ops entirely when disabled, so
  // callers can invoke this unconditionally.
  //
  // Ordered by subsystem rather than by declaration, because the report is
  // read top-down: find the dominant subsystem, read its sub-breakdown, then
  // jump to the site/opcode histograms at the end. The two "top N" opcode
  // tables and the site table are printed last for the same reason -- they are
  // the drill-down, not the overview.
  void dump(std::ostream& os) const {
    if (!enabled) {
      return;
    }

    os << "[perf] lift solvePath calls=" << solvePath.count
       << " total_ms=" << std::fixed << std::setprecision(1) << solvePath.totalMs
       << " avg_ms=" << solvePath.avgMs() << "\n";
    os << "[perf]   solvePath_cpv calls=" << solvePathCpv.count
       << " total_ms=" << solvePathCpv.totalMs << " avg_ms=" << solvePathCpv.avgMs()
       << " max_ms=" << cpvMaxMs << "\n";
    os << "[perf]   solvePath_gcv calls=" << solvePathGcv.count
       << " total_ms=" << solvePathGcv.totalMs << " avg_ms=" << solvePathGcv.avgMs()
       << "\n";
    os << "[perf]   const_resolve calls=" << solvePathConstResolve.count
       << " total_ms=" << solvePathConstResolve.totalMs
       << " avg_ms=" << solvePathConstResolve.avgMs() << "\n";
    os << "[perf]   const_backup calls=" << solvePathConstBackup.count
       << " total_ms=" << solvePathConstBackup.totalMs
       << " avg_ms=" << solvePathConstBackup.avgMs()
       << " taken=" << constBackupTaken << " skipped=" << constBackupSkipped
       << "\n";
    os << "[perf]   backup_move calls=" << backupMove.count
       << " total_ms=" << backupMove.totalMs << " avg_ms=" << backupMove.avgMs()
       << "\n";
    os << "[perf]   backup_copy calls=" << backupCopy.count
       << " total_ms=" << backupCopy.totalMs << " avg_ms=" << backupCopy.avgMs()
       << "\n";
    os << "[perf]   const_br calls=" << solvePathConstBr.count
       << " total_ms=" << solvePathConstBr.totalMs
       << " avg_ms=" << solvePathConstBr.avgMs() << "\n";
    os << "[perf]   cpv_total calls=" << cpvTotal.count
       << " total_ms=" << cpvTotal.totalMs << " avg_ms=" << cpvTotal.avgMs()
       << " cache_hits=" << cpvCacheHits << " depth_cut=" << cpvDepthCut << "\n";
    os << "[perf]   cpv_results empty/1/2/3-8/9+ = " << cpvResultEmpty << "/"
       << cpvResultOne << "/" << cpvResultTwo << "/" << cpvResultFew << "/"
       << cpvResultMany << "\n";

    os << "[perf]   gcv calls=" << gcvCalls << " const=" << gcvSolvedConst
       << " fold=" << gcvSolvedFold << " simplify=" << gcvSolvedSimplify
       << " unsolved=" << gcvUnsolved << "\n";

    os << "[perf]   solvePath_context unknown/cond/direct/ijmp/ret = "
       << solvePathContext[0] << "/" << solvePathContext[1] << "/"
       << solvePathContext[2] << "/" << solvePathContext[3] << "/"
       << solvePathContext[4] << "\n";

    os << "[perf]   solvePath_outcomes:";
    for (const auto& [name, count] : solvePathOutcomes) {
      os << " " << name << "=" << count;
    }
    os << "\n";

    os << "[perf] folder calls=" << folderCalls
       << " early=" << folderExitEarly << " pattern_hit=" << folderPatternHit
       << " create=" << folderCreateUsed
       << " known_const=" << folderExitKnownConst
       << " keep_inst=" << folderExitKeepInst << "\n";
    os << "[perf]   folder_pattern calls=" << folderPattern.count
       << " total_ms=" << folderPattern.totalMs
       << " avg_ms=" << folderPattern.avgMs() << "\n";
    os << "[perf]   folder_create calls=" << folderCreate.count
       << " total_ms=" << folderCreate.totalMs
       << " avg_ms=" << folderCreate.avgMs() << "\n";
    os << "[perf]   folder_knownbits calls=" << folderKnownBits.count
       << " total_ms=" << folderKnownBits.totalMs
       << " avg_ms=" << folderKnownBits.avgMs() << "\n";
    os << "[perf]   folder_provenance calls=" << folderProvenance.count
       << " total_ms=" << folderProvenance.totalMs
       << " avg_ms=" << folderProvenance.avgMs() << "\n";
    os << "[perf]   icmp_pattern calls=" << icmpPattern.count
       << " total_ms=" << icmpPattern.totalMs
       << " avg_ms=" << icmpPattern.avgMs() << "\n";
    os << "[perf]   icmp_knownbits calls=" << icmpKnownBits.count
       << " total_ms=" << icmpKnownBits.totalMs
       << " avg_ms=" << icmpKnownBits.avgMs() << "\n";
    os << "[perf]   trunc_knownbits calls=" << truncKnownBits.count
       << " total_ms=" << truncKnownBits.totalMs
       << " avg_ms=" << truncKnownBits.avgMs() << "\n";

    os << "[perf] create calls=" << createCalls
       << " cache_hit=" << createCacheHits
       << " cache_miss=" << createCacheMisses
       << " select_enter=" << createSelectDistEntered
       << " select_hit=" << createSelectDistHit
       << " plain_binop=" << createPlainBinOp
       << " cast=" << createCastPath << "\n";
    os << "[perf]   create_lookup calls=" << createLookup.count
       << " total_ms=" << createLookup.totalMs
       << " avg_ms=" << createLookup.avgMs() << "\n";
    os << "[perf]   create_select_dist calls=" << createSelectDist.count
       << " total_ms=" << createSelectDist.totalMs
       << " avg_ms=" << createSelectDist.avgMs() << "\n";
    os << "[perf]   create_binop calls=" << createBinOp.count
       << " total_ms=" << createBinOp.totalMs
       << " avg_ms=" << createBinOp.avgMs() << "\n";
    os << "[perf]   create_cast calls=" << createCast.count
       << " total_ms=" << createCast.totalMs
       << " avg_ms=" << createCast.avgMs() << "\n";
    os << "[perf]   create_cache_insert calls=" << createCacheInsert.count
       << " total_ms=" << createCacheInsert.totalMs
       << " avg_ms=" << createCacheInsert.avgMs() << "\n";
    os << "[perf]   create_complexity calls=" << createComplexity.count
       << " total_ms=" << createComplexity.totalMs
       << " avg_ms=" << createComplexity.avgMs() << "\n";
    os << "[perf]   create_fold_origin calls=" << createFoldOrigin.count
       << " total_ms=" << createFoldOrigin.totalMs
       << " avg_ms=" << createFoldOrigin.avgMs() << "\n";
    os << "[perf]   create_opcode top:";
    // Ranked drill-down: the ten most frequent opcodes at create time.
    {
      std::vector<std::pair<unsigned, uint64_t>> createRank;
      for (unsigned op = 0; op < createOpcode.size(); ++op) {
        if (createOpcode[op] != 0) {
          createRank.emplace_back(op, createOpcode[op]);
        }
      }
      std::sort(createRank.begin(), createRank.end(),
                [](const auto& a, const auto& b) { return a.second > b.second; });
      const size_t topN = std::min<size_t>(createRank.size(), 10);
      for (size_t i = 0; i < topN; ++i) {
        os << " op" << createRank[i].first << "=" << createRank[i].second;
      }
      os << "\n";
    }

    os << "[perf] reg_get calls=" << regGetCalls
       << " total_ms=" << regGet.totalMs << " highbyte=" << regGetHighByte
       << " rflags=" << regGetRflags << "\n";
    os << "[perf] reg_set calls=" << regSetCalls
       << " total_ms=" << regSet.totalMs << " sub8=" << regSetSub8
       << " sub16=" << regSetSub16 << " zext32=" << regSetZext32
       << " rflags=" << regSetRflags << "\n";
    os << "[perf] flag_get calls=" << flagGetCalls
       << " total_ms=" << flagGet.totalMs << "\n";
    os << "[perf] flag_set calls=" << flagSetCalls
       << " eager=" << flagSetEagerCalls << " lazy=" << flagSetLazyCalls
       << " total_ms=" << flagSet.totalMs << "\n";
    os << "[perf]   flag_set_lazy_calc calls=" << flagSetLazyCalc.count
       << " total_ms=" << flagSetLazyCalc.totalMs
       << " avg_ms=" << flagSetLazyCalc.avgMs() << "\n";
    os << "[perf]   flag_set_store calls=" << flagSetStore.count
       << " total_ms=" << flagSetStore.totalMs
       << " avg_ms=" << flagSetStore.avgMs() << "\n";
    os << "[perf]   flag_set_by_id:";
    for (unsigned i = 0; i < flagSetById.size(); ++i) {
      if (flagSetById[i] != 0) {
        os << " f" << i << "=" << flagSetById[i];
      }
    }
    os << "\n";
    os << "[perf] decode calls=" << decode.count
       << " total_ms=" << decode.totalMs << " avg_ms=" << decode.avgMs()
       << "\n";

    os << "[perf]   cpv_root_opcode top:";
    std::vector<std::pair<unsigned, uint64_t>> opcodeRank;
    for (unsigned op = 0; op < cpvRootOpcode.size(); ++op) {
      if (cpvRootOpcode[op] != 0) {
        opcodeRank.emplace_back(op, cpvRootOpcode[op]);
      }
    }
    std::sort(opcodeRank.begin(), opcodeRank.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    const size_t topOpcodes = std::min<size_t>(opcodeRank.size(), 8);
    for (size_t i = 0; i < topOpcodes; ++i) {
      os << " op" << opcodeRank[i].first << "=" << opcodeRank[i].second;
    }
    os << "\n";

    // Ranked drill-down: the twelve call sites that entered solvePath most often.
    // This is the table that turns a profile into a specific address to look
    // at -- the site VA maps back to the instruction that caused the work.
    std::vector<std::pair<uint64_t, uint64_t>> siteRank;
    siteRank.reserve(solvePathSiteCalls.size());
    for (const auto& [site, count] : solvePathSiteCalls) {
      siteRank.emplace_back(site, count);
    }
    std::sort(siteRank.begin(), siteRank.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    const size_t topSites = std::min<size_t>(siteRank.size(), 12);
    os << "[perf]   solvePath_sites top-" << topSites << " by cpv-entry:";
    for (size_t i = 0; i < topSites; ++i) {
      os << " 0x" << std::hex << siteRank[i].first << std::dec << "x"
         << siteRank[i].second;
    }
    os << "\n" << std::flush;
  }
};
