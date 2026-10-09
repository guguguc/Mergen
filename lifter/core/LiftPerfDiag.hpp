#pragma once

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

  struct Acc {
    uint64_t count = 0;
    double totalMs = 0.0;

    void add(double ms) {
      ++count;
      totalMs += ms;
    }

    double avgMs() const { return count ? totalMs / static_cast<double>(count) : 0.0; }
  };

  Acc solvePath;
  Acc solvePathCpv;
  Acc solvePathGcv;
  Acc solvePathConstResolve;
  Acc solvePathConstBackup;
  Acc solvePathConstBr;
  Acc cpvTotal;
  Acc backupMove;
  Acc backupCopy;

  Acc folderPattern;
  Acc folderCreate;
  Acc folderKnownBits;
  Acc folderProvenance;
  Acc icmpPattern;
  Acc icmpKnownBits;
  Acc truncKnownBits;

  Acc regGet;
  Acc regSet;
  Acc flagGet;
  Acc flagSet;
  Acc decode;

  uint64_t constBackupSkipped = 0;
  uint64_t constBackupTaken = 0;

  uint64_t folderCalls = 0;
  uint64_t folderExitEarly = 0;
  uint64_t folderPatternHit = 0;
  uint64_t folderCreateUsed = 0;
  uint64_t folderExitKnownConst = 0;
  uint64_t folderExitKeepInst = 0;

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

  uint64_t cpvCacheHits = 0;
  uint64_t cpvDepthCut = 0;
  uint64_t cpvResultEmpty = 0;
  uint64_t cpvResultOne = 0;
  uint64_t cpvResultTwo = 0;
  uint64_t cpvResultFew = 0;
  uint64_t cpvResultMany = 0;
  double cpvMaxMs = 0.0;

  std::array<uint64_t, 256> cpvRootOpcode{};

  std::array<uint64_t, 5> solvePathContext{};

  std::map<std::string, uint64_t> solvePathOutcomes;

  uint64_t gcvCalls = 0;
  uint64_t gcvSolvedConst = 0;
  uint64_t gcvSolvedFold = 0;
  uint64_t gcvSolvedSimplify = 0;
  uint64_t gcvUnsolved = 0;

  std::map<uint64_t, uint64_t> solvePathSiteCalls;

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

  static bool envEnabled() {
    const char* env = std::getenv("MERGEN_DIAG_PERF");
    if (env == nullptr) {
      return false;
    }
    const std::string_view value(env);
    return value == "1" || value == "true" || value == "TRUE";
  }

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
       << " lazy=" << flagSetLazyCalls << " total_ms=" << flagSet.totalMs
       << "\n";
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
