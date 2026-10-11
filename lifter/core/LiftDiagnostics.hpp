#pragma once

#include <cstdint>
#include <iostream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <map>
#include <string>
#include <vector>

// Structured diagnostics for the lifting pipeline.
// Each diagnostic has a reason code, severity, optional address, and message.
// After lifting, diagnostics can be emitted as JSON for tooling consumption.
//
// The point of routing everything through here rather than printing at each
// site is that a lift is not a human-at-a-terminal activity. Regression runs,
// the rewrite baseline gate, and scripts/rewrite/* all consume
// output_diagnostics.json, and the severity split is what lets a gate decide
// pass/fail without parsing prose. AGENTS.md requires explicit failures over
// silent fallbacks; this is where those failures land.

enum class DiagSeverity : uint8_t {
  Info,    // Informational (e.g., outlining decisions, timing)
  Warning, // Non-fatal issue that may affect output quality
  Error,   // Failure that prevents correct lifting of a region
};

// Codes are explicitly numbered rather than implicitly sequenced, and grouped
// by subsystem in the hundreds digit (1xx instruction handling, 2xx control
// flow, 3xx calls, 4xx memory/PE, 5xx pipeline).
//
// The numbers are part of the external contract: scripts and gates key off
// them, so a code must never be renumbered or reused once shipped. Gaps within
// a group are intentional, leaving room to add codes without shifting the
// ones that tooling already depends on.
enum class DiagCode : uint16_t {
  // Instruction handling (1xx)
  InstructionNotImplemented = 100,
  InstructionUnsupported    = 101,

  // Control flow (2xx)
  UnresolvedIndirectJump    = 200,
  UnresolvedRetChain        = 201,
  MultiTargetSwitch         = 210,

  // Call handling (3xx)
  CallOutlinedImportThunk   = 300,
  CallOutlinedPdata         = 301,
  CallOutlinedUser          = 302,
  CallOutlinedSpecBailout   = 303,
  CallAbiApplied            = 310,
  CallIndirectUnresolved    = 311,

  // Memory / PE (4xx)
  PdataOutlineCount         = 400,
  ExportOutlineCount        = 401,
  MemoryReadFailed          = 410,

  // Pipeline (5xx)
  LiftComplete              = 500,
  OptimizationComplete      = 501,
  SignatureSearchComplete   = 502,
  LiftBlockBudgetExceeded   = 503,
  IncompleteBlockSealed     = 504,

};

struct DiagnosticEntry {
  DiagCode    code;
  DiagSeverity severity;
  uint64_t    address;    // 0 if not applicable
  std::string message;
  std::string mnemonic;   // instruction mnemonic if applicable
};

// Coarse lift counters, emitted alongside the diagnostics. These answer "how
// much did we actually do" where the diagnostics answer "what went wrong", so
// a regression shows up as a moved number even when no new diagnostic fires.
struct LiftStats {
  unsigned blocks_attempted = 0;
  unsigned blocks_completed = 0;
  unsigned blocks_unreachable = 0;
  unsigned instructions_lifted = 0;
  unsigned instructions_unsupported = 0;
};

class LiftDiagnostics {
  std::vector<DiagnosticEntry> entries;

public:
  void add(DiagCode code, DiagSeverity severity, uint64_t address,
           const std::string& message, const std::string& mnemonic = "") {
    entries.push_back({code, severity, address, message, mnemonic});
  }

  void info(DiagCode code, uint64_t address, const std::string& message) {
    add(code, DiagSeverity::Info, address, message);
  }

  void warning(DiagCode code, uint64_t address, const std::string& message,
               const std::string& mnemonic = "") {
    add(code, DiagSeverity::Warning, address, message, mnemonic);
  }

  void error(DiagCode code, uint64_t address, const std::string& message,
             const std::string& mnemonic = "") {
    add(code, DiagSeverity::Error, address, message, mnemonic);
  }

  const std::vector<DiagnosticEntry>& getEntries() const { return entries; }
  size_t size() const { return entries.size(); }
  bool empty() const { return entries.empty(); }
  // Whether the run produced any error-severity diagnostic.
  //
  // This is the gate: InitFunction_and_LiftInstructions returns
  // `!hasErrors()` as its success value, so a lift that wrote IR but recorded
  // errors is reported as a failure. That is intentional -- a partial lift that
  // mislifted a block must not read as a clean run to an automated gate.
  bool hasErrors() const { return countBySeverity(DiagSeverity::Error) != 0; }

  size_t countBySeverity(DiagSeverity sev) const {
    size_t n = 0;
    for (const auto& e : entries)
      if (e.severity == sev) ++n;
    return n;
  }

  // Emit diagnostics + profile + stats as JSON string.
  //
  // Hand-rolled rather than via a JSON library: the schema is tiny and fixed,
  // and pulling a dependency into every translation unit that includes this
  // header (which LifterClass.hpp does) is a poor trade. The cost is that this
  // function must be kept honest by hand -- see escapeJson below.
  //
  // Optional sections are omitted entirely rather than emitted as null, so a
  // consumer can distinguish "no profile was collected" from "profile was
  // zero". Trailing commas are tracked explicitly because the entry count is
  // only known after the loop starts.
  std::string toJson(const std::vector<std::pair<std::string, double>>* profile = nullptr,
                     const struct LiftStats* stats = nullptr) const {
    std::ostringstream os;
    os << "{\n";

    // Diagnostics array.
    os << "  \"diagnostics\": [\n";
    for (size_t i = 0; i < entries.size(); ++i) {
      const auto& e = entries[i];
      os << "    {";
      os << "\"code\": " << static_cast<uint16_t>(e.code);
      os << ", \"severity\": \"" << severityStr(e.severity) << "\"";
      if (e.address != 0)
        os << ", \"address\": \"0x" << std::hex << e.address << std::dec << "\"";
      if (!e.mnemonic.empty())
        os << ", \"mnemonic\": \"" << escapeJson(e.mnemonic) << "\"";
      os << ", \"message\": \"" << escapeJson(e.message) << "\"";
      os << "}";
      if (i + 1 < entries.size()) os << ",";
      os << "\n";
    }
    os << "  ],\n";

    // Profile section.
    // The profiler input is a flat (name, ms) vector, and a stage can legitimately
    // appear more than once (a loop, a re-entered phase). Summing by name in a
    // std::map both aggregates the repeats and gives deterministic key order,
    // which matters because this JSON is consumed by regression tooling that
    // diffs it.
    if (profile && !profile->empty()) {
      os << "  \"profile\": {\n";
      double total = 0;
      std::map<std::string, double> aggregatedProfile;
      for (const auto& [name, ms] : *profile) {
        aggregatedProfile[name] += ms;
        total += ms;
      }
      size_t emitted = 0;
      for (const auto& [name, ms] : aggregatedProfile) {
        os << "    \"" << escapeJson(name) << "\": " << std::fixed
           << std::setprecision(3) << ms;
        if (++emitted < aggregatedProfile.size()) os << ",";
        os << "\n";
      }
      os << "  },\n";
      os << "  \"total_ms\": " << std::fixed << std::setprecision(3) << total << ",\n";
    }

    // Lift stats.
    if (stats) {
      os << "  \"lift_stats\": {\n";
      os << "    \"blocks_attempted\": " << stats->blocks_attempted << ",\n";
      os << "    \"blocks_completed\": " << stats->blocks_completed << ",\n";
      os << "    \"blocks_unreachable\": " << stats->blocks_unreachable << ",\n";
      os << "    \"instructions_lifted\": " << stats->instructions_lifted << ",\n";
      os << "    \"instructions_unsupported\": " << stats->instructions_unsupported << "\n";
      os << "  },\n";
    }

    // Summary.
    os << "  \"summary\": {";
    os << "\"total\": " << entries.size();
    os << ", \"info\": " << countBySeverity(DiagSeverity::Info);
    os << ", \"warning\": " << countBySeverity(DiagSeverity::Warning);
    os << ", \"error\": " << countBySeverity(DiagSeverity::Error);
    os << "}\n";
    os << "}\n";
    return os.str();
  }

  // Print human-readable summary to stderr.
  //
  // stderr, not stdout: stdout carries the lifter's primary output and is
  // redirected by scripts, while these lines are diagnostics for whoever is
  // watching the run. Silent on a clean run -- Info-only output is not noise
  // worth printing when there is nothing to act on.
  void printSummary() const {
    size_t warnings = countBySeverity(DiagSeverity::Warning);
    size_t errors = countBySeverity(DiagSeverity::Error);
    if (errors > 0)
      std::cerr << "[diagnostics] " << errors << " error(s), "
                << warnings << " warning(s)\n";
    else if (warnings > 0)
      std::cerr << "[diagnostics] " << warnings << " warning(s)\n";
  }

private:
  static const char* severityStr(DiagSeverity s) {
    switch (s) {
    case DiagSeverity::Info: return "info";
    case DiagSeverity::Warning: return "warning";
    case DiagSeverity::Error: return "error";
    }
    return "unknown";
  }

  // Escape a string for embedding in JSON.
  //
  // Messages are assembled from mnemonics, file paths, and disassembly text,
  // so they can and do contain quotes, backslashes, and newlines. An unescaped
  // quote would produce malformed JSON and take down every consumer of
  // output_diagnostics.json, not just this entry -- which is why the control
  // character arm covers everything below 0x20 rather than just \n, \r, \t.
  //
  // Bytes are iterated as `unsigned char` deliberately: signed char would make
  // c < 0x20 false for 0x80..0xFF and silently emit raw high bytes.
  static std::string escapeJson(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
      if (c == '"')       out += "\\\"";
      else if (c == '\\') out += "\\\\";
      else if (c == '\n') out += "\\n";
      else if (c == '\r') out += "\\r";
      else if (c == '\t') out += "\\t";
      else if (c < 0x20) {
        // Escape all other control characters as \uXXXX.
        char buf[8];
        snprintf(buf, sizeof(buf), "\\u%04x", c);
        out += buf;
      } else {
        out += static_cast<char>(c);
      }
    }
    return out;
  }
};

// Scoped timer for pipeline profiling. Records elapsed wall-clock time
// for each named stage into a vector of (name, milliseconds) pairs.
//
// Two ways to record, both landing in the same vector:
//   begin/end  explicit pairing, used by the pipeline stages, which call
//              profiler.begin("lift") ... profiler.end() in sequence
//   sample()   RAII ScopedSample, for sub-regions that must not be able to
//              skip the end call on an early return
// Both may be mixed; the vector is a flat event log and toJson aggregates by
// name.
class PipelineProfiler {
  using clock = std::chrono::high_resolution_clock;
  using time_point = std::chrono::time_point<clock>;

  std::vector<std::pair<std::string, double>> stages;
  std::string currentStage;
  time_point stageStart;
  bool running = false;

public:
  // RAII sample guard. The moved-from object nulls its `profiler` pointer so
  // that the destructor of the moved-to-from temporary does not record a
  // duplicate sample -- without that, moving a ScopedSample would double-count
  // the interval.
  class ScopedSample {
    PipelineProfiler* profiler;
    std::string name;
    time_point start;

  public:
    ScopedSample(PipelineProfiler& profilerRef, const std::string& sampleName)
        : profiler(&profilerRef), name(sampleName), start(clock::now()) {}

    ScopedSample(const ScopedSample&) = delete;
    ScopedSample& operator=(const ScopedSample&) = delete;

    ScopedSample(ScopedSample&& other) noexcept
        : profiler(other.profiler), name(std::move(other.name)),
          start(other.start) {
      other.profiler = nullptr;
    }

    ScopedSample& operator=(ScopedSample&& other) noexcept {
      if (this == &other)
        return *this;
      if (profiler) {
        profiler->addSample(
            name, std::chrono::duration<double, std::milli>(clock::now() - start).count());
      }
      profiler = other.profiler;
      name = std::move(other.name);
      start = other.start;
      other.profiler = nullptr;
      return *this;
    }

    ~ScopedSample() {
      if (!profiler)
        return;
      profiler->addSample(
          name, std::chrono::duration<double, std::milli>(clock::now() - start).count());
    }
  };

  // begin() closes any open stage first. Forgiving in this way means a missing
  // end() cannot leave the profiler permanently "running" -- every subsequent
  // begin() implicitly closes the previous one rather than nesting or
  // recording a bogus interval.
  void begin(const std::string& name) {
    end(); // close previous stage if any
    currentStage = name;
    stageStart = clock::now();
    running = true;
  }

  void end() {
    if (!running) return;
    auto elapsed = std::chrono::duration<double, std::milli>(
        clock::now() - stageStart).count();
    stages.push_back({currentStage, elapsed});
    running = false;
  }

  void addSample(const std::string& name, double elapsedMilliseconds) {
    stages.push_back({name, elapsedMilliseconds});
  }

  ScopedSample sample(const std::string& name) {
    return ScopedSample(*this, name);
  }

  const std::vector<std::pair<std::string, double>>& getStages() const {
    return stages;
  }
};
