#pragma once

// Argument parsing and file slurping for the CLI.
//
// Every function here reports failure by return value plus a message on
// std::cerr. None of them throw, none of them exit: the test harness drives
// these directly to cover the negative cases, so an explicit bool contract is
// what lets `python test.py negative` assert on the failure path.

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

inline void printLifterUsage(const char* executableName) {
  std::cerr << "Usage: " << executableName << " <filename> <startAddr>"
            << std::endl;
}

inline bool parseStartAddressArg(const std::string& rawStartAddress,
                                 uint64_t& outStartAddress) {
  try {
    size_t parsedLength = 0;
    // Base 0 lets one parser accept every form an analyst actually types:
    // bare decimal ("4194304"), C-style hex ("0x401000"), and octal. Addresses
    // in this workflow are overwhelmingly quoted in hex, so requiring a 0x
    // prefix would be a pointless papercut.
    //
    // parsedLength is the number of characters stoull actually consumed, and
    // requiring it to equal the whole string is what rejects trailing garbage.
    // Without that check "401000xyz" would silently lift from 0x401000 and the
    // typo would surface much later as a nonsensical IR dump rather than as a
    // usage error at the command line.
    outStartAddress = stoull(rawStartAddress, &parsedLength, 0);
    return parsedLength == rawStartAddress.size();
  } catch (const std::exception& ex) {
    // stoull throws on an empty string or on overflow. Both are genuine user
    // errors rather than internal faults, so they are reported, not rethrown.
    std::cerr << "Failed to parse start address '" << rawStartAddress
              << "': " << ex.what() << std::endl;
    return false;
  }
}

inline bool readBinaryFile(const std::string& filename,
                           std::vector<uint8_t>& outFileData) {
  // ios::ate seeks to the end on open, which yields the size in a single open
  // instead of a stat() followed by a seek.
  std::ifstream ifs(filename, std::ios::binary | std::ios::ate);
  if (!ifs.is_open()) {
    std::cerr << "Failed to open file: " << filename << std::endl;
    return false;
  }

  const std::streamsize fileSize = ifs.tellg();
  if (fileSize <= 0) {
    // Covers both a genuinely empty file and a tellg() that failed. Rejecting
    // size 0 matters because every downstream consumer assumes the buffer
    // holds at least a DOS header; letting a 0-byte file through would turn
    // this into an out-of-bounds read inside the PE parser instead of a
    // clean CLI error here.
    std::cerr << "Input file is empty or unreadable: " << filename << std::endl;
    return false;
  }

  outFileData.resize(static_cast<size_t>(fileSize));
  // Explicitly rewind: ios::ate left the position at EOF, so read() would
  // otherwise pull nothing.
  ifs.seekg(0, std::ios::beg);
  if (!ifs.read(reinterpret_cast<char*>(outFileData.data()), fileSize)) {
    // Short read. Reported rather than tolerated: a truncated buffer reads as
    // zero-filled tail bytes and produces a lifter that appears to run but
    // mislifts anything past the truncation point.
    std::cerr << "Failed to read file bytes: " << filename << std::endl;
    return false;
  }

  return true;
}
