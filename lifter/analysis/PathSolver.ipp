#pragma once

#include "CommonDisassembler.hpp"
#include "PathSolver.h"
#include "LifterClass.hpp"
#include "LifterDiagHelpers.hpp"
#include "Utils.h"
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/MemorySSA.h>
#include <llvm/Analysis/MemorySSAUpdater.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/ConstantFold.h>
#include <llvm/Support/Casting.h>
#include <functional>
#include <limits>
#include <optional>

MERGEN_LIFTER_DEFINITION_TEMPLATES(PATH_info)::solvePath(
    llvm::Function* function, uint64_t& dest, Value* simplifyValue) {
  auto pathSolveSample = profiler.sample("lift_path_solve");
  const bool perf = perfDiag.enabled;
  LiftPerfDiag::ScopedTimer solveTimer(perf ? &perfDiag : nullptr,
                                       perf ? &perfDiag.solvePath : nullptr);
  if (perf) {
    perfDiag.noteSolvePathContext(
        static_cast<unsigned>(currentPathSolveContext));
  }
  auto finishSolvePath = [&](const char* outcome, PATH_info rv) -> PATH_info {
    if (perf) {
      perfDiag.noteSolvePathOutcome(outcome);
    }
    return rv;
  };

  const uint64_t pathSolveSite = current_address - instruction.length;
  auto normalizeTargetAddress = [&](uint64_t target) -> uint64_t {
    return normalizeRuntimeTargetAddress(target);
  };

  struct ResolvedTargetBlock {
    BasicBlock* block;
    bool reusedBackedge;
    bool generalizedBackup;
  };

  // Local cache is enough: all import-resolution lambdas live in this call.
  // Avoid make_shared on the 42k-call const fast path.
  std::unordered_map<uint64_t, BasicBlock*> importBlocks;
  auto resolveImportTarget = [&](uint64_t target) -> BasicBlock* {
    auto importIt = importMap.find(target);
    if (importIt == importMap.end()) return nullptr;
    auto cached = importBlocks.find(target);
    if (cached != importBlocks.end()) return cached->second;
    const std::string& importName = importIt->second;
    BasicBlock* importBB = BasicBlock::Create(
        builder->getContext(), "bb_import_" + importName, fnc);
    BasicBlock* savedBB = builder->GetInsertBlock();
    auto savedIP = builder->GetInsertPoint();
    builder->SetInsertPoint(importBB);
    callFunctionIR(importName, nullptr);
    builder->CreateUnreachable();
    builder->SetInsertPoint(savedBB, savedIP);
    diagnostics.info(
        DiagCode::CallOutlinedImportThunk,
        current_address - instruction.length,
        "Resolved indirect-transfer import: " + importName);
    importBlocks[target] = importBB;
    return importBB;
  };

  auto resolveTargetBlock = [&](uint64_t target, const std::string& name)
      -> ResolvedTargetBlock {
    if (auto* reused = getLiftedBackedgeBB(target)) {
      record_generalized_loop_backedge(reused);
      return {reused, true, false};
    }
    // Import recognition: if the resolved target is an entry in importMap
    // (IAT slot VA or its hint/name VA alias), the transfer is actually
    // a call to a named external function.  Materialise a leaf block with
    // call @import + unreachable so we do not follow into Kernel32 or
    // try to lift the on-disk hint/name bytes as code.
    if (auto* importBB = resolveImportTarget(target)) {
      // Mark as reusedBackedge so solvePath skips queuing the target for
      // further lifting - the import block is a terminal leaf, attempting
      // to lift at its 'address' (an IAT slot or hint/name VA) would try
      // to decode on-disk data as code.
      return {importBB, /*reusedBackedge=*/true, /*generalizedBackup=*/false};
    }

    const bool backwardVisitedTarget =
        visitedAddresses.contains(target) &&
        target <= blockInfo.block_address;
    // VMProtect's dispatch encodes (VIP, vm-id) and derives the native handler
    // address from them (intel.cc:11731/11734), so a backward native target is
    // not a stable loop key: the same handler recurs across the 10 vm instances
    // without the virtual program counter repeating. Only generalize a loop
    // when an *exact* VIP (from the transfer load DAG) has been seen before.
    // Cursor-heuristic VIP (exact=0) repeats across Ultra handlers without the
    // pcode PC advancing and would close the lift early (sticky 0x1402e47e4 →
    // 105k) or on a clobbered handler VA (0x403c48fc → 405604).
    bool vipConfirmsBackedge = false;
    bool vipRepeat = false;
    if (currentVipOffset != 0) {
      // Key the backedge on (VIP, native target). Repeating a native block is
      // normal for VMProtect - the same handler runs for many different VM
      // commands - so the native address alone is not a loop. A real loop
      // repeats the same VM command AND the same handler.
      const uint64_t backedgeKey =
          currentVipOffset * 1099511628211ULL + target;
      vipRepeat = seenVipOffsets.contains(backedgeKey);
      seenVipOffsets.insert(backedgeKey);
      vipConfirmsBackedge = vipRepeat && currentVipIsExact;
    }
    if (backwardVisitedTarget && vipDiagEnabled) {
      // Unconditional cout+flush here previously dominated PathSolver time.
      std::cout << "[vip] backward target=0x" << std::hex << target
                << " cur=0x" << blockInfo.block_address << " vip=0x"
                << currentVipOffset << std::dec
                << " repeat=" << (vipRepeat ? 1 : 0)
                << " exact=" << (currentVipIsExact ? 1 : 0)
                << " confirm=" << (vipConfirmsBackedge ? 1 : 0) << "\n";
    }
    auto it = addrToBB.find(target);
    const bool hasPendingGeneralization =
        pendingLoopGeneralizationAddresses.contains(target);
    // `resolveTargetBlock` is only reached with a concrete destination, so an
    // indirect jump whose target has just resolved participates in the same
    // structured-loop generalization path that direct and conditional jumps
    // already take.
    const bool canUseStructuredLoopGeneralization =
        currentPathSolveAllowsStructuredLoopGeneralizationForResolvedTarget();
    const bool canReusePendingGeneralization =
        hasPendingGeneralization && canUseStructuredLoopGeneralization;
    const bool wantsGeneralization =
        canReusePendingGeneralization ||
        (backwardVisitedTarget && vipConfirmsBackedge &&
         canGeneralizeStructuredLoopHeader(target,
                                           /*targetResolvedConcretely=*/true));
    if (wantsGeneralization) {
      // A resolved backward target participates in the same stack-concolic
      // bypass regime regardless of whether the source jump is direct or
      // indirect — both represent a confirmed loop back-edge.
      if (currentPathSolveContext == PathSolveContext::DirectJump ||
          currentPathSolveContext == PathSolveContext::IndirectJump) {
        stackBypassGeneralizedLoopAddresses.insert(target);
      }
      const bool generalizedBackup =
          canUseStructuredLoopGeneralization &&
          stackBypassGeneralizedLoopAddresses.contains(target);
      if (canReusePendingGeneralization && it != addrToBB.end() && it->second &&
          it->second->empty()) {
        return {it->second, false, generalizedBackup};
      }
      if (!hasPendingGeneralization) {
        pendingLoopGeneralizationAddresses.insert(target);
      }
      if (it != addrToBB.end() && it->second && !it->second->empty()) {
        return {replaceWithGeneralizedLoopBlock(target, name), false,
                generalizedBackup};
      }
      return {getOrCreateBB(target, name), false, generalizedBackup};
    }

    return {getOrCreateBB(target, name), false, false};
  };

  auto backupQueuedTarget = [&](BasicBlock* targetBlock, bool generalizedBackup,
                                bool moveState = false) {
    if (targetBlock == liftAbortBlock) {
      return;
    }
    branch_backup(targetBlock, generalizedBackup, moveState);
  };

  // Const fast path: 99.99% of mix solvePath calls. Skip pv_cache clear,
  // eager-load, and dest-dag dump — they only matter for symbolic targets.
  if (auto* constInt = dyn_cast<ConstantInt>(simplifyValue)) {
    dest = normalizeTargetAddress(constInt->getZExtValue());
    run = 0;
    ResolvedTargetBlock resolved;
    {
      LiftPerfDiag::ScopedTimer t(perf ? &perfDiag : nullptr,
                                  perf ? &perfDiag.solvePathConstResolve
                                       : nullptr);
      resolved = resolveTargetBlock(dest, "bb_solved_const");
    }
    {
      LiftPerfDiag::ScopedTimer t(perf ? &perfDiag : nullptr,
                                  perf ? &perfDiag.solvePathConstBr : nullptr);
      builder->CreateBr(resolved.block);
    }
    if (!resolved.reusedBackedge) {
      blockInfo = BBInfo(dest, resolved.block);
      printvalue2("pushing block");
      {
        LiftPerfDiag::ScopedTimer t(perf ? &perfDiag : nullptr,
                                    perf ? &perfDiag.solvePathConstBackup
                                         : nullptr);
        // Single successor + run=0: current path state is abandoned after
        // return, so move into the queued backup instead of deep-copy.
        backupQueuedTarget(blockInfo.block, resolved.generalizedBackup,
                           /*moveState=*/true);
      }
      if (perf) {
        ++perfDiag.constBackupTaken;
      }
      unvisitedBlocks.push_back(blockInfo);
    } else if (perf) {
      ++perfDiag.constBackupSkipped;
    }
    return finishSolvePath("const", PATH_solved);
  }

  // Symbolic / load path below.
  // Clear memoization cache for value enumeration.
  // Each solvePath invocation may have different assumptions
  // (from different branch paths), so cached results don't carry over.
  pv_cache.clear();
  if (currentPathSolveContext != PathSolveContext::Ret) {
    if (auto* loadInst = dyn_cast<LoadInst>(simplifyValue)) {
      if (loadInst->getType()->isIntegerTy()) {
        auto* gep = dyn_cast<GetElementPtrInst>(loadInst->getPointerOperand());
        if (gep && gep->getPointerOperand() == memoryAlloc) {
          unsigned loadBits = loadInst->getType()->getIntegerBitWidth();
          if (loadBits % 8 == 0) {
            LazyValue nestedLoad([loadInst]() -> Value* { return loadInst; });
            if (auto* resolved = solveLoad(
                    nestedLoad, gep, static_cast<uint8_t>(loadBits))) {
              if (liftProgressDiagEnabled && pathSolveSite == 0x1400237F9ULL) {
                std::string resolvedText;
                llvm::raw_string_ostream os(resolvedText);
                resolved->print(os);
                std::cout << "[diag] solvePath eager load current=0x1400237f9 resolved="
                          << os.str() << "\n";
              }
              if (currentPathSolveContext == PathSolveContext::IndirectJump) {
                if (auto* resolvedCI = dyn_cast<ConstantInt>(resolved)) {
                  uint64_t normalizedResolved =
                      normalizeRuntimeTargetAddress(resolvedCI->getZExtValue());
                  if (!isMemPaged(normalizedResolved)) {
                    if (liftProgressDiagEnabled && pathSolveSite == 0x1400237F9ULL) {
                      std::cout << "[diag] solvePath eager load skipping unmapped constant=0x"
                                << std::hex << resolvedCI->getZExtValue()
                                << " normalized=0x" << normalizedResolved << std::dec
                                << "\n";
                    }
                  } else {
                    simplifyValue = resolved;
                  }
                } else {
                  simplifyValue = resolved;
                }
              } else {
                simplifyValue = resolved;
              }
            } else if (liftProgressDiagEnabled && pathSolveSite == 0x1400237F9ULL) {
              std::string offsetText;
              llvm::raw_string_ostream os(offsetText);
              gep->getOperand(1)->print(os);
              std::cout << "[diag] solvePath eager load current=0x1400237f9 returned-null offset="
                        << os.str() << "\n";
            }
          }
        }
      }
    }
  }

  // do static polymorphism here

  auto shouldTraceHotPathSolve = [&]() {
    return liftProgressDiagEnabled &&
           ((pathSolveSite >= 0x140023582ULL &&
             pathSolveSite <= 0x140023FFFULL) ||
            pathSolveSite == 0x1403B1543ULL);
  };
  auto formatPathValue = [](llvm::Value* value) {
    if (!value) {
      return std::string("<null>");
    }
    std::string text;
    llvm::raw_string_ostream os(text);
    value->print(os);
    return os.str();
  };
  auto dumpRetDestDag = [&](const char* tag, uint64_t solvedDest) {
    const uint64_t siteRva = maskedRVA(pathSolveSite);
    if (siteRva != 0x35a716ULL && siteRva != 0x3ec79eULL &&
        (solvedDest & 0x00FFFFFFULL) != 0x113eb5ULL) {
      return;
    }
    static int dumps = 0;
    if (dumps >= 8) {
      return;
    }
    ++dumps;
    std::cout << "[dest-dag] " << tag << " site=0x" << std::hex << pathSolveSite
              << " dest=0x" << solvedDest << std::dec
              << " ctx=" << static_cast<int>(currentPathSolveContext) << "\n";
    std::set<llvm::Value*> seen;
    std::vector<std::pair<llvm::Value*, int>> work{{simplifyValue, 0}};
    unsigned visited = 0;
    while (!work.empty() && visited < 80) {
      auto entry = work.back();
      work.pop_back();
      llvm::Value* v = entry.first;
      if (!v || !seen.insert(v).second) {
        continue;
      }
      ++visited;
      std::cout << "  [" << entry.second << "] "
                << formatPathValue(v).substr(0, 140) << "\n";
      if (auto* u = llvm::dyn_cast<llvm::User>(v)) {
        if (entry.second < 6) {
          for (auto& op : u->operands()) {
            work.push_back({op.get(), entry.second + 1});
          }
        }
      }
    }
    std::cout << std::flush;
  };
  dumpRetDestDag("enter", 0);

  PATH_info result = PATH_unsolved;
  if (shouldTraceHotPathSolve()) {
    std::cout << "[diag] solvePath site=0x" << std::hex << pathSolveSite
              << std::dec << " value=" << formatPathValue(simplifyValue) << "\n";
  }

  // Eager-load may have folded to a constant after the early check.
  if (auto* constInt = dyn_cast<ConstantInt>(simplifyValue)) {
    dest = normalizeTargetAddress(constInt->getZExtValue());
    result = PATH_solved;
    run = 0;
    dumpRetDestDag("const", dest);

    auto resolved = resolveTargetBlock(dest, "bb_solved_const");

    builder->CreateBr(resolved.block);
    if (!resolved.reusedBackedge) {
      blockInfo = BBInfo(dest, resolved.block);
      printvalue2("pushing block");
      backupQueuedTarget(blockInfo.block, resolved.generalizedBackup);
      unvisitedBlocks.push_back(blockInfo);
    }

    return finishSolvePath("const", result);
  }

  PATH_info gcvResult = PATH_unsolved;
  {
    LiftPerfDiag::ScopedTimer gcvTimer(perf ? &perfDiag : nullptr,
                                       perf ? &perfDiag.solvePathGcv : nullptr);
    gcvResult = getConstraintVal(function, simplifyValue, dest,
                                 perf ? &perfDiag : nullptr);
  }
  if (PATH_info solved = gcvResult) {
      dest = normalizeTargetAddress(dest);
    if (solved == PATH_solved) {
      run = 0;
      dumpRetDestDag("constraint", dest);
      std::cout << "Solved the constraint and moving to next path\n"
                << std::flush;

      auto resolved = resolveTargetBlock(dest, "bb_solved");

      builder->CreateBr(resolved.block);
      if (!resolved.reusedBackedge) {
        blockInfo = BBInfo(dest, resolved.block);
        printvalue2("pushing block");
        backupQueuedTarget(blockInfo.block, resolved.generalizedBackup);
        unvisitedBlocks.push_back(blockInfo);
      }

      return finishSolvePath("gcv", solved);
    }
  }

  // Lift PCs are often 0x40xxxxxx while imageBase is 0x140000000, so
  // address_to_mapped_address misses handlers that are still paged. Use the
  // file-backed normalization (not pageMap, which the dump overlay fragments).
  auto isPreferredImageVa = [&](uint64_t addr) -> bool {
    return file.imageBase != 0 && addr >= file.imageBase &&
           file.address_to_mapped_address(addr) != 0;
  };
  auto isHandlerPointer = [&](uint64_t addr) -> bool {
    if (addr == 0 || isStackAddress(addr) || isPreferredImageVa(addr)) {
      return false;
    }
    const uint64_t norm = normalizeFileBackedRuntimeTargetAddress(addr);
    if (norm == 0 || isPreferredImageVa(norm) ||
        vmp.dispatch.excludeBytecodeDest(isBytecodeAddress(addr),
                                         isBytecodeAddress(norm))) {
      return false;
    }
    return isModuleAddress(norm) || isModuleAddress(addr);
  };

  // Transfer-only sticky recovery. Dest: a single module pointer covered by
  // data SSA. Cond: argument-tainted predicate on a two-handler select, only
  // if a stack slot still holds a non-argument flag/counter.
  if (!isa<ConstantInt>(simplifyValue) &&
      (currentPathSolveContext == PathSolveContext::Ret ||
       currentPathSolveContext == PathSolveContext::IndirectJump)) {
    auto* topSel = dyn_cast<SelectInst>(simplifyValue);
    auto isModuleArm = [&](Value* arm) -> bool {
      auto* ci = dyn_cast<ConstantInt>(arm);
      return ci != nullptr && isHandlerPointer(ci->getZExtValue());
    };
    const bool virtualizedJcc =
        topSel != nullptr && isModuleArm(topSel->getTrueValue()) &&
        isModuleArm(topSel->getFalseValue());

    auto collectDag = [&](Value* root) {
      std::set<Value*> seen;
      std::vector<Value*> work{root};
      unsigned visited = 0;
      while (!work.empty() && visited < 4000) {
        Value* v = work.back();
        work.pop_back();
        if (!v || !seen.insert(v).second) {
          continue;
        }
        ++visited;
        if (auto* u = dyn_cast<User>(v)) {
          for (auto& op : u->operands()) {
            work.push_back(op.get());
          }
        }
      }
      return seen;
    };

    auto foldWithSubs = [&](Value* root,
                            const std::vector<std::pair<Value*, Constant*>>&
                                subsIn) -> Constant* {
      std::function<Constant*(Value*, int)> fold =
          [&](Value* v, int depth) -> Constant* {
        if (depth > 24 || v == nullptr) {
          return nullptr;
        }
        for (auto& s : subsIn) {
          if (v == s.first) {
            return s.second;
          }
        }
        if (auto* k = dyn_cast<Constant>(v)) {
          return k;
        }
        if (auto* bo = dyn_cast<BinaryOperator>(v)) {
          auto* a = fold(bo->getOperand(0), depth + 1);
          auto* b = fold(bo->getOperand(1), depth + 1);
          if (!a || !b) {
            return nullptr;
          }
          return ConstantFoldBinaryOpOperands(bo->getOpcode(), a, b,
                                              M->getDataLayout());
        }
        if (auto* cmp = dyn_cast<CmpInst>(v)) {
          auto* a = fold(cmp->getOperand(0), depth + 1);
          auto* b = fold(cmp->getOperand(1), depth + 1);
          if (!a || !b) {
            return nullptr;
          }
          return ConstantFoldCompareInstruction(cmp->getPredicate(), a, b);
        }
        if (auto* cast = dyn_cast<CastInst>(v)) {
          auto* a = fold(cast->getOperand(0), depth + 1);
          if (!a) {
            return nullptr;
          }
          return ConstantFoldCastInstruction(cast->getOpcode(), a,
                                             cast->getType());
        }
        if (auto* sel = dyn_cast<SelectInst>(v)) {
          auto* cd = fold(sel->getCondition(), depth + 1);
          auto* tv = fold(sel->getTrueValue(), depth + 1);
          auto* fv = fold(sel->getFalseValue(), depth + 1);
          if (!cd || !tv || !fv) {
            return nullptr;
          }
          return ConstantFoldSelectInstruction(cd, tv, fv);
        }
        if (auto* li = dyn_cast<LoadInst>(v)) {
          if (!li->getType()->isIntegerTy()) {
            return nullptr;
          }
          ConstantInt* offCI = nullptr;
          auto* po = li->getPointerOperand()->stripPointerCasts();
          if (auto* gep = dyn_cast<GetElementPtrInst>(po)) {
            if (gep->getPointerOperand()->stripPointerCasts() ==
                memoryAlloc->stripPointerCasts()) {
              offCI = dyn_cast_or_null<ConstantInt>(
                  fold(gep->getOperand(1), depth + 1));
            }
          }
          if (offCI == nullptr) {
            if (auto* itp = dyn_cast<IntToPtrInst>(po)) {
              offCI = dyn_cast_or_null<ConstantInt>(
                  fold(itp->getOperand(0), depth + 1));
            }
          }
          if (offCI == nullptr) {
            return nullptr;
          }
          const unsigned bits = li->getType()->getIntegerBitWidth();
          if (bits % 8 != 0 || bits > 64) {
            return nullptr;
          }
          const uint8_t nbytes = static_cast<uint8_t>(bits / 8);
          const uint64_t addr = offCI->getZExtValue();
          if (isStackAddress(addr) ||
              isStackAddress(normalizeRuntimeTargetAddress(addr))) {
            LazyValue nestedLoad([li]() -> Value* { return li; });
            if (auto* resolved =
                    retrieveCombinedValue(addr, nbytes, nestedLoad)) {
              if (auto* rci = dyn_cast<ConstantInt>(resolved)) {
                return ConstantInt::get(
                    li->getType(),
                    rci->getValue().zextOrTrunc(bits).getZExtValue());
              }
            }
            return nullptr;
          }
          uint64_t raw = 0;
          const uint64_t rva = fetchRva(addr);
          const uint64_t cands[] = {
              addr, normalizeFileBackedRuntimeTargetAddress(addr),
              file.imageBase + rva, 0x140000000ULL + rva, 0x40000000ULL + rva};
          for (uint64_t cand : cands) {
            if (cand != 0 && file.readMemory(cand, nbytes, raw)) {
              return ConstantInt::get(li->getType(), raw);
            }
          }
          return nullptr;
        }
        return nullptr;
      };
      return fold(root, 0);
    };

    auto emitSolvedBr = [&](uint64_t target, const char* name) -> PATH_info {
      dest = normalizeTargetAddress(target);
      dumpRetDestDag(name, dest);
      auto resolved = resolveTargetBlock(dest, name);
      builder->CreateBr(resolved.block);
      if (!resolved.reusedBackedge) {
        blockInfo = BBInfo(dest, resolved.block);
        backupQueuedTarget(blockInfo.block, resolved.generalizedBackup);
        unvisitedBlocks.push_back(blockInfo);
      }
      run = 0;
      return finishSolvePath("pre_cpv", PATH_solved);
    };

    if (virtualizedJcc && isArgumentDerived(topSel->getCondition()) &&
        !stickyNonArgSlot.empty()) {
      auto condSeen = collectDag(topSel->getCondition());
      Value* condSsa = nullptr;
      uint64_t predShadow = 0;
      unsigned predHits = 0;
      for (const auto& slotCopy : stickyNonArgSlot) {
        if (!isStickyPredicate(slotCopy.second)) {
          continue;
        }
        auto bufIt = buffer.find(slotCopy.first);
        if (bufIt == buffer.end() || bufIt->second.value == nullptr) {
          continue;
        }
        Value* occupied = bufIt->second.value;
        if (isa<ConstantInt>(occupied) || condSeen.count(occupied) == 0) {
          continue;
        }
        ++predHits;
        condSsa = occupied;
        predShadow = slotCopy.second;
      }
      if (predHits == 1 && condSsa != nullptr) {
        std::vector<std::pair<Value*, Constant*>> condSubs{
            {condSsa, builder->getIntN(condSsa->getType()->getIntegerBitWidth(),
                                       predShadow)}};
        if (auto* folded = foldWithSubs(topSel->getCondition(), condSubs)) {
          if (auto* fci = dyn_cast<ConstantInt>(folded)) {
            if (fci->getBitWidth() == 1) {
              static int condLogs = 0;
              if (condLogs < 40) {
                ++condLogs;
                std::cout << "[sticky-cond] rva=0x" << std::hex
                          << maskedRVA(pathSolveSite) << " pred=0x"
                          << predShadow << " taken=" << fci->getZExtValue()
                          << std::dec << "\n"
                          << std::flush;
              }
              auto* takenArm = fci->isOne() ? topSel->getTrueValue()
                                            : topSel->getFalseValue();
              if (auto* armCI = dyn_cast<ConstantInt>(takenArm)) {
                if (isHandlerPointer(armCI->getZExtValue())) {
                  return emitSolvedBr(armCI->getZExtValue(), "bb_sticky_cond");
                }
              }
            }
          }
        }
      }
    }

    if (!virtualizedJcc && !stickyNonArgSlot.empty()) {
      auto destSeen = collectDag(simplifyValue);
      std::vector<std::pair<Value*, Constant*>> vipSubs;
      for (const auto& slotCopy : stickyNonArgSlot) {
        if (!isModuleAddress(slotCopy.second) &&
            !isBytecodeAddress(slotCopy.second)) {
          continue;
        }
        auto bufIt = buffer.find(slotCopy.first);
        if (bufIt == buffer.end() || bufIt->second.value == nullptr) {
          continue;
        }
        Value* occupied = bufIt->second.value;
        if (isa<ConstantInt>(occupied) || destSeen.count(occupied) == 0) {
          continue;
        }
        vipSubs.push_back(
            {occupied, builder->getIntN(
                           occupied->getType()->getIntegerBitWidth(),
                           slotCopy.second)});
      }
      if (vipSubs.size() == 1) {
        if (auto* folded = foldWithSubs(simplifyValue, vipSubs)) {
            if (auto* fci = dyn_cast<ConstantInt>(folded)) {
              const uint64_t destAddr = fci->getZExtValue();
              auto* vipCI = dyn_cast<ConstantInt>(vipSubs[0].second);
              if (vipCI && isHandlerPointer(destAddr) &&
                  fetchRva(destAddr) != fetchRva(vipCI->getZExtValue())) {
                static int vipcopyLogs = 0;
                if (vipcopyLogs < 40) {
                  ++vipcopyLogs;
                  std::cout << "[sticky-dest] fold rva=0x" << std::hex
                            << maskedRVA(pathSolveSite) << " dest=0x"
                            << destAddr << std::dec
                            << " subs=" << vipSubs.size() << "\n"
                            << std::flush;
                }
                return emitSolvedBr(destAddr, "bb_sticky_dest");
              }
            }
        }
      }
    }
  }

  // unsolved
  printvalue(simplifyValue);
  run = 0;
  if (perf) {
    perfDiag.noteSolvePathSite(pathSolveSite);
  }
  std::set<APInt, APIntComparator> pvset;
  {
    LiftPerfDiag::ScopedTimer cpvTimer(perf ? &perfDiag : nullptr,
                                       perf ? &perfDiag.solvePathCpv : nullptr);
    pvset = computePossibleValues(simplifyValue);
  }
  if (perf) {
    perfDiag.noteCpvResult(pvset.size());
  }
  if (currentPathSolveContext == PathSolveContext::Ret && pvset.size() > 2) {
    pvset.clear();
  }
  // A loop-generalized exit value can be a PHI, which computePossibleValues
  // does not enumerate. Its incoming constants are exactly the possible
  // transfers (the virtualized JCC: "the branch has multiple real
  // destinations"), so treat them as candidates.
  if (pvset.size() < 2) {
    if (auto* phi = llvm::dyn_cast<llvm::PHINode>(simplifyValue)) {
      for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
        if (auto* ci =
                llvm::dyn_cast<llvm::ConstantInt>(phi->getIncomingValue(i))) {
          pvset.insert(ci->getValue());
        }
      }
    }
  }
  // Virtualized conditional control flow (Themida article, "Virtualized
  // Conditional Control Flow"; VMProtect encodes the two destinations through
  // ltJmpWithFlag, intel.cc:11721). When the dispatch target's DAG carries a
  // select, it has multiple real destinations: fold the target once per arm so
  // the dispatcher forks instead of collapsing to one destination. Only the
  // transfer's DAG is inspected, so mutated junk never contributes.
  std::vector<std::pair<llvm::Value*, llvm::Constant*>> subs;
  // Memoized constant fold of a transfer DAG under `subs`. The dispatch target
  // is cumulative (handler = previous target + delta), so later dispatches nest
  // earlier ones; without memoization and a higher depth they cannot fold.
  llvm::DenseMap<llvm::Value*, llvm::Constant*> foldMemo;
  std::function<llvm::Constant*(llvm::Value*, llvm::Value*,
                                llvm::Constant*, int)>
      jccFold = [&](llvm::Value* v, llvm::Value* node, llvm::Constant* repl,
                    int depth) -> llvm::Constant* {
      if (depth > 256 || !v) return nullptr;
      for (auto& s : subs) {
        if (v == s.first) return s.second;
      }
      if (v == node) return repl;
      if (auto* k = llvm::dyn_cast<llvm::Constant>(v)) return k;
      auto memoIt = foldMemo.find(v);
      if (memoIt != foldMemo.end()) return memoIt->second;
      llvm::Constant* result = nullptr;
      if (auto* bo = llvm::dyn_cast<llvm::BinaryOperator>(v)) {
        auto* a = jccFold(bo->getOperand(0), node, repl, depth + 1);
        auto* b = jccFold(bo->getOperand(1), node, repl, depth + 1);
        if (a && b) {
          result = llvm::ConstantFoldBinaryOpOperands(bo->getOpcode(), a, b,
                                                      M->getDataLayout());
        }
      } else if (auto* cmp = llvm::dyn_cast<llvm::CmpInst>(v)) {
        auto* a = jccFold(cmp->getOperand(0), node, repl, depth + 1);
        auto* b = jccFold(cmp->getOperand(1), node, repl, depth + 1);
        if (a && b) {
          result = llvm::ConstantFoldCompareInstruction(cmp->getPredicate(), a,
                                                        b);
        }
      } else if (auto* cast = llvm::dyn_cast<llvm::CastInst>(v)) {
        auto* a = jccFold(cast->getOperand(0), node, repl, depth + 1);
        if (a) {
          result = llvm::ConstantFoldCastInstruction(cast->getOpcode(), a,
                                                     cast->getType());
        }
      } else if (auto* sel = llvm::dyn_cast<llvm::SelectInst>(v)) {
        auto* cd = jccFold(sel->getCondition(), node, repl, depth + 1);
        auto* tv = jccFold(sel->getTrueValue(), node, repl, depth + 1);
        auto* fv = jccFold(sel->getFalseValue(), node, repl, depth + 1);
        if (cd && tv && fv) {
          result = llvm::ConstantFoldSelectInstruction(cd, tv, fv);
        }
      } else if (auto* li = llvm::dyn_cast<llvm::LoadInst>(v)) {
        if (li->getType()->isIntegerTy()) {
          llvm::ConstantInt* offCI = nullptr;
          auto* po = li->getPointerOperand()->stripPointerCasts();
          if (auto* gep = llvm::dyn_cast<llvm::GetElementPtrInst>(po)) {
            if (gep->getPointerOperand()->stripPointerCasts() ==
                memoryAlloc->stripPointerCasts()) {
              offCI = llvm::dyn_cast_or_null<llvm::ConstantInt>(
                  jccFold(gep->getOperand(1), node, repl, depth + 1));
            }
          }
          if (offCI == nullptr) {
            if (auto* itp = llvm::dyn_cast<llvm::IntToPtrInst>(po)) {
              offCI = llvm::dyn_cast_or_null<llvm::ConstantInt>(
                  jccFold(itp->getOperand(0), node, repl, depth + 1));
            }
          }
          if (offCI) {
            const unsigned bits = li->getType()->getIntegerBitWidth();
            if (bits % 8 == 0 && bits <= 64) {
              const uint8_t nbytes = static_cast<uint8_t>(bits / 8);
              const uint64_t addr = offCI->getZExtValue();
              if (isStackAddress(addr) ||
                  isStackAddress(normalizeRuntimeTargetAddress(addr))) {
                LazyValue nestedLoad([li]() -> Value* { return li; });
                if (auto* resolved =
                        retrieveCombinedValue(addr, nbytes, nestedLoad)) {
                  if (auto* rci =
                          llvm::dyn_cast<llvm::ConstantInt>(resolved)) {
                    result = llvm::ConstantInt::get(
                        li->getType(),
                        rci->getValue().zextOrTrunc(bits).getZExtValue());
                  }
                }
              } else {
                uint64_t raw = 0;
                const uint64_t rva = fetchRva(addr);
                const uint64_t cands[] = {
                    addr,
                    normalizeFileBackedRuntimeTargetAddress(addr),
                    file.imageBase + rva,
                    0x140000000ULL + rva,
                    0x40000000ULL + rva};
                for (uint64_t cand : cands) {
                  if (cand != 0 && file.readMemory(cand, nbytes, raw)) {
                    result = llvm::ConstantInt::get(li->getType(), raw);
                    break;
                  }
                }
              }
            }
          }
        }
      } else if (auto* p2 = llvm::dyn_cast<llvm::PHINode>(v)) {
        llvm::Constant* all = nullptr;
        bool ok = true;
        for (unsigned i = 0; i < p2->getNumIncomingValues(); ++i) {
          auto* f2 = jccFold(p2->getIncomingValue(i), node, repl, depth + 1);
          if (!f2) {
            ok = false;
            break;
          }
          if (!all) {
            all = f2;
          } else if (all != f2) {
            ok = false;
            break;
          }
        }
        if (ok) result = all;
      }
      foldMemo[v] = result;
      return result;
  };

  auto peelInt = [&](llvm::Value* off) -> llvm::Value* {
    while (auto* cast = llvm::dyn_cast<llvm::CastInst>(off)) {
      if (!cast->getSrcTy()->isIntegerTy() ||
          !cast->getDestTy()->isIntegerTy()) {
        break;
      }
      off = cast->getOperand(0);
    }
    return off;
  };
  auto loadAddrExpr = [&](llvm::LoadInst* li) -> llvm::Value* {
    auto* po = li->getPointerOperand()->stripPointerCasts();
    if (auto* gep = llvm::dyn_cast<llvm::GetElementPtrInst>(po)) {
      if (gep->getPointerOperand()->stripPointerCasts() ==
          memoryAlloc->stripPointerCasts()) {
        return peelInt(gep->getOperand(1));
      }
    }
    if (auto* itp = llvm::dyn_cast<llvm::IntToPtrInst>(po)) {
      return peelInt(itp->getOperand(0));
    }
    return nullptr;
  };
  typename VmpDispatch<Register>::TransferScan vmpScan;
  {
    std::set<Value*> loadSeen;
    std::vector<Value*> loadWork{simplifyValue};
    unsigned loadVisited = 0;
    while (!loadWork.empty() && loadVisited < 4000) {
      Value* v = loadWork.back();
      loadWork.pop_back();
      if (!v || !loadSeen.insert(v).second) {
        continue;
      }
      ++loadVisited;
      if (auto* li = dyn_cast<LoadInst>(v)) {
        if (auto* sel = dyn_cast<SelectInst>(loadAddrExpr(li))) {
          vmpScan.noteAddressMux(sel);
        }
      }
      if (auto* ph = dyn_cast<PHINode>(v)) {
        vmpScan.noteInstanceBase(ph);
      }
      if (auto* u = dyn_cast<User>(v)) {
        for (auto& op : u->operands()) {
          loadWork.push_back(op.get());
        }
      }
    }
  }

  // Virtualized conditional control flow (Themida article; VMProtect encodes
  // the destinations of ltJmpWithFlag through a select on a VM flag,
  // intel.cc:11721). Fold the transfer once per select arm and keep those
  // destinations separately: computePossibleValues cross-products the rest of
  // the expression, which would otherwise drown the real fork in heuristic
  // candidates and turn a recoverable branch into a multi-way switch.
  std::set<llvm::APInt, APIntComparator> selectArms;
  {
    // Collect every select reachable from the transfer. A virtualized
    // conditional is select(flag, destA, destB); a dispatch can carry several
    // of them. They must be substituted *all at once*: folding one while
    // another remains would make jccFold walk that other select's symbolic
    // condition and fail. Substituting every select keeps the traversal out of
    // the conditions, so each arm combination folds to a real destination.
    std::vector<llvm::SelectInst*> selects;
    std::set<llvm::Value*> selSeen;
    std::vector<llvm::Value*> selWork{simplifyValue};
    unsigned selVisited = 0;
    while (!selWork.empty() && selVisited < 4000 && selects.size() < 4) {
      llvm::Value* v = selWork.back();
      selWork.pop_back();
      if (!v || !selSeen.insert(v).second) continue;
      ++selVisited;
      if (auto* sel = llvm::dyn_cast<llvm::SelectInst>(v)) {
        if (vmpScan.keepDestSelect(sel)) {
          selects.push_back(sel);
        }
      }
      if (auto* u = llvm::dyn_cast<llvm::User>(v)) {
        for (auto& op : u->operands()) selWork.push_back(op.get());
      }
    }
    // Enumerate by root *condition*, not by select: selects that share a
    // condition are one boolean, and a select whose condition depends on
    // another select is derived. Substituting each select independently
    // cross-products them and inflates selectArms past the 2..4 adoption
    // window (turning a recoverable fork into an empty switch). Keep only real
    // handler arms.
    std::vector<llvm::Value*> rootConds;
    {
      std::set<llvm::Value*> seenConds;
      for (auto* sel : selects) {
        llvm::Value* c = sel->getCondition();
        if (c == nullptr || !c->getType()->isIntegerTy(1) ||
            !seenConds.insert(c).second) {
          continue;
        }
        bool derivedFromSelect = false;
        std::set<llvm::Value*> condSeen;
        std::vector<llvm::Value*> condWork{c};
        unsigned condVisited = 0;
        while (!condWork.empty() && condVisited < 4000 && !derivedFromSelect) {
          llvm::Value* v = condWork.back();
          condWork.pop_back();
          if (!v || !condSeen.insert(v).second) continue;
          ++condVisited;
          for (auto* sel2 : selects) {
            if (v == sel2) {
              derivedFromSelect = true;
              break;
            }
          }
          if (derivedFromSelect) break;
          if (auto* u = llvm::dyn_cast<llvm::User>(v)) {
            for (auto& op : u->operands()) condWork.push_back(op.get());
          }
        }
        if (!derivedFromSelect) rootConds.push_back(c);
      }
    }
    auto subscribeCondition = [&](unsigned mask) {
      subs.clear();
      for (unsigned i = 0; i < rootConds.size(); ++i) {
        subs.push_back({rootConds[i],
                        llvm::ConstantInt::get(rootConds[i]->getType(),
                                               (mask >> i) & 1u)});
      }
      // VMProtect's dispatch target is jmp_registr_ (the per-instance base) +
      // decrypt(vip); pin that base phi too so the combination folds to the
      // concrete handler.
      if (vmpScan.basePhi && vmpScan.baseConst) {
        subs.push_back({vmpScan.basePhi, vmpScan.baseConst});
      }
    };
    // A load-address mux is an uncommitted pcode pointer, not two dests.
    // Folding the sibling decrypt-immediate select still yields both handlers
    // and forks this transfer. That select is the same ltJmpWithFlag cond.
    if (vmpScan.suppressDestFork()) {
      selects.clear();
      rootConds.clear();
    }
    if (!rootConds.empty() && rootConds.size() <= 4) {
      const unsigned combos = 1u << rootConds.size();
      for (unsigned mask = 0; mask < combos && selectArms.size() <= 8; ++mask) {
        subscribeCondition(mask);
        foldMemo.clear();
        if (auto* folded = jccFold(simplifyValue, nullptr, nullptr, 0)) {
          if (auto* fci = llvm::dyn_cast<llvm::ConstantInt>(folded)) {
            if (vmp.dispatch.isLiveHandler(vmpScan, fci->getZExtValue(),
                                           isHandlerPointer(fci->getZExtValue()))) {
              selectArms.insert(fci->getValue());
            }
          }
        }
      }
    } else if (!selects.empty()) {
      // Fallback: no independent condition found (or too many). Keep the
      // per-select scan so existing behaviour is preserved.
      const unsigned combos = 1u << selects.size();
      for (unsigned mask = 0; mask < combos && selectArms.size() <= 8; ++mask) {
        subs.clear();
        for (unsigned i = 0; i < selects.size(); ++i) {
          llvm::Constant* arm =
              ((mask >> i) & 1)
                  ? llvm::cast<llvm::Constant>(selects[i]->getTrueValue())
                  : llvm::cast<llvm::Constant>(selects[i]->getFalseValue());
          subs.push_back({selects[i], arm});
        }
        if (vmpScan.basePhi && vmpScan.baseConst) {
          subs.push_back({vmpScan.basePhi, vmpScan.baseConst});
        }
        foldMemo.clear();
        if (auto* folded = jccFold(simplifyValue, nullptr, nullptr, 0)) {
          if (auto* fci = llvm::dyn_cast<llvm::ConstantInt>(folded)) {
            if (vmp.dispatch.isLiveHandler(vmpScan, fci->getZExtValue(),
                                           isHandlerPointer(fci->getZExtValue()))) {
              selectArms.insert(fci->getValue());
            }
          }
        }
      }
    }
    subs.clear();
  }
  if (vmpScan.suppressDestFork()) {
    pvset.clear();
    auto destFromFolded = [&](Constant* folded, uint64_t pcode) -> ConstantInt* {
      auto* fci = dyn_cast_or_null<ConstantInt>(folded);
      if (fci == nullptr) {
        return nullptr;
      }
      const uint64_t destAddr = fci->getZExtValue();
      if (vmp.dispatch.isLiveHandler(vmpScan, destAddr,
                                     isHandlerPointer(destAddr), pcode)) {
        return fci;
      }
      return nullptr;
    };
    auto foldDestWithSelectArm = [&](SelectInst* sel,
                                     ConstantInt* arm) -> ConstantInt* {
      subs.clear();
      subs.push_back({sel, arm});
      if (vmpScan.basePhi && vmpScan.baseConst) {
        subs.push_back({vmpScan.basePhi, vmpScan.baseConst});
      }
      foldMemo.clear();
      auto* folded = jccFold(simplifyValue, nullptr, nullptr, 0);
      subs.clear();
      return destFromFolded(folded, arm->getZExtValue());
    };

    ConstantInt* pinnedDest = nullptr;
    bool pinConflict = false;
    auto takePin = [&](ConstantInt* d) {
      if (d == nullptr) {
        return;
      }
      if (pinnedDest && pinnedDest->getValue() != d->getValue()) {
        pinConflict = true;
        return;
      }
      pinnedDest = d;
    };

    if (pinnedDest == nullptr && !pinConflict &&
        vmp.dispatch.canPinDest(isBytecodeAddress(vmp.vipOffset()) ||
                                isModuleAddress(vmp.vipOffset()))) {
      for (SelectInst* sel : vmpScan.vipLoadSelects) {
        auto* tArm = dyn_cast<ConstantInt>(sel->getTrueValue());
        auto* fArm = dyn_cast<ConstantInt>(sel->getFalseValue());
        ConstantInt* pinArm = vmp.dispatch.pinLoadSelectArm(tArm, fArm);
        if (pinArm == nullptr) {
          continue;
        }
        subs.clear();
        subs.push_back({sel, pinArm});
        const bool takeTrue = pinArm == tArm;
        subs.push_back(
            {sel->getCondition(),
             ConstantInt::get(sel->getCondition()->getType(), takeTrue ? 1 : 0)});
        {
          std::set<Value*> seenSel;
          std::vector<Value*> workSel{simplifyValue};
          unsigned visSel = 0;
          while (!workSel.empty() && visSel < 4000) {
            Value* v = workSel.back();
            workSel.pop_back();
            if (!v || !seenSel.insert(v).second) {
              continue;
            }
            ++visSel;
            if (auto* other = dyn_cast<SelectInst>(v)) {
              if (other != sel && other->getCondition() == sel->getCondition()) {
                Value* arm = takeTrue ? other->getTrueValue()
                                      : other->getFalseValue();
                if (auto* aci = dyn_cast<ConstantInt>(arm)) {
                  subs.push_back({other, aci});
                }
              }
            }
            if (auto* u = dyn_cast<User>(v)) {
              for (auto& op : u->operands()) {
                workSel.push_back(op.get());
              }
            }
          }
        }
        if (vmpScan.basePhi && vmpScan.baseConst) {
          subs.push_back({vmpScan.basePhi, vmpScan.baseConst});
        }
        foldMemo.clear();
        Constant* folded = jccFold(simplifyValue, nullptr, nullptr, 0);
        subs.clear();
        auto* d = destFromFolded(folded, pinArm->getZExtValue());
        if (maskedRVA(pathSolveSite) == 0x35a716ULL) {
          std::cout << "[dest-dag] pin lastmod=0x" << std::hex
                    << vmp.vipOffset() << " arm=0x"
                    << pinArm->getZExtValue() << " raw=";
          if (auto* fci = dyn_cast_or_null<ConstantInt>(folded)) {
            std::cout << "0x" << fci->getZExtValue();
          } else {
            std::cout << "null";
          }
          std::cout << " kept=0x" << (d ? d->getZExtValue() : 0) << std::dec
                    << "\n"
                    << std::flush;
        }
        takePin(d);
      }
    }

    if (pinnedDest == nullptr && !pinConflict) {
      for (SelectInst* sel : vmpScan.vipLoadSelects) {
        subs.clear();
        if (vmpScan.basePhi && vmpScan.baseConst) {
          subs.push_back({vmpScan.basePhi, vmpScan.baseConst});
        }
        foldMemo.clear();
        Constant* foldedCond =
            jccFold(sel->getCondition(), nullptr, nullptr, 0);
        subs.clear();
        auto* condCI = dyn_cast_or_null<ConstantInt>(foldedCond);
        if (condCI == nullptr || condCI->getBitWidth() != 1) {
          continue;
        }
        auto* arm = condCI->isOne() ? cast<ConstantInt>(sel->getTrueValue())
                                    : cast<ConstantInt>(sel->getFalseValue());
        takePin(foldDestWithSelectArm(sel, arm));
      }
    }

    if (pinnedDest && !pinConflict) {
      selectArms.clear();
      selectArms.insert(pinnedDest->getValue());
      pvset.clear();
      pvset.insert(pinnedDest->getValue());
    }
    subs.clear();
  }
  bool selectDerived = false;
  if (selectArms.size() >= 2 && selectArms.size() <= 4) {
    pvset = selectArms;
    selectDerived = true;
  } else if (pvset.size() < 2) {
    pvset.insert(selectArms.begin(), selectArms.end());
  }
  if (!vmpScan.vipLoadAddrs.empty() && !pvset.empty()) {
    pvalueset filtered;
    for (const auto& val : pvset) {
      const uint64_t addr = val.getZExtValue();
      if (vmpScan.isVipLoadAddr(addr)) {
        continue;
      }
      filtered.insert(val);
    }
    pvset.swap(filtered);
  }
  std::vector<APInt> pv(pvset.begin(), pvset.end());
  if (maskedRVA(pathSolveSite) == 0x35a716ULL) {
    std::cout << "[dest-dag] pv site=0x" << std::hex << pathSolveSite
              << std::dec << " n=" << pv.size();
    for (const auto& c : pv) {
      std::cout << " 0x" << std::hex << c.getZExtValue() << std::dec;
    }
    std::cout << " selectDerived=" << selectDerived << " lastmod=0x" << std::hex
              << vmp.vipOffset() << " vip=0x" << currentVipOffset
              << " vipSels=" << std::dec << vmpScan.vipLoadSelects.size()
              << " selArms=" << selectArms.size() << "\n"
              << std::flush;
  }
  // Virtualized-JCC rewrite (Themida article "Virtualized Conditional Control
  // Flow"; VMProtect encodes the destinations through ltJmpWithFlag and the
  // vm-instance selector through set_jmp_value, intel.cc:11721/11734).
  //
  // The dispatch target of a vm loop is base_phi + decrypt(read(addr)). The
  // base_phi mixes the per-vm-instance bases, so the target only becomes
  // concrete once the instance is fixed. Speculate on that phi with pure
  // constant folding (no IR insertion) and see what each arm resolves to.
  if (pvset.empty() && shouldTraceHotPathSolve()) {
    std::function<llvm::Constant*(llvm::Value*, llvm::PHINode*,
                                  llvm::ConstantInt*, int)>
        foldWith = [&](llvm::Value* v, llvm::PHINode* phi, llvm::ConstantInt* c,
                       int depth) -> llvm::Constant* {
      if (depth > 24 || !v) {
        return nullptr;
      }
      if (v == phi) {
        return c;
      }
      if (auto* k = llvm::dyn_cast<llvm::Constant>(v)) {
        return k;
      }
      if (auto* bo = llvm::dyn_cast<llvm::BinaryOperator>(v)) {
        auto* a = foldWith(bo->getOperand(0), phi, c, depth + 1);
        auto* b = foldWith(bo->getOperand(1), phi, c, depth + 1);
        if (!a || !b) return nullptr;
        return llvm::ConstantFoldBinaryOpOperands(bo->getOpcode(), a, b,
                                                  M->getDataLayout());
      }
      if (auto* cmp = llvm::dyn_cast<llvm::CmpInst>(v)) {
        auto* a = foldWith(cmp->getOperand(0), phi, c, depth + 1);
        auto* b = foldWith(cmp->getOperand(1), phi, c, depth + 1);
        if (!a || !b) return nullptr;
        return llvm::ConstantFoldCompareInstruction(cmp->getPredicate(), a, b);
      }
      if (auto* cast = llvm::dyn_cast<llvm::CastInst>(v)) {
        auto* a = foldWith(cast->getOperand(0), phi, c, depth + 1);
        if (!a) return nullptr;
        return llvm::ConstantFoldCastInstruction(cast->getOpcode(), a,
                                                 cast->getType());
      }
      if (auto* sel = llvm::dyn_cast<llvm::SelectInst>(v)) {
        auto* cd = foldWith(sel->getCondition(), phi, c, depth + 1);
        auto* tv = foldWith(sel->getTrueValue(), phi, c, depth + 1);
        auto* fv = foldWith(sel->getFalseValue(), phi, c, depth + 1);
        if (!cd || !tv || !fv) return nullptr;
        return llvm::ConstantFoldSelectInstruction(cd, tv, fv);
      }
      if (auto* p2 = llvm::dyn_cast<llvm::PHINode>(v)) {
        llvm::Constant* all = nullptr;
        for (unsigned i = 0; i < p2->getNumIncomingValues(); ++i) {
          auto* f2 = foldWith(p2->getIncomingValue(i), phi, c, depth + 1);
          if (!f2) return nullptr;
          if (!all) all = f2;
          else if (all != f2) return nullptr;
        }
        return all;
      }
      return nullptr;
    };

    std::set<llvm::Value*> seen2;
    std::vector<llvm::Value*> work2{simplifyValue};
    unsigned visited2 = 0;
    while (!work2.empty() && visited2 < 2000) {
      llvm::Value* v = work2.back();
      work2.pop_back();
      if (!v || !seen2.insert(v).second) continue;
      ++visited2;
      if (auto* phi = llvm::dyn_cast<llvm::PHINode>(v)) {
        bool allConst = phi->getNumIncomingValues() > 0;
        for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i)
          if (!llvm::isa<llvm::ConstantInt>(phi->getIncomingValue(i)))
            allConst = false;
        if (allConst) {
          std::cout << "[diag] spec phi with " << phi->getNumIncomingValues()
                    << " const arms:\n";
          for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
            auto* arm = llvm::cast<llvm::ConstantInt>(phi->getIncomingValue(i));
            auto* folded = foldWith(simplifyValue, phi, arm, 0);
            std::cout << "    arm=0x" << std::hex << arm->getZExtValue()
                      << " -> ";
            if (folded) {
              std::string t;
              llvm::raw_string_ostream os(t);
              folded->print(os);
              std::cout << os.str();
            } else {
              std::cout << "<not-constant>";
            }
            std::cout << std::dec << "\n";
          }
        }
      }
      if (auto* u = llvm::dyn_cast<llvm::User>(v))
        for (auto& op : u->operands()) work2.push_back(op.get());
    }
    std::cout << std::flush;
  }
  if (pvset.empty() && shouldTraceHotPathSolve()) {
    std::string pv0Text;
    llvm::raw_string_ostream pv0Os(pv0Text);
    simplifyValue->print(pv0Os);
    std::cout << "[diag] pv0 site=0x" << std::hex << pathSolveSite << std::dec
              << " valueID=" << simplifyValue->getValueID()
              << " text=" << pv0Text.substr(0, 200) << "\n"
              << std::flush;
    std::set<llvm::Value*> ps;
    std::vector<llvm::Value*> pw{simplifyValue};
    unsigned pv2 = 0;
    while (!pw.empty() && pv2 < 3000) {
      llvm::Value* v = pw.back();
      pw.pop_back();
      if (!v || !ps.insert(v).second) continue;
      ++pv2;
      if (auto* ph = llvm::dyn_cast<llvm::PHINode>(v)) {
        bool allc = ph->getNumIncomingValues() > 0;
        for (unsigned i = 0; i < ph->getNumIncomingValues(); ++i)
          if (!llvm::isa<llvm::ConstantInt>(ph->getIncomingValue(i)))
            allc = false;
        std::cout << "[diag] pv0-phi n=" << ph->getNumIncomingValues()
                  << " allConst=" << allc;
        if (allc) {
          std::cout << " arms=";
          for (unsigned i = 0; i < ph->getNumIncomingValues(); ++i)
            std::cout << "0x" << std::hex
                      << llvm::cast<llvm::ConstantInt>(ph->getIncomingValue(i))
                             ->getZExtValue()
                      << std::dec << " ";
        }
        std::cout << "\n";
      }
      if (auto* u = llvm::dyn_cast<llvm::User>(v))
        for (auto& op : u->operands()) pw.push_back(op.get());
    }
    std::cout << std::flush;
  }
  if (shouldTraceHotPathSolve()) {
    std::cout << "[diag] solvePath site=0x" << std::hex << pathSolveSite
              << std::dec << " pv_count=" << pvset.size();
    size_t shown = 0;
    for (const auto& candidate : pvset) {
      if (shown++ >= 4) {
        std::cout << " ...";
        break;
      }
      std::cout << " candidate=0x" << std::hex << candidate.getZExtValue()
                << std::dec;
    }
    std::cout << "\n";
  }
  if (pv.size() == 1) {
    printvalue2(pv[0]);
    dest = normalizeTargetAddress(pv[0].getZExtValue());
    result = PATH_solved;
    dumpRetDestDag("single", dest);

    auto resolved = resolveTargetBlock(dest, "bb_single");
    builder->CreateBr(resolved.block);
    if (!resolved.reusedBackedge) {
      blockInfo = BBInfo(dest, resolved.block);
      printvalue2("pushing block");
      backupQueuedTarget(blockInfo.block, resolved.generalizedBackup);
      unvisitedBlocks.push_back(blockInfo);
    }
    return finishSolvePath("cpv_single", result);
  }
  if (pv.size() == 2) {
    uint64_t rawFirstTarget = pv[0].getZExtValue();
    uint64_t rawSecondTarget = pv[1].getZExtValue();
    uint64_t filteredFirstTarget = normalizeTargetAddress(rawFirstTarget);
    uint64_t filteredSecondTarget = normalizeTargetAddress(rawSecondTarget);
    auto isViableIndirectTarget = [&](uint64_t rawTarget, uint64_t normalizedTarget) {
      return rawTarget != 0 && normalizedTarget != 0 &&
             isMemPaged(normalizedTarget);
    };
    if (currentPathSolveContext == PathSolveContext::IndirectJump) {
      const bool firstViable =
          isViableIndirectTarget(rawFirstTarget, filteredFirstTarget);
      const bool secondViable =
          isViableIndirectTarget(rawSecondTarget, filteredSecondTarget);
      if (liftProgressDiagEnabled && pathSolveSite == 0x1400237F9ULL) {
        std::cout << "[diag] solvePath filter current=0x1400237f9 rawFirst=0x"
                  << std::hex << rawFirstTarget << " rawSecond=0x"
                  << rawSecondTarget << " first=0x" << filteredFirstTarget
                  << " second=0x" << filteredSecondTarget << std::dec
                  << " firstViable=" << firstViable
                  << " secondViable=" << secondViable << "\n";
      }
      if (firstViable != secondViable) {
        auto* selectInst = dyn_cast<SelectInst>(simplifyValue);
        if (selectInst) {
          llvm::Value* branchCondition = selectInst->getCondition();
          bool trueGoesToViable =
              firstViable
                  ? (selectInst->getTrueValue() == builder->getIntN(
                        simplifyValue->getType()->getIntegerBitWidth(),
                        pv[0].getZExtValue()))
                  : (selectInst->getTrueValue() == builder->getIntN(
                        simplifyValue->getType()->getIntegerBitWidth(),
                        pv[1].getZExtValue()));
          dest = firstViable ? filteredFirstTarget : filteredSecondTarget;
          result = PATH_solved;
          dumpRetDestDag("filtered-sel", dest);
          auto resolved = resolveTargetBlock(dest, "bb_filtered");
          auto* trueBlock = trueGoesToViable ? resolved.block : liftAbortBlock;
          auto* falseBlock = trueGoesToViable ? liftAbortBlock : resolved.block;
          auto* br = builder->CreateCondBr(branchCondition, trueBlock, falseBlock);
          RegisterBranch(br);
          if (!resolved.reusedBackedge) {
            blockInfo = BBInfo(dest, resolved.block);
            printvalue2("pushing block");
            backupQueuedTarget(blockInfo.block, resolved.generalizedBackup);
            unvisitedBlocks.push_back(blockInfo);
          }
          return finishSolvePath("cpv_filtered_sel", result);
        }
        dest = firstViable ? filteredFirstTarget : filteredSecondTarget;
        result = PATH_solved;
        dumpRetDestDag("filtered", dest);
        auto resolved = resolveTargetBlock(dest, "bb_filtered");
        builder->CreateBr(resolved.block);
        if (!resolved.reusedBackedge) {
          blockInfo = BBInfo(dest, resolved.block);
          printvalue2("pushing block");
          backupQueuedTarget(blockInfo.block, resolved.generalizedBackup);
          unvisitedBlocks.push_back(blockInfo);
        }
        return finishSolvePath("cpv_filtered", result);
      }
    }

    // auto bb_false = BasicBlock::Create(function->getContext(), "bb_false",
    //                                    builder->GetInsertBlock()->getParent());
    // auto bb_true = BasicBlock::Create(function->getContext(), "bb_true",
    //                                   builder->GetInsertBlock()->getParent());

    auto firstcase = pv[0];
    auto secondcase = pv[1];

    auto try_simplify = [&](APInt c1,
                                   Value* simplifyv) -> std::optional<Value*> {
      if (auto si = dyn_cast<SelectInst>(simplifyv)) {
        auto firstcase_v = builder->getIntN(
            simplifyv->getType()->getIntegerBitWidth(), c1.getZExtValue());
        if (si->getTrueValue() == firstcase_v) {
          printvalue(si);
          printvalue(firstcase_v);
          return si->getCondition();
        }
      }
      return std::nullopt;
    };

    Value* condition = nullptr;

    // condition value is a kind of hack
    // 1- if its a select, we can extract the condition
    // 1a- if firstcase is in the select, extract the condition
    // 1b- if secondcase is in the select, extract the condition and reverse
    // values
    // 2- create a hacky compare for condition == potentialvalue

    printvalue2(firstcase);
    printvalue2(secondcase);

    if (auto can_simplify = try_simplify(firstcase, simplifyValue)) {
      printvalue2("b");
      condition = can_simplify.value();
    } else if (auto can_simplify2 = try_simplify(secondcase, simplifyValue)) {
      // The select's trueValue is `secondcase`, not `firstcase`.
      // Downstream code wires `firstcase` to bb_true and `secondcase`
      // to bb_false (see CreateCondBr below), so the firstcase/secondcase
      // labels need to mean "true side" and "false side" respectively.
      // Swap them once here so the existing wiring stays correct without
      // a parallel reversed-branch path.
      printvalue2("c");
      std::swap(firstcase, secondcase);
      condition = can_simplify2.value();
    } else {
      printvalue2("a");
      condition = createICMPFolder(
          llvm::CmpInst::ICMP_EQ, simplifyValue,
          builder->getIntN(simplifyValue->getType()->getIntegerBitWidth(),
                           firstcase.getZExtValue()));
    }

    printvalue2(firstcase);
    printvalue2(secondcase);
    const uint64_t firstTarget =
        normalizeTargetAddress(firstcase.getZExtValue());
    const uint64_t secondTarget =
        normalizeTargetAddress(secondcase.getZExtValue());
    auto trueTarget = resolveTargetBlock(firstTarget, "bb_true");
    auto falseTarget = resolveTargetBlock(secondTarget, "bb_false");
    auto* bb_true = trueTarget.block;
    auto* bb_false = falseTarget.block;
    printvalue(condition);
    auto BR = builder->CreateCondBr(condition, bb_true, bb_false);

    RegisterBranch(BR);

    printvalue2(firstcase);
    printvalue2(secondcase);
    blockInfo = BBInfo(secondTarget, bb_false);
    // for [this], we can assume condition is true
    // we can simplify any value tied to is dependent on condition,
    // and try to simplify any value calculates condition

    // for [newlifter], we can assume condition is false
    auto newblock = BBInfo(firstTarget, bb_true);

    // this->blockInfo = newblock;
    printvalue(condition);

    // lifters.push_back(newlifter);

    // Constant conditions are already resolved — only track assumptions
    // for instruction-produced conditions that need runtime disambiguation.
    if (auto* condInst = dyn_cast<Instruction>(condition)) {
      if (!falseTarget.reusedBackedge && blockInfo.block != liftAbortBlock) {
        assumptions[condInst] = 0;
        backupQueuedTarget(blockInfo.block, falseTarget.generalizedBackup);
        addUnvisitedAddr(blockInfo);
      }

      if (!trueTarget.reusedBackedge && newblock.block != liftAbortBlock) {
        this->assumptions[condInst] = 1;
        backupQueuedTarget(newblock.block, trueTarget.generalizedBackup);
        addUnvisitedAddr(newblock);
      }
    } else {
      // Condition is a constant (e.g., from folded ICMP). Both branches
      // are statically determined — back them up without assumption state.
      if (!falseTarget.reusedBackedge && blockInfo.block != liftAbortBlock) {
        backupQueuedTarget(blockInfo.block, falseTarget.generalizedBackup);
        addUnvisitedAddr(blockInfo);
      }
      if (!trueTarget.reusedBackedge && newblock.block != liftAbortBlock) {
        backupQueuedTarget(newblock.block, trueTarget.generalizedBackup);
        addUnvisitedAddr(newblock);
      }
    }

    debugging::doIfDebug([&]() {
      std::string Filename = "output_newpath.ll";
      std::error_code EC;
      llvm::raw_fd_ostream OS(Filename, EC);
      function->getParent()->print(OS, nullptr);
      std::cout << "created a new path\n" << std::flush;
    });
    result = PATH_solved;
    dest = firstTarget;
    dumpRetDestDag("twoway", dest);
    return finishSolvePath("cpv_dual", result);
  }

  if (pv.size() > 2) {
    // N-way branch: emit SwitchInst for multi-target resolution.
    // Default must stay unresolved because computePossibleValues() is heuristic.
    unsigned bitWidth = simplifyValue->getType()->getIntegerBitWidth();

    auto* bb_default_unresolved =
        createBudgetedBasicBlock("bb_switch_default_unresolved", current_address);
    if (bb_default_unresolved == liftAbortBlock) {
      builder->CreateRet(UndefValue::get(function->getReturnType()));
      return finishSolvePath("cpv_multi_abort", PATH_unsolved);
    }
    DTU->applyUpdates(
        {{DominatorTree::Insert, this->blockInfo.block, bb_default_unresolved}});

    auto* SI = builder->CreateSwitch(
        simplifyValue, bb_default_unresolved, static_cast<unsigned>(pv.size()));

    // Add every discovered target as an explicit case.
    std::set<uint64_t> emittedTargets;
    size_t switchCaseIndex = 0;
    for (const auto& caseVal : pv) {
      // computePossibleValues can emit a raw zero when it cross-products a
      // select whose unreachable branch defaults to 0.  That zero has no
      // relationship to any real control-flow target; passing it through
      // normalizeTargetAddress would re-emit `file.imageBase` as a bogus
      // switch case.  Drop the raw zero before we normalize.
      const uint64_t rawTarget = caseVal.getZExtValue();
      if (rawTarget == 0) {
        continue;
      }
      const uint64_t normalizedTarget = normalizeTargetAddress(rawTarget);
      if (!emittedTargets.insert(normalizedTarget).second) {
        continue;
      }

      // computePossibleValues is heuristic: for an uncorrelated symbolic
      // transfer it cross-products select arms into targets that were never
      // real destinations. Lifting those decodes arbitrary bytes, and enough
      // of them corrupts the IR (mid-instruction operand types, switch blow-up)
      // until the process dies. A candidate is only adopted as code when it is
      // already known code - a re-visited block or an outlined function entry.
      // Everything else is left to the (unresolved) default below instead of
      // being guessed at.
      const bool knownCode =
          selectDerived || visitedAddresses.contains(normalizedTarget) ||
          inlinePolicy.isOutline(normalizedTarget);
      if (!isMemPaged(normalizedTarget) || !knownCode) {
        std::cout << "[diag] dropping unproven switch target 0x"
                  << std::hex << normalizedTarget << std::dec << "\n"
                  << std::flush;
        continue;
      }

      auto bb_case = getOrCreateBB(
          normalizedTarget, "bb_switch_" + std::to_string(switchCaseIndex++));
      SI->addCase(
          cast<ConstantInt>(builder->getIntN(bitWidth, normalizedTarget)),
          bb_case);

      auto caseBlock = BBInfo(normalizedTarget, bb_case);
      addUnvisitedAddr(caseBlock);
      branch_backup(caseBlock.block);
    }

    // Conservative fallback for values not enumerated in pv:
    // keep default path data-dependent instead of returning undef, which can
    // let later optimizations fold valid cases into arbitrary constants.
    llvm::IRBuilder<> defaultBuilder(bb_default_unresolved);
    Value* unresolvedRet = simplifyValue;
    if (unresolvedRet->getType() != function->getReturnType()) {
      if (unresolvedRet->getType()->isIntegerTy() &&
          function->getReturnType()->isIntegerTy()) {
        unresolvedRet = defaultBuilder.CreateZExtOrTrunc(
            unresolvedRet, function->getReturnType(),
            "switch_default_unresolved");
      } else {
        unresolvedRet = UndefValue::get(function->getReturnType());
      }
    }
    defaultBuilder.CreateRet(unresolvedRet);
    // Destination remains unknown for multi-target switches.
    dest = 0;
    result = PATH_multi_solved;

    debugging::doIfDebug([&]() {
      std::string Filename = "output_switch.ll";
      std::error_code EC;
      llvm::raw_fd_ostream OS(Filename, EC);
      function->getParent()->print(OS, nullptr);
      std::cout << "created multi-target switch with " << emittedTargets.size()
                << " targets\n"
                << std::flush;
    });
  }

  if (pv.empty()) {
    // computePossibleValues exhausted its budget without resolving any
    // concrete targets.  Emit an undef-return sentinel so the block has a
    // valid terminator; do NOT use unreachable, which would let LLVM erase
    // this reachable-but-unresolved path.
    builder->CreateRet(UndefValue::get(function->getReturnType()));
    return finishSolvePath("cpv_empty", result);
  }

  if (result == PATH_multi_solved) {
    return finishSolvePath("cpv_multi", result);
  }
  return finishSolvePath("other", result);
}
