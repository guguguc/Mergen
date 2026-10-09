#ifndef STRAIGHT_LINE_REROLL_PASS_H
#define STRAIGHT_LINE_REROLL_PASS_H

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/Casting.h"

#include <cassert>
#include <cstdint>
#include <optional>
#include <utility>

// Post-O2: fold repeated straight-line iterative reductions into a counted loop.
//
// Grow forward from a seed; skip non-pure ops (llvm.assume etc.).  Each same-type
// value V is a candidate whose body is the backward slice V→seed (side chains
// like PF/flag math are excluded from the body).  Uses of slice intermediates
// that only feed llvm.assume are allowed (common after VM flag materialization).
// Prefer the candidate round size that yields the longest identical-fingerprint
// run.
class StraightLineRerollPass
    : public llvm::PassInfoMixin<StraightLineRerollPass> {
public:
  static constexpr unsigned MinRounds = 2;
  static constexpr unsigned MaxBodySize = 64;
  static constexpr unsigned MaxChainScan = 4096;

  llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager&) {
    bool changed = false;
    for (llvm::Function& F : M) {
      if (F.isDeclaration())
        continue;
      bool local = true;
      while (local) {
        local = rerollOnce(F);
        changed |= local;
      }
    }
    return changed ? llvm::PreservedAnalyses::none()
                   : llvm::PreservedAnalyses::all();
  }

private:
  struct Round {
    llvm::Value* seed = nullptr;
    llvm::Instruction* out = nullptr;
    llvm::SmallVector<llvm::Instruction*, 8> body;
    uint64_t fingerprint = 0;
  };

  struct Chain {
    llvm::SmallVector<Round, 8> rounds;
  };

  static bool isPureOp(const llvm::Instruction* I) {
    if (!I)
      return false;
    if (llvm::isa<llvm::BinaryOperator>(I) || llvm::isa<llvm::UnaryOperator>(I) ||
        llvm::isa<llvm::CastInst>(I) || llvm::isa<llvm::ICmpInst>(I) ||
        llvm::isa<llvm::FCmpInst>(I) || llvm::isa<llvm::SelectInst>(I) ||
        llvm::isa<llvm::ExtractElementInst>(I) ||
        llvm::isa<llvm::InsertElementInst>(I) ||
        llvm::isa<llvm::ShuffleVectorInst>(I)) {
      return !I->mayReadOrWriteMemory() && !I->mayHaveSideEffects();
    }
    return false;
  }

  static bool isAssumeCall(const llvm::Instruction* I) {
    auto* C = llvm::dyn_cast<llvm::CallInst>(I);
    if (!C)
      return false;
    return C->getIntrinsicID() == llvm::Intrinsic::assume;
  }

  // True if every use-path from V ends at llvm.assume (or is dead).
  static bool onlyFeedsAssumes(llvm::Value* V,
                               llvm::SmallPtrSetImpl<llvm::Value*>& seen) {
    if (!seen.insert(V).second)
      return true;
    if (V->use_empty())
      return true;
    for (llvm::User* U : V->users()) {
      auto* I = llvm::dyn_cast<llvm::Instruction>(U);
      if (!I)
        return false;
      if (isAssumeCall(I))
        continue;
      if (!isPureOp(I))
        return false;
      if (!onlyFeedsAssumes(I, seen))
        return false;
    }
    return true;
  }

  static bool onlyFeedsAssumes(llvm::Value* V) {
    llvm::SmallPtrSet<llvm::Value*, 16> seen;
    return onlyFeedsAssumes(V, seen);
  }

  static uint64_t mixHash(uint64_t h, uint64_t v) {
    h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    return h;
  }

  static uint64_t fingerprintRound(
      llvm::Value* seed, llvm::Instruction* out,
      const llvm::SmallVectorImpl<llvm::Instruction*>& body) {
    llvm::DenseMap<const llvm::Value*, unsigned> id;
    id[seed] = 0;
    unsigned next = 1;
    for (llvm::Instruction* I : body)
      id[I] = next++;

    uint64_t h = 0xcbf29ce484222325ULL;
    h = mixHash(h, body.size());
    for (llvm::Instruction* I : body) {
      h = mixHash(h, static_cast<uint64_t>(I->getOpcode()));
      h = mixHash(h, I->getType()->getTypeID());
      if (auto* Ty = llvm::dyn_cast<llvm::IntegerType>(I->getType()))
        h = mixHash(h, Ty->getBitWidth());
      if (auto* Cmp = llvm::dyn_cast<llvm::CmpInst>(I))
        h = mixHash(h, static_cast<uint64_t>(Cmp->getPredicate()));
      if (auto* Cast = llvm::dyn_cast<llvm::CastInst>(I))
        h = mixHash(h, static_cast<uint64_t>(Cast->getOpcode()));
      for (llvm::Value* Op : I->operands()) {
        if (auto* C = llvm::dyn_cast<llvm::ConstantInt>(Op)) {
          h = mixHash(h, 1);
          h = mixHash(h, C->getZExtValue());
          continue;
        }
        if (auto* CF = llvm::dyn_cast<llvm::ConstantFP>(Op)) {
          h = mixHash(h, 2);
          h = mixHash(h, CF->getValueAPF().bitcastToAPInt().getZExtValue());
          continue;
        }
        auto it = id.find(Op);
        if (it == id.end())
          return 0;
        h = mixHash(h, 3);
        h = mixHash(h, it->second);
      }
    }
    h = mixHash(h, id.lookup(out));
    return h == 0 ? 1 : h;
  }

  static bool operandsAvailable(
      llvm::Instruction* I, llvm::Value* seed,
      const llvm::SmallPtrSetImpl<llvm::Value*>& avail) {
    for (llvm::Value* Op : I->operands()) {
      if (llvm::isa<llvm::Constant>(Op))
        continue;
      if (Op == seed || avail.contains(Op))
        continue;
      return false;
    }
    return true;
  }

  static std::optional<llvm::SmallVector<llvm::Instruction*, 8>>
  sliceToSeed(llvm::Instruction* out, llvm::Value* seed,
              const llvm::SmallPtrSetImpl<llvm::Value*>& pool) {
    llvm::SmallPtrSet<llvm::Instruction*, 16> inSlice;
    llvm::SmallVector<llvm::Instruction*, 16> stack;
    stack.push_back(out);
    inSlice.insert(out);

    while (!stack.empty()) {
      llvm::Instruction* I = stack.pop_back_val();
      for (llvm::Value* Op : I->operands()) {
        if (llvm::isa<llvm::Constant>(Op) || Op == seed)
          continue;
        auto* J = llvm::dyn_cast<llvm::Instruction>(Op);
        if (!J || !pool.contains(J))
          return std::nullopt;
        if (inSlice.insert(J).second)
          stack.push_back(J);
      }
    }
    if (inSlice.size() > MaxBodySize)
      return std::nullopt;

    for (llvm::Instruction* I : inSlice) {
      if (I == out)
        continue;
      for (llvm::User* U : I->users()) {
        auto* UI = llvm::dyn_cast<llvm::Instruction>(U);
        if (!UI)
          return std::nullopt;
        if (inSlice.contains(UI))
          continue;
        if (onlyFeedsAssumes(UI))
          continue;
        return std::nullopt;
      }
    }

    bool usesSeed = false;
    for (llvm::Instruction* I : inSlice) {
      for (llvm::Value* Op : I->operands()) {
        if (Op == seed) {
          usesSeed = true;
          break;
        }
      }
      if (usesSeed)
        break;
    }
    if (!usesSeed)
      return std::nullopt;

    llvm::DenseMap<llvm::Instruction*, unsigned> indeg;
    for (llvm::Instruction* I : inSlice)
      indeg[I] = 0;
    for (llvm::Instruction* I : inSlice) {
      for (llvm::Value* Op : I->operands()) {
        if (auto* J = llvm::dyn_cast<llvm::Instruction>(Op)) {
          if (inSlice.contains(J))
            indeg[I]++;
        }
      }
    }
    llvm::SmallVector<llvm::Instruction*, 8> ready;
    for (auto& KV : indeg) {
      if (KV.second == 0)
        ready.push_back(KV.first);
    }
    llvm::SmallVector<llvm::Instruction*, 8> topo;
    llvm::SmallPtrSet<llvm::Instruction*, 16> seen;
    while (!ready.empty()) {
      llvm::Instruction* I = ready.pop_back_val();
      if (!seen.insert(I).second)
        continue;
      topo.push_back(I);
      for (llvm::User* U : I->users()) {
        auto* UI = llvm::dyn_cast<llvm::Instruction>(U);
        if (!UI || !inSlice.contains(UI))
          continue;
        if (--indeg[UI] == 0)
          ready.push_back(UI);
      }
    }
    if (topo.size() != inSlice.size())
      return std::nullopt;
    return topo;
  }

  static void collectCandidateRounds(llvm::Value* seed, llvm::BasicBlock* BB,
                                     llvm::SmallVectorImpl<Round>& outRounds) {
    outRounds.clear();
    if (!seed || !BB)
      return;

    llvm::Instruction* start = nullptr;
    if (auto* SI = llvm::dyn_cast<llvm::Instruction>(seed)) {
      if (SI->getParent() != BB)
        return;
      start = SI->getNextNode();
    } else {
      start = &*BB->begin();
    }
    if (!start)
      return;

    llvm::SmallPtrSet<llvm::Value*, 32> avail;
    avail.insert(seed);
    llvm::SmallPtrSet<llvm::Value*, 32> pool;

    for (llvm::Instruction* I = start; I && I != BB->getTerminator();
         I = I->getNextNode()) {
      if (!isPureOp(I))
        continue;
      if (!operandsAvailable(I, seed, avail))
        continue;
      avail.insert(I);
      pool.insert(I);

      if (I->getType() != seed->getType())
        continue;
      auto body = sliceToSeed(I, seed, pool);
      if (!body)
        continue;
      uint64_t fp = fingerprintRound(seed, I, *body);
      if (fp == 0)
        continue;
      Round R;
      R.seed = seed;
      R.out = I;
      R.body = std::move(*body);
      R.fingerprint = fp;
      outRounds.push_back(std::move(R));
    }
  }

  static std::optional<Round> findMatchingRound(llvm::Value* seed,
                                                llvm::BasicBlock* BB,
                                                uint64_t fp) {
    llvm::SmallVector<Round, 8> cands;
    collectCandidateRounds(seed, BB, cands);
    for (Round& R : cands) {
      if (R.fingerprint == fp)
        return R;
    }
    return std::nullopt;
  }

  static std::optional<Chain> findBestChain(llvm::Function& F) {
    std::optional<Chain> best;
    auto considerSeed = [&](llvm::Value* seed0, llvm::BasicBlock& BB) {
      llvm::SmallVector<Round, 8> firsts;
      collectCandidateRounds(seed0, &BB, firsts);
      for (Round& first : firsts) {
        Chain C;
        C.rounds.push_back(first);
        llvm::Value* cur = first.out;
        for (unsigned n = 1; n < MaxChainScan; ++n) {
          auto next = findMatchingRound(cur, &BB, first.fingerprint);
          if (!next || next->seed != cur)
            break;
          C.rounds.push_back(*next);
          cur = next->out;
        }
        if (C.rounds.size() < MinRounds)
          continue;
        if (!best || C.rounds.size() > best->rounds.size())
          best = std::move(C);
      }
    };

    for (llvm::BasicBlock& BB : F) {
      for (llvm::Argument& A : F.args())
        considerSeed(&A, BB);
      for (llvm::Instruction& I : BB) {
        if (I.getType()->isVoidTy())
          continue;
        considerSeed(&I, BB);
      }
    }
    return best;
  }

  static void eraseAssumeSideUsers(
      const llvm::SmallPtrSetImpl<llvm::Instruction*>& body) {
    llvm::SmallVector<llvm::Instruction*, 16> side;
    llvm::SmallPtrSet<llvm::Instruction*, 16> seen;
    llvm::SmallVector<llvm::Instruction*, 16> work;
    for (llvm::Instruction* B : body) {
      for (llvm::User* U : B->users()) {
        if (auto* UI = llvm::dyn_cast<llvm::Instruction>(U))
          work.push_back(UI);
      }
    }
    while (!work.empty()) {
      llvm::Instruction* I = work.pop_back_val();
      if (body.contains(I) || !seen.insert(I).second)
        continue;
      if (!onlyFeedsAssumes(I) && !isAssumeCall(I))
        continue;
      side.push_back(I);
      for (llvm::User* U : I->users()) {
        if (auto* UI = llvm::dyn_cast<llvm::Instruction>(U))
          work.push_back(UI);
      }
    }
    for (auto it = side.rbegin(); it != side.rend(); ++it) {
      llvm::Instruction* I = *it;
      if (!I->use_empty())
        I->replaceAllUsesWith(llvm::PoisonValue::get(I->getType()));
      I->eraseFromParent();
    }
  }

  static bool applyReroll(llvm::Function& F, Chain& chain) {
    if (chain.rounds.size() < MinRounds)
      return false;

    Round& first = chain.rounds.front();
    Round& last = chain.rounds.back();
    llvm::BasicBlock* BB = last.out->getParent();
    if (!BB || first.out->getParent() != BB)
      return false;

    llvm::SmallPtrSet<llvm::Instruction*, 32> toRemove;
    for (Round& R : chain.rounds) {
      for (llvm::Instruction* I : R.body)
        toRemove.insert(I);
    }

    for (size_t i = 0; i + 1 < chain.rounds.size(); ++i) {
      for (llvm::User* U : chain.rounds[i].out->users()) {
        auto* UI = llvm::dyn_cast<llvm::Instruction>(U);
        if (!UI)
          return false;
        if (toRemove.contains(UI) || onlyFeedsAssumes(UI))
          continue;
        return false;
      }
    }

    llvm::Instruction* earliest = nullptr;
    for (llvm::Instruction& I : *BB) {
      if (toRemove.contains(&I)) {
        earliest = &I;
        break;
      }
    }
    if (!earliest)
      return false;

    const unsigned N = static_cast<unsigned>(chain.rounds.size());
    llvm::Value* seed0 = first.seed;
    llvm::Type* ty = seed0->getType();
    llvm::LLVMContext& Ctx = F.getContext();

    llvm::BasicBlock* exitBB = BB->splitBasicBlock(earliest, "reroll.exit");
    BB->getTerminator()->eraseFromParent();

    llvm::BasicBlock* header =
        llvm::BasicBlock::Create(Ctx, "reroll.header", &F, exitBB);

    llvm::IRBuilder<> preBuilder(BB);
    preBuilder.CreateBr(header);

    llvm::IRBuilder<> hb(header);
    auto* i32Ty = llvm::Type::getInt32Ty(Ctx);
    auto* iv = hb.CreatePHI(i32Ty, 2, "reroll.iv");
    auto* acc = hb.CreatePHI(ty, 2, "reroll.acc");
    iv->addIncoming(llvm::ConstantInt::get(i32Ty, 0), BB);
    acc->addIncoming(seed0, BB);

    llvm::DenseMap<llvm::Value*, llvm::Value*> map;
    map[first.seed] = acc;
    llvm::Value* next = nullptr;
    for (llvm::Instruction* I : first.body) {
      llvm::Instruction* cloned = I->clone();
      for (unsigned oi = 0, oe = cloned->getNumOperands(); oi != oe; ++oi) {
        auto it = map.find(cloned->getOperand(oi));
        if (it != map.end())
          cloned->setOperand(oi, it->second);
      }
      hb.Insert(cloned);
      map[I] = cloned;
      if (I == first.out)
        next = cloned;
    }
    assert(next && "round out must be a member of its body");

    llvm::Value* ivNext =
        hb.CreateAdd(iv, llvm::ConstantInt::get(i32Ty, 1), "reroll.iv.next");
    iv->addIncoming(ivNext, header);
    acc->addIncoming(next, header);

    llvm::Value* cond = hb.CreateICmpULT(
        ivNext, llvm::ConstantInt::get(i32Ty, N), "reroll.cond");
    hb.CreateCondBr(cond, header, exitBB);

    llvm::IRBuilder<> eb(&*exitBB->getFirstInsertionPt());
    auto* result = eb.CreatePHI(ty, 1, "reroll.result");
    result->addIncoming(next, header);
    last.out->replaceAllUsesWith(result);

    eraseAssumeSideUsers(toRemove);

    llvm::SmallVector<llvm::Instruction*, 32> kill;
    for (Round& R : chain.rounds) {
      for (auto it = R.body.rbegin(); it != R.body.rend(); ++it)
        kill.push_back(*it);
    }
    for (llvm::Instruction* I : kill) {
      if (!I->use_empty())
        I->replaceAllUsesWith(llvm::PoisonValue::get(I->getType()));
      I->eraseFromParent();
    }
    return true;
  }

  static bool rerollOnce(llvm::Function& F) {
    auto chain = findBestChain(F);
    if (!chain)
      return false;
    return applyReroll(F, *chain);
  }
};

#endif
