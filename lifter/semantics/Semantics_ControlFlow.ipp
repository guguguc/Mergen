// Semantics_ControlFlow.ipp — mov, cmov, call, ret, jmp, conditional branches
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_mov() {
  LLVMContext& context = builder->getContext();

  //  auto Rvalue2 =      GetIndexValue(src, src.size,
  //  std::to_string(current_address));
  auto Rvalue = GetIndexValue(1);

  printvalue(Rvalue);

  switch (instruction.mnemonic) {
  case Mnemonic::MOVSX: {
    Rvalue = createSExtFolder(
        Rvalue, Type::getIntNTy(context, GetTypeSize(instruction.types[0])),
        "movsx-" + std::to_string(current_address) + "-");
    break;
  }
  case Mnemonic::MOVZX: {
    Rvalue = createZExtFolder(
        Rvalue, Type::getIntNTy(context, GetTypeSize(instruction.types[0])),
        "movzx-" + std::to_string(current_address) + "-");
    break;
  }
  case Mnemonic::MOVSXD: {
    Rvalue = createSExtFolder(
        Rvalue, Type::getIntNTy(context, GetTypeSize(instruction.types[0])),
        "movsxd-" + std::to_string(current_address) + "-");
    break;
  }
  default: {
    break;
  }
  }
  printvalue(Rvalue);

  switch (instruction.types[1]) {
  // case OperandType::Immediate64:
  case OperandType::Immediate8:
  case OperandType::Immediate16:
  case OperandType::Immediate32: {
    Rvalue = createSExtFolder(
        Rvalue, Type::getIntNTy(context, GetTypeSize(instruction.types[0])));
    break;
  }
  default:
    break;
  }

  printvalue(Rvalue);

  SetIndexValue(0, Rvalue);

  if (instruction.mnemonic == Mnemonic::MOV &&
      instruction.types[0] == OperandType::Register64) {
    const bool srcIsMemory =
        instruction.types[1] >= OperandType::Memory8 &&
        instruction.types[1] <= OperandType::Memory128;
    Register srcReg = Register::None;
    if (instruction.types[1] == OperandType::Register64) {
      srcReg = getBiggestEncoding(instruction.regs[1]);
    }
    auto* ci = llvm::dyn_cast_or_null<llvm::ConstantInt>(Rvalue);
    vmp.onMov(
        getBiggestEncoding(instruction.regs[0]), srcReg,
        srcIsMemory ? getBiggestEncoding(instruction.mem_base) : Register::None,
        srcIsMemory, Rvalue, ci && isBytecodeAddress(ci->getZExtValue()));
  }

  // Provenance tagging: if this is `mov reg, [rip+disp]` and disp+RIP
  // resolves to an IAT slot, remember which import the register now holds.
  // A later `call reg` can then emit a named external call without needing
  // SSA-level back-tracing through the folded load.
  if (instruction.types[0] >= OperandType::Register8 &&
      instruction.types[0] <= OperandType::Register64 &&
      instruction.types[1] >= OperandType::Memory8 &&
      instruction.types[1] <= OperandType::Memory64 &&
      instruction.mem_base == Register::RIP &&
      instruction.mem_index == Register::None) {
    uint64_t ea = current_address + instruction.mem_disp;
    auto it = importMap.find(ea);
    if (it != importMap.end()) {
      registerImportSource[getBiggestEncoding(instruction.regs[0])] =
          it->second;
    }
  }
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_cmovcc() {

  auto getCondition = [&] {
    switch (instruction.mnemonic) {

    case Mnemonic::CMOVZ: {
      return getFlag(FLAG_ZF);
    }

    case Mnemonic::CMOVNZ: {
      return createNotFolder(getFlag(FLAG_ZF));
    }

    case Mnemonic::CMOVB: {
      return getFlag(FLAG_CF);
    }
    case Mnemonic::CMOVNB: {
      return createNotFolder(getFlag(FLAG_CF));
    }

    case Mnemonic::CMOVBE: {
      return createOrFolder(getFlag(FLAG_CF), getFlag(FLAG_ZF));
    }
    case Mnemonic::CMOVNBE: {
      return createNotFolder(
          createOrFolder(getFlag(FLAG_CF), getFlag(FLAG_ZF)));
    }

    case Mnemonic::CMOVL: {
      return createXorFolder(getFlag(FLAG_SF), getFlag(FLAG_OF));
    }
    case Mnemonic::CMOVNL: {
      // equal
      return createNotFolder(
          createXorFolder(getFlag(FLAG_SF), getFlag(FLAG_OF)));
    }

    case Mnemonic::CMOVLE: {
      return createOrFolder(createXorFolder(getFlag(FLAG_SF), getFlag(FLAG_OF)),
                            getFlag(FLAG_ZF));
    }
    case Mnemonic::CMOVNLE: {
      return createAndFolder(
          createNotFolder(createXorFolder(getFlag(FLAG_SF), getFlag(FLAG_OF))),
          createNotFolder(getFlag(FLAG_ZF)));
    }

    case Mnemonic::CMOVO: {
      return getFlag(FLAG_OF);
    }
    case Mnemonic::CMOVNO: {
      return createNotFolder(getFlag(FLAG_OF));
    }

    case Mnemonic::CMOVS: {
      return getFlag(FLAG_SF);
    }
    case Mnemonic::CMOVNS: {
      return createNotFolder(getFlag(FLAG_SF));
    }

    case Mnemonic::CMOVP: {
      return getFlag(FLAG_PF);
    }
    case Mnemonic::CMOVNP: {
      return createNotFolder(getFlag(FLAG_PF));
    }

    default: {
      return static_cast<Value*>(nullptr);
    }
    }
  };

  auto dest = GetIndexValue(0);

  auto src = GetIndexValue(1);

  auto result = createSelectFolder(getCondition(), src, dest);

  SetIndexValue(0, result);
}

// for now assume every call is fake
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_call() {
  LLVMContext& context = builder->getContext();

  auto RspValue = GetRegisterValue(Register::RSP);

  auto val = ConstantInt::getSigned(Type::getInt64Ty(context),
                                    file.getMode() == arch_mode::X64 ? 8 : 4);

  auto result = createSubFolder(RspValue, val, "pushing_newrsp");

  uint64_t jump_address = current_address;

  std::string block_name = "jmp_call-" + std::to_string(jump_address) + "-";

  // Track whether we emitted an external CreateCall (not inlineable).
  // When true, skip the Unflatten inlining path below.
  bool emittedExternalCall = false;

  // Fast path: detect `call [rip+disp]` (FF 15) direct IAT calls.
  // These are memory-operand calls where the effective address is an IAT slot.
  // Resolve the import name and emit a named function call without loading
  // the stale on-disk IAT value.
  if (instruction.types[0] >= OperandType::Memory8 &&
      instruction.types[0] <= OperandType::Memory64 &&
      instruction.mem_base == Register::RIP &&
      instruction.mem_index == Register::None) {
    // EA = RIP (post-instruction) + displacement.  current_address is already
    // advanced past the instruction, so it equals RIP at this point.
    uint64_t ea = current_address + instruction.mem_disp;
    auto it = importMap.find(ea);
    if (it != importMap.end()) {
      const auto& importName = it->second;
      callFunctionIR(importName, nullptr);
      debugging::doIfDebug([&]() {
        std::cout << "[call-abi] resolved import: " << importName << "\n"
                  << std::flush;
      });
      emittedExternalCall = true;

      // Skip the switch/Unflatten path entirely.
      goto call_done;
    }
    // Unresolved RIP-relative call: importMap has no entry for this IAT
    // slot.  Emit an opaque external call with strict-ABI clobber and
    // continue at the post-call address.  Falling through to operand
    // dispatch would treat the raw on-disk IAT bytes as a jump target
    // and silently corrupt the lift (the post-call block ends up
    // sealed with ret undef).
    {
      auto fx = this->buildUnknownCallFx();
      fx.target = CallTargetClass::UnknownIndirect;
      auto* eaValue = builder->getInt64(ea);
      auto* targetPtr = builder->CreateIntToPtr(
          eaValue, PointerType::get(context, 0));
      auto* callResult = builder->CreateCall(
          parseArgsType(nullptr, context), targetPtr, parseArgs(nullptr));
      applyPostCallEffects(callResult, fx);
      abi::printCallEffectsDiag(fx, current_address - instruction.length);
      diagnostics.warning(
          DiagCode::CallIndirectUnresolved,
          current_address - instruction.length,
          "Unresolved RIP-relative IAT call at EA=0x" +
              std::to_string(ea) + " (no importMap entry)");
      emittedExternalCall = true;
      goto call_done;
    }
  }

  // Provenance-based fast path for register-indirect calls.  If this
  // register was last loaded from an IAT slot, emit the named external
  // call directly — this covers the common MSVC pattern:
  //   mov rsi, [rip+iat]
  //   call rsi
  //   ... args setup ...
  //   call rsi
  // where the concolic engine has folded the load to a ConstantInt
  // matching the on-disk IAT value, losing SSA provenance.
  if (instruction.types[0] >= OperandType::Register8 &&
      instruction.types[0] <= OperandType::Register64) {
    Register reg = getBiggestEncoding(instruction.regs[0]);
    auto it = registerImportSource.find(reg);
    if (it != registerImportSource.end()) {
      const auto& importName = it->second;
      callFunctionIR(importName, nullptr);
      debugging::doIfDebug([&]() {
        std::cout << "[call-abi] resolved import via register provenance: "
                  << importName << "\n" << std::flush;
      });
      diagnostics.info(
          DiagCode::CallOutlinedImportThunk,
          current_address - instruction.length,
          "Resolved register-indirect import: " + importName);
      emittedExternalCall = true;
      goto call_done;
    }
  }

  { // Non-IAT call path: operand-based dispatch.
  auto registerValue = GetIndexValue(0);
  switch (instruction.types[0]) {
  case OperandType::Immediate8:
  case OperandType::Immediate16:
  case OperandType::Immediate32:
  case OperandType::Immediate64: {
    // Fall through to register/memory handling.
  }
  case OperandType::Memory8:
  case OperandType::Memory16:
  case OperandType::Memory32:
  case OperandType::Memory64:
  case OperandType::Register8:
  case OperandType::Register16:
  case OperandType::Register32:
  case OperandType::Register64: {
    registerValue =
        createAddFolder(registerValue, GetRegisterValue(Register::RIP));
    if (getControlFlow() == ControlFlow::Basic ||
        !isa<ConstantInt>(registerValue)) {

      // --- Emit external call (unknown/indirect target) ---
      auto fx = this->buildUnknownCallFx();
      fx.target = isa<ConstantInt>(registerValue)
                      ? CallTargetClass::UnknownDirect
                      : CallTargetClass::UnknownIndirect;

      auto idltvm =
          builder->CreateIntToPtr(registerValue, PointerType::get(context, 0));

      auto callResult =
          builder->CreateCall(parseArgsType(nullptr, context), idltvm,
                             parseArgs(nullptr));

      applyPostCallEffects(callResult, fx);
      abi::printCallEffectsDiag(fx, current_address - instruction.length);
      emittedExternalCall = true;
      break;
    }
    auto registerCValue = cast<ConstantInt>(registerValue);
    uint64_t rawTargetAddr = registerCValue->getZExtValue();
    uint64_t normalizedTargetAddr = normalizeRuntimeTargetAddress(rawTargetAddr);
    auto* normalizedTargetValue =
        builder->getIntN(registerCValue->getBitWidth(), normalizedTargetAddr);
    if ((inlinePolicy.isOutline(normalizedTargetAddr) ||
         shouldOutlineCall(normalizedTargetAddr)) &&
        !shouldInlineTinyOutlinedCall(normalizedTargetAddr)) {

      // --- Emit external call (outlined known-address target) ---
      auto importName = resolveImportName(normalizedTargetAddr);

      if (!importName.empty()) {
        // Named import: emit a proper LLVM function declaration.
        callFunctionIR(importName, nullptr);
        debugging::doIfDebug([&]() {
          std::cout << "[call-abi] resolved import: " << importName << "\n"
                    << std::flush;
        });
        diagnostics.info(DiagCode::CallOutlinedImportThunk,
                         current_address - instruction.length,
                         "Outlined import call: " + importName);
      } else {
        // Unknown outlined target: emit opaque inttoptr call.
        auto fx = this->buildUnknownCallFx();
        fx.target = CallTargetClass::UnknownDirect;

        auto idltvm = builder->CreateIntToPtr(
            normalizedTargetValue, PointerType::get(context, 0));
        auto callResult = builder->CreateCall(
            parseArgsType(nullptr, context), idltvm, parseArgs(nullptr));

        applyPostCallEffects(callResult, fx);
        abi::printCallEffectsDiag(fx, current_address - instruction.length);
        diagnostics.info(DiagCode::CallAbiApplied,
                         current_address - instruction.length,
                         "Outlined unknown-target call (inttoptr)");
      }
      emittedExternalCall = true;
      break;
    }
    jump_address = normalizedTargetAddr;
    break;
  }
  default:
    UNREACHABLE("unreachable in call");
    break;
  }

  // Unflatten inlining path: push return address to stack and branch to
  // the call target.  Skip this when we already emitted a CreateCall for
  // an external/indirect target — the call semantics are fully handled.
  if (!emittedExternalCall && getControlFlow() == ControlFlow::Unflatten) {

    // Speculative inlining: only start if enabled (maxCallInlineBudget > 0)
    // and not already inside a speculative inline.
    if (maxCallInlineBudget > 0 && !speculativeCall.active) {
      auto returnBB = getOrCreateBB(current_address, "call_return_cont");
      branch_backup(returnBB);

      speculativeCall.active        = true;
      speculativeCall.returnAddr    = current_address;
      speculativeCall.worklistFloor = unvisitedBlocks.size();
      speculativeCall.bailedOut     = false;
      speculativeCallBudget         = maxCallInlineBudget;
    }

    // Normal Unflatten path: push return address, branch to callee.
    SetRegisterValue(Register::RSP, result);

    auto push_into_rsp = GetRegisterValue(Register::RIP);

    SetMemoryValue(getSPaddress(), push_into_rsp);

    auto bb = getOrCreateBB(jump_address, "bb_call");

    branch_backup(bb);
    builder->CreateBr(bb);

    blockInfo = BBInfo(jump_address, bb);
    printvalue2("pushing block");
    addUnvisitedAddr(blockInfo);
    run = 0;
  }
  } // end non-IAT call path
call_done:;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_ret() { // fix
  LLVMContext& context = builder->getContext();
  // [0] = rip
  // [1] = rsp
  // [2] = [rsp]

  // if its ret 0x10
  // then its
  // [0] = 0x10
  // [1] = rip
  // [2] = rsp
  // [3] = [rsp]

  auto rspvalue = GetRegisterValue(Register::RSP);

  // IMPORTANT, change logic
  auto realval = GetMemoryValue(getSPaddress(), 64); // todo : based on bitness

  auto block = builder->GetInsertBlock();
  auto function = block->getParent();
  // auto lastinst = builder->CreateRet(realval);

  printvalue(rspvalue);

  // remov
  debugging::doIfDebug([&]() {
    std::string Filename = "output_rets.ll";
    std::error_code EC;
    raw_fd_ostream OS(Filename, EC);
    function->getParent()->print(OS, nullptr);
  });

  auto emitResolvedFunctionReturn = [&]() {
    auto rax = GetRegisterValue(Register::RAX);
    rax = createZExtFolder(
        rax, builder->getIntNTy(file.getMode() == arch_mode::X64 ? 64 : 32));
    builder->CreateRet(rax);
    run = 0;
    finished = 1;
    printvalue2(finished);
  };

  uint64_t destination = 0;

  uint8_t rop_result = REAL_return;

  if (llvm::ConstantInt* constInt =
          llvm::dyn_cast<llvm::ConstantInt>(rspvalue)) {
    int64_t rspval = constInt->getSExtValue();
    printvalue2(rspval);
    rop_result = rspval == STACKP_VALUE ? REAL_return : ROP_return;
    std::cout << "[ret] at 0x" << std::hex
              << (current_address - instruction.length) << " rsp=0x"
              << static_cast<uint64_t>(rspval) << " initRSP=0x"
              << static_cast<uint64_t>(STACKP_VALUE) << std::dec
              << " disp=" << (rspval - static_cast<int64_t>(STACKP_VALUE))
              << " rop=" << static_cast<int>(rop_result) << "\n"
              << std::flush;
  }
  printvalue2(rop_result);

  if (rop_result == REAL_return) {
    block->setName("real_return-" + std::to_string(current_address) + "-");
    emitResolvedFunctionReturn();
    return;
  }


  // --- ROP/continuation return: pop return address and adjust RSP ---
  const int ptrSize = (file.getMode() == arch_mode::X64) ? 8 : 4;
  auto val = ConstantInt::getSigned(Type::getInt64Ty(context), ptrSize);
  auto rsp_result = createAddFolder(
      rspvalue, val, "ret-new-rsp-" + std::to_string(current_address) + "-");

  // Handle `ret imm16` (callee-cleanup: stdcall, fastcall, or thunks).
  if (instruction.types[0] == OperandType::Immediate16) {
    rsp_result =
        createAddFolder(rsp_result, ConstantInt::get(rsp_result->getType(),
                                                     instruction.immediate));

    // Diagnostic: callee-cleanup detected via ret-immediate.
    const auto retCleanup =
        (getEffectiveAbi() == AbiKind::X86_STDCALL ||
         getEffectiveAbi() == AbiKind::X86_FASTCALL)
            ? StackCleanup::Callee
            : StackCleanup::Unknown;
    debugging::doIfDebug([&]() {
      std::cout << "[call-abi] ret imm=" << instruction.immediate
                << " cleanup=" << abi::stackCleanupName(retCleanup)
                << " at 0x" << std::hex
                << (current_address - instruction.length)
                << std::dec << "\n" << std::flush;
    });
  }

  SetRegisterValue(Register::RSP, rsp_result);

  if (auto* targetConst = llvm::dyn_cast<llvm::ConstantInt>(realval)) {
    uint64_t targetVA =
        normalizeFileBackedRuntimeTargetAddress(targetConst->getZExtValue());
    auto importIt = importMap.find(targetVA);
    if (importIt != importMap.end()) {
      auto* contVal = GetMemoryValue(getSPaddress(), 64);
      if (auto* contConst = llvm::dyn_cast<llvm::ConstantInt>(contVal)) {
        uint64_t contVA = contConst->getZExtValue();
        auto* contRsp = createAddFolder(
            rsp_result,
            ConstantInt::getSigned(Type::getInt64Ty(context), ptrSize),
            "ret-chain-cont-rsp-" + std::to_string(current_address) + "-");
        SetRegisterValue(Register::RSP, contRsp);
        const std::string& importName = importIt->second;
        // Emit `call @import` but with an EMPTY volatileRegs set so the
        // lifter does not clobber caller-saved GPRs post-call. Rationale:
        // VM-staged imports are invoked from a dispatcher that preserves
        // its own caller-saved state across the external call in the
        // real binary (otherwise the VM would be broken). Clobbering
        // those regs in the lifter makes the dispatcher's next step
        // non-concrete, trapping further exploration in one handler.
        auto* externFuncType = parseArgsType(
            signatures.getFunctionInfo(importName), builder->getContext());
        llvm::Function* externFunc = llvm::cast<llvm::Function>(
            fnc->getParent()
                ->getOrInsertFunction(importName, externFuncType)
                .getCallee());
        std::vector<llvm::Value*> args =
            parseArgs(signatures.getFunctionInfo(importName));
        auto* callResult = builder->CreateCall(externFunc, args);
        auto fx = buildUnknownCallFx();
        fx.target = CallTargetClass::KnownByName;
        fx.volatileRegs = {};
        applyPostCallEffects(callResult, fx);
        auto* contBB = getOrCreateBB(contVA,
            "bb_after_import_" + importName + "_" + std::to_string(contVA));
        builder->CreateBr(contBB);
        if (!visitedAddresses.contains(contVA)) {
          addUnvisitedAddr(BBInfo(contVA, contBB));
        }
        chainedImportRetSites.insert(current_address - instruction.length);
        destination = contVA;
        // Stop the outer per-instruction lift loop for this block: the
        // chain has emitted the block's terminator (br to contBB). Any
        // further instruction lift here would emit a SECOND terminator,
        // leaving the block malformed - the second br silently orphans
        // everything the chain's first br reached, so the new import's
        // call ends up in a dead BB that O2 then DCEs.
        run = 0;
        finished = 1;
        return;
      }
    }
  }

  ScopedPathSolveContext pathSolveContext(this, PathSolveContext::Ret);
  currentTransferValue = realval;
  currentVipIsExact = false;
  const uint64_t vipFromMod = vipModuleOffset(realval, &currentVipIsExact);
  const uint64_t vipFromChain =
      vipFromMod == 0 ? vipFromFoldChain(realval) : 0;
  const uint64_t vipFromCur = vmp.vipOffset();
  if (vipFromMod != 0) {
    currentVipOffset = vipFromMod;
  } else if (vipFromChain != 0) {
    currentVipOffset = vipFromChain;
    currentVipIsExact = isBytecodeAddress(vipFromChain);
  } else if (isBytecodeAddress(vipFromCur)) {
    currentVipOffset = vipFromCur;
  } else {
    currentVipOffset = 0;
  }
  logTransferVipPick("ret", realval, vipFromMod, vipFromChain, vipFromCur);
  const uint64_t retRVA = maskedRVA(current_address - instruction.length);
  auto dumpRetTargetDag = [&](const char* tag) {
    std::cout << "[rdag] " << tag << " ret target at 0x" << std::hex
              << (current_address - instruction.length) << " rva=0x" << retRVA
              << std::dec << " :\n"
              << std::flush;
    std::set<llvm::Value*> seen;
    std::vector<std::pair<llvm::Value*, int>> work{{realval, 0}};
    unsigned visited = 0;
    unsigned loadN = 0;
    llvm::Value* firstBlocker = nullptr;
    while (!work.empty() && visited < 300) {
      auto entry = work.back();
      work.pop_back();
      llvm::Value* v = entry.first;
      if (!v || !seen.insert(v).second)
        continue;
      ++visited;
      std::cout << "  [" << entry.second << "] " << irText(v, 110);
      if (auto* li = llvm::dyn_cast<llvm::LoadInst>(v)) {
        ++loadN;
        std::cout << "  <LOAD#" << loadN
                  << " ptr=" << irText(li->getPointerOperand(), 90) << ">";
        llvm::Value* idxV = nullptr;
        if (auto* g = llvm::dyn_cast<llvm::GetElementPtrInst>(
                li->getPointerOperand())) {
          if (g->getNumOperands() >= 2)
            idxV = g->getOperand(1);
        }
        auto tryRetrv = [&](uint64_t off, const char* rtag) {
          LazyValue nl([li]() -> llvm::Value* { return li; });
          auto* rc = retrieveCombinedValue(
              off, li->getType()->getIntegerBitWidth() / 8, nl);
          std::cout << "  <RETRV-" << rtag << " off=0x" << std::hex << off
                    << std::dec << " -> ";
          if (!rc) {
            std::cout << "NULL buf=" << (buffer.count(off) ? 1 : 0);
          } else if (auto* ci = llvm::dyn_cast<llvm::ConstantInt>(rc)) {
            std::cout << "CI=0x" << std::hex << ci->getZExtValue() << std::dec;
          } else {
            std::cout << "SSA=" << irText(rc, 80);
          }
          std::cout << ">";
        };
        if (auto* oc = llvm::dyn_cast_or_null<llvm::ConstantInt>(idxV)) {
          tryRetrv(oc->getZExtValue(), "ci");
        } else if (auto* bo =
                       llvm::dyn_cast_or_null<llvm::BinaryOperator>(idxV)) {
          if (bo->getOpcode() == llvm::Instruction::Add) {
            auto* a0 = llvm::dyn_cast<llvm::ConstantInt>(bo->getOperand(0));
            auto* a1 = llvm::dyn_cast<llvm::ConstantInt>(bo->getOperand(1));
            if (a0 && !a1) {
              std::cout << "  <GEP-idx=add CI=0x" << std::hex
                        << a0->getZExtValue() << std::dec
                        << " + SSA=" << irText(bo->getOperand(1), 60) << ">";
              tryRetrv(a0->getZExtValue(), "base");
            } else if (a1 && !a0) {
              std::cout << "  <GEP-idx=add SSA="
                        << irText(bo->getOperand(0), 60) << " + CI=0x"
                        << std::hex << a1->getZExtValue() << std::dec << ">";
              tryRetrv(a1->getZExtValue(), "base");
            } else {
              std::cout << "  <GEP-idx=add nonCI>";
            }
          } else {
            std::cout << "  <GEP-idx=binop " << bo->getOpcodeName() << ">";
          }
        } else if (idxV) {
          std::cout << "  <GEP-idx=SSA " << irText(idxV, 70) << ">";
        } else {
          std::cout << "  <GEP-idx=?>";
        }
        if (!firstBlocker)
          firstBlocker = li;
      }
      if (llvm::isa<llvm::Argument>(v)) {
        std::cout << "  <ARG>";
        if (!firstBlocker)
          firstBlocker = v;
      }
      std::cout << "\n";
      if (auto* u = llvm::dyn_cast<llvm::User>(v))
        for (auto& op : u->operands())
          work.push_back({op.get(), entry.second + 1});
    }
    if (firstBlocker)
      std::cout << "[rdag] first-blocker: " << irText(firstBlocker, 160)
                << "\n";
    std::cout << "[rdag] loads_seen=" << loadN << " nodes=" << visited << "\n"
              << std::flush;
  };
  {
    static bool dumpedAny = false;
    // Always dump the known mix exit ret (0x33ce78); otherwise first ret only.
    const bool dumpThis = (retRVA == 0x33ce78ull) || !dumpedAny;
    if (dumpThis) {
      dumpedAny = true;
      std::cout << "[vipret] at 0x" << std::hex
                << (current_address - instruction.length) << " rva=0x" << retRVA
                << " isLoad=" << llvm::isa<llvm::LoadInst>(realval)
                << " isCI=" << llvm::isa<llvm::ConstantInt>(realval)
                << " valueID=" << realval->getValueID()
                << " bufHas14fc58=" << buffer.count(0x14fc58)
                << " bufHas14fe70=" << buffer.count(0x14fe70)
                << " bufSize=" << buffer.size()
                << " provSize=" << loadProvenance.size()
                << " lastModLoad=0x" << vmp.vipOffset() << std::dec
                << " realval=" << irText(realval, 220) << "\n"
                << std::flush;
      // Top shape: add i64 %x, 0x14000750c  (customer ret VA)
      if (auto* bo = llvm::dyn_cast<llvm::BinaryOperator>(realval)) {
        if (bo->getOpcode() == llvm::Instruction::Add) {
          auto* c0 = llvm::dyn_cast<llvm::ConstantInt>(bo->getOperand(0));
          auto* c1 = llvm::dyn_cast<llvm::ConstantInt>(bo->getOperand(1));
          llvm::Value* other = nullptr;
          uint64_t imm = 0;
          if (c1 && !c0) {
            other = bo->getOperand(0);
            imm = c1->getZExtValue();
          } else if (c0 && !c1) {
            other = bo->getOperand(1);
            imm = c0->getZExtValue();
          }
          if (other) {
            std::cout << "[vipret] add-shape imm=0x" << std::hex << imm
                      << " (==750c? " << (imm == 0x14000750cull) << ")"
                      << " other_isCI=" << llvm::isa<llvm::ConstantInt>(other)
                      << std::dec << " other=" << irText(other, 160) << "\n"
                      << std::flush;
          }
        }
      }
      // Dump DAG BEFORE solvePath: AV has been observed inside solvePath on
      // this site, which previously skipped the post-unsolved rdag dump.
      if (retRVA == 0x33ce78ull && !llvm::isa<llvm::ConstantInt>(realval)) {
        dumpRetTargetDag("pre-solve");
      }
    }
  }
  auto pathResult = solvePath(function, destination, realval);
  if (pathResult == PATH_unsolved) {
    uint64_t diagAddr = current_address - instruction.length;
    const bool chained =
        chainedImportRetSites.find(diagAddr) != chainedImportRetSites.end();
    if (!chained) {
      ++liftStats.blocks_unreachable;
      diagnostics.warning(DiagCode::UnresolvedRetChain, diagAddr,
                          "Unresolved ROP chain (ret to symbolic address)");
      static unsigned dumpedRdCount = 0;
      // 0x33ce78 already dumped pre-solve; dump other first unresolved (≤2).
      if (retRVA != 0x33ce78ull && dumpedRdCount < 2) {
        ++dumpedRdCount;
        dumpRetTargetDag("unsolved");
      }
    }
    // Block is currently unterminated: solvePath did not resolve the popped
    // RIP, no chain fired, and we are at a `ret`. The most accurate
    // semantic is "return to a caller we do not have context for" -
    // degrade to REAL_return behaviour: emit `ret rax` and stop the
    // block. This keeps the IR well-formed, lets DCE collapse the block
    // if it ends up unreachable, and prevents the outer per-instruction
    // lift loop from advancing past the ret and emitting a second
    // terminator into the same block.
    if (!builder->GetInsertBlock()->getTerminator()) {
      auto rax = GetRegisterValue(Register::RAX);
      rax = createZExtOrTruncFolder(
          rax,
          llvm::Type::getIntNTy(
              context, file.getMode() == arch_mode::X64 ? 64 : 32));
      builder->CreateRet(rax);
    }
    run = 0;
    finished = 1;
    return;
  }

  // If the callee returned to our speculative call's return address,
  // the inline succeeded — deactivate the budget.
  if (speculativeCall.active && destination == speculativeCall.returnAddr) {
    speculativeCall.active = false;
    speculativeCallBudget = 0;
  }
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jmp() {
  LLVMContext& context = builder->getContext();
  // auto dest = operands[0];
  auto Value = GetIndexValue(0);
  auto ripval = GetRegisterValue(Register::RIP);
  Value = createSExtFolder(Value, ripval->getType());
  // TODO:
  // if its an imm, sext
  // if its r/m then we probably need to zext
  // auto newRip = createAddFolder(
  //    Value, ripval, "jump-xd-" + std::to_string(current_address) + "-");
  jmpcount++;
  auto targetv = Value;
  auto trunc = createSExtOrTruncFolder(targetv, Type::getInt64Ty(context),
                                       "jmp-register");
  printvalue(ripval);
  printvalue(trunc);
  uint64_t destination = 0;
  auto function = builder->GetInsertBlock()->getParent();
  const bool isDirectJump = instruction.types[0] == OperandType::Immediate8 ||
                            instruction.types[0] == OperandType::Immediate16 ||
                            instruction.types[0] == OperandType::Immediate32 ||
                            instruction.types[0] == OperandType::Immediate64;
  // For direct jumps the immediate is RIP-relative, so add it to the
  // current RIP to get the absolute target. Indirect jumps already hold
  // an absolute address (or a computed pointer) in `trunc`.
  if (isDirectJump) {
    trunc = createAddFolder(trunc, ripval);
    printvalue(trunc);
  }
  ScopedPathSolveContext pathSolveContext(
      this, isDirectJump ? PathSolveContext::DirectJump
                         : PathSolveContext::IndirectJump);
  currentTransferValue = trunc;
  currentVipIsExact = false;
  const uint64_t vipFromMod = vipModuleOffset(trunc, &currentVipIsExact);
  const uint64_t vipFromChain =
      vipFromMod == 0 ? vipFromFoldChain(trunc) : 0;
  const uint64_t vipFromCur = vmp.vipOffset();
  if (vipFromMod != 0) {
    currentVipOffset = vipFromMod;
  } else if (vipFromChain != 0) {
    currentVipOffset = vipFromChain;
    currentVipIsExact = isBytecodeAddress(vipFromChain);
  } else if (isBytecodeAddress(vipFromCur)) {
    currentVipOffset = vipFromCur;
  } else {
    currentVipOffset = 0;
  }
  logTransferVipPick(isDirectJump ? "djmp" : "ijmp", trunc, vipFromMod,
                     vipFromChain, vipFromCur);
  if (liftProgressDiagEnabled &&
      (current_address - instruction.length == 0x1403B1543ULL ||
       current_address - instruction.length == 0x1403B4FF9ULL)) {
    static int trampolineDiag = 0;
    if (trampolineDiag++ < 4) {
      std::string tv;
      llvm::raw_string_ostream tvo(tv);
      trunc->print(tvo);
      std::cout << "[fold] trampoline@0x" << std::hex
                << (current_address - instruction.length) << " target=" << tv
                << " isConst=" << llvm::isa<llvm::Constant>(trunc)
                << " vip=0x" << currentVipOffset << " chain=0x"
                << vipFromFoldChain(trunc) << " lastModLoad=0x"
                << vmp.vipOffset() << std::dec << "\n"
                << std::flush;
    }
  }
  auto pathResult = solvePath(function, destination, trunc);
  if (pathResult == PATH_unsolved || pathResult == PATH_multi_solved) {
    uint64_t diagAddr = current_address - instruction.length;
    if (pathResult == PATH_unsolved) {
      ++liftStats.blocks_unreachable;
      diagnostics.warning(DiagCode::UnresolvedIndirectJump, diagAddr,
                          "Unresolved indirect jump (symbolic target)");
    }

    // One-shot register census at the instruction whose target could not be
    // resolved. The dispatch is `movsxd r8,r8d; add r10,r8; jmp r10`, so the
    // whole question is whether r10/r8 descend from a concrete value or from a
    // register that the lifter only holds symbolically. Printed in full (no
    // truncation) because the answer is usually the last operand of a long
    // expression.
    if (liftProgressDiagEnabled) {
      auto full = [&](llvm::Value* v) {
        std::string s;
        llvm::raw_string_ostream os(s);
        if (v) {
          v->print(os);
        } else {
          os << "<null>";
        }
        return os.str();
      };
      std::cout << "[halt] unresolved at 0x" << std::hex << diagAddr
                << std::dec << " pv=" << (int)pathResult
                << " transfer=" << full(trunc) << "\n";
      const std::pair<Register, const char*> regs[] = {
          {Register::RSP, "RSP"}, {Register::RBP, "RBP"},
          {Register::RAX, "RAX"}, {Register::RBX, "RBX"},
          {Register::RCX, "RCX"}, {Register::RDX, "RDX"},
          {Register::RSI, "RSI"}, {Register::RDI, "RDI"},
          {Register::R8, "R8"},   {Register::R9, "R9"},
          {Register::R10, "R10"}, {Register::R11, "R11"},
          {Register::R12, "R12"}, {Register::R13, "R13"},
          {Register::R14, "R14"}, {Register::R15, "R15"},
      };
      for (const auto& [reg, name] : regs) {
        std::cout << "[halt]   " << name << " = " << full(GetRegisterValue(reg))
                  << "\n";
      }
      std::cout << std::flush;
    }

    // VIP diagnostic (Aftermath Labs, VMP): the last module load feeding the
    // indirect jump is the VIP. When the target stays symbolic, dumping every
    // load reachable from it shows which bytecode load failed to promote.
    static int dumpedVipDag = 0;
    if (dumpedVipDag < 0) {
      ++dumpedVipDag;
      std::string targetText;
      llvm::raw_string_ostream targetOs(targetText);
      trunc->print(targetOs);
      std::cout << "[vip] unresolved indirect target at 0x" << std::hex
                << diagAddr << std::dec << " = " << targetOs.str() << "\n";

      std::set<llvm::Value*> seen;
      std::vector<std::pair<llvm::Value*, int>> work{{trunc, 0}};
      unsigned visited = 0;
      unsigned loads = 0;
      while (!work.empty() && visited < 20000) {
        auto entry = work.back();
        work.pop_back();
        llvm::Value* v = entry.first;
        if (!v || !seen.insert(v).second) {
          continue;
        }
        ++visited;
        if (auto* li = llvm::dyn_cast<llvm::LoadInst>(v)) {
          std::string ptrText;
          llvm::raw_string_ostream ptrOs(ptrText);
          li->getPointerOperand()->print(ptrOs);
          std::cout << "[vip] load#" << loads++ << " (" << li->getType()
                    << ") ptr=" << ptrOs.str();
          if (auto* gep =
                  llvm::dyn_cast<llvm::GetElementPtrInst>(li->getPointerOperand())) {
            if (auto* off = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1))) {
              std::cout << " off=0x" << std::hex << off->getZExtValue() << std::dec;
            } else {
              std::string offText;
              llvm::raw_string_ostream offOs(offText);
              gep->getOperand(1)->print(offOs);
              std::cout << " off=<sym " << offOs.str() << ">";
            }
          }
          std::cout << "\n";
        } else if (visited <= 220) {
          std::string nodeText;
          llvm::raw_string_ostream nodeOs(nodeText);
          v->print(nodeOs);
          std::cout << "[vip] [" << entry.second << "] "
                    << nodeOs.str().substr(0, 150) << "\n";
        }
        if (auto* u = llvm::dyn_cast<llvm::User>(v)) {
          for (auto& op : u->operands()) {
            work.push_back({op.get(), entry.second + 1});
          }
        }
      }
      std::cout << "[vip] dag visited=" << visited << " loads=" << loads << "\n"
                << std::flush;
    }
  }
  printvalue2(destination);
  // printvalue(newRip);
  // SetRegisterValueWrapper(Register::RIP, newRip);
}

// jnz and jne
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jnz() {

  auto zf = getFlag(FLAG_ZF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jnz");

  printvalue(zf);

  branchHelper(zf, "jnz", branchnumber, 1);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_js() {

  auto sf = getFlag(FLAG_SF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "js");

  branchHelper(sf, "js", branchnumber);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jns() {

  auto sf = getFlag(FLAG_SF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jns");

  branchHelper(sf, "jns", branchnumber, 1);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jz() {

  // if 0, then jmp, if not then not jump

  auto zf = getFlag(FLAG_ZF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jnz");

  branchHelper(zf, "jz", branchnumber);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jle() {
  // If SF != OF or ZF = 1, then jump. Otherwise, do not jump.

  auto sf = getFlag(FLAG_SF);
  auto of = getFlag(FLAG_OF);
  auto zf = getFlag(FLAG_ZF);

  // auto dest = operands[0];
  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jle");

  // Check if SF != OF or ZF is set
  auto sf_neq_of = createXorFolder(sf, of, "jle_SF_NEQ_OF");
  auto condition = createOrFolder(sf_neq_of, zf, "jle_Condition");

  branchHelper(condition, "jle", branchnumber);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jl() {
  auto sf = getFlag(FLAG_SF);
  auto of = getFlag(FLAG_OF);

  // auto dest = operands[0];
  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jl");
  printvalue(sf);
  printvalue(of);
  auto condition = createXorFolder(sf, of, "jl_Condition");

  branchHelper(condition, "jl", branchnumber);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jnl() {
  auto sf = getFlag(FLAG_SF);
  auto of = getFlag(FLAG_OF);

  // auto dest = operands[0];
  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jnl");

  printvalue(sf);
  printvalue(of);

  auto condition = createXorFolder(sf, of, "jl_condition");

  branchHelper(condition, "jnl", branchnumber, 1);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jnle() {
  // If SF != OF or ZF = 1, then jump. Otherwise, do not jump.

  auto sf = getFlag(FLAG_SF);
  auto of = getFlag(FLAG_OF);
  auto zf = getFlag(FLAG_ZF);

  // auto dest = operands[0];
  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jle");

  // Check if SF != OF or ZF is set
  auto sf_neq_of = createXorFolder(sf, of, "jle_SF_NEQ_OF");
  auto condition = createOrFolder(sf_neq_of, zf, "jle_Condition");

  branchHelper(condition, "jnle", branchnumber, 1);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jbe() {

  auto cf = getFlag(FLAG_CF);
  auto zf = getFlag(FLAG_ZF);
  printvalue(cf) printvalue(zf) // auto dest = operands[0];

      // auto Value = GetIndexValue( dest, 64);
      // auto ripval = GetRegisterValue( Register::RIP);
      // auto newRip = createAddFolder( Value, ripval, "jbe");

      auto condition = createOrFolder(cf, zf, "jbe_Condition");

  branchHelper(condition, "jbe", branchnumber);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jb() {

  auto cf = getFlag(FLAG_CF);
  printvalue(cf);
  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jb");

  auto condition = cf;
  branchHelper(condition, "jb", branchnumber);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jnb() {

  auto cf = getFlag(FLAG_CF);
  printvalue(cf);
  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jnb");

  auto condition = cf;
  branchHelper(condition, "jnb", branchnumber, 1);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jnbe() {

  auto cf = getFlag(FLAG_CF);
  auto zf = getFlag(FLAG_ZF);
  printvalue(cf) printvalue(zf); // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);
  // auto newRip = createAddFolder( Value, ripval, "jbe");

  auto condition = createOrFolder(cf, zf, "jnbe_Condition");

  branchHelper(condition, "jnbe", branchnumber, 1);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jo() {

  auto of = getFlag(FLAG_OF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jo");

  printvalue(of);
  branchHelper(of, "jo", branchnumber);

  branchnumber++;
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jno() {

  auto of = getFlag(FLAG_OF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jno");

  branchHelper(of, "jno", branchnumber, 1);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jp() {

  auto pf = getFlag(FLAG_PF);
  printvalue(pf);
  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jp");

  branchHelper(pf, "jp", branchnumber);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_jnp() {

  auto pf = getFlag(FLAG_PF);

  // auto dest = operands[0];

  // auto Value = GetIndexValue( dest, 64);
  // auto ripval = GetRegisterValue( Register::RIP);

  // auto newRip = createAddFolder( Value, ripval, "jnp");

  printvalue(pf);
  branchHelper(pf, "jnp", branchnumber, 1);

  branchnumber++;
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_loopx() {
  if (instruction.length != 2 || instruction.attributes != InstructionPrefix::None) {
    Function* externFunc = cast<Function>(
        fnc->getParent()
            ->getOrInsertFunction("not_implemented", fnc->getReturnType())
            .getCallee());
    builder->CreateRet(builder->CreateCall(externFunc));
    run = 0;
    finished = 1;
    return;
  }


  const auto counterRegister =
      getRegOfSize(Register::RCX, file.getMode() == arch_mode::X64 ? 64 : 32);
  auto counterValue = GetRegisterValue(counterRegister);
  auto one = ConstantInt::get(counterValue->getType(), 1);
  auto decrementedCount =
      createSubFolder(counterValue, one, "loop-count-" + std::to_string(current_address));
  SetRegisterValue(counterRegister, decrementedCount);

  auto countNonZero = createICMPFolder(
      CmpInst::ICMP_NE, decrementedCount, ConstantInt::get(counterValue->getType(), 0),
      "loop-count-nonzero");

  Value* branchCondition = nullptr;
  switch (instruction.mnemonic) {
  case Mnemonic::LOOP:
    branchCondition = countNonZero;
    break;
  case Mnemonic::LOOPE:
    branchCondition = createAndFolder(countNonZero, getFlag(FLAG_ZF), "loope-cond");
    break;
  case Mnemonic::LOOPNE:
    branchCondition = createAndFolder(
        countNonZero, createNotFolder(getFlag(FLAG_ZF)), "loopne-cond");
    break;
  default:
    UNREACHABLE("unreachable mnemonic in lift_loopx");
  }

  branchHelper(branchCondition, "loop", branchnumber);
  branchnumber++;
}
