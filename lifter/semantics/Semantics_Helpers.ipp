// Semantics_Helpers.ipp — Flag computation, branch helper, call support

// GPR order used for unknown-call argument passing (compat mode).
// This is the canonical x64 GPR ordering without duplicates.
// The memory pointer is appended separately.
template <typename Register>
static constexpr std::array<Register, 16> kAllGPROrder = {
    Register::RAX, Register::RCX, Register::RDX, Register::RBX,
    Register::RSP, Register::RBP, Register::RSI, Register::RDI,
    Register::R8,  Register::R9,  Register::R10, Register::R11,
    Register::R12, Register::R13, Register::R14, Register::R15,
};

// Compat passes all 16 GPRs even though the ABI only uses a few of them. That
  // is the point of compat mode: over-approximating which registers the callee
  // might read keeps more of the caller's state available to the path solver,
  // at the cost of a wider call signature in the emitted IR.
  //
  // Every argument is zero-extended rather than bitcast, so a 32-bit register
  // read still yields a well-typed i64 with the upper bits clear. That matches
  // how the rest of the lifter represents registers.
MERGEN_LIFTER_DEFINITION_TEMPLATES(FunctionType*)::parseArgsType(
    funcsignatures<Register>::functioninfo* funcInfo, LLVMContext& context) {
  if (!funcInfo) {
    // Unknown call: build type from ABI config.
    //
    // Compat mode: 16 GPRs (i64) + memory ptr = 17 args, returns i64.
    // Strict mode: only ABI arg registers + memory ptr, returns i64.
    //
    // Both modes include the memory pointer as the final argument
    // so the callee can model memory side effects.
    const auto fx = this->buildUnknownCallFx();
    std::vector<llvm::Type*> argTypes;

    if (this->callModelMode == CallModelMode::Compat) {
      // Pass all 16 GPRs for maximum information preservation.
      argTypes.assign(16, llvm::Type::getInt64Ty(context));
    } else {
      // Strict: only ABI argument registers.
      argTypes.assign(fx.argRegs.size(), llvm::Type::getInt64Ty(context));
    }
    // Memory pointer (always last).
    argTypes.push_back(llvm::PointerType::get(context, 0));

    return FunctionType::get(Type::getInt64Ty(context), argTypes, false);
  }

  // Known function: build type from funcInfo arg descriptors.
  std::vector<llvm::Type*> argTypes;
  for (const auto& arg : funcInfo->args) {
    unsigned bitWidth = 64;
    switch (static_cast<ArgType>(arg.argtype.size)) {
    case ArgType::I8:   bitWidth = 8;   break;
    case ArgType::I16:  bitWidth = 16;  break;
    case ArgType::I32:  bitWidth = 32;  break;
    case ArgType::I64:  bitWidth = 64;  break;
    case ArgType::I128: bitWidth = 128; break;
    default:            bitWidth = 64;  break;
    }

    llvm::Type* type = llvm::Type::getIntNTy(context, bitWidth);
    if (arg.argtype.isPtr) {
      type = type->getPointerTo();
    }
    argTypes.push_back(type);
  }

  return llvm::FunctionType::get(llvm::Type::getInt64Ty(context), argTypes,
                                 false);
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(std::vector<Value*>)::parseArgs(
    funcsignatures<Register>::functioninfo* funcInfo) {
  auto& context = builder->getContext();

  if (!funcInfo) {
    // Unknown call: build arg list from ABI config.
    const auto fx = this->buildUnknownCallFx();
    std::vector<Value*> args;

    if (this->callModelMode == CallModelMode::Compat) {
      // Compat: pass all 16 GPRs in canonical order (no duplicates).
      for (auto reg : kAllGPROrder<Register>) {
        args.push_back(
            createZExtFolder(GetRegisterValue(reg),
                             Type::getInt64Ty(context)));
      }
    } else {
      // Strict: only ABI argument registers.
      for (auto reg : fx.argRegs) {
        args.push_back(
            createZExtFolder(GetRegisterValue(reg),
                             Type::getInt64Ty(context)));
      }
    }
    // Memory pointer (always last).
    args.push_back(memoryAlloc);
    return args;
  }

  // Known function: build args from funcInfo descriptors.
  std::vector<Value*> args;
  for (const auto& arg : funcInfo->args) {
    Value* argValue = GetRegisterValue(arg.reg);

    unsigned bitWidth = 64;
    switch (static_cast<ArgType>(arg.argtype.size)) {
    case ArgType::I8:   bitWidth = 8;   break;
    case ArgType::I16:  bitWidth = 16;  break;
    case ArgType::I32:  bitWidth = 32;  break;
    case ArgType::I64:  bitWidth = 64;  break;
    case ArgType::I128: bitWidth = 128; break;
    default:            bitWidth = 64;  break;
    }

    argValue =
        createZExtOrTruncFolder(argValue, Type::getIntNTy(context, bitWidth));
    if (arg.argtype.isPtr)
      argValue = getPointer(argValue);
    args.push_back(argValue);
  }
  return args;
}

// Apply post-call ABI effects after a CreateCall for an external/unknown target.
// In compat mode: only assign return value (RAX = call result).
// In strict mode: assign return value + clobber all volatile registers.
// UndefValue, not a fresh zero. The callee may or may not have written the
  // register; zero would assert it did not, which is a stronger and usually
  // wrong claim. Undef is the weakest correct answer and lets later
  // simplification collapse the value when nothing reads it.
//
// Return-register writes are skipped in this loop because they were already
  // written in step 1 with the call result; clobbering RAX with Undef after
  // storing the return value would discard the result.
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::applyPostCallEffects(
    Value* callResult, const CallEffects<Register>& fx) {
  auto& context = builder->getContext();

  // 1. Assign return value to the ABI return register(s).
  //    For x64 MSVC and all x86 CCs, the primary return register is RAX.
  if (!fx.retRegs.empty()) {
    auto retReg = *fx.retRegs.begin();
    auto retVal = createZExtOrTruncFolder(
        callResult,
        Type::getIntNTy(context,
                        file.getMode() == arch_mode::X64 ? 64 : 32));
    SetRegisterValue(retReg, retVal);
  }

  // 2. Clobber volatile registers (strict mode only).
  //    Write UndefValue to each volatile register to model the fact that
  //    the callee may have destroyed their contents.
  //    Skip registers that are also return registers (already written above).
  for (auto reg : fx.volatileRegs) {
    if (fx.retRegs.contains(reg))
      continue;
    auto undef = llvm::UndefValue::get(
        Type::getIntNTy(context,
                        file.getMode() == arch_mode::X64 ? 64 : 32));
    SetRegisterValue(reg, undef);
  }

  // 3. Memory effects.
  //    MayReadWrite: no action needed in the current memory model (the
  //    memory pointer is passed to the callee and any alias analysis
  //    already treats external calls as opaque).
  //    Preserve: no action needed (default).
}

// Two shapes of call, and the null funcInfo is what distinguishes them.
//
//   funcInfo supplied  a signature matched at this address (see
//                      Semantics.ipp's probe) -- we know the real signature
//   funcInfo null      a call out of the image; look the name up by symbol
//
// Either way the same lowering happens: declare or reuse a module function and
// emit a call to it. The lifter does not model the callee's body; it models
// the call's ABI effects and lets the path solver decide what that implies.
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::callFunctionIR(
    const std::string& functionName,
    funcsignatures<Register>::functioninfo* funcInfo) {
  auto& context = builder->getContext();

  if (!funcInfo) {
    funcInfo = signatures.getFunctionInfo(functionName);
  }
  FunctionType* externFuncType = parseArgsType(funcInfo, context);
  auto M = builder->GetInsertBlock()->getParent()->getParent();

  Function* externFunc = cast<Function>(
      M->getOrInsertFunction(functionName, externFuncType).getCallee());
  std::vector<Value*> args = parseArgs(funcInfo);
  auto callresult = builder->CreateCall(externFunc, args);

  // Build call effects for the known call.
  // Known calls use the same ABI but with KnownByName target class.
  auto fx = this->buildUnknownCallFx();
  fx.target = CallTargetClass::KnownByName;
  applyPostCallEffects(callresult, fx);
  abi::printCallEffectsDiag(fx, current_address - instruction.length);

  return callresult;
}

// Signed overflow for ADC.
//
// The trick is that `add` already contains the carry-in, so adding it back
// would double-count. `ofAdd = add + cf` is used here to *undo* the carry:
// since add = L + R + cf (mod 2^n), adding cf again would be wrong, but the
// XOR-with-sum identity below needs the carry-free sum. The convention here
// treats cf as subtracted (`add - cf`); the add is expressed as an add because
// this lifter has no sub folder wired up at this layer.
//
// Overflow for addition is then: (L ^ sum) & (R ^ sum) has the sign bit set.
// Each XOR isolates the carry into the top bit from one operand, and signed
// overflow requires both to have carried.
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::computeOverflowFlagAdc(
    Value* Lvalue, Value* Rvalue, Value* cf, Value* add) {
  auto cfc = createZExtOrTruncFolder(cf, add->getType(), "ofadc1");
  auto ofAdd = createAddFolder(add, cfc, "ofadc2");
  // (L ^ sum) isolates the carry chain that started in L.
  auto xor0 = createXorFolder(Lvalue, ofAdd, "ofadc3");
  // (R ^ sum) isolates the one that started in R.
  auto xor1 = createXorFolder(Rvalue, ofAdd, "ofadc4");
  // Both set => the top bit flipped relative to both inputs => signed overflow.
  auto ofAnd = createAndFolder(xor0, xor1, "ofadc5");
  // Test the sign bit by signed-comparing against 0.
  return createICMPFolder(CmpInst::ICMP_SLT, ofAnd,
                          ConstantInt::get(ofAnd->getType(), 0), "ofadc6");
}

// Signed overflow for plain ADD. Same identity as the ADC case with no
// carry-in to undo, so `add` is used directly.
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::computeOverflowFlagAdd(
    Value* Lvalue, Value* Rvalue, Value* add) {
  auto xor0 = createXorFolder(Lvalue, add, "ofadd");
  auto xor1 = createXorFolder(Rvalue, add, "ofadd1");
  auto ofAnd = createAndFolder(xor0, xor1, "ofadd2");
  return createICMPFolder(CmpInst::ICMP_SLT, ofAnd,
                          ConstantInt::get(ofAnd->getType(), 0), "ofadd3");
}

// Signed overflow for SUB.
//
// A different identity, because subtraction is addition of the two's
// complement: (L ^ R) gives the borrow pattern across all bits, and
// (L ^ result) gives the borrow into the top bit specifically. Their AND,
// sign-tested, is set exactly when the subtraction under- or overflowed.
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::computeOverflowFlagSub(
    Value* Lvalue, Value* Rvalue, Value* sub) {
  auto xor0 = createXorFolder(Lvalue, Rvalue, "ofsub");
  auto xor1 = createXorFolder(Lvalue, sub, "ofsub1");
  auto ofAnd = createAndFolder(xor0, xor1, "ofsub2");
  return createICMPFolder(CmpInst::ICMP_SLT, ofAnd,
                          ConstantInt::get(ofAnd->getType(), 0), "ofsub3");
}

// Signed overflow for SBB (subtract with borrow).
//
// Written differently from the SUB case on purpose: instead of XOR identities
// it shifts each value right by (width-1) to reduce it to its sign bit alone.
// A logical right shift by width-1 yields 0 or 1 -- that is, the sign bit --
// so the following XORs and the final comparison happen over 0/1 values only.
//
//   result_idk  = sign(L) ^ sign(R)   -- operands differ in sign
//   result_idk2 = sign(L) ^ sign(res) -- result disagrees with the operands
//   idk3        = the sum of those two
//
// Both being 1 means "operands differ in sign AND the result has the wrong
// sign", which is precisely signed overflow. Since each term is 0 or 1 the sum
// is 0, 1, or 2, so testing for == 2 is an exact encoding of "both set" and
// needs no AND.
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::computeOverflowFlagSbb(
    Value* Lvalue, Value* Rvalue, Value* cf, Value* sub) {

  // Logical, not arithmetic: shifting arithmetically would smear the sign bit
  // and defeat the point of extracting it.
  auto bitWidth = Lvalue->getType()->getIntegerBitWidth();
  auto signBit = builder->getIntN(bitWidth, bitWidth - 1);

  auto lhsSign = createLShrFolder(Lvalue, signBit);
  auto rhsSign = createLShrFolder(Rvalue, signBit);
  auto resultSign = createLShrFolder(sub, signBit);

  auto result_idk = createXorFolder(lhsSign, rhsSign);
  auto result_idk2 = createXorFolder(lhsSign, resultSign);
  auto result_idk3 = createAddFolder(result_idk, result_idk2);

  return createICMPFolder(CmpInst::ICMP_EQ, result_idk3,
                          ConstantInt::get(result_idk3->getType(), 2),
                          "ofsbb5");
}
// Auxiliary carry flag (AF): the carry out of bit 3 into bit 4.
//
// AF is the classic "half carry", the only flag the 8086-era hardware actually
// used (for BCD adjust). Its only user in practice is DAA/DAS/AAA/AAS.
//
// The identity: `result ^ (L ^ R)` has bit 4 set exactly when a carry crossed
// from bit 3 into bit 4. Masking with 0x10 and comparing against 0x10 turns
// that into a boolean.
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::computeAuxFlag(Value* Lvalue,
                                                           Value* Rvalue,
                                                           Value* result) {
  // 0x10 is bit 4 -- the boundary AF reports on, not bit 3.
  auto auxc = ConstantInt::get(result->getType(), 0x10);
  auto aux1 = createXorFolder(result, createXorFolder(Lvalue, Rvalue));
  auto aux2 = createAndFolder(auxc, aux1);
  auto af = createICMPFolder(CmpInst::ICMP_EQ, aux2, auxc);
  return af;
}

/*
https://graphics.stanford.edu/~seander/bithacks.html#ParityWith64Bits

Compute parity of a byte using 64-bit multiply and modulus division
unsigned char b;  // byte value to compute the parity of
bool parity =
  (((b * 0x0101010101010101ULL) & 0x8040201008040201ULL) % 0x1FF) & 1;
The method above takes around 4 operations, but only works on bytes.
*/
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::computeParityFlag(Value* value) {
  LLVMContext& context = value->getContext();

  // Low byte, zero-extended to i64 so the 64-bit constants below type-check.
  // Parity is defined over the low 8 bits only -- that is the definition of
  // the flag, not an approximation.
  Value* lsb = createZExtFolder(
      createAndFolder(value, ConstantInt::get(value->getType(), 0xFF), "lsb"),
      Type::getInt64Ty(context));

  // The published bit hack: multiply by the bit-spreading constant, mask with
  // the folded-XOR mask, reduce mod 0x1FF, take bit 0. Four operations, and
  // only valid on bytes -- which is why the widening above happens first.
  //
  // URem rather than SRem: both operands are known non-negative here, and
  // choosing the unsigned form keeps the solver from having to prove the sign
  // of the multiply result first. There is an unanswered "s or u?" note here
  // -- the choice is safe but the reasoning was never written down.
  Value* parity = createAndFolder(

      createURemFolder(
          createAndFolder(

              createMulFolder(
                  lsb, ConstantInt::get(lsb->getType(), 0x0101010101010101),
                  "pf1"),
              ConstantInt::get(lsb->getType(), 0x8040201008040201ULL), "pf2"),
          ConstantInt::get(lsb->getType(), 0x1FF), "pf3"),
      ConstantInt::get(lsb->getType(), 1), "pf4");
  // parity
  // PF (parity flag) is set when the number of set bits in the low byte is
  // EVEN, so it reads as "no parity error". The expression above computes
  // parity == 1 meaning an ODD count; the final EQ against 0 inverts that to
  // match the architectural definition. Do not "simplify" the inversion away.
  parity = createICMPFolder(CmpInst::ICMP_EQ,
                            ConstantInt::get(lsb->getType(), 0), parity, "pf5");
  return parity; // Returns 1 if even parity, 0 if odd
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::computeZeroFlag(
    Value* value) { // x == 0 = zf
  return createICMPFolder(CmpInst::ICMP_EQ, value,
                          ConstantInt::get(value->getType(), 0), "zeroflag");
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::computeSignFlag(
    Value* value) { // x < 0 = sf
  return createICMPFolder(CmpInst::ICMP_SLT, value,
                          ConstantInt::get(value->getType(), 0), "signflag");
}

// this function is used for jumps that are related to user, ex: vms using
// different handlers, jmptables, etc.
//
// A conditional branch that does not need structured control flow. Both arms
// become a single select, which is then handed to the path solver: if the
// select folds to a constant the branch collapses to a direct jump, and if it
// does not, the caller falls back to emitting a real branch.
//
// "related to user" means control flow the protector invented rather than the
// original program's -- VM dispatch and jump tables. Those do not have a
// natural two-block shape, which is why this emits a select instead of the
// structured branch the ret-to-IAT path uses.
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::branchHelper(
    Value* condition, const std::string& instname, int numbered, bool reverse) {
  // TODO:
  // save the current state of memory, registers etc.,
  // after execution is finished, return to latest state and continue
  // execution from the other branch
  //
  // That TODO is the real limitation: only the taken side is ever lifted. The
  // untaken side is never emitted, so a branch whose condition stays symbolic
  // loses the other arm entirely rather than modelling both.

  auto block = builder->GetInsertBlock();
  block->setName(instname + std::to_string(numbered));
  auto function = block->getParent();

  // RIP-relative: the immediate is a displacement from the *next*
  // instruction, and current_address is updated to that next address before
  // semantics run.
  auto true_jump_addr = instruction.immediate + current_address;

  Value* true_jump =
      ConstantInt::get(function->getReturnType(), true_jump_addr);

  // The untaken arm is a fallthrough to the next instruction, which is what
  // the lifted function's straight-line fallthrough already models. So this
  // is really a one-armed branch represented as a two-way select.
  auto false_jump_addr = current_address;
  Value* false_jump =
      ConstantInt::get(function->getReturnType(), false_jump_addr);
  Value* next_jump = nullptr;

  // reverse swaps the arms, which is how a "jump if not condition" or an
  // inverted-flag form is normalised without a second code path.
  if (!reverse)
    next_jump = createSelectFolder(condition, true_jump, false_jump);
  else
    next_jump = createSelectFolder(condition, false_jump, true_jump);

  uint64_t destination = 0;
  ScopedPathSolveContext pathSolveContext(this,
                                        PathSolveContext::ConditionalBranch);
  PATH_info pathInfo = solvePath(function, destination, next_jump);
  this->hadConditionalBranch = true;
  this->lastConditionalBranchResolved = (pathInfo != PATH_unsolved);

  // Three-way decision on whether the branch actually went somewhere.
  //
  // Getting this wrong is expensive downstream, so each case is explicit:
  //
  //   unresolved        -> lastBranchTaken = false. The default of "not taken"
  //                        is a deliberate refusal to guess. Inferring
  //                        taken/not-taken from the default destination when
  //                        the destination is symbolic produces confident,
  //                        wrong control-flow decisions downstream.
  //
  //   both arms equal   -> only decidable if the condition is itself constant.
  //                        If it is not, both destinations are the same
  //                        address, so "taken" is unobservable and the branch
  //                        is reported unresolved rather than arbitrarily
  //                        resolved.
  //
  //   normal            -> compare against the taken arm.
  //
  // hadConditionalBranch is recorded unconditionally because downstream code
  // uses "was there a branch at all" separately from "did we resolve it".
  if (!this->lastConditionalBranchResolved) {
    // Direction is unresolved/symbolic; do not infer taken/not-taken from default destination.
    this->lastBranchTaken = false;
  } else if (true_jump_addr == false_jump_addr) {
    if (auto* condConst = llvm::dyn_cast<llvm::ConstantInt>(condition)) {
      const bool condValue = condConst->isOne();
      this->lastBranchTaken = reverse ? !condValue : condValue;
    } else {
      // Ambiguous when both destinations are equal and condition is symbolic.
      this->lastBranchTaken = false;
      this->lastConditionalBranchResolved = false;
    }
  } else {
    this->lastBranchTaken = (destination == true_jump_addr);
  }

  // Embed the resolved destination in the block name. This is a debugging aid
  // that became load-bearing: the golden-IR diffs and the semantic reports
  // both read block names, so the address appearing here is often the only
  // way to tell which path a given block came from after the fact.
  block->setName("previousjmp_block-" + std::to_string(destination) + "-");
  // cout << "pathInfo:" << pathInfo << " dest: " << destination  <<
  // "\n";
}
