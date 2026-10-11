// Semantics_Bitwise.ipp — Bitwise ops, rotate, inc/dec, stack push/pop
//
// Every handler here follows the same four-step shape, and reading one of
// them tells you what all of them do:
//
//   1. fetch operands via GetIndexValue
//   2. widen the source to the destination's type
//   3. emit the operation through a *folder* (createXorFolder etc.)
//   4. set SF/ZF/PF from the result, clear OF/CF, write the destination
//
// Two things are worth knowing before editing any of them.
//
// Step 2 is not optional. GetIndexValue can hand back a narrower LLVM type
// than the destination -- an 8-bit source read as i8 against an i32
// destination -- and LLVM's bitwise ops require both operands to have
// identical types. Sign-extension (not zero-extension) is what the
// architecture specifies for these forms.
//
// Step 4 passes *lambdas*, not values. setFlag stores the closure and forces
// it later, so the flag computation is only materialised if something
// actually reads the flag. On VM code where most flags are never consumed
// this removes a large amount of dead arithmetic from the lifted IR. The
// captures are by value for exactly that reason -- `result` must be pinned,
// not re-read from the builder, which may have moved on.
//
// The OF/CF clears follow the Intel SDM: logic operations always clear both.
// Do not "fix" that into a computed overflow flag.

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_xor() {
  /* auto dest = operands[0];
  auto src = operands[1]; */
  auto Lvalue = GetIndexValue(0);
  auto Rvalue = GetIndexValue(1);

  // Widen the source to the destination's width before the XOR. See the file
  // header: LLVM requires matching operand types, and the architecture
  // specifies sign extension for this form.
  Rvalue = createSExtFolder(Rvalue, Lvalue->getType());

  // Named with the address baked in. These names are load-bearing: the
  // rewrite smoke corpus and the semantic reports both match on the emitted
  // value names, and an address-qualified name is what lets a report say
  // *which* instruction produced a value after the IR has been merged and
  // optimised.
  auto result = createXorFolder(
      Lvalue, Rvalue, "realxor-" + std::to_string(current_address) + "-");

  printvalue(Lvalue) printvalue(Rvalue) printvalue(result);

  // auto pf = computeParityFlag(result);
  //  The OF and CF flags are cleared; the SF, ZF, and PF flags are set
  //  according to the result. The state of the AF flag is undefined.

  // Lazy: each lambda is stored and only forced if the flag is read later.
  // SF/ZF/PF come from the result; OF and CF are unconditionally cleared,
  // which is architecturally defined for XOR. AF is left untouched because
  // the SDM calls its state undefined after a logic operation -- modelling
  // "undefined" as "unchanged" is the only option that does not assert
  // something the ISA does not guarantee.
  setFlag(FLAG_SF, [this, result]() { return computeSignFlag(result); });
  setFlag(FLAG_ZF, [this, result]() { return computeZeroFlag(result); });
  setFlag(FLAG_PF, [this, result]() { return computeParityFlag(result); });

  setFlag(FLAG_OF, [this]() {
    return ConstantInt::getSigned(Type::getInt1Ty(builder->getContext()), 0);
  });
  setFlag(FLAG_CF, [this]() {
    return ConstantInt::getSigned(Type::getInt1Ty(builder->getContext()), 0);
  });

  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_or() {
  // LLVMContext& context = builder->getContext();
  /*   auto dest = operands[0];
    auto src = operands[1]; */

  auto Lvalue = GetIndexValue(0);
  auto Rvalue = GetIndexValue(1);

  Rvalue = createSExtFolder(Rvalue, Lvalue->getType());
  auto result = createOrFolder(
      Lvalue, Rvalue, "realor-" + std::to_string(current_address) + "-");

  printvalue(Lvalue);
  printvalue(Rvalue);
  printvalue(result);

  // auto pf = computeParityFlag(result);
  // The OF and CF flags are cleared; the SF, ZF, and PF flags are set
  // according to the result. The state of the AF flag is undefined.

  setFlag(FLAG_SF, [this, result]() { return computeSignFlag(result); });
  setFlag(FLAG_ZF, [this, result]() { return computeZeroFlag(result); });
  setFlag(FLAG_PF, [this, result]() { return computeParityFlag(result); });

  setFlag(FLAG_OF, [this]() {
    return ConstantInt::getSigned(Type::getInt1Ty(builder->getContext()), 0);
  });
  setFlag(FLAG_CF, [this]() {
    return ConstantInt::getSigned(Type::getInt1Ty(builder->getContext()), 0);
  });

  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_and() {
  // LLVMContext& context = builder->getContext();
  /*  auto dest = operands[0];
   auto src = operands[1]; */

  auto Lvalue = GetIndexValue(0);
  auto Rvalue = GetIndexValue(1);

  Rvalue = createSExtFolder(Rvalue, Lvalue->getType());

  auto result = createAndFolder(
      Lvalue, Rvalue, "realand-" + std::to_string(current_address) + "-");

  // auto pf = computeParityFlag(result);

  // The OF and CF flags are cleared; the SF, ZF, and PF flags are set
  // according to the result. The state of the AF flag is undefined.

  setFlag(FLAG_SF, [this, result]() { return computeSignFlag(result); });
  setFlag(FLAG_ZF, [this, result]() { return computeZeroFlag(result); });
  setFlag(FLAG_PF, [this, result]() { return computeParityFlag(result); });

  setFlag(FLAG_OF, [this]() {
    return ConstantInt::getSigned(Type::getInt1Ty(builder->getContext()), 0);
  });
  setFlag(FLAG_CF, [this]() {
    return ConstantInt::getSigned(Type::getInt1Ty(builder->getContext()), 0);
  });

  printvalue(Lvalue) printvalue(Rvalue) printvalue(result);

  SetIndexValue(0, result);
}
// VEX three-operand form: the destination is NOT one of the inputs, so
  // operands map as [dest, src1, src2] and the read starts at index 1.
//
// This is the one handler in the file that does not widen: all three operands
// already share a width under the VEX encoding, so there is no narrow-source
// case to normalise. ANDN computes (~src1) & src2 -- note the operand order,
// which is the opposite of AND and a frequent source of silent bugs.
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_andn() {
  // ANDN (VEX): dest = ~src1 & src2, so operands map to [dest, src1, src2].
  auto src1 = GetIndexValue(1);
  auto src2 = GetIndexValue(2);

  auto result = createAndFolder(
      createNotFolder(src1), src2,
      "realand-" + std::to_string(current_address) + "-");

  setFlag(FLAG_SF, [this, result]() { return computeSignFlag(result); });
  setFlag(FLAG_ZF, [this, result]() { return computeZeroFlag(result); });
  setFlag(FLAG_PF, [this, result]() { return computeParityFlag(result); });

  setFlag(FLAG_OF, [this]() {
    return ConstantInt::getSigned(Type::getInt1Ty(builder->getContext()), 0);
  });
  setFlag(FLAG_CF, [this]() {
    return ConstantInt::getSigned(Type::getInt1Ty(builder->getContext()), 0);
  });

  printvalue(src1) printvalue(src2) printvalue(result);

  SetIndexValue(0, result);
}

/*

tempCOUNT := (COUNT & COUNTMASK) MOD SIZE
WHILE (tempCOUNT ≠ 0)
        DO
        tempCF := MSB(DEST);
        DEST := (DEST ∗ 2) + tempCF;
        tempCOUNT := tempCOUNT – 1;
        OD;
ELIHW;
IF (COUNT & COUNTMASK) ≠ 0
        THEN CF := LSB(DEST);
FI;
IF (COUNT & COUNTMASK) = 1
        THEN OF := MSB(DEST) XOR CF;
        ELSE OF is undefined;
FI
*/
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_rol() {
  LLVMContext& context = builder->getContext();
  /*   auto dest = operands[0];
    auto src = operands[1]; */

  auto destsize = GetTypeSize(instruction.types[0]);

  auto Lvalue = GetIndexValue(0);
  auto Rvalue = GetIndexValue(1);

  // Zero-extend here, unlike the logic ops above which sign-extend. The count
  // is masked immediately afterwards, so the high bits are discarded either
  // way; sign-extension would only risk making the mask interact with a
  // negative-looking value.
  Rvalue = createZExtFolder(Rvalue, Lvalue->getType());

  auto bitWidth = ConstantInt::get(Lvalue->getType(), destsize);
  // x86 masks rotate counts to 6 bits on 64-bit operands and 5 on 32-bit
  // before reducing modulo the width. Masking first (rather than just doing
  // mod width) is what reproduces the ISA's behaviour for large counts -- a
  // count of 64 rotates by 0, and only this masking makes that fall out.
  auto countmask =
      ConstantInt::get(Lvalue->getType(), destsize == 64 ? 0x3f : 0x1f);

  auto one = ConstantInt::get(Lvalue->getType(), 1);
  auto zero = ConstantInt::get(Lvalue->getType(), 0);

  auto MSBpos = ConstantInt::get(Lvalue->getType(), destsize - 1);
  // COUNTMASK then MOD SIZE -- the two steps from the SDM pseudocode above,
  // kept separate because they are not the same operation.
  Rvalue = createURemFolder(createAndFolder(Rvalue, countmask, "maskRvalue"),
                            bitWidth);

  // The rotate is expressed as a left shift by n OR a right shift by
  // (width - n). The right shift brings the top n bits down to the bottom,
  // which is exactly the wraparound half of the rotation.
  Value* shiftedLeft = createShlFolder(Lvalue, Rvalue);

  Value* shiftedRight =
      createLShrFolder(Lvalue, createSubFolder(bitWidth, Rvalue), "rol");

  Value* result = createOrFolder(shiftedLeft, shiftedRight);

  // CF is the bit rotated out of the top, which is bit 0 of shiftedRight.
  Value* cf = createZExtOrTruncFolder(shiftedRight, Type::getInt1Ty(context));

  // When the masked count is 0 the SDM says CF and OF are *unmodified*, not
  // zero. These two selects are what implement that: the old values are read
  // back and selected through instead of the computed ones. Modelling
  // "unmodified" as "zero" would silently change the flags for a no-op rotate,
  // which is common in VM dispatch code that rotates by a computed amount.
  Value* isZeroBitRotation = createICMPFolder(CmpInst::ICMP_EQ, Rvalue, zero);
  Value* oldcf = getFlag(FLAG_CF); // undefined

  cf = createSelectFolder(isZeroBitRotation, oldcf, cf);

  result = createSelectFolder(isZeroBitRotation, Lvalue, result);
  // of = cf ^ MSB
  //
  // Read the MSB of the *result*, not the input: the SDM defines OF as the new
  // MSB XOR CF, which is only meaningful once the rotation has happened.
  Value* newMSB = createLShrFolder(result, MSBpos, "rolmsb");
  auto of1 = createZExtOrTruncFolder(newMSB, Type::getInt1Ty(context));

  Value* of = createXorFolder(cf, of1);
  // crash?

  // Use Select to conditionally update OF based on whether the shift
  // amount is 1
  //
  // OF is only architecturally defined when the masked count is exactly 1.
  // For any other count it is undefined, and the SDM's own pseudocode says so.
  // The implementation keeps the old OF in that case rather than inventing a
  // value -- the same "unmodified" reading used for CF above.
  Value* isOneBitRotation = createICMPFolder(CmpInst::ICMP_EQ, Rvalue, one);
  Value* ofCurrent = getFlag(FLAG_OF);
  of = createSelectFolder(isOneBitRotation, of, ofCurrent);
  setFlag(FLAG_CF, cf);
  setFlag(FLAG_OF, of);
  printvalue(Lvalue) printvalue(Rvalue) printvalue(result);
  SetIndexValue(0, result);
}

/*

tempCOUNT := (COUNT & COUNTMASK) MOD SIZE
WHILE (tempCOUNT ≠ 0)
        DO
        tempCF := LSB(SRC);
        DEST := (DEST / 2) + (tempCF ∗ 2SIZE);
        tempCOUNT := tempCOUNT – 1;
        OD;
ELIHW;
IF (COUNT & COUNTMASK) ≠ 0
        THEN CF := MSB(DEST);
FI;
IF (COUNT & COUNTMASK) = 1
        THEN OF := MSB(DEST) XOR MSB − 1(DEST);
        ELSE OF is undefined;
FI

*/
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_ror() {

  LLVMContext& context = builder->getContext();
  /*
    auto dest = operands[0];

    auto src = operands[1]; */

  auto destsize = GetTypeSize(instruction.types[0]);

  auto Lvalue = GetIndexValue(0);

  auto Rvalue = GetIndexValue(1);

  Rvalue = createZExtFolder(Rvalue, Lvalue->getType());

  auto bitWidth = ConstantInt::get(Lvalue->getType(), destsize);

  auto countmask =
      ConstantInt::get(Lvalue->getType(), destsize == 64 ? 0x3f : 0x1f);

  auto one = ConstantInt::get(Lvalue->getType(), 1);

  auto zero = ConstantInt::get(Lvalue->getType(), 0);

  auto MSBpos = ConstantInt::get(Lvalue->getType(), destsize - 1);

  auto secondMSBpos = ConstantInt::get(Lvalue->getType(), destsize - 2);

  printvalue(Rvalue);

  Rvalue = createURemFolder(createAndFolder(Rvalue, countmask, "maskRvalue"),
                            bitWidth);

  Value* rightshifted = createLShrFolder(Lvalue, Rvalue);

  Value* leftshifted =
      createShlFolder(Lvalue, createSubFolder(bitWidth, Rvalue));

  Value* result =
      createOrFolder(rightshifted, leftshifted,
                     "ror-" + std::to_string(current_address) + "-");

  Value* msb = createLShrFolder(result, MSBpos);
  Value* cf = createZExtOrTruncFolder(msb, Type::getInt1Ty(context), "ror-cf");

  Value* secondMsb = createLShrFolder(result, secondMSBpos, "ror2ndmsb");

  auto ofDefined =
      createZExtOrTruncFolder(createXorFolder(msb, secondMsb), cf->getType());

  auto isOneBitRotation = createICMPFolder(CmpInst::ICMP_EQ, Rvalue, one);

  auto isZeroBitRotation = createICMPFolder(CmpInst::ICMP_EQ, Rvalue, zero);
  Value* ofCurrent = getFlag(FLAG_OF);
  Value* of =
      createSelectFolder(isOneBitRotation, ofDefined, ofCurrent, "ror-of");

  cf = createSelectFolder(isZeroBitRotation, getFlag(FLAG_CF), cf);
  setFlag(FLAG_CF, cf);
  setFlag(FLAG_OF, of);

  result = createSelectFolder(isZeroBitRotation, Lvalue, result, "ror-result");

  printvalue(Lvalue) printvalue(Rvalue) printvalue(result);

  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_inc() {
  // auto operand = operands[0];

  Value* Lvalue = GetIndexValue(0);

  Value* one = ConstantInt::get(Lvalue->getType(), 1, true);
  Value* result = createAddFolder(
      Lvalue, one, "inc-" + std::to_string(current_address) + "-");
  // Value* of = computeOverflowFlagAdd(Lvalue, one, result);
  // The CF flag is not affected. The OF, SF, ZF, AF, and PF flags are set
  // according to the result.
  // treat it as add r, 1 for flags

  printvalue(Lvalue) printvalue(result);

  // Value* sf = computeSignFlag(result);
  // Value* zf = computeZeroFlag(result);
  // Value* pf = computeParityFlag(result);

  setFlag(FLAG_OF, [this, result, one, Lvalue]() {
    return computeOverflowFlagAdd(Lvalue, one, result);
  });
  setFlag(FLAG_SF, [this, result]() { return computeSignFlag(result); });

  setFlag(FLAG_ZF, [this, result]() { return computeZeroFlag(result); });
  setFlag(FLAG_PF, [this, result]() { return computeParityFlag(result); });

  setFlag(FLAG_AF, [this, Lvalue, one]() {
    auto lowerNibbleMask = ConstantInt::get(Lvalue->getType(), 0xF);
    auto destLowerNibble = createAndFolder(Lvalue, lowerNibbleMask, "adcdst");
    auto srcLowerNibble = one;
    auto sumLowerNibble = createAddFolder(destLowerNibble, srcLowerNibble);
    return createICMPFolder(CmpInst::ICMP_UGT, sumLowerNibble, lowerNibbleMask);
  });
  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_dec() {
  // auto operand = operands[0];

  Value* Lvalue = GetIndexValue(0);

  Value* one = ConstantInt::get(Lvalue->getType(), 1, true);
  Value* result = createSubFolder(
      Lvalue, one, "dec-" + std::to_string(current_address) + "-");
  Value* of = computeOverflowFlagSub(Lvalue, one, result);

  // The CF flag is not affected. The OF, SF, ZF, AF, and PF flags are set
  // according to the result.
  // treat it as sub r, 1 for flags

  printvalue(Lvalue) printvalue(result);

  Value* sf = computeSignFlag(result);
  Value* zf = computeZeroFlag(result);
  Value* pf = computeParityFlag(result);

  printvalue(sf);

  setFlag(FLAG_OF, of);
  setFlag(FLAG_SF, sf);
  setFlag(FLAG_ZF, zf);
  setFlag(FLAG_PF, pf);

  auto lowerNibbleMask = ConstantInt::get(Lvalue->getType(), 0xF);
  auto RvalueLowerNibble =
      createAndFolder(Lvalue, lowerNibbleMask, "lvalLowerNibble");
  auto op2LowerNibble = one;
  auto af = createICMPFolder(CmpInst::ICMP_ULT, RvalueLowerNibble,
                             op2LowerNibble, "sub_af");
  setFlag(FLAG_AF, af);
  SetIndexValue(0, result);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_push() {
  LLVMContext& context = builder->getContext();
  /* auto src = operands[0]; // value that we are pushing
  auto dest = operands[2];
  auto rsp = operands[1]; */

  auto Rvalue = GetIndexValue(0);

  auto RspValue = GetRegisterValue(Register::RSP);

  auto destsize = instruction.stack_growth;
  printvalue2(destsize);
  auto val = ConstantInt::getSigned(Type::getInt64Ty(context),
                                    destsize); //

  auto result = createSubFolder(
      RspValue, val, "pushing_newrsp-" + std::to_string(current_address) + "-");

  printvalue(Rvalue);
  printvalue(RspValue);
  printvalue(result);

  SetRegisterValue(Register::RSP, result);
  // SetIndexValue(rsp, result, std::to_string(current_address));
  //  sub rsp 8 first,

  // sign extend
  switch (instruction.types[0]) {
  // case OperandType::Immediate64:
  case OperandType::Immediate8:
  case OperandType::Immediate16:
  case OperandType::Immediate32: {
    Rvalue = createSExtFolder(Rvalue,
                              builder->getIntNTy(instruction.stack_growth * 8));
    break;
  }
  default:
    break;
  }

  SetMemoryValue(getSPaddress(), Rvalue);
  // SetIndexValue(dest, Rvalue, std::to_string(current_address));
  // then mov rsp, val
}

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_pushfq() {
  LLVMContext& context = builder->getContext();
  /* auto src = operands[2];  // value that we are pushing rflags
  auto dest = operands[1]; // [rsp]
  auto rsp = operands[0];  // rsp */

  auto Rvalue = GetRFLAGSValue();
  // auto Rvalue = GetRFLAGS(builder);
  auto RspValue = GetRegisterValue(Register::RSP);

  // work.md 7.12.6/7.12.7 and mix 0x2F528E: a symbolic flag bit here becomes a
  // symbolic RFLAGS qword; later unaligned VM-stack loads cannot fold it.
  if (std::getenv("MERGEN_DIAG_RFLAGS")) {
    const uint64_t rva = maskedRVA(current_address - instruction.length);
    if (rva == 0x396B77ULL || rva == 0x2F528EULL) {
      dumpRflagsDiag("pushfq", rva, Rvalue);
    }
  }

  auto srcsize = 64; // based on bitness  ---

  auto val = ConstantInt::get(Type::getInt64Ty(context), srcsize / 8);
  auto result = createSubFolder(RspValue, val);

  SetRegisterValue(Register::RSP, result);
  // SetIndexValue(rsp, result, std::to_string(current_address));
  //  sub rsp 8 first,

  // pushFlags( dest, Rvalue,
  // std::to_string(current_address));;

  SetMemoryValue(getSPaddress(), Rvalue);
  // SetIndexValue(dest, Rvalue, std::to_string(current_address));
  // then mov rsp, val
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_pop() {
  LLVMContext& context = builder->getContext();
  /* auto dest = operands[0]; // value that we are pushing
  auto src = operands[2];
  auto rsp = operands[1]; */

  auto destsize = instruction.stack_growth;

  auto Rvalue = GetMemoryValue(getSPaddress(), destsize * 8); // [rsp]

  auto RspValue = GetRegisterValue(Register::RSP);

  auto val = ConstantInt::getSigned(Type::getInt64Ty(context), destsize);
  auto result = createAddFolder(RspValue, val,
                                "popping_new_rsp-" +
                                    std::to_string(current_address) + "-");

  printvalue(Rvalue) printvalue(RspValue) printvalue(result);

  SetRegisterValue(Register::RSP, result); // then add rsp 8

  // Guard: `pop rsp` (destination operand IS RSP) with a concrete popped
  // value outside the tracked pseudo-stack range is a VM stack-switch
  // gadget whose subsequent [rsp] loads dereference into unmapped
  // memory and crash the lifter. When we can see this statically, bail
  // the block with a structured warning and an unreachable terminator
  // instead of letting the next memory op take us down. Symbolic Rvalue
  // is already handled by the existing symbolic-load path.
  if (instruction.types[0] >= OperandType::Register8 &&
      instruction.types[0] <= OperandType::Register64 &&
      getBiggestEncoding(instruction.regs[0]) == Register::RSP) {
    if (auto* rvConst = llvm::dyn_cast<llvm::ConstantInt>(Rvalue)) {
      uint64_t rv = rvConst->getZExtValue();
      if (!isTrackedStackAddress(rv)) {
        diagnostics.warning(
            DiagCode::UnresolvedIndirectJump,
            current_address - instruction.length,
            "pop rsp loaded an out-of-range concrete value; bailing to"
            " avoid a downstream unmapped-memory crash");
        builder->CreateUnreachable();
        run = 0;
        finished = 1;
        return;
      }
    }
  }

  SetIndexValue(0, Rvalue); // op
                            // mov val, rsp first
                            /* ???
                              Rvalue =
                                  createZExtFolder(Rvalue, builder->getIntNTy(instruction.stack_growth));
                                  */
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_leave() {
  const auto stackRegisterSize = file.getMode() == arch_mode::X64 ? 64 : 32;
  const auto stackRegister = getRegOfSize(Register::RSP, stackRegisterSize);
  const auto frameRegister = getRegOfSize(Register::RBP, stackRegisterSize);

  auto frameValue = GetRegisterValue(frameRegister);
  SetRegisterValue(stackRegister, frameValue);

  auto poppedFrame = popStack(stackRegisterSize / 8);
  poppedFrame = createZExtOrTruncFolder(poppedFrame, frameValue->getType());
  SetRegisterValue(frameRegister, poppedFrame);
}
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::lift_popfq() {
  LLVMContext& context = builder->getContext();
  /*  auto dest = operands[2]; // value that we are pushing
   auto src = operands[1];  // [rsp]
   auto rsp = operands[0];  // rsp */

  auto destsize = 64; // GetTypeSize(instruction.types[0]);

  auto Rvalue = GetMemoryValue(getSPaddress(), destsize); // [rsp]

  auto RspValue = GetRegisterValue(Register::RSP);

  auto val = ConstantInt::getSigned(Type::getInt64Ty(context), destsize / 8);
  auto result = createAddFolder(
      RspValue, val, "popfq-" + std::to_string(current_address) + "-");

  SetRFLAGSValue(Rvalue);
  // mov val, rsp first
  SetRegisterValue(Register::RSP, result); // then add rsp 8
  // then add rsp 8
}
