// The opcode dispatch layer: one x86 instruction in, one IR update out.
//
// This file is the seam between "what the disassembler said" and "what the
// lifter does about it". It is an .ipp rather than a .hpp because it is
// included exactly once -- from Lifter.cpp -- and defines members of the
// lifter template. That is also why it has no include guard.
//
// Dispatch is X-macro driven: x86_64_opcodes.x names which mnemonic maps to
// which lift_ handler, and expanding it here keeps that mapping in one place.
// AGENTS.md makes this explicit -- extend instruction support by editing the
// opcode table and implementing the handler, never by adding a parallel
// dispatch path. A second switch would mean two tables free to disagree.

#include "CommonDisassembler.hpp"
#include "FunctionSignatures.hpp"
#include "OperandUtils.ipp"
#include "PathSolver.ipp"
#include "FileReader.hpp"
#include "Includes.h"
#include "LifterClass.hpp"
#include "Utils.h"
#include <immintrin.h>
#include <iostream>
#include <llvm/IR/Constant.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Support/VersionTuple.h>
#include <magic_enum/magic_enum.hpp>

// #include <popcntintrin.h>

using namespace llvm;


// File-scoped naming counters for debug block names
int ret_count = 0;
int jmpcount = 0;
int branchnumber = 0;

// Semantic handler sub-files
#include "Semantics_Helpers.ipp"
#include "Semantics_Misc.ipp"
#include "Semantics_ControlFlow.ipp"
#include "Semantics_Arithmetic.ipp"
#include "Semantics_Bitwise.ipp"

// Dispatch machinery
//
// OPCODE_CASE expands one table entry into a switch case that calls lift_<fn>.
// OPCODE(fn, mn1, mn2, ...) expands a whole row through PP_FOREACH, so a row
// naming five mnemonics produces five cases pointing at the same handler.
//
// The handlers live in the Semantics_*.ipp files included above, which is why
// those includes precede the switch: the table references lift_jmp and
// friends, and they have to be declared before the expansion that names them.

#include "PPMacros.hpp"

MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::liftInstructionSemantics() {

  switch (instruction.mnemonic) {

#define OPCODE_CASE(fn, mnemonic)                                              \
  case Mnemonic::mnemonic:                                                     \
    lift_##fn();                                                               \
    break;

#define OPCODE(fn, ...) __VA_OPT__(PP_FOREACH(OPCODE_CASE, fn, __VA_ARGS__))

#include "x86_64_opcodes.x"
#undef OPCODE
#undef OPCODE_CASE
  // Trap instructions: INT1, INT3, UD2.
//
// These appear constantly in VM code as anti-debug bait and as deliberate
// traps, so they are modelled rather than rejected. Calling an opaque
// `exception` stub and returning keeps the IR well-formed and keeps the lift
// moving past the trap, which is what the surrounding VM dispatch expects.
//
// finished = 1 stops the per-instruction loop: there is no successor to lift,
// and continuing would emit past a terminator.
case Mnemonic::INT1:
  case Mnemonic::INT3:
  case Mnemonic::UD2: {
    Function* externFunc = cast<Function>(
        fnc->getParent()
            ->getOrInsertFunction("exception", fnc->getReturnType())
            .getCallee());
    builder->CreateRet(builder->CreateCall(externFunc));
    run = 0;
    finished = 1;
    return;
  }
  // INT 0x29 is __fastfail: the compiler's "this cannot continue" primitive,
// emitted for things like a failed CFG check. It is common enough in release
  // builds of real code to be worth modelling precisely, because it means the
  // path is dead rather than merely unknown.
//
// CreateUnreachable (not a ret) because __fastfail does not return. That is
  // what makes the CFG honest about it.
//
// Every other INT falls through to the not_implemented arm below: an
// interrupt vector we do not model has no defined semantics, so guessing one
  // would be worse than recording that we do not know.
case Mnemonic::INT: {
    if (instruction.immediate == 0x29) {
      auto* fastFailType = llvm::FunctionType::get(
          llvm::Type::getVoidTy(context),
          {llvm::Type::getInt64Ty(context)}, false);
      auto* fastFail = llvm::cast<llvm::Function>(
          fnc->getParent()
              ->getOrInsertFunction("fastfail", fastFailType)
              .getCallee());
      auto* code = createZExtOrTruncFolder(
          GetRegisterValue(Register::RCX), llvm::Type::getInt64Ty(context));
      builder->CreateCall(fastFail, {code});
      builder->CreateUnreachable();
      run = 0;
      finished = 1;
      return;
    }
    {
      std::string mnem(magic_enum::enum_name(instruction.mnemonic));
      uint64_t instrAddr = current_address - instruction.length;
      diagnostics.error(DiagCode::InstructionNotImplemented, instrAddr,
                        "Instruction not implemented: " + mnem, mnem);
    }
    Function* externFunc = cast<Function>(
        fnc->getParent()
            ->getOrInsertFunction("not_implemented", fnc->getReturnType())
            .getCallee());
    builder->CreateRet(builder->CreateCall(externFunc));
    run = 0;
    finished = 1;
    break;
  }
  // FXRSTOR/FXSAVE/PAUSE/NOP have no architectural effect this lifter models,
// so they lower to nothing and the lift continues.
//
// No diagnostic: these are legitimately implemented, just as no-ops. Recording
// them would make the diagnostics stream useless by burying real gaps.
case Mnemonic::FXRSTOR:
  case Mnemonic::FXSAVE:
  case Mnemonic::PAUSE:
  case Mnemonic::NOP: {
    break;
  }

  // The disassembler could not decode these bytes. Distinct from `default`:
  // here the *decoder* failed, whereas default means we recognised the
  // instruction and lack a handler for it. The two point at different bugs.
  case Mnemonic::Invalid: {

    printvalueforce2(this->counter);
    std::cout << "invalid: " << magic_enum::enum_name(instruction.mnemonic)
              << " runtime: " << std::hex << current_address << std::endl;
    /*
        std::string Filename = "output_notimplemented.ll";
        std::error_code EC;
        raw_fd_ostream OS(Filename, EC);
        builder->GetInsertBlock()->getParent()->getParent()->print(OS, nullptr);
        */
    // UNREACHABLE("Instruction not implemented");
    Function* externFunc = cast<Function>(
        fnc->getParent()
            ->getOrInsertFunction("invalid", fnc->getReturnType())
            .getCallee());
    builder->CreateRet(builder->CreateCall(externFunc));
    run = 0;
    finished = 1;
    break;
  }
  // Everything not in the opcode table.
//
// The policy here is AGENTS.md's "explicit failures over silent fallbacks":
// record a structured diagnostic AND emit a call to a `not_implemented` stub,
// then stop this block's lift.
//
// Note what is *not* done. There is no UNREACHABLE, even though one is
// commented out below. Crashing the lifter on an unmodelled instruction would
// make it unusable on real-world input, where unmodelled instructions are
// routine. Instead the stub keeps the IR well-formed, the diagnostic keeps the
// gap machine-visible in output_diagnostics.json, and the run continues. The
// stub's return type matches the enclosing function's so the module stays
// verifiable.
default: {

    {
      std::string mnem(magic_enum::enum_name(instruction.mnemonic));
      uint64_t instrAddr = current_address - instruction.length;
      printvalueforce2(this->counter);
      std::cout << "not implemented: " << mnem
                << " runtime: " << std::hex << instrAddr << std::endl;
      diagnostics.error(DiagCode::InstructionNotImplemented, instrAddr,
                        "Instruction not implemented: " + mnem, mnem);
    }
    /*
        std::string Filename = "output_notimplemented.ll";
        std::error_code EC;
        raw_fd_ostream OS(Filename, EC);
        builder->GetInsertBlock()->getParent()->getParent()->print(OS, nullptr);
        */
    // UNREACHABLE("Instruction not implemented");
    Function* externFunc = cast<Function>(
        fnc->getParent()
            ->getOrInsertFunction("not_implemented", fnc->getReturnType())
            .getCallee());
    builder->CreateRet(builder->CreateCall(externFunc));
    run = 0;
    finished = 1;
    break;
  }
  }
}

// Lift one instruction at `current_address`.
//
// Two probes run before the opcode switch, because both can pre-empt it
// entirely:
//
//   1. Does the address match a known signature? Then this is a call into a
//      recognised library function -- emit the call and branch to the return
//      address on the stack, never reaching the switch.
//
//   2. Is the address not readable? Then execution has left the image, which
//      means an external call. Emit it and return, again without reaching the
//      switch.
//
// Both probes do a `return` rather than falling through, so the switch below
// only ever sees instructions that actually have semantics to dispatch.
MERGEN_LIFTER_DEFINITION_TEMPLATES(void)::liftInstruction() {

  // in future this function could be staticly dispatched for custom logic?

  LLVMContext& context = builder->getContext();
  // RIP gets updated before execution of the instruction->
  /*
  auto val = ConstantInt::getSigned(Type::getInt64Ty(context),
                                    current_address);
  SetRegisterValueWrapper(Register::RIP, val);
  */
  // auto rsp = GetRegisterValue(Register::RSP);
  // printvalue(rsp);
  printvalue2(current_address);

  {
    auto prologueSample = profiler.sample("lift_prologue");
    auto funcInfo = signatures.getFunctionInfo(current_address);

    // The function at `current_address` matched a signature we know. Emit the
      // call, then pop the return address the call pushed and branch there --
      // modelling the call/return as a direct branch rather than actually
      // invoking anything.
      //
      // popStack rather than reading [RSP] directly because the slot holds a
      // runtime address that may need normalising, and popStack is where that
      // normalisation and the x86/x64 width difference are handled.
      if (funcInfo) {
      callFunctionIR(funcInfo->name.c_str(), funcInfo);
      debugging::doIfDebug([&]() {
        outs() << "calling: " << funcInfo->name.c_str() << "\n";
        outs().flush();
      });
      auto next_jump = popStack(file.getMode() == arch_mode::X64 ? 8 : 4);

      // get [rsp], jump there
      if (!isa<ConstantInt>(next_jump)) {
        UNREACHABLE("next_jump is not a ConstantInt.");
        return;
      }
      auto RIP_value = cast<ConstantInt>(next_jump);
      auto jump_address =
          normalizeRuntimeTargetAddress(RIP_value->getZExtValue());

      auto bb = getOrCreateBB(jump_address, "bb_call");
      builder->CreateBr(bb);

      blockInfo = BBInfo(jump_address, bb);
      addUnvisitedAddr(blockInfo);
      run = 0;
      return;
    }

    // if really an import, jump_address + imagebase should return a std::string
    // (?)
    uint64_t jump_address = current_address;
    uint64_t temp;
    bool isReadable = file.readMemory(jump_address, 1, temp);
    // bool isImport = file.isImport(jump_address); check if rwx?

    // this ~~would~~ SHOULD catch missed function calls, probably take care of
    // this in solvePath?

    // Unreadable address == execution left the image == an external call.
    //
    // The RSP check is what keeps this from firing at the end of the lift. At
    // the outermost frame RSP is still STACKP_VALUE; past that it has moved,
    // which is the signature of a real return. Without this the lifter would
    // treat its own return as an external call at the end of every function.
    if (!isReadable &&
        cast<ConstantInt>(GetRegisterValue(Register::RSP))->getValue() !=
            STACKP_VALUE) {
      printvalueforce2(jump_address);

      // actually call the function first
      auto functionName = file.getName(jump_address);
      debugging::doIfDebug([&]() {
        outs() << "calling : " << functionName
               << " addr: " << (uint64_t)jump_address;
        outs().flush();
      });

      callFunctionIR(functionName, nullptr);

      auto next_jump = popStack(file.getMode() == arch_mode::X64 ? 8 : 4);

      // get [rsp], jump there
      auto RIP_value = cast<ConstantInt>(next_jump);
      jump_address = normalizeRuntimeTargetAddress(RIP_value->getZExtValue());
      auto bb = getOrCreateBB(jump_address, "bb_indirectly_called");

      builder->CreateBr(bb);

      blockInfo = BBInfo(jump_address, bb);
      addUnvisitedAddr(blockInfo);
      run = 0;
      return;
    }

    /*
      if (!isReadable && !isImport) {
        // done something wrong;
        std::string Filename = "output_external.ll";
        std::error_code EC;
        raw_fd_ostream OS(Filename, EC);
        builder->GetInsertBlock()->getParent()->getParent()->print(OS, nullptr);

        outs().flush();
        // UNREACHABLE("Trying to execute invalid external function");
      }
    */
    // do something for prefixes like rep here
  }
  // Everything else: a genuine instruction with semantics to dispatch.
  //
  // Profiled separately from lift_prologue above because these two dominate
  // very differently -- the prologue is the per-block cost, this is the
  // per-instruction cost, and on a VM-protected sample the split is usually
  // the difference between "too many blocks" and "too many instructions".
  auto semanticsSample = profiler.sample("lift_semantics");
  liftInstructionSemantics();
}