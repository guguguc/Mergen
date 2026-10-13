@echo off
setlocal EnableExtensions
rem One-shot: lift mix with --reg rcx + insn/wr streams, then chase diverge.
rem Usage:
rem   scripts\dev\run_mix_chase.cmd
rem   scripts\dev\run_mix_chase.cmd chase-only
rem   scripts\dev\run_mix_chase.cmd lift-only

set "REPO=%~dp0..\.."
cd /d "%REPO%\build_msvc_dbg" || exit /b 1

set "PE=D:\sogen\dr\vmptest\test_fixed4.exe"
set "DUMP=D:\sogen\dr\vmptest\entry_7450.dmp"
set "DR_INSN=D:\sogen\dr\vmptest\mix_dr_insn.csv"
set "LF_INSN=%CD%\mix_rerun_insn.csv"
set "LF_WR=%CD%\mix_rerun_wr.csv"
set "OUT=%CD%\mix_chase_report.txt"
set "MODE=%~1"
if "%MODE%"=="" set "MODE=all"

if not exist "lifter.exe" (
  echo lifter.exe missing in %CD%
  exit /b 2
)
if not exist "%PE%" (
  echo PE missing: %PE%
  exit /b 2
)
if not exist "%DUMP%" (
  echo DUMP missing: %DUMP%
  exit /b 2
)

set "MERGEN_MAX_BLOCK_BUDGET=131072"
set "MERGEN_INSN_STREAM_FILE=%LF_INSN%"
set "MERGEN_WRITE_STREAM_FILE=%LF_WR%"
set "MERGEN_DIAG_VIP="
set "MERGEN_VERIFY_SLOT_FCD8="
set "MERGEN_VERIFY_LEA_CX="
set "MERGEN_VERIFY_LOAD_FCD8="
set "MERGEN_DIAG_LIFT_PROGRESS="

if /I "%MODE%"=="chase-only" goto CHASE
if /I "%MODE%"=="all" goto LIFT
if /I "%MODE%"=="lift-only" goto LIFT
echo usage: %~nx0 [all^|lift-only^|chase-only]
exit /b 2

:LIFT
echo === lift mix --reg rcx ===
lifter.exe "%PE%" 0x140007450 --mem-dump "%DUMP%" --reg rcx=0x12345678 > mix_rerun.out 2> mix_rerun.err
echo lift exit=%ERRORLEVEL%
type mix_rerun.err
if /I "%MODE%"=="lift-only" exit /b %ERRORLEVEL%

:CHASE
if not exist "%LF_INSN%" (
  echo LF insn missing: %LF_INSN%
  exit /b 2
)
if not exist "%DR_INSN%" (
  echo DR insn missing: %DR_INSN%
  exit /b 2
)
echo === chase_mix_diverge ===
python "%REPO%\scripts\dev\chase_mix_diverge.py" --lf "%LF_INSN%" --dr "%DR_INSN%" --wr "%LF_WR%" --pe "%PE%" --reg rcx --steps 12 --out "%OUT%"
exit /b %ERRORLEVEL%

rem No-reg length stop example (LF stops before DR, same RVA prefix):
rem   python scripts\dev\chase_mix_diverge.py ^
rem       --lf build_msvc_dbg\mix_noreg_wr_insn.csv ^
rem       --dr D:\sogen\dr\vmptest\mix_dr_insn.csv ^
rem       --wr build_msvc_dbg\mix_noreg_wr.csv ^
rem       --stop-seq 301739 --regs rbp,r10,rcx --reg rbp --steps 8
