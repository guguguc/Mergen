# VMP Ultra 反虚拟化工作区（Mergen 基座）

目标：静态反虚拟化 VMProtect Ultra（10 实例）保护的 `add_only(a,b)=a+b`，
产出可读 LLVM IR（`add i32` + 真实 `ret`）。方法必须**通用**（不特判、不认 handler 形态、不做 trace）。

- 策略与决策依据：见 [`DEVIRT_STRATEGY.md`](./DEVIRT_STRATEGY.md)
- 基座源码：`refs/Mergen`（通用 x64 PE → LLVM SSA lifter）
- 样本 / trace：`vmptest/`

---

## 0. 来龙去脉 / 复现入口

### 0.1 这份笔记是什么

对 **VMProtect Ultra 保护的最小样本**（`add_only(a,b)=a+b`）做**静态反虚拟化**的
工作记录。基座是通用 x64 PE → LLVM SSA lifter（Mergen），路线是**通用方法**
（不特判 handler 形态、不认字节码表、不依赖 trace），即博客里的
lift → concretize → continue 跑到不动点。

**注意**：`D:\sogen\dr\work.md` 是**旧的短副本**（8 节 / 5.3K），
**本文件（`dr\refs\Mergen\work.md`）才是当前有效版**。

### 0.2 被分析的样本

```
sample/add/add_test_fixed4.exe   ← 本文分析的二进制（~10 MB）
sample/add/add_test.cpp          ← 源码（VMProtectBeginUltra("add_only")）
sample/add/build.cmd             ← 构建 + 保护 + 解包 一条龙
sample/add/entry_7210.dmp        ← 客户入口 0x140007210 内存快照
sample/add/README.md             ← 编译 / dump / lift 命令
```

`build.cmd` 的链路：

```bat
cl /O2 /GS- /Zi /I D:\sogen\vmp\sdk add_test.cpp /OUT:add_test.exe
D:\sogen\vmp\bin\64\Debug\VMProtectCon.exe add_test.exe add_test_vmp.exe   :: Ultra 保护
D:\sogen\dr\vmptest\VMPStatic.exe add_test_vmp.exe add_test_unpacked.exe     :: 静态解包
D:\vmp-crcfix\saltscan.exe add_test_vmp.exe add_test_unpacked.exe             :: salt 扫描
```

`add_test_fixed4.exe` 是第四轮 crc 定点修复后的映像（工具仍在 `D:\sogen\dr\vmptest\crcfix_fixpoint.py`）。

样本固定事实见第 3 节（ImageBase `0x140000000`、客户入口 `0x140007210` 等）。

### 0.3 工具链路径

| 件 | 路径 |
|---|---|
| VMProtect SDK（头/库） | `D:\sogen\vmp\sdk` |
| VMProtect 保护器 | `D:\sogen\vmp\bin\64\Debug\VMProtectCon.exe` |
| VMProtect 源码（用于查 `intel.cc` 等） | `D:\vmp\core`（工作副本 `D:\sogen\vmp`） |
| 静态解包器 | `D:\sogen\dr\vmptest\VMPStatic.exe` |
| salt 扫描 | `D:\vmp-crcfix\saltscan.exe` |
| Mergen 源码 | `D:\sogen\dr\refs\Mergen` |
| Mergen 构建脚本 | `D:\sogen\tools\rebuild_mergen_msvc_dbg.cmd` |
| DynamoRIO | `D:\DynamoRIO\bin64\drrun.exe` |
| DR client 源码 / DLL | `D:\sogen\dr\vmpdrtrace.c` / `vmpdrtrace7.dll` |
| DR client 构建 | `D:\sogen\dr\build_vmpdrtrace7.bat` |

### 0.4 复现命令（四套：DR 快照 / 无快照 lift / 带快照 lift / DR trace）

构建（唯一入口）：`D:\sogen\tools\rebuild_mergen_msvc_dbg.cmd`（输出 `build_msvc_dbg\lifter.exe`）。
注意：增量构建**不跟踪 `.ipp`**，改过 `.ipp` 必须先删 `CMakeFiles` 下的
`Lifter.cpp.obj Utils.cpp.obj PathSolver.cpp.obj TestInstructions.cpp.obj`。

**A. DynamoRIO 采入口内存快照（`-dumpmem`）**

在**首次执行到 lift 起点**时，一次性 dump 已提交的可写页（映像脏页 + 堆）。不跟指令流。

```powershell
cd D:\sogen\dr\refs\Mergen\sample\add
$DR='D:\DynamoRIO\bin64\drrun.exe'; $DLL='D:\sogen\dr\vmpdrtrace7.dll'
$argl=@('-c',$DLL,'-entry','0x140007210','-imagebase','0x140000000',
        '-dumpmem',"$PWD\entry_7210.dmp",
        '--',"$PWD\add_test_fixed4.exe")
Start-Process -FilePath $DR -ArgumentList $argl -WorkingDirectory $PWD -Wait
```

- `-entry 0x140007210` 必须与 lift 起点一致（快照即「该 RIP 上的进程映像」）。
- 加 `-dumpmem-exit` 可在 dump 完成后立即退出（不跑完整个程序）。
- 产物（实测）：`regions=84`，约 **19 MB**，格式 `MRGNDMP1` + `{dumpImageBase, imageSize, nregions, flags}` + 每区 `{va, size, prot, bytes}`。
- 采集过滤（`dump_want_region`）：主模块全收；可写 `MEMTYPE_DATA` 仅收 `VA < 0x7FF000000000`（排除 ntdll 等，否则 overlay 爆）。

**B. lifter：无 dump（历史基线）**

```powershell
cd D:\sogen\dr\refs\Mergen\build_msvc_dbg
$env:MERGEN_MAX_BLOCK_BUDGET='131072'
cmd /c "lifter.exe ..\sample\add\add_test_fixed4.exe 0x140007210 > run.out 2> run.err"
```

期望：`13291 blocks (1 completed, 2 unreachable), 128252 instructions (0 unsupported)`，0 error，
诊断 `Unresolved indirect jump @0x140323cc0` + `Unresolved ROP chain @0x1403da685`。

**C. lifter：加载快照（当前基线）**

```powershell
cd D:\sogen\dr\refs\Mergen\build_msvc_dbg
$env:MERGEN_MAX_BLOCK_BUDGET='131072'
cmd /c "lifter.exe ..\sample\add\add_test_fixed4.exe 0x140007210 --mem-dump ..\sample\add\entry_7210.dmp > run_dump.out 2> run_dump.err"
```

- 等价写法：`--mem-dump=<file>`，或环境变量 `MERGEN_MEM_DUMP=<file>`。
- **不要**开 `MERGEN_DIAG_LIFT_PROGRESS`（日志会爆）。
- `stderr` 预期两行：
  `[mem-dump] loaded <N> spans from <file>` / `[mem-dump] concrete spans <K>/<N> bytes <B>`
  （实测 `433 spans`、`concrete 375/433 bytes 389392` ≈ 380 KB —— 只 CONCRETE「映像 + 2 跳指针可达堆」）。
- **期望（当前基线，a3a45c5）**：`24240 blocks (1 completed, 1 unreachable), 209049 instructions (0 unsupported)`，
  `0 error`，**~13s**；唯一告警 `Unresolved ROP chain @0x14032281c`。
  真机 30270 块，约 80%。
- 地址空间规则（硬约束）：dump 映像页 → `PE ImageBase + RVA`（并 alias 回 dump VA），
  其余（堆）原 VA 原样；**格子里的 qword 不 rebase**；禁止区 = `STACKP±0x100000` 与 TEB `0x7FFD0000..0x7FFD2000`。

**D. DynamoRIO 指令 trace / 寄存器真值（可选）**

```powershell
$argl=@('-c',$DLL,'-entry','0x1401f0efb','-imagebase','0x140000000',
        '-o',"$PWD\t.trace",'-regs',"$PWD\t.regs",'-mem',"$PWD\t.mem",'-trackmem',
        '--',"$PWD\add_test_fixed4.exe")
```

- 其它选项：`-r8 <file>`（R8 解密链真值，输出 `R8,<rva>,<r8>,<r10>`）、`-bc`、`-analysis`、`-max <N>`、`-perentry <N>`。
- **口径**：`-regs` 探针读的是**执行前**，lifter 写流记录的是**执行后**（见 §7.6.12）。
- **实测坑**：`-max` / `-perentry` 默认 0（不限），但 trace 会在**客户入口那段 stub 交出去**时自然结束
  （实测 ~20 万条指令、6 MB），所以**深地址可能根本没被 trace 到** —— 用「trace 里没有」下结论前先确认这一点。
- **警告**：`-trackmem` 全量内存流很大（数万行量级）；写探针带值（`-memval`）会让 DR 崩，寄存器/`-r8` 探针安全。

### 0.5 博客与依据

- Aftermath Labs《Static Devirtualization of Themida》2026-05-09
  <https://aftermathlabs.net/blog/09/05/2026/>
  —— 本文的 **lift → concretize → continue**、*Constant Promotion*、
  *configurable range policy*、以及「从跳转目标反向走 IR DAG 找最后一次模块 load」
  都出自这里。文中 VMP 也能还原：从**被虚拟化的函数**起抬（不是 `AddressOfEntryPoint`），
  RSP 具体、VM 栈在 native 栈上 store-forward；Themida 的 context 才在映像里。
  细节与本样本差异见 7.6.34。
- Aftermath Labs《Static Devirtualization of Tencent VM》2026-07-31
  <https://aftermathlabs.net/blog/31/07/2026/>
- NaC-L《Lifting》<https://nac-l.github.io/2025/01/25/lifting_0.html>
  —— Mergen 的 lift 思路。

本地策略长文：`D:\sogen\dr\DEVIRT_STRATEGY.md`（含上述链接与逐条决策依据）。

---

## 1. 方法与依据

路线：**通用 lifter + SSA 常量折叠跑到不动点**，即博客 Aftermath Labs
《Static Devirtualization of Themida》里的 **lift → concretize → continue**。

派发形状（VMP 源码 `vmp/core/intel.cc`）：

```
AddEndHandlerCommands (intel.cc:27836)
  AddReadCommand  → mov reg1, [pcode_registr_]      (27802)   ← 字节码读
  movsxd reg1, reg1                                   (27844)
  add   jmp_registr_, reg1                            (27845)   ← 目标 = 实例基址 + 解密值
  jmp   ...                                                     ← 间接跳
```

- VIP = 本 handler 里**最后一条模块读**（`lastModuleLoadOffset`）。
- 虚拟化条件：`ltJmpWithFlag`（`intel.cc:11721`）编码两个目标 → 应形成 `select` → **fork**。
- 环境指纹（`intel.cc:15881-15918`、`loader.cc:959`）：`gs:[0x60]`=PEB、
  `[PEB+0x120]`=OSBuildNumber、`cpu_salt = OSBuildNumber<<7` —— VM key 与运行时环境绑定。

## 2. 构建与运行

```bat
:: 构建（RelWithDebInfo + Zydis lane；不是 -O0）
cmd /c "D:\sogen\tools\rebuild_mergen_msvc_dbg.cmd"

:: 跑（客户函数入口 0x140007210）
set MERGEN_MAX_BLOCK_BUDGET=131072
set MERGEN_DIAG_LIFT_PROGRESS=1
cmd /c "cd D:\sogen\dr\refs\Mergen\build_msvc_dbg && lifter.exe ..\sample\add\add_test_fixed4.exe 0x140007210 --mem-dump ..\sample\add\entry_7210.dmp"
```

产物：`build_msvc_dbg\output.ll` / `output_no_opts.ll` / `output_diagnostics.json`。

DR trace（可选真值对照）：

```bat
cmd /c D:\sogen\dr\build_vmpdrtrace5.bat
D:\DynamoRIO\bin64\drrun.exe -c D:\sogen\dr\vmpdrtrace5.dll ^
  -entry 1401f0efb -imagebase 140000000 -regs vmptest\probe_regs.txt ^
  -max 2000000 -- D:\sogen\dr\vmptest\add_test_fixed4.exe
```

`vmpdrtrace.c` 的寄存器探针（`poff == 0x34ECFD/0x34ED0E/0x38349F/0x3834A2/0x2E17EE/0x2E17D5/...`）
在指定 RVA 处 dump 寄存器 + `[RBX]`/`[R11]`，是**真值对照的唯一可靠来源**。
注意：带**值**的写探针（`instrument_writes_value`）会让 DR 在 `0x71082ae2` 崩，已从
`event_app_instruction` 撤掉；寄存器探针安全。

## 3. 真值（样本固定事实）

| 项 | 值 |
|---|---|
| PE `AddressOfEntryPoint` | `0x1404FD849`（`.rZu2` 壳 stub；TLS 空） |
| 客户函数 entry（lift 起点） | `0x140007210`（`.text`；prologue 后 `jmp 0x1401f0efb`） |
| 真实 `add_only` | `0x140007231 lea eax,[rbx+rdi]`（`a=ECX`,`b=EDX`），被 `jmp 0x1401f0efb` 跳过 |
| VM entry | `0x1401f0efb`（= RVA `0x1f0efb`） |
| dispatcher | `0x1403a5ff4` |
| 期望输出 | `add_only(0x12345678,0x0F0F0F0F) = 0x21436587` |
| 块级 trace | `vmptest/add_seq.txt`（30270 块，基址 `0x7ff7f5b00000`） |
| 指令级 trace | `vmptest/mem_add.trace`（`seq,ip,bytes`） |

## 4. 本工作区的工程改动（全部未提交）

基座 `refs/Mergen` 内：

1. **VIP provenance 修复**（`LifterClass.hpp: vipModuleOffset`）
   删掉按值查 `loadProvenance` 的兜底 —— LLVM uniques 常量会让几十条不同字节码读
   折成同一常量、互相覆盖，产生假 VIP、假回边、假循环泛化。
   改落到 `lastModuleLoadOffset`（`intel.cc:27836`）。
   **效果：与 DR 连续一致块 5805 → 13280；唯一地址 2045 → 3275。**

2. **`pv.size()>2` 越界 lift 判据**（`PathSolver.ipp`）
   启发式候选不再全当代码 lift：`knownCode = selectDerived || visitedAddresses || inlinePolicy.isOutline`。
   **效果：`UNREACHABLE` 与非指令边界解引用导致的 `0xc0000005` 消失。**

3. **段前缀 `gs:`/`fs:` 建模**（真架构修复）
   - `disasm/CommonDisassembler.hpp`：指令结构加 `mem_segment`
   - `disasm/ZydisDisassembler.hpp`：从 `op.mem.segment` 填入
   - `semantics/OperandUtils.ipp: GetEffectiveAddress`：`gs:/fs:` 折 `tebBase + offset`
   （`getPointer` 里 `// if (segment == Register::GS) memoryOperand = TEB;` 一直是注释，现已接通）

4. **TEB/PEB 结构建模**（`LifterClass.hpp: modelProcessEnvironment`）
   `tebBase=0x7FFD0000`；种 Self / EnvironmentPointer=0 / PEB 指针 / BeingDebugged=0 / NtGlobalFlag=0；
   **OSBuildNumber 故意留未知**（环境相关，应交给 fork）。

5. **虚拟化条件 fork**（`PathSolver.ipp`）
   `pvset.size()<2` 的门打开，改为**同时替换所有 `select`** 做臂的笛卡尔积；
   2~4 臂时优先 `pvset = selectArms` 并 `selectDerived=true`。

6. **基础设施**（早前"值全丢"的根因 + 中性）
   - `memory/GEPTracker.h`：`ValueByteReference::value → llvm::WeakTrackingVH`；`ValueByteReferenceRange` 拆 union
   - `LifterClass_Concolic.hpp`：`vec`/`vecflag → WeakTrackingVH`；`InitRegisters()` 由**派生类构造**调用
     （原来在 `lifterClassBase` 构造里调，此时 `vec` 未构造 → 寄存器值全丢）
   - `IRBuilder` 由 `InstSimplifyFolder` → `ConstantFolder`（前者会删掉刚建的指令使 ValueHandle 失效）
   - `MergenPB.hpp` 补 `#pragma once`

改动本身**行为中性部分**已验证（块数/指令数/`[vip]` 一致）。

7. **range policy / 不提升入口前改写的 8 字节 0**（见 7.6.31–7.6.32）
   `MemoryPolicySetup.hpp`、`FileReader.hpp`、`GEPTracker.ipp`、`LifterClass_Concolic.hpp`、`CustomPasses.hpp`。
   无 overlay、无按节名灌值。16:05 重跑块数仍 13291。

## 5. 现状

**当前（dump + 主机 `CPUID` + 真 `RDTSC`）** — 见 §7.11.13 / §7.11.14。

| 项 | 值 |
|---|---|
| 块 / 指令 | **18129 / 176805**（`1 completed, 0 unreachable`） |
| 耗时 | lift ~8.5s（`output_diagnostics.json` total ~23s） |
| 错误 | `0 error` / `0 warning` / `0 unsupported` |
| 出口 | `[ret] 0x14000723e` `rsp=STACKP` `disp=0` `rop=1`（客户函数尾；insn 末条 `0x723e`） |
| IR | `output.ll` 已折成 **`EAX = (RCX + RDX) & 0xffffffff`**（`add_only` 语义）。insn 流走到 `0x7231`/`0x723e`，RAX 为 SSA `-`，**没有** DR 调用现场的 `0x21436587` |
| 对照 | 与任意一趟 DR `-insn` 的 RVA 前缀对齐到 TSC 倒计时 `dec rax; jne`（`0x335d4c`/`0x335d4f`）后分叉；圈数随 TSC 变。DR 在客户 `ret` 之后还记到 `0x6ca07`（进程尾巴），lift 在 `0x723e` 停 |
| 已闭合 | 假 CPUID（§7.11.11）；空 `lift_rdtsc` 残值 `EAX=0x70`（§7.11.13）。**不要**把某趟 DR 的 TSC 写进 lifter |

**提交基线 a3a45c5（有 dump + InstructionCache 共享索引，假 CPUID）**

| 项 | 值 |
|---|---|
| 块 / 指令 | **24240 / 209049**（真机 30270 块，约 80%） |
| 耗时 | **~13s**（此前重建平面表为 ~325s，见 §7.9） |
| 错误 | `0 error` |
| 卡点 | 日志仍写 `Unresolved ROP @0x14032281c`；**真正先分叉的是第 4 次 `0x3B4FF9`（§6.1 / §7.11）**。`0x32281c` 在分叉之后，真机根本不执行 |
| 已消除 | 旧卡点 `Unresolved indirect jump @0x140323cc0`；`mergen.stale_file_zero`（IR 中 0 次） |

**历史基线（无 dump，供对照）**：13291 块 / 128252 指令，卡在 `0x140323cc0`。

**已定结论**

- `shouldPromoteFileValue` / `mergen.stale_file_zero` **保留，不还原**（`795f21b`、`f298e4e`）。
  IR 里是 `%stale.file + 88`，**不再把槽读成 `0`**，也不再伪造 `0x58`。
- 13291 那条路停止的原因是 **`[heap+0x58]` 的表在堆上、进函数前已填好**，空合成页不够（§7.6.35）——
  这正是引入 **入口内存快照**（`ac06524`）的动机。
- 按博客（Aftermath Labs）仍**从 `0x7210` 抬**，不从 `0x4FD849` 起抬（§7.6.33 / §7.6.34）。
- **不要在 `solveLoad` 里对同类 DAG 做 unique-fold**，也**不要把 `addrToBB` 已有块一律当回边**（§7.10）。
- dump 已读入（§7.6.36 / `--mem-dump`）。**不要再把 `0xEF850` / 文件 0 当当前根因。**
## 6. 卡点与已否证的假设

无 dump 时：`0x1403b4ff9` 解错 → 停在 **13291 块**。有 dump 后仍从同一块分叉，只是继续抬到 24240（§7.10 的 `0x32281c` 是分叉后的死胡同）。

### 6.1 路径对比（严格逐块，同一次运行）

lifter 的块序列相对真机只多一个入口块（`0x7210`），逐块比较（有/无 dump 的**第一个分歧相同**）：

```
lifter[1..] vs real[0..] 共 13290 块: 一致 13281 (99.93%)
第一个分歧: lifter[13282]

lifter[13281] = 0x3B4FF9   real[13280] = 0x3B4FF9     同一块
lifter[13282] = 0x369063   real[13281] = 0x2D8CD0     ← 分歧
```

`0x3B4FF9` 在真机共出现 5 次（idx 5295/11500/12602/13280/15391）。
前 3 次后继两边一致；**第 4 次** dump 解出 `0x369063`，DR 走 `0x2D8CD0`。
真机第 5 次才后接 `0x369063`。这不是「还原了真机没走的合法叉」，是 **走错路**（§7.11）：
蹦床 `jmp r10` 算对了，进蹦床的 **R8 已经是下一轮的 delta**。

### 6.2 已否证的假设：`0x14FE48` 槽的「地址退化成裸偏移」

> **本节原判「根因」已被 7.6.18 之后的实测否证**，只保留作为排查记录与教训。

当时的观察：`0x14FE48` = `STACKP_VALUE - 0x58`，IR 里出现 `%memory + 88`（= `0x58`）的 GEP，
于是判断「一条栈槽 load 的地址退化成了裸偏移」。

**否证依据**：

- `0x58` 从来不是任何指令的字面位移（7.2 在 `0x1402B0000..0x140400000` 内零匹配）；
- 真机在 `0x140037ebaa` / `0x1403e9af2` 一带确实会算出 `0x58`，**是 VM 的合法还原**（7.6.22 同 visit 实测）；
- 真正让 lifter 变差的是 **`0x1400EF850` 那格被文件镜像的 0 冒充**（7.6.29 / 7.6.31），
  它经 `[RSP] → 0x3357C6 → … → 0x37507A` 一路传播；
- `%memory + 88` 这个 GEP 是**后果**不是原因：换成 `stale.file + 88` 后该 GEP 消失（§7.6.31 后已验证）。

**教训**：IR 里出现一个「可疑常量 GEP」不等于它就是根因；
必须先用**同一次运行的两侧真值**确认它是不是进程真实行为。

### 6.3 `0x1403e9af2` 的真实行为（两流对齐实测）

`0x1403e9af2` 是 `mov [rsp+rdi], r8`，**每次迭代写不同槽**，不是固定写某一格：

```
seq=41119  RSP = 0x14fc58
seq=41123  RSP = 0x14fc60
seq=41127  R8  = <symbolic>
seq=41135  RDI = 0x80
seq=41175  MEM store 0x1403e9af2 -> 0x14fcd8      (0x14FC58 + 0x80 ✓ 地址自洽)
```

**地址计算是自洽的，`R8` 在那一刻是符号值 —— 而 IR 里这条 store 是裸常量
`store i64 88`。** 即「符号值 → 裸常量 88」的转换发生在 lift 期。

注意 `RDI` 在该块内被 `0x1403e9ad9`（`dec dil`）等指令反复改写为小值，
`RDI = 0x58` 在整次 lift 中共出现 26 处（`0x140357598` / `0x14037a054` /
`0x1403a8e3f` / `0x1403e9ad9` / `0x1403fc0dd` …），其中 `0x1403e9ad9`
与那条 store 同块。

### 6.4 已否证的假设（勿重复排查）

| 假设 | 否证方式 |
|---|---|
| 堆分配被具体化到伪栈 | 真机 `RBX` 指向的就是程序栈（与 `RSP` 同区），delta 映射一致 |
| 路径错位 / VM 迭代错位 | **13281 块逐块严格相同** |
| `loadProvenance` 提升是元凶 | 加 `MERGEN_NO_MODULE_PROMOTION` 跑，块数/指令数**完全不变** |
| `folderBinOps` 类型不匹配 | 实测仅 1 次（`@0x1401f0f00`，入口 veneer），块数不变 |
| RFLAGS 缺 bit1/bit9 | 实测 `flag[1]=true`、`flag[9]=true` |
| `rol r8b,1` 子寄存器语义错 | `0x2C<<1 = 0x58` 验算正确 |
| 字节码读地址错 | 3982 条按序与真机逐条一致 |
| 写地址错 | 2630 个共同 RVA 零偏离 |
| `r10`（rolling key）错 | 低 32 位一致 |
| 解密常量错 | 与反汇编固定常量一致 |
| `0x58` 是栈被踩坏 | 该值是单独写的，邻居 write 都在别的 slot |
| `foldOrigin` 记账链可信 | 它给的来源 `0x14033578e` 实际写 `R11`，与真实 use-def 不符 |

### 6.5 为什么没出现符号爆炸

concolic 保持具体值；唯一会爆的 `computePossibleValues` cross-product 已被第 2 项裁掉。
遇到符号值时它是**错误具体化 / 丢路**，而不是 **fork** —— 所以既不爆，也没还原条件。

## 7. 阶段性证据（两流统一序号对齐后）

### 7.1 `getPointer` 的语义（关键）

```cpp
MERGEN_LIFTER_DEFINITION_TEMPLATES(Value*)::getPointer(Value* address) {
  std::vector<Value*> indices;
  indices.push_back(address);
  Value* pointer =
      builder->CreateGEP(Type::getInt8Ty(context), memoryAlloc, indices);
  return pointer;
}
```

**GEP 的下标就是传入的 `address`**。所以 IR 里的
`%70238 = getelementptr i8, ptr %memory, i64 88`
意味着那次调用是 `GetMemoryValue(88, …)` —— **有效地址整体等于 `0x58`**。

### 7.2 `0x58` 不是任何指令的字面位移

扫描 `0x1402B0000..0x140400000`（VM 代码区）全部指令，
**带基址寄存器且 `mem.disp == 0x58` 的内存操作数：0 个**。

⇒ `88` 是**算出来的**，不是从指令编码里读出来的。

### 7.3 `0x1403e9af2` 的地址计算全部正确（14 次迭代核对）

`wr6.csv` 的 slot 与同刻 `reg6.csv` 的 `RSP + RDI` 逐一相符：

```
seq=41175  slot=0x14FCD8  RSP=0x14fc60  RDI=0x78  calc=0x14FCD8  OK
seq=45419  slot=0x14FCB8  RSP=0x14fc60  RDI=0x58  calc=0x14FCB8  OK
seq=49848  slot=0x14FCA8  RSP=0x14fc60  RDI=0x48  calc=0x14FCA8  OK
seq=62244  slot=0x14FC90  RSP=0x14fc60  RDI=0x30  calc=0x14FC90  OK
...
（14 次全部 OK）
```

**这条指令每次迭代写不同槽，且寻址完全正确** —— 问题不在它的地址。

### 7.4 `0x14FE48` 槽的写入史

全部写入地址自洽。**最早一条是 `seq=60  insn=0x1403a600d (push r11) val=<符号>`**，
即 VM 入口的 `push r11` 写入的是**符号值**，不是 `0x58`。

### 7.5 读回 `0x58` 的那条写

```
seq=102322  insn=0x1402e17ee  slot=0x14FCB8  val=0x58   (RDI=0x58, 地址自洽)
```

### 7.6 尚未验证的一点（勿当结论）

`%memory + 88` 与 `0x14FE48` 槽**不是同一个地址**（零基址下 `88` 即地址 `0x58`）。
把两者等同是未经核对的推论，**已作废**。

### 7.6.12 从撤销的结论里保留的教训（读日志必知）

原 7.6.1–7.6.12 那一条链（`R8=0x58` 由 `rol r8b,1` 产生 → `0x1403C4475` 的 `movsx r8w,bpl`
→ `RBP` 伪栈低字节 → 「VM 把栈指针低字节当数据」）**已被 7.6.18 之后的实测否证并撤销**。

**但其中两条观察仍然有效，读 `[rdag]` / 诊断日志时必须知道：**

1. **`[rdag]` 有 300 节点硬上限**。日志里看到的最大深度（如 278）**不代表链的真实深度** ——
   根因常常在未打印的那一段。想靠 `[rdag]` 定位根，必须先确认它没被截断。
2. **两侧口径必须校准后才能比较**：DR `-regs` 探针读的是**执行前**，lifter 写流记录的是**执行后**。
   正确对照是「真机在 X 处的 pre 值」↔「lifter 在 X 的**前驱**的 post 值」。
   不校准就对照，会得出整片假结论（原 7.6.7–7.6.9 就是这么错的）。

### 7.6.18 `0x37EBAA` 的 43 次真机对照（本轮新数据）

`vmpdrtrace8.dll` 新增 `0x37EBAA` / `0x37EBB4` 站点后的真机真值：

```
真机 @0x37EBAA (mov r8,[rbx])  43 次:
   RBX  = 0x540f2ff730 / 0x540f2ff788 / 0x540f2ff79a / 0x540f2ff7ae / …
          （真实栈，与 RBP 同区）
   [RBX]= 0x0 / 0x0 / 0x202 / 0x202 / 0x0 / 0x540f1ab000 / 0x286 / 0x206 / 0x282 / …
   R8   = 上述 [RBX] 的值（该指令就是 mov r8,[rbx]）

lifter @0x14037ebaa:
   R8 = 符号 / 0x0 / 0x7ffd1000 / 0x90 / …
lifter @0x14037ebb4 (add rbx,8):
   RBX = 0x14fdd0 / 0x14fe28 / 0x14fe3a / 0x14fe4e / …
```

**两侧 `RBX` 都在各自的栈上，读出的都是「小整数 / flag 族」**
（真机 `0x0/0x202/0x286/0x206/0x282`，lifter `0x0/0x90/0x7ffd1000`），
**真机 43 次里 `[RBX]` 从不等于 `0x58`。**

### 7.6.19 因果链的诚实边界（务必读）

**已确证（从派发目标倒推，均有两侧实测）**：

```
派发目标符号化
  <- 0x14034ed0e 读 [0x58] 得垃圾（R11 = 0x58）
  <- 0x14034ecfd mov r11,[rbx]  从槽 0x14FE48 读回 0x58
  <- 0x1402e17ee mov [rbx],rdi  把 0x58 写进 0x14FE48
  <- 0x1402e17d5 mov rdi,[rsp+0x30]  从 0x14FC90 读出 0x58
  <- 0x1403e9af2 mov [rsp+rdi],r8    把 R8=0x58 写进 0x14FC90
  <- R8 = 0x58
```

**未确证（当时）**：**`R8` 为何是 `0x58`**。已由 7.6.20 用同一次 `wr6`/`reg6`（`RBP` 用 `reg8`）闭合。

### 7.6.20 致命 `R8=0x58` 已锁到 `add rcx, rbp`

同一次跑：`wr6.csv` + `reg6.csv`（seq 共用）；`reg8.csv` 补 `RBP`。
**不要用 `reg7.csv` 对 `wr6` 的 seq**（不是同一次 lift）。

致命 store：

```
W,100464  0x1403e9af2  mov [rsp+rdi], r8   0x58 -> 0x14FC90
```

store 前最后一条 `R8` 写：

```
REG,100416  0x14037ebaa  mov r8, [rbx]   R8=0x58   （读 0x14FDC0）
```

这是自循环读回，不是第一次产生。自循环：

```
88652  0x37507a  mov r8,[rbx]         R8=0x58     ← 槽 0x14FE1A
88698  0x3750eb  mov [rsp+rdi],r8     -> 0x14FCA0
100231 0x37990b  mov rdi,[rsp+r11]    RDI=0x58
100233 0x379916  mov [rbx],rdi        -> 0x14FDC0
100416 0x37ebaa  mov r8,[rbx]         R8=0x58
100464 0x3e9af2  致命 store
```

**跳出循环的第一次产生**：

```
88300  RBX = 0x14FE12
88123  0x3d1461  mov [rbx], r11    写 0x4790dfe23097efcd -> 0x14FE1A
88368  0x341334  mov rbp, [rbx]    RBP = 0x1402B2FA8     （槽里的模块指针）
88371  0x34133a  mov r8, [rbp]     R8  = 0xb86f201dcf68108b
88372  0x34133f  mov [rbx], r8     写该常量 -> 0x14FE12
88391  0x31138e  mov rcx, [rbx]    RCX = 0xb86f201dcf68108b
88392  0x311391  mov rbp, [rbx+8]  RBP = 0x4790dfe23097efcd
88393  0x36b360  add rcx, rbp      RCX = 0x58
88394  0x3f010a  mov [rbx+8], rcx  把 0x58 写进 0x14FE1A
```

验算：`0xb86f201dcf68108b + 0x4790dfe23097efcd ≡ 0x58 (mod 2^64)`。
第二操作数 = `rol(bswap 链后的 R11, 0x3b)`，数值上恰好是 `-第一操作数 + 0x58`。

文件里 `VA 0x1402B2FA8` 的 qword **就是** `0xb86f201dcf68108b`（模块常量，load 本身对）。

真机 `@0x341337`（执行前，`rbx.regs`）：

```
RBP = 0x7ff6f57d2edc   RVA = 0xC2EDC
[RBX] = 0x7ff6f57d2edc
该 RVA 的模块 qword = 0x4cbf50eb4bd88e9c   ≠  0xb86f...
```

**（7.6.20 当时的推论）** `0x58` 在 lifter 里来自那对 qword 的 `add`；模块常量 load 对上过文件。
真机对照见 7.6.21：**链条在 lifter 内成立，但那一对不是真机的组合。**
`0x3C4475` / 伪栈 `BPL` 仍不是这条致命链的源头。

### 7.6.21 真机对照：一个关键吻合 + 一个关键否定

**吻合**：真机也产出过那个模块常量。

```
真机 @0x34133F (第 2 次命中):  R8 = 0xb86f201dcf68108b    ← 与 lifter 完全一致
真机 @0x34133F 三次:           R8 = 0x4a0d2053d469b5f0 / 0xb86f201dcf68108b / 0x067c680f36eaf106
```

7.6.20 链条里的第一操作数 `0xB86F201DCF68108B` 是真机确实产出的值。

**否定**：那两个操作数在真机上不是「和 = 0x58」的那个组合。

```
真机 @0x31138E (15 次):  RCX = 0xfffffffffffdafb3 / 0xfffffffffff798f7 / 0x48f2 / 0x48f2 / …
                          RBP = 0x8394fff790 / 0x8394fff790 / 0xfffffffffffa832b / …
真机 @0x311391 (15 次):  RCX = 0x7ff589f00000 / 0x7ff589f00000 / 0x202 / 0x120 / …
真机 @0x36B360 (add)   :  RCX = 0x7ff589f00000 / 0x7ff589f00000 / 0x202 / 0x120 / …
                          RBP = 0x1402b2e94 / 0x1402b2ea8 / 0x84 / 0x83951ed000 / …
```

真机这一对是「小整数 / flag 族 + 指针」；
lifter 那一对 `0xB86F201DCF68108B + 0x4790DFE23097EFCD` 是「两个随机 qword，互补到只差 0x58」。

**⇒ 真机在 `0x31138E`/`0x311391` 的值域与 lifter 完全不同。**

7.6.20 描述的是 **lifter 内的事实**，不是真机的事实：

- 对：`0x58` 在 lifter 里确实是 `add rcx,rbp` 得到的，两操作数与和均已验算。
- 对：自循环、seq、致命 store 全部准确。
- 不对：真机在这一对上的取值与 lifter 不同，所以「两 qword 互补到 0x58」是 **lifter 特有**，不是真机行为。

**（7.6.21 当时按 15 次聚合的结论过头了，见 7.6.22。）**

### 7.6.22 更正：互补 `add → 0x58` 是真机真实行为

`add.regs` 里 **`0x34133F` 产出 `0xb86f…` 的那一次**（与 lifter 致命路径同型）紧接着：

```
真机 @0x34133F  R8  = 0xb86f201dcf68108b   RBP = 0x7ff6ca1b2fa8
真机 @0x31138E  [RBX] = 0xb86f201dcf68108b
真机 @0x311391  RCX = 0xb86f201dcf68108b
真机 @0x36B360  RCX = 0xb86f…   RBP = 0x4790dfe23097efcd   ← 同一对
真机 @0x3F010A  RCX = 0x58     （add 之后、store 之前）
```

**⇒ 「两 qword互补到 0x58」不是 lifter 特有，是 VM 在这一 visit 的故意还原。**
7.6.21 的「值域完全不同」来自把其它 visit（flag/`0x202`/模块基址）和这一 visit 混在一起。

### 7.6.23 真正分歧：`0x58` 写出之后，槽内容分叉

同一 visit，`0x3F010A`（`mov [rbx+8], rcx`）应把 `0x58` 写入 `RBX+8`：

| | 真机 | lifter |
|---|---|---|
| store 时 RBX | `0x8394fff80a` | `0x14FE12` |
| 写入地址 | `0x8394fff812` | `0x14FE1A` |
| store 值 | `0x58` | `0x58` |
| 下一探针 `@0x37507A` 的 RBX | `0x8394fff812`（= store 地址） | `0x14FE1A`（读时） |
| **`@0x37507A` 的 `[RBX]`** | **`0x00000207f4edb7a8`（堆指针）** | **`0x58`** |
| 其后 `@0x3E9AF2` 的 R8 | `0x297`（flag 族） | `0x58` → 致命链 |

两侧 RAX（`0xc4808`）/ RSI 高位（`0x1c722438…`）连续，是同一次迭代。

**⇒ `0x58` 的产生是对的；错在「产生之后到 `0x37507A` 之间」。**
真机把该槽换成了堆指针，lifter 仍留着 `0x58`，于是自循环把它送进派发链。

lifter 在 `88394`（首写 `0x58`）与 `88652`（`0x37507A` 读回）之间，对 `0x14FE1A` 的写入只有
`88560 0x2c28ec` 再次写 `0x58`（`add rcx,rbp` 且 `RBP` 已是 `0x58` 的自回声）——
**从未写成堆指针。**

### 7.6.24 窗口内 lifter 在做什么（`0x3F010A` → `0x37507A`）

lifter `reg8`/`wr6`，seq **88394–88652**（`RBX` 基址 `0x14FE12` ≡ 真机 `0x8394fff80a`）：

```
88394  0x3f010a  mov [rbx+8], rcx     写 0x58 → 0x14FE1A     ← 与真机一致
88399  0x3f0113  pushfq               写 0x11 → 0x14FC58     （真机 FLG=0x213，flags 已开始偏）
88405  0x3f011d  pop  [rbx]           写 0x11 → 0x14FE12     （覆盖刚 load 的 0xb86f…）
88431  jmp/ret 到 0x3bc020
88435  0x3bc020  mov r8, [rbx]        R8=0x11
88436          add rbx, 8            RBX=0x14FE1A   （VSP 指到 0x58 那格）
…
88518  0x3357bc  inc r11b             R11=0
88523  0x3357c6  mov rdi, [rsp+r11]   RDI=0          ← [0x14FC60]
88524  0x3357ca  sub rbx, 8           RBX=0x14FE12
88525  0x3357d1  mov [rbx], rdi       写 0 → 0x14FE12  （把 0 压进 VM 栈）
88556  0x3e73ed  mov rcx, [rbx]       RCX=0
88558          mov rbp, [rbx+8]      RBP=0x58
88559          add rcx, rbp          RCX=0x58
88560  0x2c28ec  mov [rbx+8], rcx     再写 0x58 → 0x14FE1A
88652  0x37507a  mov r8, [rbx]        R8=0x58         ← 真机同槽是堆指针
```

`0x14FE1A` 在整个窗口里只被写成 `0x58`（两次）。**没有堆指针 store。**

`[rsp+r11]=[0x14FC60]` 的最后一次写入早在 seq **73857**（`0x0`）；之后 native 栈一直在 `0x14FC58` 活动，**再也没写过 `0x14FC60`**。所以 `mov rdi,[rsp]` 读到 0，再压进 VM 栈，`add` 变成 `0+0x58`。

真机同 visit `@0x37507A`：`[0x8394fff812]=0x207f4edb7a8`。
要让同一条 `add rcx,[rbx+8]` 得到堆指针，真机的 `[rbx]`（即 `[rsp+r11]` 压上去的值）就不能是 0。

**⇒ 下一刀：`0x3357C6 mov rdi, [rsp+r11]`（R11=0 ⇒ `[RSP]`）。**
lifter 读到 0；真机若读到堆指针，后面的 `add`/`0x2c28ec`/`0x37507A` 就全对得上。

### 7.6.25 native 槽 `0x14FC60` 的 0 从哪来

最后写入：seq **73857** `0x31BF20` → `[0x14FC60]=0`。
紧挨着的 `0x31BF08` 把 `RDI` 写成 0（该站点历史上写出过 `0x00/0x10/0x18/0x20/0x60` 这类小立即数，不像堆指针）。

`R11` 在读之前：`0xfe → 0xff → 0x00`（`inc r11b` 绕回）。高位全程为 0。

`RAX` 在 `0x3357C6` 仍是 **`0xc4808`**（seq 87806 写入后未再改）。

两种分叉都还活着：
- 真机 `[RSP]` 已是堆指针（槽内容不同）
- 真机 `R11` 高位非 0，读的不是这一格

`vmpdrtrace.c` 已加探针 `0x3357C6` / `0x3357D1` / `0x3E73ED` / `0x2C28EC`：
`0x3357C6` 打 `loadEA=RSP+R11` 和 `[EA]`；后三个打 `[RBX+8]` / `RDI` / `RCX`。

### 7.6.26 真机 `win3357.regs`：R11 一致，`[RSP]` 不一致

同 visit `RAX=0xc4808`（`win3357.regs` @ 2304）：

| 站点 | 真机 | lifter |
|---|---|---|
| `0x3357C6` R11 | **0** | **0** |
| `0x3357C6` `[RSP+R11]` | **`0x1dc7614d1a0`**（堆） | **0** |
| `0x3357D1` RDI | `0x1dc7614d1a0` | 0 |
| `0x3E73ED` `[RBX]` / `[RBX+8]` | heap / `0x58` | `0` / `0x58` |
| `0x2C28EC` RCX（将写入 `[RBX+8]`） | `0x1dc7614d1f8` = heap+`0x58` | `0x58` |
| `0x37507A` `[RBX]` | `0x1dc7614d1f8` | `0x58` |

上一轮 `add.regs` 的 `0x207f4edb7a8` 是同形态（heap+`0x58`），堆基随 ASLR 变。

**R11 高位假设否掉。** 分叉就是 native 栈顶那一格：真机是堆指针，lifter 是 0。

lifter 该格（`0x14FC60`）最后写入：seq **73857** `0x31BF20` 存 **0**（`RDI` 刚被 `0x31BF08` 写成 0）。之后到 `0x3357C6` 再没人写它。

`0x31BEA3` 每次把 `RDI` 写成非常量 `-`，随后混淆算术在本 visit 收成 0。真机若 `0x31BF20` 存的是堆指针而不是 0，根因就在这个 handler。

已加探针 `0x31BF08` / `0x31BF20`（打 `[RSP]`、`RDI`）。对齐用 `RAX=0xa3a86`（seq 72669，是 73857 之前最后一次 RAX）。

### 7.6.27 `0x31BF20` 存的是 R8；0 来自 `0x3D50FE`

`0x31BF20` 的写入值与同 visit `0x31BE9D` 的 **R8** 逐条相符（`0` / `0x55` / `-` / `0x4` / `0x11` / `0x814`…）。
`0x31BF08` 的 RDI 是 `[rsp+rdi]` 的偏移（本 visit 为 0），不是存进去的值。

本 visit（`RAX=0xa3a86`）链：

```
73712  RBX=0x14FE44
73786  0x3d50f7  R8=0xfffc
73789  0x3d50fe  R8=0            ← 16 位 0xff43 之后变成 0（像 shr 把高位清掉）
73792  0x3d510e  [0x14FE44]=0    ← 写进 VM 栈
73810  0x31be9d  R8=0            ← 从 [RBX] 再读回来
73857  0x31bf20  [0x14FC60]=R8=0 ← 写到 native [RSP]
```

同站点其它 visit：`0x3D50FE` 的 R8 可以是 `0xb76fd9292e668893` 这种满 qword，所以它不是 `xor r8,r8`。
本 visit 收成 0，很像 **R8 在 `0x3D50F7/FB` 已经被截成 16 位**，再移位/运算就变成 0；真机若还是满宽堆指针，这里就会把堆写进 `[RSP]`。

已加探针 `0x31BE9D` / `0x3D50FE` / `0x3D510E`。对齐 **`RAX=0xa3a86`**。

### 7.6.28 真机 `win31bf.regs`：`0x3D50FE` 写出堆指针；PE 里同址是 0

同 visit `RAX=0xa3a86`：

| 站点（执行前） | 真机 R8 | lifter（执行后） |
|---|---|---|
| `0x3D50FE` | `0xfd41`（即将被覆盖） | 下一条写出 **0** |
| `0x3D510E` | **`0x1c0688cd1a0`**（堆） | 0 |
| `0x31BE9D` | 堆，`[RBX]`=堆 | 0 |
| `0x31BF20` | 堆，`RDI=0`（写 `[RSP]`） | 0 → `[0x14FC60]` |

同一趟后面 `RAX=0xc4808` @ `0x3357C6`：`[RSP]=0x1c0688cd1a0`，`0x37507A` `[RBX]=0x1c0688cd1f8`。整条链闭环。

`0x3D50FE` 时 RBP：真机 `0x7ff6c9fef850`，lifter `0x1400ef850`，**同一 RVA `0xEF850`**（节 `.rZu0`）。磁盘上这 8 字节是 **0**。真机这条指令把 R8 从 `0xfd41` 变成堆指针，最像 `mov r8, [rbp]` 读到运行时写进去的 VM 堆指针。

**7.6.27 的「shr 截宽」否掉**：R8 输入宽度无关，`mov` 会整寄存器覆盖。根因是 **file-backed 映像在 `0x1400EF850` 仍是 0，进程里已被 VMP 初始化写成堆指针。**

### 7.6.29 根因的机制（已核到源码路径）

**lifter 取值路径**（`GEPTracker.ipp` `retrieveCombinedValueImpl`）：

1. `trackedBufferConstant(...)` — 若该地址被**跟踪写**覆盖，用 buffer 值（正确）；
2. 否则 `file.readMemory(...)` — **回落到文件镜像**（第 336 / 340 行）；
3. 再否则 `extractBytes(orgLoad)`。

`.rZu0` 在 `configureDefaultMemoryPolicy`
（`MemoryPolicySetup.hpp:18`）里被整节标为 `CONCRETE`（值取自文件）。

**而 RVA `0xEF850` 这一格：**

```
PE 文件:   bytes = 00 00 00 00 00 00 00 00      全 0（已核）
所在节:    .rZu0  Characteristics=0x60000020   （未声明可写；但 VMP 运行时改了它）
真机:      RBP = 0x7ff6c9fef850 → 该格已被 VMP 写成堆指针
lifter:    0x3D50F7 只读不写 → 无跟踪写 → 走 file.readMemory → 得到 0
```

**⇒ 机制：`.rZu0` 里存在「文件为 0、运行时被 VMP 初始化为堆指针」的格子。
lifter 对这类格子没有跟踪写，于是回落到文件镜像拿到 0，
再经 `0x3D510E → 0x31BE9D → 0x31BF20 → [RSP] → 0x3357C6 → … → 0x37507A`
一路传播成致命的 `0x58`。**

**这也解释了 6.4 里「关掉模块 promotion 无效」**：那个开关管的是 `loadProvenance` 记账，
而这里是 `file.readMemory` 的**取值回落**，是另一条路径。

### 7.6.30 已加的实验开关（未改变默认行为）

`GEPTracker.ipp` 里 `file.readMemory` 的两处回落现由 `MERGEN_NO_FILE_PROMOTION` 门控：
置 `1` 时「无跟踪写的模块字节」保持符号，不再用文件镜像当常量。

**用途**：判定「文件镜像回落」是否就是那条致命的取值来源
（对照 `13291 blocks / 128252 instructions` 是否变化）。
**注意**：这是诊断开关，不是修法 —— `.rZu0` 的加密字节码**必须**保持具体，
所以不能整节停用；正确的修法是**只对「会被 VM 运行时改写」的格子**不给文件值。

### 7.6.31 修复（range policy）

错改：`MERGEN_NO_FILE_PROMOTION` 只挡 SYMBOLIC 早退支路，而 `.rZu0` 当时是 CONCRETE，走 composed → `file.readMemory` → PE 零。

已改（通用，不是灌值）：
1. 白名单节 CONCRETE；**可执行**的未知节也 CONCRETE（加密字节码要从 PE 读）。
2. 不可执行的未知节 SYMBOLIC。
3. 非白名单节里 **≥8 字节且值为 0** 的 file 读不提升（`0xEF850` 这类运行时写的指针槽），1–4 字节字节码仍提升。

`shouldPromoteFileValue` 已接到 lift 时 `retrieveCombinedValue`、concolic buffer 回退，以及事后 `GEPLoadPass`。重测见 7.6.32。

### 7.6.30 DR 证据：堆指针在 `0x7210` 之前由 `0x88AFE2` 写入

`ef850_7210.regs`（`-entry 0x140007210` = lifter 同起点，`-trackmem` 盯 `image+0xEF850`）：

```
watchW#1..#8  pre_entry=1  ip=image+0x88AFE2  size=1  逐字节写 EF850..EF857
=== vm_entry / probe 0x7210 ===
  [image+0xef850]=0x000002910ceee250   ← 已是堆，writes_seen=8
```

相对 `-entry 0x1f0efb` 同样：入口时已是堆，触写全在 `pre_entry=1`。
写手 **`0x88AFE2`**（`.rZu2`），不是 VM 里的 `0x3D50FE`。

先前「磁盘 0 ⇒ 没有 runtime init」被否掉：有 init，只是在 **`0x7210` 之前**（壳/CRT 路径，来自 `AddressOfEntryPoint`）。

### 7.6.32 历史：promotion 全路径接上后块数仍未动（已被 §7.9 的 24240/13s 取代）

构建：`D:\sogen\tools\rebuild_mergen_msvc_dbg.cmd`（不是 `scripts\dev\configure_iced.cmd`）。
运行：`work.md` 0.4 A，起点 **`0x140007210`**。

| 二进制 | 块 / 指令 | 停 |
|---|---|---|
| 15:34 | 13291 / 128252 | `0x140323cc0` 未解析间接跳 |
| **16:05**（`stale-zero` 不看 buffer 覆盖；`PathSolver` `solveLoad` 用 bitwidth） | **13291 / 128252** | 同左；另 `0x1403da685` 未解析 ROP |

exit 0，0 error。`shouldPromoteFileValue` 编进去了，**这条 `0xEF850 → 0x58` 路径在 lift 里没有被拆掉**。

`0x58` 不是把堆指针读错：真机是 `堆+0x58`，lifter 是 `0+0x58`。不提升文件 0 的目标是变成符号堆基，不是还原堆页。

### 7.6.33 `0x88AFE2` 与真正的进程入口

PE 头（不是 lifter 参数）：

| | |
|---|---|
| `AddressOfEntryPoint` | **`0x1404FD849`**（`.rZu2`） |
| TLS 目录 | **空** |
| 用户一直 lift 的 `0x140007210` | 原 `.text` 函数：prologue 之后 `jmp 0x1401F0EFB`（VM 入口） |
| 写手 `image+0x88AFE2` | `.rZu2`：`mov byte ptr [r14+r10-1], r11b`（`45 88 5c 16 ff`），随后 VMP 假 `jmp $+5`；与 DR 的 8 次 size=1 写吻合 |
| `HeapAlloc` / `LocalAlloc` | IAT 在 **`.rZu1` `0x140406000`**（RW，非 X） |

DR `-entry 0x140007210` 时 `pre_entry=1` 的写，就是 **PE 入口 stub 在跳进 `0x7210` 之前跑完的**，不是 TLS，也不是 VM handler。

从 `0x7210` 起 lift 看不到这次 store。`.rZu1` 现行 policy 是 SYMBOLIC；若改从 `AddressOfEntryPoint` 起抬，IAT 的 `HeapAlloc` 会先变成符号调用。

### 7.6.34 博客怎么做；本样本差在哪

Aftermath Labs《Static Devirtualization of Themida》2026-05-09 把 **VMP 也算进能还原的范围**（「Fully reducing Themida or VMP」）。不是从 `AddressOfEntryPoint` 起抬。

- 从被虚拟化的函数起抬；寄存器符号，**只有 RSP 具体**。
- Themida：VM context / 虚拟栈在**映像里**。VMP：在 **native 栈**上 → 靠具体 RSP + store-forward，不靠 promote 映像里的 context。
- 字节码从模块 promote；VMP 的 VIP = 喂进间接跳的最后一次模块 load。
- 写过再 load 禁止回落文件（range policy）。store 不在本次 CFG 里 → **不 promote**，不是去 lift 壳 stub。

`0xEF850` **不是**博客说的 VMP 虚拟栈（那是 `[RSP]` / VSP）。它是壳在进 `0x7210` 之前写进映像的堆指针。经典 VMP 还原不依赖这块堆。本 Ultra 样本真机把堆指针压进 VM 栈再 `+0x58`；lifter 用文件 0 做成 `0x58` 去派发。

已改文件（无 overlay、无按 `.rZu*` 灌值）：

- `MemoryPolicySetup.hpp` — 白名单 / 可执行未知节 CONCRETE
- `FileReader.hpp` — `shouldPromoteFileValue`
- `GEPTracker.ipp` — composed + `stale-zero`
- `LifterClass_Concolic.hpp` — buffer 回退
- `CustomPasses.hpp` — `GEPLoadPass`

### 7.6.35 堆表在 exe 段外；空合成页会再停

`ef850_7210`（`-entry 0x140007210`，`trackmem` 从入口才记）：

| | |
|---|---|
| 进 `0x7210` 时 `[image+0xEF850]` | `0x2910ceee250`（堆，不在 ImageBase） |
| 写手 `0x88AFE2` | 只把 **指针** 写入映像 RVA `0xEF850`（`.rZu0` 脏页；磁盘仍是 0） |
| `[heap, heap+0x1000)` 入口后到关键读 | **0 次写** |
| 第一次碰 `heap+0x58` | **读**，`0x34ed0e mov ecx,[r11]`，seq 111337 |
| 该次 `[R11]` | `0x2910c50dc57`（另一块堆，差约 10MB，非 0） |

运行前写了两层：指针在映像节里，**表在 HeapAlloc 出来的堆上**。只符号 `0xEF850`、只种空 `heapBase`、只读 PE 节，第一次 `load [heap+0x58]` 仍是 0/符号。

### 7.6.36 入口 dump 的地址空间（硬约束，已接线）

dump 映像 ASLR 在 `0x7FF781290000`（`0xEF850` → `0x7FF78137F850`）；lifter 映像永远是 PE `ImageBase=0x140000000`（`0xEF850` → `0x1400EF850`）。堆是第三套 VA（本样本 `0x2910…`）。

页进 lifter 稀疏 map 的规则：

| dump 页 | 映射 |
|---|---|
| `[dump_base, dump_base+SizeOfImage)` | 字节放到 **`ImageBase+RVA`**；需要时 **alias** 同一页到 `dump_base+RVA`（堆里若还有 dump 空间映像指针） |
| 其余 RW（堆） | **原 VA 原样** |

格子里的 qword **不要当地址 rebase**（`[0xEF850]` 是堆指针）。不要把 lifter `ImageBase` 改成 `0x7FF…`，不要把堆滑到 `0x1400…`，不要灌死样本堆地址。碰撞只查 `ImageBase…+SizeOfImage`、`STACKP` 窗口、`tebBase=0x7FFD0000`。

## 7.7 下一步（按优先级）

**先前代码不还原。** `795f21b`（可执行未知节 CONCRETE、`shouldPromoteFileValue`、composed 0 → `stale.file`）继续留着：没有它会回到 `0+0x58`。主 lift 仍从 `0x7210`，不从 `0x4FD849`。不要整节 SYMBOLIC，不要 overlay 一个堆常量。

dump overlay **已经接上**（§7.6.36 标题仍写「未实现」是旧文；以 0.4 C / 本节验收为准）。当前该做的是 **§7.11**：第 2 次 `0x301D45` 的栈槽 VIP，不是再采 dump。

历史步骤（已完成，留作复现）：

1. **DR**：第一次执行到 lift RVA 时 dump 已提交 RW（主模块映像页 + `MEM_PRIVATE` 堆）。不要 dump ntdll。格式 `MRGNDMP1`：`dump_image_base`、`SizeOfImage`、若干 `(va, size, prot, bytes)`。
   ```
   D:\sogen\dr\build_vmpdrtrace7.bat
   D:\DynamoRIO\bin64\drrun.exe -c D:\sogen\dr\vmpdrtrace7.dll -entry 0x140007210 -dumpmem D:\sogen\dr\vmptest\entry_7210.dmp -dumpmem-exit -- D:\sogen\dr\vmptest\add_test_fixed4.exe
   ```
3. dump 映像先把落在 `[dump_base, dump_base+SizeOfImage)` 的 qword 折成 `ImageBase+RVA`，再和 PE 比。脏判断按 **整颗 qword**：任一字节不同则 8 字节全 overlay（避免 `0xEF850` 堆指针高位 0 留洞导致 `covers(va,8)` 失败）。CONCRETE = 这些 dirty span + 从中走到的堆（再一跳）。
   ```
   lifter.exe D:\sogen\dr\vmptest\add_test_fixed4.exe 0x140007210 --mem-dump D:\sogen\dr\vmptest\entry_7210.dmp
   ```
3. **再从 `0x7210` 抬**：RSP 仍具体。期望 `[0x1400EF850]` 是堆指针、`[heap+0x58]` 能读到表项。
验收（分层 cache + dirty qword dump，exit 0）：**24240 blocks / 209049 insns**（真机 30270）。`[EF850]` 已是堆指针。旧蹦床间接跳诊断消失。**先修 §7.11 第 4 次 VIP，再谈 §7.10。** `buffer` 仍深拷。
5. `foldOrigin` 仍不可信（6.4）。

实现：`RuntimeMemDump.hpp`、`FileReader` overlay、`--mem-dump`、`vmpdrtrace -dumpmem` 已接线。`795f21b` 不还原。无 dump 时 policy 与 13291 路径相同。

`InstructionCache` 见 **7.9**。`buffer` 仍深拷。

## 7.9 为什么这次 ~13s（24240 块）

同一样本、同一入口、同一 dump，三次墙钟：

| 版 | 时间 | 结果 |
|---|---|---|
| `1caa185` `uniqueMap` 整表 COW | ~90s（后来本机 ~62s `bad_alloc`） | 24240 或 OOM |
| 分层但 restore **全链 flatten** | ~325s | 24240 |
| 分层 + 备份**共享 index** | **~13s**（lift 10.7s） | 24240，仍卡 `0x32281c` |

Unflatten 每个新块都 `branch_backup` 一份 `InstructionCache`。folder（尤其 `zext`）每个 `getOrCreate` 都 lookup/insert。24240 块 × 每块大量 zext，cache 才是热路径。

**90s / OOM：** `uniqueMap` 在 `use_count()>1` 时 `SmallDenseMap` **整表拷一份**。每个备份块各持一张几乎完整的历史表，内存随块数线性炸；拷本身也贵。第一次 insert 在 `createZExtFolder` 上 `std::bad_alloc`。

**325s：** 改成链表分层，备份只分享指针、新 key 写当前层，OOM 没了。但 `flat` **不随备份走**，`load_backup` 后 `flatReady=0`，下一次 lookup 从根把几千层 **merge 成一张新表**。restore 次数 × 历史 key 数 ≈ O(n²)，所以比整表拷还慢。

**13s：** 备份同时分享已经累加好的 `index`（到 `indexAt` 为止是完整的）。lookup = `hot` → 最多扫 `indexAt` 之后新增的几层 → `index`。restore 不用重建。`index` 仍被备份引用时隔 32 层才 COW 一份，避免每块一张全表。语义仍是写时分叉，只是热路径不再拷、也不再扫整条历史。

块数没变，所以不是少抬了。`buffer` 仍深拷，只是没落在这条热路径上。

## 7.10 卡点 `Unresolved ROP @0x14032281c`

这不是 dispatcher 没走完。在此之前的 `ret` 弹出的是栈上的**具体 RIP**（`rsp=0x14fc58` 那条 VM 帧），和 DR 对齐，所以能抬到 24240。

卡住的这条 `ret` 在 **`0x14032281c`**（日志截断成 `0x4032281c`）。`rsp=0x14fe70`（相对 `STACKP=0x14fea0` 只低 0x30），**不是** VM 调度帧。弹出的「返回地址」不是 `[rsp]` 里的常量，而是一条还没折完的 SSA：

- 重复形态：`xor i32 (load i32 [%memory + 1076960216 + 4*(x & 255)]), 2080459474`
- `1076960216 = 0x40311BD8` = `0x140311BD8` 的低 32 位（映像里的字节表，dump 里有）
- `2080459474` 是固定 round key；中间还夹 `not` / `add` / 截断扩展
- `[rdag]` 300 个节点封顶，叶子仍是同一张表的 `load`，没有落到 `ConstantInt`

`solvePath` 要的是**一个**具体 RIP。这条 DAG **唯一确定**（嵌套 load 对着 CONCRETE/dump 逐层取值只会得到一个 i32），但现有求解走不通：

1. **`getPossibleValues` 把 `max_unknown==0` 当成失败**（`GEPTracker.ipp` 与 `>=10` 一起 `return {}`）。日志里一串 `max_unknown : 0` 就是它：KnownBits 认为没有未知位，函数却交空集，调用方当 PATH_unsolved。
2. **嵌套 `load` 的 GEP 偏移不是常量**（`base + 4*(x&255)`，`x` 又是上一层 xor/load）。`computePossibleValues` / `solveLoad` 只在偏移已是 `ConstantInt` 时 `retrieveCombinedValue`；不会沿 use-def 把内层 load 先读成数再折外层。
3. **不能按 `x&255` 枚举 256 路**。那是控制流分叉，每臂深拷 `buffer`，会 OOM。正确是 **unique-fold**：只对这条解不出的 `ret` 弹出值做整数 DAG 求值（const / cast / binop / 对 `%memory` 的 load），得到 **一个** RIP 再入队。不要在 lift 期对所有同类 load 做同样的折（会把已经对齐的 dispatcher `ret` 走歪）；不要把 `addrToBB` 里 `.pdata` outline 空壳当回边（会收成几十块）。

**当前优先级低于 §7.11。** 真机从不执行 `0x32281c`；它出现是因为第 4 次 `0x3B4FF9` 已经走进 `0x369063`。先把 VIP/`R8` 对齐，这条 ROP 会自己从主路径消失。unique-fold 约束仍有效，只是不要再把它当「当前该解的题」。

实现约束（若仍碰 Ret 嵌套表）：`tryFoldConcolicInt` **只**在 `PathSolveContext::Ret` 且弹出值还不是 `ConstantInt` 时跑；失败则保持 PATH_unsolved（Ret 上 `pvset>2` 清空，禁止 256 路）。lift 期 `solveLoad` 不动。Ret 求解中的 `retrieveCombinedValue` 不写 VIP。不要 `addrToBB` outline 当回边。

## 7.11 第 4 次 `0x3B4FF9`：R8 错在 VIP，不在蹦床

口径：DR `-regs` = **指令前**；lifter `[tramp] enter` / `[vip] pre` = **进块前**（与 §7.6.12 相同）。dump overlay 已加载。不要再开 `0xEF850`。

蹦床本身（`0x3B4FF9` `sub/not/movsxd r8` + `add r10,r8` + `jmp r10 @ 0x3B501C`）两边一致。R10 稳定 `…57026` / `0x402E7026`。第 1–3 次入口 R8 一致；**第 4 次 dump 入口 R8=`0x3E13644` = 真机第 5 次**，真机第 4 次是 `0x3EA39D7` → 后继 `0x2D8CD0`。dump 因此跳到 `0x369063`。

进蹦床前 native 前缀两边仍对齐：

```
0x2E6FF6  mov rsi, r9
0x2E7043  mov r8d, [r9]      ← 从 VIP 取 dispatch dword
0x2EB20F  xor r8d, esi
0x3543AF  dec / bswap / neg
0x2FD67F  dec / not / sub / ror
0x3B4FF9  jmp r10
```

`0x2E7043` pre（`build_msvc_dbg/run_vip.out` vs `vmptest/vip.regs`，2026-10-04）：

| 次 | dump R9 / dword[R9] | DR R9 RVA / dword[R9] |
|---|---|---|
| 1 | `0x14012E4EA` / `0x1DA6BFD9` | `0x12E4EA` / `0x1DA6BFD9` |
| 2 | `0x14012CD1D` / `0x1BA60196` | `0x12CD1D` / `0x1BA60196` |
| 3 | `0x140205928` / `0x1894DF79` | `0x205928` / `0x1894DF79` |
| **4** | **`0x14014AAE0` / `0x18203851`** | **`0x20557A` / `0x1D940E49`** |
| 5 | `0x1402266B6` / `0x1696D5A7` | `0x1E4887` / `0x182ADA3E` |

`0x2E6FF6` 第 3 次（喂第 4 次 load）：dump R9=`0x14014AAE4`，DR=`image+0x20557E`。两块之间只把 R9 减 4，算术对。

VIP 抄自 `0x301D45`（`mov rcx,[rbx]; mov r9,rcx`）。该块两边都只进 **2** 次（不是漏探）：

| 次 | dump 进块 R8 | DR R8 = `[RBX]` |
|---|---|---|
| 1 | `0x14020592C` | `image+0x20592C`（随后蹦床第 3 次） |
| **2** | **`0x14014AAE4`** | **`image+0x20557E`（应喂蹦床第 4 次）** |

dump 的 RBX 是伪栈 **`0x14FDB0`**（`STACKP-0xF0`）；`file.readMemory` 读不到槽 SSA。第 2 次进 `0x301D45` 时 **VM 栈槽 / R8 已经是错 VIP**。`lastModuleLoad` 仍停在 `0x14020568B` 一带（和 DR 当时的 R9 同邻域），所以不是「整段字节码指针丢了」，是 **栈上那份 VIP 副本写错/写早**。

上表是 flags 修之前的常数路径（VIP 被折死成 `0x14014AAE4`，蹦床第 4 次进 `0x369063`，块数 **24240**）。`0x217` 对齐之后现象变了，见下两小节。不要 256 枚举，不要 overlay 堆常量，不要 unique-fold 普通 load，不要 `GetRFLAGSValue |= 0x202`。

探针（未提交）：lifter `[vip] pre` / `[tramp]`；`vmpdrtrace.c` 同址。

### 7.11.1 `0x217` 怎么改了旧路径

真机 `0x360B07` `[rbx] = 0x217` = CF|PF|AF|reserved1|IF（加法留下 `0x15`，再拼 bit1 和 IF）。VMP 会 `pushfq` / `pop [rbx]`，把这份 RFLAGS **当栈数据** 去做 `shr` / NAND，不是只给条件跳用。

修之前 dump 同槽是 **`0x15` / `0x17`**（缺 IF，有时缺 reserved1）：

| 原因 | 效果 |
|---|---|
| `InitRegisters` 写基类闲置 `FlagList`，`pushfq` 读 concolic `vecflag` | IF、bit1 入口就是 0 |
| `lift_cli` 无条件清 IF；`popfq` 从栈装 IF | 用户态 CPL>IOPL 不该改 IF |
| `FLAGS_END = FLAG_IOPL` 且 loop `< FLAGS_END` | 系统位拼不全（后来扩到 `FLAG_ID+1`） |

错 flags 是**常数**。进 `shr rdx, cl`（`0x1402E6408`）和后面 NAND 时 KnownBits 全常数，`select(ZF,-1,0)` 被收成 `-1` 或 `0`。NAND 只剩一路：**`0x14014AAE4`**（`3C2BA9` 加法结果；`~0xFFFFFFFEBFEB551B`）。`2C28EC` 写过真 VIP `0x14020557E` 到 `0x14FE48`，被这条常数链盖掉。`0x301D45` 第 2 次弹出 `14AAE4`，蹦床第 4 次具体跳到错的 `0x369063`。

**不是 SHR 当年算对了。** 是错的常数 flags 把符号路径折死了。

已做（通用 x86，不是样本常数）：入口 `setFlag` 写 `vecflag`（IF=1、reserved1=1）；用户态 `cli`/`popfq` 在 IOPL<CPL 时不改 IF；bit1 保持 1；`GetRFLAGSValue` 只按 `getFlag` 拼。dump 现：`0x360B07` `[rbx]=0x217`、`0x3D0FB9` `[rbx]=0x286` 与 DR 一致。禁止再 `|= 0x202` 去凑 `0x217`。

### 7.11.2 当前卡点：`shr rdx, cl` 的 ZF 折不掉

flags 槽对了之后，那次 `shr rdx, cl` 的 **RDX 或 CL 有一边不是常数**。IR：

`%76487 = icmp eq i64 %shr-lshr-…402E640B-, 0`

（名里的地址是指令后 RIP 的 32 位：`0x1402E640B` → 移位在 `0x1402E6408`。）

`0x403F5FE3` 一带把这个 ZF 扩成 `select(ZF, -1, 0)`。`getOrCreate` 把后续 and/not/add 拆进同一个 i1，VIP 变成：

`select i1 %76487, 0x14014AAE4, 0x14020557E`

DR 走 **false**（`20557E`，NAND 槽 `-1`）。Mergen 不能决定 ZF → `0x301D45`/`0x2E7043` 的 R9 是 select → 蹦床第 4 次 `r8` 是 `zext`/`sext`，解不出 `0x2D8CD0`。lift **13282** 块结束（不再 24240 / `0x32281c`），末尾是 unproven switch。

`tryFoldConcolicInt` 仍 **只许 Ret**。不要在 `createSelectFolder` / 普通 load 里 unique-fold。不要为了消 select 去写死 VIP。

### 7.11.3 `shr rdx, cl`：CL 已是常数，RDX = `(sym+1) & 0x40`

探针（`run_shr.out`，VIP≈`0x205807`）：

| 站点 | 事实 |
|---|---|
| `0x2E63E1` `mov rdx,[rbx]` | `buf[rbx]=and(realadd, 64)`，`buf[rbx+8]=0x6` |
| `0x2E6408` `shr rdx, cl` | **`rcx=0x20006`（CL=6，常数）**；**`rdx=and i64 %realadd-…, 64`（符号）** |
| `0x31EA2B` `and rbp, r11` | **`rbp=0x40`**；**`r11=%realadd-1077257398- = add (%realand-1077197814-, 1)`** |

同一 BB 里 CL 来自 `mov cl,[rbx+8]`（前面的 `adc cl,0x3f` 被盖掉）。移位量不是问题。

RDX 数据流：

```
… → and ?          @ ~0x34BBFx（IR 名 realand-1077197814）
  → add …, 1         @ ~0x35A4Bx（IR 名 realadd-1077257398，邻域 0x35A499）
  → and rbp, r11     @ 0x31EA2B   （rbp=0x40 → 取出 bit6）
  → 进 VSP
  → mov rdx,[rbx]    @ 0x2E63E1
  → shr rdx, cl      @ 0x2E6408   （>>6）
  → ZF = icmp eq (lshr, 0)        ← VIP select 的条件
```

因此 ZF 实际是在问：**`realadd` 的 bit6 是否为 0**。DR 走 VIP select 的 false 臂（`20557E`）⇒ 真机这次 ZF=0 ⇒ bit6 **置位**。Mergen 的 `realadd` / 内层 `realand` 仍是 SSA，bit6 未知 ⇒ select 消不掉。

同 BB 在 `and` 前有 `not r11`（`0x31EA21`）。探针进 `0x31EA2B` 时 **R11 仍是未取反的 `realadd`**，而 `buf[rbx+8]` 里已经有 `xor realadd, -1`。需要确认：dispatch 是否直接落在 `0x31EA2B`（跳过 `not`），还是 `not` 没写回 R11。先别假定要强行补 `not`。

### 7.11.4 日志：`realand` 的符号来自 AF≪4 的 DeMorgan 链

探针（`run_andop.out`，`[andop]/[notop]/[addop]`）：

`0x14034BBF3` `and rbp, r11`（IR 名 `realand-1077197814`，post=`0x4034BBF6`）：

| | 值 |
|---|---|
| L（`~[rbx]`，`[rbx]=0x815`） | **`0xfffffffffffff7ea` = `-2070`（常数）** |
| R（`~[rbx+8]`） | **`~(%not-PConsRegister-96463)`（符号）** |
| 结果 | `and i64 %realnot-…, -2070` 仍符号 |

`96463` 的 IR 定义链：

```
%68962 = icmp eq i32 %(L^R^(L-R))&16, 16     ; computeAuxFlag → AF
%createrflag2-95864 = shl (zext %68962), 4     ; AF 装进 RFLAGS bit4
%not_v96460 = xor %createrflag2-95864, -1
%not-PConsRegister-96461 = and %not_v, -3      ; ~bit1
%not-PConsRegister-96462 = and …, -129         ; ~bit7
%not-PConsRegister-96463 = and …, -513         ; ~bit9 (IF)
```

即 `96463 = ~(AF≪4 | 0x282)`（`0x282` = reserved1|SF|IF）。随后 `realand = ~96463 & ~0x815`，再 `+1`（`0x35A4B3`），再 `&0x40`（`0x31EA2B`）→ `shr` ZF。

**先前否掉「AF 链接到 select」不完整**：AF 确实不在 `0x2E6408` 的 RDX 上并行出现，但它是 **更早写进 VSP 的 `96463` 的源头**，经 NAND/`+1`/`&0x40` 才进 SHR。

代数上若只有 AF 未知：`(AF≪4 | 0x282) & ~0x815` 应恒为 **`0x282`**（`~0x815` 清掉 bit4）。KnownBits 没折出来（链深超过默认递归）。但折成 `0x282` 后 `(0x282+1)&0x40=0` → SHR 的 ZF=1 → VIP 仍走 `14AAE4`，和 DR 不一致。

### 7.11.5 DR 对照（`andop.regs`）：真机是 `~0x246`，不是 AF 链

同 VIP `r9≈0x12c97a` 进 `0x34BBF3`（`andop.regs` 第 2 次；`3D0FB9` v35 两边都是 `[rbx]=0x203,[+8]=0x815`）：

| | Mergen | DR |
|---|---|---|
| `[rbx]` | `0x815` | `0x815` |
| `[rbx+8]` | **`and(…,-513)` = `~(AF≪4\|0x282)`（符号）** | **`0xfffffffffffffdb9` = `~0x246`（常数）** |
| `and` 后（RBP∧R11） | 符号 `realand` | **`~0x815 & 0x246` = `0x242`** |
| `+1`（`0x35A4B3`） | 符号 | **`0x246`**（DR `35a499` v12 槽是 `0x242+0x4`；`31ea2b` v03 的 R11=`0x246`） |
| `&0x40` | 符号 | **`0x40`** → SHR ZF=0 → VIP `20557E` |

`0x246` = ZF|PF|reserved1|IF（bit6 是 **ZF**，不是数据 bit6）。Mergen 把该槽做成了 `AF|SF|reserved1|IF`（`0x282|AF≪4`）的 DeMorgan，**缺 ZF/PF、多了错误的 SF/AF**。

根因不在 `0x34BBF3` 的 AND 语义，而在更早写进 VSP 的 flags。

### 7.11.6 `pushfq @ 0x2D353E` 读的是前面 `and ecx, edi` 的 flags

`[pushfq]`：`0x1402D353E` 打出 `creatingrflag95867`，`CF=0 PF=0 AF=sym ZF=0 SF=1 IF=1`。

同一 BB（`0x2D34FE` 起）：

```
mov ecx, [rbx]
mov edi, [rbx+4]
sub rbx, 4
not ecx
sbb r11d, 0x1d7777c0   ; 只搅 r11，随后被 AND 盖掉 flags
not edi
and ecx, edi           ; 状态位以这次为准
pushfq
pop [rbx]
```

`and`/`or`/`xor` 清 CF/OF，按结果设 ZF/SF/PF；AF 未定义。真机槽 `0x246` = ZF|PF|reserved1|IF ⇒ **NAND 结果为 0**。Mergen 这次 AND 看成非 0（SF=1），AF 还留着 SBB 的符号值。对照见 7.11.7。仍禁止 unique-fold / 写死 VIP / `|=0x202` / `STACKP±8`。

### 7.11.7 NAND 操作数是 `0x5004f` 不是 `-1`：来自 `add eax, r11d` 回绕

VIP `r9=0x14012CA20`（`run_dump.out` + `nand.regs`）。相对 VSP：Mergen `rbx=0x14FE34` ≡ DR `0x3280BEF7BC`（相对 `STACKP`/`RSP` 都是 `-0x6C`）。

| 站点 | Mergen | DR |
|---|---|---|
| `3BC020` `r9=12CA4E` | `[rbx]=0x257`，`[+8]=0` | `[rbx]=0x257`，`[+8]=0x20200000000`（低 32 也是 0） |
| `37507A` `r9=12CA2D` | `[rbx]=0x203`，`[+8]=0x5004f`，`r11=0xf1ffea81` | `[rbx]=0x286`，`RAX=-1`，`r11=0xd348eac1` |
| `2D34FE` `r9=12CA20` | `[rbx]=0x5004f`，`[+8]=0`，`r11=0x5004f` | `[rbx]=-1`，`[+8]=0x20200000000`，`r11=-1` |

`3BC020` 之后才分叉。`0x2D34FE` 的 NAND：

```
mov ecx, [rbx]       ; M 0x5004f / D -1
mov edi, [rbx+4]     ; 两边 0
not; not; and ecx, edi
```

Mergen：`~0x5004f & ~0 = 0xfffaffb0`（`[andop] @ 0x2D3524`，非 0 → SF=1）。  
DR：`~(-1) & ~0 = 0` → `pushfq @ 0x2D353E` 得到 `FLG=0x246`。

`0x5004f` 是 **4 字节** 写进 VSP 的。`0x14FE34` 窗口（`[vspwr]`）时间线，VIP `12CA4E→12CA20`：

| insn | 指令 | 写 |
|---|---|---|
| `0x3D4517` | （8 字节） | `0x14FE34 = 0x257`（两边仍对齐） |
| `0x3A861C` | `mov dword [rbx], ebp` | `0x14FE34 = 0xf1faea31`（盖掉 `0x257`） |
| `0x3BD90B` | `mov dword [rbx+8], ebp` | `0x14FE34 = 0xe0515ce` |
| `0x38447D` | `add eax, r11d` | **`0xF1FFEA81 + 0x0E0515CE = 0x10005004F` → 32 位 `0x5004F`** |
| `0x384484` | `mov dword [rbx+8], eax` | `0x14FE38 = 0x5004f` |
| `0x384492` | `pop qword [rbx]` | `0x14FE30 = 0x203`（高 4 字节清掉） |
| `0x3DCE97` | `mov dword [rbx], r11d` | `0x14FE34 = 0x5004f`（NAND 读到的槽） |

真机 `37507A` 时 `RAX` 已是 `-1`，即同一条 `add eax, r11d` 的和应是全 1，不是 `0x5004F`。闭合见 7.11.8：设计上是 `x + ~x`，Mergen 的两个加数不是同一份 `x`。不要在 `add`/`NAND`/`pushfq` 上特判结果。

### 7.11.8 `0x5004f` 的加数：`[rsp+0x18]` 与 `[rsp+0xa8]` 不是同一份 `x`

对照：`build_msvc_dbg\run_dump.out`（13282 blocks，dump overlay）+ `vmptest\nand.regs`（`add_only=21436587`）+ `entry_7210.dmp`。禁止贴 DR 活堆指针、禁止 unique-fold / VIP overlay / `STACKP±8` / `GetRFLAGSValue |= 0x202`。

**真机靠 `add eax, r11d` 消掉堆 ASLR。** 令 `x` 为某次更早 NAND 的 32 位输出。DR 在 `0x38447D`：

```
EAX = 0xf18a153e = ~x
R11 = 0x0e75eac1 = x
EAX+R11d → 0xffffffff
```

`x ^ ~x = 0xffffffff`，与堆基址无关。dump 世界若两格是同一份 `x`，同样应得 `-1`。

#### 不是 EA、不是 dump 读错

`0x30D3FB` `mov ebp, [rsp+r8]`：两边 `r8=0x18`，相对 EA 对齐（Mergen `0x14FC78`，DR `rsp+0x18`）。格子里 dword：Mergen `0xf1ffeef7`，DR `0x0e75eeb7`，XOR `0xff8a0040`。

这份 dword 的写入链：

1. `0x3BB469` `mov dword [rsp+r8], ebp` → `0x14FC78 = 0xf1ffeef7`（native scratch，存本身没问题）。
2. 值来自 `0x34ED0E` `mov ecx, dword [r11]` / `0x34ED19` `mov [rbx], ecx`（VIP `12CC73`）。
3. `r11` 来自 `0x34ECFD` `mov r11, [rbx]`。VIP `12CCC3`/`0x37507A` 时两边 `[rbx]` 都还是 `0x3f2b205760414255`；到 `12CC73` DR 已换成堆指针 `0x21e0ecbd108`。
4. 覆盖发生在 `0x2E17D5` `mov rdi, [rsp+r11]`（`r11=0x30`）+ `0x2E17EE` `mov [rbx], rdi`。native `[rsp+0x30]` 由 `0x3E9AF2` `mov [rsp+rdi], r8`（`rdi=0x30`）写入。相对偏移两边对齐。
5. Mergen 写入/读出的是 overlay 堆对象 **`0x21cf141d148`**。`GetMemoryValue` 的 dword **就是 dump 字节**：qword `0x21cf1ffeef7`，低 32 `0xf1ffeef7`。dump 里没有 `0x0e75eeb7`。
6. dump 与这次 DR 的堆 ASLR：`0x21cf141d148 ^ 0x21e0ecbd108 = 0x2ff8a0040`，字段 `0x21cf1ffeef7 ^ 0x21e0e75eeb7` 同差。低 32 XOR 即先前的 `0xff8a0040`。**不要贴 DR 的 `0x21e0ecbd108`。**

更早两次 `34ED0E` 解引用 PE 镜像指针时两边对齐（例如 `0x906d9883`）。

`0x34ED0E` 读到的堆指针低 32 **不是** 后面 `add` 用的 `x`。`x` 来自更早的 `0x2FF112` NAND（见下）。`34ED` 这条链把 dump 堆低 32 写进 `[rsp+0x18]` 的未掩码形态 `0xf1ffeef7`，再经 `0x3500D8` NAND（`& 0xfffffb89`）变成 dump 世界的 `0xf1ffea81`，只更新了 `0x18`。

#### 分岔：`0x18` 对、`0xa8` 错

| 槽 | dump 世界应有的 `x` | DR | Mergen |
|---|---|---|---|
| `[rsp+0x18]` `0x14FC78` | `0xf1ffea81` | `0x0e75eac1` | `0xf1ffea81`（`0x363F85` 写入，对） |
| `[rsp+0xa8]` `0x14FD08` | 同一份 `x` | `0x0e75eac1` | **`0xf1faea31`**（`x XOR 0x500b0`） |

`0x3A8609`（`r8=0xa8`）两边相对 EA 都对。DR 两格都是 `0x0e75eac1`。随后 `0x3D966D` 对 VSP 上两份相同值做 NAND 得 `~x`，`0x38447D` 与 `[rsp+0x18]` 的 `x` 相加。

Mergen：`0x3A8609` 读到过期的 `0xf1faea31` → `0x3D966D` 对两份它做 NAND → `~0xf1faea31 = 0xe0515ce` → `0xe0515ce + 0xf1ffea81 = 0x5004f`。

**不是 NAND 之后少写 `0xa8`。** `0x31BC29` `mov qword [rsp+rdi], r8`（`rdi=0xa8`，VIP `12CCE6`）比 `0x37EBAA`（VIP `12CCE1`）先执行。DR 此时 R8 已是 `0x0e75eac1`，一存到底。Mergen 存的是当时的 R8=`0xf1faea31`。`0x363F85` 只更新 `0x18`。

#### `0xf1faea31` 出生在 `0x2FF112`

VIP `12D636`，`0x2FF112`：`not ecx; not edi; and ecx, edi`。`rax` 两边都是 `0x84b3`。Mergen 结果 `0xf1faea31`，DR `rcx=0x0e75eac1`。验算 NAND 本身成立：

```
Mergen: ~(0x0e04050e) & ~(0x000110c0) = 0xf1faea31
DR 槽:  ~(0xf100050e) & ~(0x008a1030) = 0x0e75eac1
```

操作数（VIP `12D63A`/`12D63F`）：

| 槽 | Mergen | DR | 写入 |
|---|---|---|---|
| 低 dword | `0x0e04050e` | `0xf100050e` | `0x2F587A` `and ecx, edi; mov [rbx+8], ecx` |
| 高 dword | `0x000110c0` | `0x008a1030` | `0x3AA40E` 同样 `and ecx, edi` |

`0x3CDBD3` `mov ebp, [rsp+r8]; mov [rbx], ebp` 曾把 `0xf141d0f0`（dump 对象 `0x21cf141d0f0` 低 32，与 `34ED` 的 `0x21cf141d148` 差 `0x58`）写入低槽，随即被 `0x2F587A` 覆盖，**不是这次 NAND 的操作数**。

VIP `12D65A` `0x3E9AF2`：VSP 已是 Mergen `0xff44c53e` vs DR `0xff41c58e`，XOR **`0x500b0`**，与 `0xf1faea31 ^ 0xf1ffea81` 同一份差。

VIP `12CD57` `0x3357C6`：DR `[rbx]=0x0e75eac1`，Mergen `buf[0x14FE10]=0xf1faea31`，再进 R8 / `0x31BC29`。

`0x2F587A` / `0x3AA40E` 的 `and` 本身按输入是对的；`0x500b0` 在它们之前已在 RAX 上。闭合见 7.11.9。不要特判 `0x5004f`/`-1`。

### 7.11.9 `0x500b0` 在 `2FF112` 之前：RAX `0xbb3ac1` vs `0xbe3a71`

对照仍是 `run_dump.out` + `nand.regs`。`0x2F587A` / `0x3AA40E` 不是语义 bug。

#### `2FF112` 的输入来自 `[rsp+0x28]` 里已经错的 RAX

VIP `12D668` `0x3A8609` `mov ebp, [rsp+r8]`（`r8=0x28`）：相对 EA 对齐（Mergen `0x14FC88`）。dword：

| | Mergen | DR |
|---|---|---|
| `[rsp+0x28]` | `0xbb3ac1`（`[stkld]`） | `0xbe3a71`（`loadEA`） |

`0xbb3ac1 ^ 0xbe3a71 = 0x500b0`，与 `0xf1faea31 ^ 0xf1ffea81` 同一份差。

随后：

| insn | 作用 | Mergen | DR |
|---|---|---|---|
| `0x3A861C` | 写进 VSP | `0xbb3ac1` | `0xbe3a71` |
| `0x309660` | `mov [rbx+8], ebp`（NOT） | `0xff44c53e = ~0xbb3ac1` | `0xff41c58e = ~0xbe3a71` |
| `0x3AA40E` | `and ecx, edi` 高 dword | `0x110c0` | `0x8a1030` |
| `0x2F587A` | `and ecx, edi` 低 dword | `0xe04050e` | `0xf100050e` |

`[rsp+0x28]` 不在 VSP 窗口 `[0x14FE30,0x14FE40)`，`3A8609` 读到 `0xbb3ac1` 之前没有 `[vspwr] 0x14FC88`。第一次打到该槽的写是更晚的 `0x3641D4 = 0xf1faea31`。值是当时 RAX 存进 native scratch。

#### VIP `12D74C` 的 `35A499` 不写这份 RAX

进 `0x35A499` 时 RAX **已经**分叉：Mergen `0xbb3ac1`，DR `0xbe3a71`。handler 是 `mov rcx, [rbx]; mov rbp, [rbx+8]; add rcx, rbp`。`[addop] @ 0x35A4B3`：`L=0 R=0x1402B2F36 res=0x1402B2F36`（handler 指针，DR `[rbx+8]` 同）。**不是** 7.11.5 的 `+1`，也不改 RAX。

#### VIP `12DCFF` 的 `34BBF3` 是另一次（7.11.5 那条 SSA）

`nand.regs` ~2232 / mergen `run_dump.out` ~8326。与 `12D74C` 不是同一次访问。

| | Mergen | DR |
|---|---|---|
| `[rbx]` / `[rbx+8]` | SSA `or(realnot, 1)` → `not-PConst-52985 = and(realadd, -2)` | 两边 **`0xfffffffffffffd79`** |
| NAND `0x34BBF3` | 仍是 SSA（`[andop]` 8331） | **`0x286`**（`~0xfd79` 的低 16 可见部分） |
| `0x3E9AF2` VIP `12DCFA` | `rdi=0x10`，SSA 写入 `[rsp+0x10]`（`0x14FC70`） | 存 **R8=`0x202`（flags）**；`[rbx]=0x286` |

这次 NAND 的 SSA **没有**在 `8331–9385` 折成 `0xbb3ac1`。`12DCFF` 与这份 `0x500b0` **尚未接上**。`[andop]` 白名单仍只有 `34BBF3/31EA2B/2D3524`，没有 `2F587A/3AA40E`。

#### RAX 变成 `0xbb3ac1` 的窗口：VIP `12D7A2 → 12D74C`

两边在 `0x30D3FB` VIP `12D7A2` 仍对齐：`RAX=0xa3a86`，`r8=0x48`，`[rsp+0x48]` dword **`0x332c00`**（DR `loadEA` = Mergen `[stkld]`）。

下一探针对齐点 `0x35A499` VIP `12D74C` 时 RAX 已是 `0xbb3ac1` vs `0xbe3a71`。中间 Mergen：

- `0x377027`：`mov ebp, [rsp+r8]; mov dword [rbx], ebp`，`[vspwr] 0x14FE3C size=4 val=0x880ec1`
- `0x880ec1 + 0x332c00 = 0xbb3ac1`

`0x332c00` 两边相同。闭合见 7.11.10：`377027` 拷贝 `0x880ec1`，`0x2D806B` `add eax, r11d` 把它和 `0x332c00` 加进 RAX。

### 7.11.10 VIP `12D7A2–12D74C`：`2D806B` 按输入是对的；错在更早的 `0x880ec1`

`[addop]` 只打 `35A4B3`/`38447D`，这条 add 原先不在日志里。`0x2D8072` 写回 `0x14FE40`，落在 `[vspwr]` 窗口 `[0x14FE30,0x14FE40)` 右开外面。

`0x2D8040`（VIP `12D799`）：

```
mov eax, [rbx]
mov r11d, [rbx+4]
sub rbx, 4
add eax, r11d          ; 0x2D806B
mov [rbx+8], eax
pushfq
pop [rbx]              ; 0x2D807D → flags 0x202（有 [vspwr]）
```

加之前 VSP：

| 槽 | Mergen | 来源 |
|---|---|---|
| `[rbx]` `0x14FE3C` | `0x880ec1` | `0x377027` `mov ebp, [rsp+r8]; mov [rbx], ebp` |
| `[rbx+4]` `0x14FE40` | `0x332c00` | `0x30D415` VIP `12D7A2`（两边相同） |

`0x880ec1 + 0x332c00 = 0xbb3ac1` → EAX = `12D74C` 进 `35A499` 时的 RAX。

DR 无 `2D806B`/`377027`，但夹在中间：

- `376FF7` VIP `12D79D`：`RAX` 仍 `0xa3a86`，`r8=0x6c`，`[rbx]` 低 32 仍是 `0x332c00`（`377013` `mov ebp,[rsp+r8]` 尚未执行）
- `35A499` VIP `12D74C`：DR `RAX=0xbe3a71`

`0xbe3a71 - 0x332c00 = 0x8b0e71`。真机同一条 add 是 **`0x8b0e71 + 0x332c00`**。`377027` 只是把 native `[rsp+r8]`（DR `r8=0x6c`）拷到 VSP。

`0x880ec1` 出生在 VIP `12E2FF`/`12E2FB`，`0x3D44FB` `add eax, r11d` + `0x3D4502` `mov [rbx+8], eax`：

| | Mergen | DR（`3D0FB9` VIP `12E2FB`） |
|---|---|---|
| `r11` / 一个加数 | `0x800800`（`0x31C1EE` 写入，两边同） | `0x800800` |
| 另一个加数 | `0x0806c1`（`0x2F2499`） | **`0x0b0671`** |
| 和 / RAX / `[rbx+8]` | `0x880ec1` | **`0x8b0e71`** |

`0x806c1 ^ 0xb0671 = 0x300b0` = `0x880ec1 ^ 0x8b0e71`。再加同一个 `0x332c00` 后 `0xbb3ac1 ^ 0xbe3a71 = 0x500b0`（进位改了 XOR 图案，算术差仍是 `0x300b0`）。

`0x2F2484`：`mov ebp, [rsp+r8]`；`0x2F2499`：`mov [rbx], ebp`。已用新探针验证（`nand_806.regs` + 新 `run_dump.out`）：

- `2F2468` 时 DR `r8=0x6c` 是 **load 之前** 的混淆值。真正 `2F2484` 时 **两边 `r8=0x28`**，EA 对齐（Mergen `0x14FC88`）。
- `[stkld]` / DR `loadEA` dword：Mergen **`0x806c1`**，DR **`0xb0671`**。索引对，格子内容错。
- `[addop] 3D44FB` VIP `12E2FF`：Mergen `0x806c1+0x800800=0x880ec1`；DR EAX 进指令已是 `0xb0671`，出 `0x8b0e71`。
- `[addop] 2D806B` VIP `12D799`：Mergen `0x880ec1+0x332c00=0xbb3ac1`；DR EAX=`0x8b0e71` R11=`0x332c00`。

`0x14FC88` 的 Mergen 写入：`0x3F48CD` 在 VIP `12E4D6` 之后立刻把当时的 `0x806c1` 存进 `[rsp+0x28]`。DR 同槽应是 `0xb0671`（来自 `360B07` 的 `[rbx]`）。

`0x14FDD8`（`360B07` 的 `[rbx]`）由 **`0x3FCC8F`** 写入 `0x806c1`（VIP `1A3322` 与 `1A3108` 各一次）。DR 同槽是 `0xb0671`。

**未闭合（已闭合，见 7.11.11）**：`0x3FCC8F` 只是把已经错的 VM dword 存进 `0x14FDD8`。根因是 `lift_cpuid` 写死 leaf-1 EAX=`0x806C1`，本机 DR 为 `0xB0671`，差即 `0x300B0`。

### 7.11.11 `0x806c1` 出生点：`CPUID`（seq 19642 `0x2CB5ED`）

insn 流（`insn_lift.csv` / `insn_dr.csv`）从 `0x3FCC8F` 往回：

| seq | RVA | 指令 | 作用 |
|---|---|---|---|
| 19642 | `0x2CB5ED` | `cpuid`（EAX=1） | lift EAX=`0x806c1`，DR EAX=`0xb0671` |
| 19645 | `0x3884FB` | `mov [rbp+0xc], eax` | 把 CPUID.EAX 推进 VSP `0x14FE2C` |
| 28721 | `0x3C449D` | `mov [rbp], r8` | 拷到 `0x14FE38`（r8 已是该 dword） |
| 30789 | `0x2EA69E` | `mov rbx, [rbp]` | 从 `0x14FE38` 弹出 |
| 30817 | `0x3B87F5` | `mov [rsp+rcx], rbx` | `rcx=0x10` → `0x14FC70` |
| 35543 | `0x2DF516` | `mov [rbp], rcx` | 写入 `0x14FE08` |
| 36864 | `0x339EC4` | `mov rdi, [rbx]` | 弹出 `0x14FE08` |
| 42637 | `0x3FCC7A` | `mov rdi, [rsp+rcx]` | `rcx=0x88` → `0x14FCE8` |
| 42642 | `0x3FCC8F` | `mov [rbx], rdi` | 写入 `0x14FDD8` |

`0xb0671 - 0x806c1 = 0x300b0`。`lift_cpuid` 原先对所有 leaf 返回固定 Intel 模板（EAX=`0x000806C1`，EBX=`0x00800800`）；ECX/EDX 碰巧与本机 leaf 1 相同。VMP 把 CPUID 四寄存器当 VM 数据用，再与 `entry_7210.dmp`（真机 CPUID 世界）混合，中间常数无法对消。已改为常量 leaf 时走主机 `__cpuidex`。

重 lift 后 `[vspwr]`：`3FCC8F`/`3F48CD` 写 `0xb0671`；`3D44FB` `0xb0671+0x800800=0x8b0e71`；`2D806B` `0x8b0e71+0x332c00=0xbe3a71`。日志里 `0x806c1`/`0x880ec1`/`0xbb3ac1`/`0x5004f`/`0xf1faea31` 为 0。

### 7.11.12 CPUID 修复后 insn 流对照（`insn_lift.csv` / `insn_dr.csv`）

产物：lift **178945** 行（与 `instructions_lifted` 同），DR **194330** 行。按 seq 对齐。这是诊断对照，不是用 trace 抬 IR。

**已对齐、不再是分叉：**

| seq | RVA | 备注 |
|---|---|---|
| 1 | `0x7210` | 入口 |
| 19643 | `0x2CB5EF` | `cpuid` 之后 EAX/EBX/ECX/EDX 两边都是 `0xb0671` / `0x20800800` / `0x7ffafbbf` / `0xbfebfbff` |
| 42642 | `0x3FCC8F` | `rdi=0xb0671`（旧流这里是 `0x806c1` vs `0xb0671`） |
| 1–173740 | 同 RVA | 控制流一致 |

忽略（环境，不是语义 bug）：映像基 `0x140…` vs `0x7ff7182a…`；`STACKP` vs DR 真栈；dump 堆 vs 本趟 DR 堆（含 `rdi=0` vs `0x7ff5d82a0000`）；lift 上大量 SSA `-`。禁止贴活堆指针、禁止 overlay。

**控制流分叉（当前卡点）：seq 173741**

```
173739  0x335d4c  dec rax          lift RAX=0xa0   DR RAX=0x1
173740  0x335d4f  jne 0x2ca58a     lift 已 dec 成 0x9f，跳转成立
173741  lift → 0x2ca58a            DR 落空 → 0x335d55 pop rsi
```

`0x38d866` `jmp 0x335d4c` 进这条循环。lift 计数器 `0xa0`，DR `0x1`，所以多转一圈。lift 在 `0x14000723e` 先 `ret`；DR 后面还跑到 seq 194330（`0x6ca07`）。

空 `rdtsc` 修掉之后，对**某一趟** DR 仍会在同一对 `dec/jne` 分叉，圈数改成「各自 TSC」而不是残值 `0xa4`（§7.11.14）。两趟 DR 自己也会在这里分叉。

**分叉之前、过滤环境后仍在的 GP 差（未追）：**

| seq | RVA | 差 |
|---|---|---|
| 287 | `0x36e7e7` | RCX `0xb0000` vs `0xb6b87` |
| 336 | `0x35c8d6` | RCX `0x40164097` vs `0x18404097` |
| 527 | `0x2ba795` | RCX `0x1` vs `0x0` |
| 659+ | `0x350111` 一带 | RDX `0x206` vs `0x202`（flags；**不要** `GetRFLAGSValue \|= 0x202`） |

计数器 `0xa0` vs `0x1` 的**残值根因**已闭合，见 7.11.13。修好后圈数仍随 TSC 变，见 7.11.14。早期 RCX/flags 差是否另有后果未追。

### 7.11.13 循环计数 `0xa4` vs `0x5`：空的 `lift_rdtsc`

从 `seq 173739` `dec rax` 往回（insn 流，不算站点白名单）：

| seq | RVA | 指令 | 作用 |
|---|---|---|---|
| 163302 | `0x32D2F9` | **`rdtsc`** | lift 不写寄存器，留下 `EAX=0x70` `EDX=0x2b7af`；DR 写出真 TSC（该趟 `EAX=0xc2236c6e` `EDX=0x1f14`，**不要写进代码**） |
| 163308 | `0x32D308` | `mov [r10+4], eax` | TSC 低 32 推进 VSP |
| 163358 | `0x32F20E` | `add r11d, eax` | `0x2b7af+0x70=0x2b81f` vs `0x1f14+TSC_lo` |
| 163988 | `0x3F4D6A` | `add r11d, eax` | 再加一份两边相同的 `0x21ad612a` → `0x21b01949` vs `0xe3d0ecac` |
| 165243 | `0x3F8195` | `div ecx`（`ecx=0x8d5` 同） | 商/余 `0x3d074,0x8c5` vs `0x19cb57,0x549` |
| 165837 | `0x2BF83B` | `mul edx`（`edx=0xc` 同） | **`0x693c` vs `0x3f6c`**（差 `0x29d0`） |
| 167306 | `0x2E4DB8` | `add r11, rax` | 映像基 `0x3fec65` 两边同 + 偏移 → RVA `0x4055a1` vs `0x402bd1` |
| 169129 | `0x3FD47A` | `mov ecx, [rax]` | 取错立即数 `0x70d10864` vs `0x70d108c5` |
| 169514 | `0x3AB877` | NAND | `0xffffffdb` vs `0xfffffffa` |
| 170346 | `0x391ADD` | 再 NAND | **`0xa4` vs `0x5`** |
| 173626 | `0x2C20A9` | `mov rax, [r10+8]` | 循环次数进 RAX |
| 173739 | `0x335D4C` | `dec rax; jne` | lift 多转 ~159 圈 |

沿途 `mul`/`div`/`add`/`NAND` 按输入都对。`lift_rdtsc` 原先是空函数，EAX/EDX 仍是 rdtsc 前的 VM 残值，不是一次 TSC 的高低 32 位。VMP 把 TSC 当 VM dword 用（与 CPUID 同类）。DR 每次 `add_only` 结果相同，说明算法应对**任意一次完整 TSC** 成立，禁止把某趟 DR 的 `0xc2236c6e` 写死进 lifter。修复：`rdtsc` 必须从**同一个** 64 位计数写出 `EDX:EAX`。

### 7.11.14 真 `RDTSC` 之后：客户函数跑完；`add` 在 IR 里；DR 圈数本就不固定

`Semantics_Misc.ipp`：`lift_rdtsc` 在 Win32 上 `__rdtsc()` 一次，低 32 → EAX、高 32 → EDX。`vmpdrtrace` **不**拦 `rdtsc`，`-insn` 只是指令前 INTEGER|CONTROL 快照。

重 lift（`MERGEN_INSN_STREAM_FILE=insn_lift.csv`，dump overlay）：**18129 / 176805**，0 error，末条客户 `ret 0x723e`。进 `0x32D2F9` 时两边仍是残值 `EAX=0x70` `EDX=0x2b7af`；出来后 lift 写成一对真 TSC（该趟 `EDX:EAX=0x2680_92e1eec6`），不再留残值。

**「每次 DR 都是同一条 trace」不成立（寄存器 / 圈数），`add_only` 结果成立。** 连跑两趟 `-insn`（`vmptest\insn_dr_a.csv` / `insn_dr_b.csv`）：

| | A | B |
|---|---|---|
| `add_only(...)` | `21436587` | `21436587` |
| 条数 | 274530 | 217690 |
| `rdtsc` 后 seq 163303 `0x32d2fb` EAX:EDX | `0x270b_167b3394` | `0x2732_cff56b20` |
| 前 197100 条 RVA | 相同 | 相同 |
| seq 197101 `dec rax; jne` | RAX=`0xb1a` → `0x2ca58a` | RAX=`0` → `0x335d55` |

`vmpdrtrace` 没有把 TSC 钉死。倒计时之前控制流几乎不依赖 TSC，只看 PC 会觉得两趟一样；从 `0x335d4c`/`0x335d4f` 起圈数不同，连 RVA 都错位。早期 GP 差（堆 ASLR，seq 189 的 RDX 等）也每趟不同，与语义无关。

对照 **lift vs DR**（入口都是 `0x7210`，都经过 `0x723e`）：

| | 条数 | 末条 | `0x723e` |
|---|---|---|---|
| lift | 176805 | `0x723e`（函数级结束） | seq 176805，RAX=`-` |
| DR old `insn_dr.csv` | 194330 | `0x6ca07` | seq 175765，RAX=`0x21436587` |
| DR a / b | 274530 / 217690 | `0x6ca07` | seq 255965 / 199125，RAX=`0x21436587` |

RVA 前缀：vs 旧 DR **173740** 条后 lift 还在转圈（RAX=`0x34`）；vs a/b **174780** 条后 lift 已落空（RAX=`0`）。都是 TSC 倒计时，不是 `jne` 解错。DR 在客户 `ret` 之后继续记 CRT/退出到 `0x6ca07`，不应要求 lift 对齐那截。

**有 add。** 优化后 `output.ll`：

```llvm
%bvalue_indexvalue_set = add i64 %RDX, %RCX
%0 = and i64 %bvalue_indexvalue_set, 4294967295
ret i64 %0
```

insn 流有 `0x7231`（真机 `lea eax,[rbx+rdi]`）再 `0x723e`。lift 从函数入口抬，RCX/RDX 是参数，不会出现 `main` 里的 `0x12345678+0x0F0F0F0F=0x21436587`。要那个十进制数需再代入参数。

禁止：把 DR 的 TSC 写进 `lift_rdtsc`；unique-fold；VIP overlay；`STACKP±8`；`GetRFLAGSValue |= 0x202`；贴活堆指针。

未追：§7.11.12 分叉前的早期 RCX/flags 差（seq 287/336/527/659+）。

## 7.12 mix（`0x140007450`）：PC 对齐到 `push r11; ret`，VIP 从 context 槽没取回

样本在 `D:\sogen\dr\vmptest\`（不是 `sample/add`）：`test.cpp` 的 `mix`，入口 `0x140007450`，映像 `test_fixed4.exe`，入口 dump `entry_7450.dmp`（16:45–16:46，`dumpmem-exit`，exit=0）。同文件还有 `compute_sum` `0x1400072d0`、`classify` `0x140007220`。lift **不要**从 PE AddressOfEntryPoint 起，停在客户函数。

insn 流：DR `D:\sogen\dr\vmptest\mix_dr_insn.csv`（444770 `I-`行）；lift `build_msvc_dbg\mix_lift_insn.csv`（221160，FileReader/PC-widen 回退后重采）。格式同 §7.8。

**不要再做的：** FileReader 拒 `va<imageBase`、lift PC `0x40xxxxxx→0x140` 拓宽（overlay 会打到所有 handler fetch，add 从能出 IR 变成 Unresolved ROP）；`STACKP±8` / 把 `STACKP_VALUE` 低 4 位改成 8；unique-fold；VIP overlay；`GetRFLAGSValue |= 0x202`；贴活堆指针；把 DR TSC 写进 lifter。`and rsp,-16` 两边相对入口差 8 **已否证为本次停住的根因**（§7.12.5）。

### 7.12.1 表面现象

| | 条数 | 末 PC | 下一跳 |
|---|---|---|---|
| lift | 221160 | RVA `0x35a716` `ret`（`disp=-584` `rop=0`） | 无（Unresolved ROP） |
| DR | 444770 | 继续 | seq 221161 RVA `0x34e2f2` |

前 **221160** 条 RVA 与 DR 前缀相同。不是 PC 走岔。add 回退后仍能出 `add i64 %RDX,%RCX` + 客户 `ret 0x723e`。

末段（insn 流是**指令前**快照）：

| seq | RVA | 指令 | DR r11 | lift r11 |
|---|---|---|---|---|
| 221157 | `0x3ba47b` | `add r11, rdx` | `0x7ff720883c7c`（RVA `0x423c7c`） | `0x40423c7c`（同 RVA） |
| 221158 | `0x3ba47e` | `jmp 0x35a714` | `0x7ff7207ae2f2`（RVA `0x34e2f2`） | `-` |
| 221159 | `0x35a714` | `push r11` | 同上 | `-` |
| 221160 | `0x35a716` | `ret` | 同上 | `-` |
| 221161 | `0x34e2f2` | （DR 继续） | | |

`add r11, rdx` 的 rdx：DR `0xfffffffffff2a676`（前面 `ror edx,3` / `movsxd rdx,edx`）；lift `-`。r11 从此符号，ret 解不出 `0x34e2f2`。

### 7.12.2 不是 R9−RSP「8 字节偏了」

`0x41f361` `mov r9, [rbp]`（文件==dump：`4c8b4c2500`）。seq 3429 指令前 r9 仍是 `0xefc9a`；seq 3430 才看见写入。相对**入口栈**两边都是 `-0x50`（DR `0x31448ff8d8` vs `0x31448ff928`；lift `0x14fe50` vs `STACKP 0x14fea0`）。`r9-当前rsp` 的 `0x1f8` vs `0x1f0` 没有意义：R9 是 `[rbp]` 取出的指针，不是 RSP 的函数。`cmp_mix_r9rsp.py` 的 34801 次 skew 是同一度量，忽略。

`bsf esi, ebp` 在 seq 5350 的 RSI `3` vs `5` 也是垃圾，随后 `mov esi, [r11]` 两边重新对齐。

### 7.12.3 末段只是后果：RSI 还在，RCX 已经空

到 seq 221113，**RSI 仍是 VIP**（DR `0x7ff720573f4e` = dump_ib+`0x113f4e`；lift `0x140113f4e`）。然后垃圾毁掉 RSI，`mov rsi, rcx` 用已经符号的 RCX 写回去，`mov edx, [rsi]` / `add r11, rdx` / `push r11; ret` 全断。

| seq | RVA | 指令 | 作用 |
|---|---|---|---|
| 221113 | `0x35dfaf` | `mov rcx, [r9]` | DR：RCX=VIP；lift：`[r9]` 不是常数 |
| 221114–221116 | `0x35dfb2`… | `or esi, edi` / `sal sil, 2` / `movsx esi, r13w` | 两边都毁掉 RSI（垃圾） |
| 221119 | `0x35dfc8` | `mov rsi, rcx` | DR 写回 VIP；lift 写入符号 RCX |
| 221157 | `0x3ba47b` | `add r11, rdx` | 见 7.12.1 |

`221071` `mov rdx, [rsp+r8]`（`r8=rbp=0x68` 两边相同）DR 读到 VIP、lift 仍 `-`，**不是因为 `[rsp+0x68]` 相对入口差 8**。上一拍 `219865` `mov [rsp+rbp], rdx` 已经用同一相对槽：DR 写 VIP，lift 写 `-`。`rol edx, cl` 只是在 RCX 已符号时把 rdx 弄成 `-`，设计上该被这次 load 盖掉。

### 7.12.5 VIP 槽在 218543 被 R10 写坏（RCX 当时还是 VIP）

VIP = PE `0x140113f4e` / dump `0x7ff720573f4e`。`~VIP` = `0xfffffffebfeec0b1`。

seq **218197** `mov [r9+8], rcx`：两边都把 `0x140113f4e` 写进 **入口相对 `-0x30`**（lift `0x14fe70` / DR `0x31448ff8f8`）。这是 VIP 槽。lift 最后一次 RCX=VIP 在 **218536** `not rcx`（两边变成 `~VIP`）。

RCX 仍是 VIP 时，RDX 先坏：

| seq | RVA | 指令 | DR | lift |
|---|---|---|---|---|
| 217710 | `0x3c1efd` | `mov [r9+8], rcx` | 写入 `0`（同一 `-0x30` 槽） | 写入 `-` |
| 217806 | `0x30d9e1` | `mov rdx, [r9]` | rdx=`0` | `-` |
| 217824 | `0x30da2a` | `mov [rsp+rbp], rdx`（`rbp=0x88`） | 写 `0` | 写 `-` |
| 218308 | `0x344247` | `mov rdx, [rsp+r8]`（`r8=0x88`） | rdx=`0` | `-` |
| 218313 | `0x391208` | `mov [r9], rdx`（入口相对 `-0x38`） | 写 `0` | 写 `-` |

两边 `rsp+0x88` / `r9±8` 的**相对槽一致**。不是 STACKP 低 4 位。

然后 R10 没能从 RCX 把 VIP 救回，并把符号值写进 VIP 槽：

| seq | RVA | 指令 | DR | lift |
|---|---|---|---|---|
| 218524 | `0x40a986` | `mov r10, [r9]` | r10=`-1` | `-` |
| 218532 | `0x40a9a3` | `not r10` | `0` | `-` |
| 218536 | `0x40a9ae` | `not rcx` | `~VIP` | `~VIP`（RCX 仍常数） |
| 218539 | `0x40a9b7` | **`or r10, rcx`** | `0 \| ~VIP = ~VIP` | `- \| ~VIP = -` |
| 218543 | `0x40a9c4` | **`mov [r9+8], r10`** | 把 `~VIP` 写回 `-0x30` 槽 | 把 `-` 写进去 |

之后全是这条坏槽的传播：`218683` `mov rbp, [r10]`、`218685` `mov [r9], rbp`、`218711`/`218713` 再 load、`219755`/`219835`/`219865` 再存 `[rsp+rbp]`，直到 7.12.3。

**未追（已接到 7.12.6）：** `217710` 时 RCX 已是 `0` vs `-`。

### 7.12.6 `217710`：`add rcx, rdi` 的 RDI 来自未对齐 `[r9]` 上的 `pushfq`

`217709` `add rcx, rdi`：两边 RCX 仍是 `-1`。`217708` `mov rdi, [r9+8]` 之后 DR RDI=`1`、lift `-`。`-1+1=0` vs `-1+符号`。`217710` 把这结果写进 `-0x30` 槽。

`1` 从哪来：`217178` `mov [r9+8], rdx`（DR rdx=`1`，lift `-`）。`217177` `shr rdx, cl`：DR `4 >> 2 = 1`（`cl` 来自 `rcx=…02`）。`217172` **`mov rdx, [r9]`**，r9 **未对齐**（两边相对入口都是 `-0x32`：`0x14fe6e` / `0x31448ff8f6`）：DR rdx=`4`，lift 仍 `-`。

更早一次未对齐 load **成功**：`217016` `mov rdx, [r9]` r9=`0x14fe5e`（`-0x42`）两边都是 `0x282`。下一次失败：

| seq | RVA | 指令 | r9（lift） | DR rdx | lift rdx |
|---|---|---|---|---|---|
| 217082 | `0x396b77` | `pushfq` | `0x14fe66` | `0x282` | `0x282` |
| 217085 | `0x396b80` | `pop qword ptr [r9]` | `0x14fe66`（未对齐 +6） | | |
| 217112 | `0x410840` | `mov rdx, [r9]` | 同 | **`0x202`** | **`-`** |

`0x202` 是 FLAGS（含保留位 1）。lift 的 `pushfq` 写到未对齐 `[r9]` 的不是可折常数，随后 qword load 变 `-`。`217172` 再 load `4` 也盖不回去。禁止 `GetRFLAGSValue \|= 0x202`；这里是 **整段 FLAGS 符号**，不是只差 bit1。

`r9` 走 `…e6 / …ee / …f6`（+2/+6），不是 8 字节格。`sub r9, 6` 在 `217176`，发生在 `217172` 之后。

### 7.12.7 FLAGS 分字节写 tracker：add 回归（已撤回 overlay）

`build_msvc_dbg` 18:57 构建含：`GetRFLAGSByte`、`lift_pushfq` 在 `SetMemoryValue` 之后对常数字节 `addValueReference`、`trackedBufferConstant` 对非 `ConstantInt` 做 `extractBytes` 折常数。

| 配置 | add `0x140007210` + `entry_7210.dmp` |
|---|---|
| 完整改动 | ~8s；`output.ll` = `ret i64 1076726992`；`[ret] 0x40379500` `disp=-584` `rop=0`。无客户 `0x14000723e`。 |
| 去掉 extract-fold，保留 pushfq overlay | 同样塌成 `ret i64 1076726992` / `disp=-584`。 |
| 再去掉 pushfq overlay（只留未接线的 `GetRFLAGSByte`） | 恢复：`[ret] 0x14000723e` `disp=0` `rop=1`；IR `add i64 %RDX, %RCX` 再 `and` 低 32 位。 |

原因：即使 8 字节 FLAGS 整体仍是符号，`addValueReference` 会把**已经是常数的 FLAG 字节**写进 byte buffer。后续小于 8 的 load / 未对齐 load 会把「半截 FLAGS」折成错常数，jcc 走错 handler。这和 `|= 0x202` 同类：用局部已知位冒充完整 EFLAGS。`usedFoldedExtract && combined.isZero()` 挡不住非零错常数。

`GetRFLAGSByte` 仍在 `OperandUtils.ipp`，**没有**接到 `pushfq`。mix 的 217112 路径因此也还没修。不要把 overlay 接回去，除非 retrieve 在「有任一符号字节」时拒绝整段折常数（包括子宽度 load）。

### 7.12.8 倒追 mix `0x410840` 的 `-`：源头是 `0x416691` 读未对齐 `[r9+8]`

**倒着追，链已闭合到单条指令。** §7.12.6 只说 `217112` 的 `rdx` 是 `-`，没说 `-` 从哪来。往后（DR→lift）查不动，往前（lift→DR）两步就到根：

`MERGEN_DIAG_RFLAGS`（新增，只听 `pushfq` + 那几个槽）打出来的东西：

```
[pushfq] rva=0x396B77 symbolic=[PF= %pf5197336 = icmp eq i64 0, %pf4197335,
                               ZF= %zeroflag197330 = icmp eq i64 %realand-1078027935-, 0]
        rflags_ir= %creatingrflag197343 = or i64 %creatingrflag197342, 512
```

`%realand-1078027935-` 里那个十进制数 = `0x41669F`，是**紧邻 `pushfq` 的那条指令的 VA**（`createAndFolder` 拿 `current_address` 拼名字），不是操作数。顺着它反汇编 `0x416687..0x4166a3`：

```
0x416687  mov r8, [r9]          ; r9 = 0x14fe66
0x41668a  or  r10b, 0x7d
0x41668e  or  r10b, sil         ; r10 -> 0x223ff
0x416691  mov r10, [r9+8]       ; ★ 读 0x14fe6e：lift '-'/ DR 0xa02
0x416695  not r8
0x416698  cmc
0x416699  not r10
0x41669c  and r8, r10
0x41669f  mov [r9+8], r8         ; 写回 0x14fe6e（写流 seq 15772 value '-'）
0x4166a3  jmp 0x396b77           ; → pushfq → ZF/PF 符号化
```

**算术自洽**：`0x223ff & 0xa02 = 0x202` —— 正是 DR 在 `217112` 读到的值。`r10` 之所以该是 `0xa02`，全靠 `[r9+8]` 折出来。

`mov r10, [r9+8]` 两侧输入完全相同（`r9` 都是 `0x14fe66`、前一条都是 `0x223ff`），**只有输出不同**：`0xa02` vs `-`。所以分歧点就是这一条 load，而它读的是**未对齐**（`0x14fe6e`，+6）的 8 字节，和它兄弟 `0x416687` 读的 `0x14fe66`（+6）一样未对齐。`r8` 的 `-` 是 `0x41669c` 的 `and` 传染的下游，不是独立故障。

**注意**：`r10` 的 `-` 在 `0x416691` 就出现，`r8` 的 `-` 到 `0x41669c` 才出现——「谁先变符号」能区分根因与传染，别把 `r8` 当根。

### 7.12.9 根因：qword 槽的**部分字节**从未被写过，`mov [r9],reg` 只写 8 字节对齐槽

再往下一层，根因是**结构性的，不是 flag、也不是 unaligned fold**：

`0x416691` 读 `0x14fe6e..0x14fe75`（8 字节，+6 未对齐）。写流里这 8 字节的 **1100 次**重叠写，**全部**落在两个 8 字节对齐槽 `0x14fe68` / `0x14fe70` 上——**没有任何一条写 `0x14fe6e` 本身**。而这两个槽的**最后一次写都是符号**：

| 槽 | 最后一次写 | 指令 | 值 |
|---|---|---|---|
| `0x14fe68` | seq 16004 | `0x3932b5  mov qword ptr [r9], rdx` | `-` |
| `0x14fe70` | seq 16000 | `0x367eaa  mov qword ptr [r9], rdx` | `-` |

**但 `rdx` 当时是具体常数 `0x0`。** 寄存器流（`MERGEN_REG_STREAM_FILE`，记的是指令**尾**地址、重基形式）给出决定性证据：

```
=== 0x14fe68 <- rdx  (RDX written at reg-seq 166136) ===
      seq 166133  0x402e7061   const 0x9d
      seq 166134  0x402e7069   const 0x0
    last CONSTANT rdx: seq 166134 at 0x402e7069 value 0x0
```

即：store 之前 2 次 `rdx` 写都是**已知常数**，store 却把整个 8 字节槽记成符号。insn 流同窗口（seq 192589–192593）也一致：

```
192589  0x2e7069  rdx=0x9d   r9=0x14fe58
192590  0x2e706d  rdx=0x0    r9=0x14fe58
192591  0x3932ad  rdx=0x0    r9=0x14fe58     ; sub r9,8
192592  0x3932b4  rdx=0x0    r9=0x14fe50
192593  0x3932b5  rdx=0x0    r9=0x14fe50     <== mov qword ptr [r9],rdx
```

所以 **`rdx` 不是根因**；`0x14fe6e` 这 8 字节该由谁写成 `0xa02`（`02 0a 00 00 00 00 00 00`）才是。`0xa02` 的高 6 字节是 0，说明真机上这 8 字节**大部分是零**，只有 byte6=`0x02`、byte7=`0x0a` 非零——而这两个字节正落在 `0x14fe68` 槽的**高 2 字节**。也就是说：真机这 8 字节是**两个槽拼接**的结果（`0x14fe68` 高 2 字节 + `0x14fe70` 低 6 字节），lifter 两个槽都记成符号，于是拼接不出来。

**这解释了为什么 §7.12.7 的 overlay 方向是错的**：不是「8 字节 FLAGS 整体符号」的问题，而是 **VM 把一个逻辑 qword 拆在两个 8 字节槽里、且只更新其中一部分**。`GetRFLAGSByte` 那种「把已知字节折进去」正是这个形状，但 §7.12.7 已经证明直接接 `pushfq` 会让 jcc 走错 handler。

**修复方向（三选一，按风险排序）**：

1. **对齐写合并**（正解，最小面）：`mov qword ptr [r9], rdx` 在 r9 变化时只覆盖槽内 8 字节是对的；问题在**读**侧。`retrieveCombinedValueImpl` 的 `trackedBufferConstant` 要求 8 字节全 `ConstantInt`。可加一步：若 `0x14fe6e` 未被直接写过，则按 byte 分别从 `0x14fe68`(+6,+7) 和 `0x14fe70`(+0..+5) 取——**仅当每字节都是 `ConstantInt` 才折**。真机 `0xa02` 恰好满足。但要防 §7.12.7 那类「用局部已知字节冒充完整值」：必须逐字节判 `ConstantInt`，不能只判「非零/有 extract」。

2. **让 store 保住具体性**：既然 `rdx` 是 `ConstantInt 0` 而 store 记成 `-`，先查 `insertMemoryOp` → `addValueReference(inst->getValueOperand(), …)` 这一路为什么没拿到 `ConstantInt`（`getValueOperand` 在 `O2` 前应是常数）。这是**最窄**的怀疑点，若成立则一改全链通。

3. **别指望 fold**：`0x410840` 的 `rdx` 即使折不出 `0x202`，也应能靠 `pushfq` 写进 `[0x14fe6e]` 的**已知字节**反推。这条最复杂，收益最低。

**下一步先做 (2)**：它能一句话验证「store 是否真的丢了 `ConstantInt`」。加一个只听 `r9∈{0x14fe68,0x14fe70}` 的 store 探针，打 `getValueOperand()` 的 `isa<ConstantInt>` 与 IR，即可判定走 (1) 还是 (2)。

### 7.12.10 决定性结果：store 没丢常数，是**两个槽的值本来就都不是 `0xa02`**

`MERGEN_DIAG_SLOTSTORE`（只听 `0x14fe68` / `0x14fe70`）打出来：

```
[slotstore] rva=0x3932b5 slot=0x14fe68 isConst=0 ir=  %134920 = zext i32 %134186 to i64
[slotstore] rva=0x367eaa slot=0x14fe70 isConst=0 ir=i64 %RSI
```

所以 (2) 被否证：store 收到的确实是符号，但**原因不是「丢了已知常数」**。`0x14fe68` 那个 `zext i32` 里 `%134186` 是**被 zext 之前的 32 位值**，它本身可能折叠，但 zext 后不再是 `ConstantInt`，`trackedBufferConstant` 的逐字节 `dyn_cast<ConstantInt>` 就直接 `return nullptr` 了（`GEPTracker.ipp:320`）。

**真正的根因在 `0x14fe70` 那个槽**，而且比前面想的严重：

| | `0x14fe68` ← rdx @`0x3932b5` | `0x14fe70` ← rsi @`0x367eaa` |
|---|---|---|
| DR（真机） | `rdx = 0x7ff5e0460000` | `rsi = 0x7ff720574a44` |
| lift | `0x0` | `0x140114a44` |

**两边存进去的就不是同一个东西。** `0x14fe70` 真机存的是**堆指针** `0x7ff720574a44`，lift 存的是 `0x140114a44`——**模块内地址**。低 20 位 `0x114a44` 恰好一致，但高 32 位被换成了模块基址。这是**地址来源错误**，不是精度丢失：值"具体"但语义完全错。

这解释了为什么 `0x410840` 读出 `0x202` 这么难：真机 `0x14fe6e..0x14fe75` = `02 0a 00 00 00 00 00 00`，其中高 6 字节为 0，说明**真机上这两个槽在那个时刻的有效部分已经被清零**（`0x14fe68` 的高 2 字节 = `02 0a`，`0x14fe70` 低 6 字节 = 0）。而 lift 的 `0x14fe68` 是 `0x0`（丢了这 2 字节）、`0x14fe70` 是堆指针（不该有值），**拼不出** `0xa02`。

**堆指针被系统性改写的规模**（`0x7ff7…` → `0x1401…`）：

| 寄存器 | lift 中形如 `0x1401xxxxx` 的次数 |
|---|---|
| `r9` | 88575 |
| `rsi` | 40636 |
| `rax` | 20871 |
| `r8` | 12786 |
| `rdx` | 4574 |
| `r10` | 4469 |

且 `rsi` 在 DR 上 **100% 具体**（502492/502492），lift 只有 94.8%；`rdx` DR 100%，lift 80.2%。

**结论：根因是堆指针的 provenance 被换成模块基址，不是 flag 折叠、不是 unaligned fold、也不是 store 丢常数。** 之前 §7.12.6–7.12.8 全部在下游找错了目标。

**修复方向随之改变，按优先级**：

1. **堆地址归一化**（真正的根）：DR 的 `0x7ff720574a44` 与 lift 的 `0x140114a44` 必须能互转。查 `lifter/memory/` 里把文件/堆 VA 折成 lifter 内部地址的代码（`normalizeRuntimeTargetAddress` / `shouldPromoteFileValue` 一线），确认它对**非映像基址**的堆地址做了什么。低 20 位一致说明映射偏移是 `0x140000000 - 0x7ff700000000 + …` 之类的固定重定位，逻辑上可逆。

2. **`zext i32` 的常数回折**（次要，但独立有效）：`0x14fe68` 那个 store 写的是 `zext i32 %v to i64`。`trackedBufferConstant` 逐字节 `dyn_cast<ConstantInt>` 见到 `zext` 就返回 null，即使 `%v` 是常数。给它加一条 "zext/sext of ConstantInt" 的回折即可独立修好 `0x14fe68`。**注意**：这与 §7.12.7 被撤回的 overlay 是同一类改动，必须逐字节校验，不得用局部已知字节冒充完整 qword。

3. **`0x202` 的最后 4 字节从别处补**：`0x14fe70` 在真机该时刻低 6 字节为 0。若 (1) 修好，`0xa02` 会自然拼出；不要为此再加 overlay。

**下一步做 (1)**：加一个只听 r9/rsi 携带堆指针的探针，打 lifter 内部把堆 VA 折成什么、走的哪个函数。这是唯一能把 88575 次 `r9` 改写定位到具体函数的方法。

### 7.12.11 ❌ 撤回 7.12.10 的「堆指针被换成模块基址」

**7.12.10 的根因判断是错的。** 我当时把手算的差值当成了验证结果。实测否证：

```
DR rsi    = 0x7ff720574a44
lift rsi  = 0x140114a44
difference= 0x7ff5e0460000   （碰巧等于该点 DR 的 rdx）
DR rsi - ASLR_slide = 0x280114a44  → 不是 lift 的 rsi
低 16 位相同 = 0x4a44 ；低 20 位不同
DR 轨迹里 rsi == 0x140114a44 的行数：0
```

三条独立否证：(a) 减去 ASLR slide **得不到** lift 的值；(b) `0x140114a44` 在 DR 轨迹中**从未出现**；(c) lifter 在 seq 191742（远早于故障点 217075）就已是 `0x140114a45`。**它们不是同一值的重定位，是两个不同对象。**

**还错在把 DR 当基准。** 两条流 RVA 100% 对齐（221160/221160），但寄存器从**第 0 条**（`0x7450` 客户入口）就全不同：

```
rva 0x7450:  DR rbx=0x1fc45d23d40  rsp=0x11eb8ffe08   ← 真机进程状态
             lift rbx=-  rsp=0x14fea0                ← 空寄存器 + 伪栈顶
```

这是**设计如此**（`STACKP_VALUE` 伪栈）。所以「DR 有 X / lift 无」在本样本上**不是 lifter 缺陷的证据**。§7.12.9 那句「两边存进去的就不是同一个东西」也一并作废。

### 7.12.12 ❌ 前提被 7.12.13 实测推翻：不是「cast 丢常数」，是真符号

不依赖 DR，只看 lifter 自己。`MERGEN_DIAG_SLOTSTORE` 的 321 条 `0x14fe68`/`0x14fe70` store，按 IR 形态分类：

> **⚠️ 本节的分类方法有缺陷**，见 §7.12.13。表中「源操作数已是字面量」是错的——我用正则把 SSA 名字也替换成了 `N`，实际源操作数是符号。**本节结论作废，以 §7.12.13 为准。**

| 形态 | 数量 | ~~能否折~~ |
|---|---|---|
| `trunc i64 <常数> to i32/i16` | 38 | ~~本该能折~~ **否，源是符号** |
| `trunc i64 %newreg to i32` | 11 | 源符号，真实不可折 |
| `or i64 %creatingrflag…`（RFLAGS 重组） | 26 | 不可 naive 折 |
| `i64 %RSI` / `%RBP` / `%RDI` / `%RAX` | 8 | 真实符号 |
| `select i1 %c, i64 <const>, i64 <const>` | 13（10 两臂皆常数） | 条件符号，可后续折 |
| `zext i32 %v to i64` | 2 | ~~本该能折~~ **否，源是符号** |

`isConst=1` 有 218 条，说明 store 侧**能**拿到常数——不是全盘失效。

**（已作废的）故障链推断**：`0x14fe68` 槽被 `zext`/`trunc` 包着的常数写成非 `ConstantInt` → `0x14fe70` 槽是 `i64 %RSI` → `0x416691` 读未对齐 `0x14fe6e..0x14fe75` 必须跨槽合并（VM 从不写 `0x14fe6e` 本身，1100 次重叠写全落在两个对齐槽）→ `trackedBufferConstant`（`GEPTracker.ipp:291-326`）逐字节 `dyn_cast<ConstantInt>` 见到非 `ConstantInt` 立刻 `return nullptr` → 整段不折 → `r10` 符号 → `and` 传染 → `pushfq` 的 ZF/PF 符号化 → `0x410840` 读出 `-` 而非 `0x202`。

**仍然成立的部分**：`0x14fe6e` 是未对齐读、VM 只写 8 字节对齐槽、因此必然依赖跨槽合并——这三点是实测事实（该 8 字节的 1100 次重叠写全部落在 `0x14fe68`/`0x14fe70`）。**不成立的部分**：跨槽合并失败的原因不是「常数被 cast 丢掉」，而是那两个槽本来就是符号。

### 7.12.13 ❌ 实施 (A) 后实测无效：可被 cast 折叠的 store 是 **0 条**

按 §7.12.12 实现了 `peelToConstantInt`（在 `addValueReference` 里、写入 buffer 之前，只放行 `trunc`/`zext`/`sext` + 常量条件的 `select`，显式拒绝 `and`/`or`/`shl`/`lshr`），加 `MERGEN_DIAG_PEEL` 探针。编译通过，但：

```
peel fired: 0
mix output.ll SHA256: 11C03F153C3C...   ← 与改动前逐字节相同
```

**§7.12.12 的前提是错的。** 我用 `re.sub(r"%?\d+", "N", ir)` 抽象 IR 形态分类，把 **SSA 名字和类型宽度** 一起替换成了 `N`：

```
%134920 = zext i32 %134186 to i64
          ^^^^^^  ^^^^  ^^^^^^  ^^^^  ^^^^^
          临时名  源类型 操作数  目标类型  ← 两个 N 是类型宽度，不是操作数
```

于是 `trunc i64 %x to i32` 被我读成「`trunc` 的源操作数**已经是常数**」。实际源操作数是 `%x`，**符号**。

321 条 store 的诚实分类：

| 形态 | 数量 | peel 能否折 |
|---|---|---|
| plain constant | 208 | 已是 `ConstantInt`，无关 |
| `trunc`/`zext` **符号源** | 51 | **不能**（源真符号） |
| `or`/`lshr`（RFLAGS 重组） | 27 | **故意不折**（§7.12.7 的坑） |
| `select` 符号条件 | 13 | 不能（条件 `%138038` 等是符号） |
| 裸寄存器 `%RSI`/`%RBP`/… | 12 | 不能 |
| 其它窄常数（`i16`/`i32`） | 10 | 无关 |
| **cast 源为常数** | **0** | — |

13 个 `select` 的条件全是符号（`%138038` ×10、`%92289` ×2、`%103191` ×1），没有一个是常量条件。

**结论：那两个槽在故障时刻是「真符号」，不是「被 cast 丢掉的常数」。** 故障链第 1 环（§7.12.12 写的「cast 包着的常数写成非 `ConstantInt`」）不存在，因此 (A) 无效是正确的实测结果，不是实现 bug。

**代码处置：`peelToConstantInt` 保留。** 它语义正确、有价值（防止将来出现「已知常数被 cast 包一层」时静默丢具体性），零输出、零行为变化（实测哈希不变），且带 `MERGEN_DIAG_PEEL` 开关可复验。但**它不是 mix 故障的修复**，不要当成修复引用。

### 7.12.14 剩下的唯一可查点：`%138038` 与 `%134186` 的来源

故障时刻两个槽的符号源已经定位到具体 SSA 值：

- `0x14fe68` 末写 @`0x3932b5`：`zext i32 %134186 to i64`
- `0x14fe70` 末写 @`0x367eaa`：`i64 %RSI`
- 另有 13 个 `select` 全部以 `%138038` 为条件（同一条件反复出现，值固定），`%138038` 显然是个**被反复复用的 VM 谓词**

注意 `0x14fe68` 槽在 seq 216303（`0x3932b5` 之前的一次执行）写的是**常数 `0x0`**，而 seq 219981 变成 `zext %134186`。**同一个 slot 两次执行、`rdx` 一次具体一次符号**——这不是 fold 规则问题，是 `%134186` 在两次执行间从「具体」变成了「符号」。

**下一步该查的是 `%134186` 和 `%138038` 的定义**：它们在 IR 里是哪个函数/哪个基本块产生的、上游是什么。如果它们是**路径求解/分支决策**的产物而非真正的数据依赖，那根因就在路径求解而不在内存模型——之前所有查法都在内存侧（`trackedBufferConstant`、跨槽合并、store 具体性），方向一开始就错了。

查法：给 `MERGEN_DIAG_SSA58`（已有的真实 SSA use-def 上溯探针）指到 `%134186`，或直接在 lift 结束时 dump 这两个值的定义点。**先确认它们是不是 path-solve 产生的**——这决定后续是查内存模型还是查 PathSolver。

**下一步该查的**（不是 flag 折叠）：`0x14fe6e..0x14fe75` 这 8 字节该由谁写成一个可折常数。写流里这 8 字节的 550 次重叠写中，`seq < 217075` 的最后一次是 `0x403932b5` 写 `0x14fe68` 值 `-`；`0x14fe6e` 本身在 `seq 15724`（`0x403330a6`）写过常数 `0x213`，之后被符号写覆盖。这才是要收敛的地方。（**注**：本节拿 DR 的 `rsi`/`rdx` 与 lift 对比的推断已在 §7.12.11 撤回——DR 是真机进程状态、lift 是伪栈，从入口起就不是同一个机器。真正的根因见 §7.12.12。）

**本次只加诊断，不改语义。** 验证：默认（无 env）`mix 0x140007450` 仍 `221160 insns / 22317 blocks_attempted`，`output.ll` SHA256 `11C03F15…`。`test.py quick` / `micro` 本机跑不了（缺 NASM、`LLVM_DIR` 未设），与本改动无关。

**顺手修掉的诊断 bug**：`addValueReference` 的写流门是 `current_address >= 0x140000000`，但 lift 把映像重基到 `0x40000000`，所以 `MERGEN_WRITE_STREAM_FILE` 只会记下 3 行 setup 写、没有任何按指令的行（写流等于不可用）。改成 `0x40000000..0x50000000` 后同一趟记 32164 行。同理，任何按指令卡点的探针都必须比 `maskedRVA()` 而不是裸地址，否则在重基 lane 上静默不触发——本次先踩了这个坑才误判「`pushfq` 一次都没执行」。

### 7.12.15 FLAGS 链：167342 的 `0x206` 不是 164799 留下的 RFLAGS

对照：`build_msvc_dbg\mix_lift_insn.csv` + `mix_lift_wr.csv`，DR `vmptest\mix_dr_insn_rerun.csv`。写流按 **RVA 访问下标 zip insn seq**（不能用「该 RVA 最后一次命中」）。insn 列是指令前快照。scratch `[rsp+disp]` 的基是 **`0x14fc60`**（`0x10→0x14fc70`，`0x48→0x14fca8`，`0x60→0x14fcc0`，`0xa0→0x14fd00`），不是 `STACKP 0x14fea0`。

停在 221157 的 `rdx=-` 往前是同一套 VSP NAND / scratch 反复中毒。紧挨 FLAGS 的那一环：

| seq | RVA | 做什么 | lift | DR |
|---|---|---|---|---|
| 167251 | `0x331230` | `mov rcx, [rsp+rax]` `rax=0x10` → `0x14fc70` | `-` | `0x206` |
| 167253 | `0x33123b` | `mov [rdi], rcx` `rdi=0x14fe5c` | 写 `-` | 写 `0x206` |
| 167311 | `0x36f18a` | `mov [rdi], rcx` `rdi=0x14fe54` | 写 `-` | 写 `0x206` |
| 167342 | `0x3891a8` | `mov rsi, [rdi]` `rdi=0x14fe54` | `-` | `0x206` |
| 167346 | `0x3891b4` | `mov rdx, [rdi+8]` → `0x14fe5c` | `-` | `0x206` |
| 167350+ | `0x3891c2`… | `not rsi` / `not rdx` / `or`（NAND-or 形） | `-` | `~0x206 = 0xfdf9` |
| 167359 | `0x3891e0` | `mov [rdi+8], rsi` → `0x14fe5c` | 写 `-` | 写 `0xfdf9` |

**两边是同一份 scratch，不是两个独立 FLAGS。** `0x206 NAND 0x206` 在 DR 上就是 `0xfdf9`，对上 167857 那次 64-bit NAND 读 `0x14fe5c` 的 `0xfdf9`（`~0x206`）。

scratch `0x14fc70` 最后写入是 **166407** `mov [rsp+rbx], r8`（`rbx=0x10`）。`r8` 来自 **166380** `mov r8, [rdi]`，`rdi=0x14fe5c`。那一格是 **166350** `pop [rdi]`，紧跟 **166346** `pushfq`。

`pushfq` 抓的不是 AND 的 FLAGS，而是 **166341** `shld rax, rbp, cl` 的 FLAGS。三个操作数在 lift 里都已经是 `-`。DR 上 `shld` 结果 `0x131f6340a0`，FLAGS **碰巧也是 `0x206`**（PF+IF+reserved1）。

`rax` 来自 **166331** `mov rax, [rdi]`，`rdi=0x14fe5a`（未对齐），值是 VM dword **`0x98fb1a05` vs `-`**：

- 166258 `mov [rdi], rsi` 把 VSP 指针 `0x14fe62` 压到 `0x14fe5a`
- 166293 `mov rbp, [rdi]` / 166296 `mov r8, [rbp]` 解引用得到 `0x98fb1a05`
- 166300 `mov [rdi], r8` 写回 `0x14fe5a`

`0x98fb1a05` 更早在 **163042** `mov ebx, [rsp+rax]`（`rax=0x50` → `0x14fcb0`）就已经是 `-`，163045 写进 `0x14fe70`，165092 `mov eax, [rdi]` 读出来做 32-bit NAND（165102 `and eax, ebp`）。所以 167342 的 `0x206` 是 **已经符号的 VM dword 再经 `shld` 产出的 FLAGS**，不是 164799 那次真实 RFLAGS 留下来的。

**真正 concrete 的 FLAGS 被盖掉了，不是 `pushfq` 算不出：**

| seq | 写什么 | lift |
|---|---|---|
| 163956 | `[rsp+0x10] = r8 = 0x207` | concrete |
| 164799 | `pop [0x14fe5c] = 0x206` | concrete |
| 166880 | `pop [0x14fe54] = 0x217`（`add rax,rbp` 得到 `0xd4` 之后） | **concrete** |
| 165343 | `[rsp+0x10] = r8 = 0x286` | 已是 `-`（scratch FLAGS 更早一次变符号；167342 不用这份） |
| 166350 / 166407 / 167311 | 用 shld-FLAGS `0x206` 盖掉上面那些格 | `-` |

166880 证明：**操作数 concrete 时 `pushfq` 能写出 concrete FLAGS**（这里是 `0x217`）。167342 的洞不在 FLAGS 语义，而在 `shld` 的输入 dword 已经是 `-`。不要 FLAGS 分字节 overlay（§7.12.7）、不要 `GetRFLAGSValue |= 0x202`。`0x98fb1a05` 的来源见 §7.12.16。

### 7.12.16 `0x98fb1a05` 是嵌套 32-bit NAND，原料早已是符号

`0x98fb1a05` 不是 FLAGS。NAND 算术自洽；lift 两侧 load 都是 `-`。

接到 163042：

| seq | RVA | 做什么 | lift | DR |
|---|---|---|---|---|
| 161456 | `0x3704b8` | `mov eax, [rdi]` `rdi=0x14fe6c` | `-` | `0x98fb1a05` |
| 161484 | `0x37051c` | `mov [rsp+rcx], eax` `rcx=0x50` → `0x14fcb0` | 写 `-` | 写 `0x98fb1a05` |
| 163042 | `0x42697f` | `mov ebx, [rsp+rax]` `rax=0x50` | `-` | `0x98fb1a05` |
| 163045 | `0x42698c` | `mov [rdi], ebx` → `0x14fe70` | 写 `-` | 写 `0x98fb1a05` |

161290 `mov ax, [rdi]`（`rdi=0x14fe5a`，字 `0x78`）也会把 `rax` 变成 `-`，但 **161456 整 32 位覆盖**，stash 用的是这次 load，不是那次 16-bit。

`0x14fe6c` 最后写入 **160126** `mov [rdi+8], eax`（`rdi=0x14fe64`），即下面这次 NAND 的结果：

| seq | 指令 | DR |
|---|---|---|
| 160108 | `mov eax, [rdi]` `rdi=0x14fe68` | `0x6704edff` |
| 160110 | `mov edx, [rdi+4]` → `0x14fe6c` | `0xfffff7fa` |
| 160116 | `not eax` | `0x98fb1200` |
| 160120 | `not edx` | `0x805` |
| 160122 | `or eax, edx` | `0x98fb1a05` |

`~0x6704edff | ~0xfffff7fa = 0x98fb1a05`。

这两个操作数各自还是更早一次 `not`/`or`：

- `0x6704edff` ← 160015 `or eax, edx` 后 160016 写入 `0x14fe68`：`0x4c7d | ~0x98fb5678`
- `0xfffff7fa` ← 159590 `or eax, edx` 后 159591 写入 `0x14fe6c`：`~0x4c7d | ~0x98fb5678`

共同原料两份 scratch（`edx` 比 `eax` 先死，和后面 `0x8ccc*` 链同一形态）：

| 值 | 第一次变成 `-` 的 load | scratch 来源 |
|---|---|---|
| `0x98fb5678` | 159278 `mov ebx, [rsp+rax]` `rax=0x60`；edx 在 **159392** `mov edx, [rdi+4]` 先死 | `0x14fcc0`，最后写入 **148834** `mov [rsp+rcx], eax`（`rcx=0x60`），`eax` 当时已是 `-` vs `0x98fb5678`。该槽上次 concrete 写是 133106 的 `0x1402b8ec4` |
| `0x4c7d` | 159844 `mov ebx, [rsp+rax]` `rax=0x50`；eax 在 **159885** `mov eax, [rdi]` `rdi=0x14fe60` 才死 | `0x14fcb0`，最后写入 **157734** 同一 stash handler，`eax` 当时已是 `-` vs `0x4c7d` |

**下一步：** `0x98fb5678` 在 148834 之前、以及 `0x4c7d` 在 157734 之前，是哪次 load 把 `eax` 弄成 `-`。不要再往 `pushfq` 上修。

### 7.12.17 根因合拢：符号从 mix 参数 `%RCX` 进来；`--reg rcx=0x12345678` 能越过 221160

FLAGS / NAND / `0x98fb1a05` / `0x4c7d` / `0x98fb5678` 都是 **mix 的 xorshift 数据流**，不是 `pushfq` 坏了。

`test.cpp`：`mix(uint32_t seed)` 做 8 轮 `seed^=seed<<13; ^=seed>>17; ^=seed<<5`，`main` 调 `mix(0x12345678u)`。Win64 第一参在 **RCX**。客户入口 seq 3 `mov ebx,ecx`：DR 从 seq 1 起 `rcx=0x12345678`；lift 的 `%RCX` 是函数参（insn 列为 `-`）。后面 `0x12345678<<13 = 0x8acf0000`、拼出 `0x98fb5678`、`>>17` 得到 `0x4c7d`，再经 VM NAND 变成 `0x98fb1a05`，`shld` 的 FLAGS 才变符号。221157 `add r11,rdx` 的 `rdx=-` 是这条链的下游。

两条路：

1. **诊断**：lift 入口在 `InitRegisters` 之后把 RCX 写成 `ConstantInt`（CLI `--reg`，值不要写进 handler）。
2. **通用**：保持 `%RCX` 符号，修 VIP 槽不要把数据槽当 VIP 吃掉。

**已做 (1)。** 通用开关，不特判 mix：

```
lifter.exe … 0x140007450 --mem-dump entry_7450.dmp --reg rcx=0x12345678
```

`ParseResult::entryRegs`；`ecx`/`rcx` 都落到 `RCX`。`MERGEN_MAX_BLOCK_BUDGET=131072`。

| | 无 `--reg` | `--reg rcx=0x12345678` |
|---|---|---|
| 块 / 指令 | 22317 / 221160 | **41816 / 405604** |
| error | 0 | 0 |
| 客户 `ret` | 无（停在 `0x35a716` `push r11; ret`，`disp=-584` `rop=0`） | 仍无；末条仍是 `disp=-584` `rop=0` |
| 优化 IR | 符号 ZF 在两个常数 RIP 间 `select` | **`bb1: br bb1` 死循环**（`output.ll`） |

期望 `mix(0x12345678)=0xc5186e29` **没有**出现在优化 IR。末段 VIP 在 `0x403c4b78` ↔ `0x14008b4aa` 来回（`[lmlrep]`，`confirm=1`），`GEPTracker.ipp:898 max_unknown : 0`。

**(1) 证明：把参数折死，xorshift/NAND/FLAGS 链能继续 lift，旧停点 221160 不是 handler 特判能修的洞。** 它不能当通用解：真实 mix 入口 RCX 应保持符号。下一步仍是 (2) VIP 取回，不要 unique-fold / VIP overlay / STACKP±8 / `GetRFLAGSValue |= 0x202`。

### 7.12.18 试过「未对齐槽拼接」：博客要的是字节级 store-forward，peel 宽度修了但 mix 不动

Aftermath Themida 篇（work.md 0.5）对内存模型的原话：

> Propagation is modeled at the **byte level**, so overlapping stores are handled correctly. A narrow store that partially overlaps a wider load is composed properly rather than silently producing a stale or incorrect value.

NaC-L / `DEVIRT_STRATEGY.md` 同一条：concolic buffer 按字节跟踪先前 store，允许部分重叠。**不是** VIP overlay，也不是 `GetRFLAGSValue |= 0x202`。

已有 `peelToConstantInt` 只走 cast/select，**不**折 or/shl FLAGS 链（§7.12.7）。但 `zext i32 C to i64` 剥出来的是 **32 位** `ConstantInt`，`addValueReference` 因宽度不等拒收，`trackedBufferConstant` 见到 zext 就 bail。这和博客「重叠要能拼」相反：槽里明明是整常数，未对齐 load 却拼不出。

**改动**（`GEPTracker.ipp`）：peel 把 zext/sext/trunc **按目标宽度**做成同宽 `ConstantInt`；`trackedBufferConstant` 对非 `ConstantInt` 也 peel。仍逐字节全 `ConstantInt` 才折，有任一符号字节整段保持符号。

**无 `--reg` 实测 mix `0x140007450` + dump：** 仍 **22317 / 221160**，末 `ret` 仍 `0x4035a716` `disp=-584`。insn 流相对改前 **0 行多出具体值**；217113 `rdx`、218543 `r10` 仍是 `-`。add `0x140007210` 仍是 `add i64 %RDX, %RCX` + 低 32 `and`，没有 §7.12.7 那种塌成常数 RIP。

**为什么不够：** §7.12.10 已写过，`0x14fe70` 那次 store 的 IR 是 `i64 %RSI`（符号），不是 cast 包着的常数。peel 只修「整段已知却被 zext 挡住」；跨槽 load 只要邻居有一字节是 SSA，按 7.12.7 规则就**不该**折。VIP 槽在 218543 被 `-` 盖掉，根因仍是数据 SSA 进了控制槽，不是 peel 宽度。

保留 peel（通用、add 不回归）。下一步不是再 overlay FLAGS，而是让 VIP 取回在数据槽为 SSA 时仍读出具体指针（或避免把 SSA 写进 VIP 槽）——仍禁止 unique-fold / VIP overlay / STACKP±8 / `|= 0x202`。

### 7.12.19 两层停点根因（DR 对照 + RCX 诊断）：二次 `ret` SYM vs 假 VIP `confirm=1`

入口 `0x140007450`，dump `entry_7450.dmp`，`MERGEN_MAX_BLOCK_BUDGET=131072`。DR：`mix_dr_insn.csv`（19 列含 r12–r15）。LF：`MERGEN_INSN_STREAM_FILE`。

#### A. 无 `--reg`（产品路径）

> **⚠️ 本小节的归因已被 §7.12.23 否证**（"依赖 ABI 第一参 `%RCX`" 不成立）。仍然有效的只有：无 seed 停点 ≈301739、第一次 `0x3ec79e` 能过第二次不能、以及 "`--reg R12=0` 之类不推进停点"。

停在第二次 `ret @0x3ec79e`（insn ≈ **301739**；更早口径曾写 221160 / `0x35a716`，同一类 unresolved ROP）。栈顶目标不是常数：`r8` 经 `add r8,rcx` 仍依赖 **ABI 第一参 `%RCX`（必须保持 SYM）**。第一次 `0x3ec79e`（≈224254）能过（目标具体）；第二次不能。

**不是** entry 非 ABI 种子问题：无 seed 已是 301739；`--reg R12=0` 等不推进停点。

#### B. `--reg RCX=0x12345678`（诊断，非通用解）

| | 无 seed | `RCX=0x12345678` |
|---|---|---|
| insn | ≈301739 | **405604** |
| 两次 `0x3ec79e` | 第二次 unresolved | **都过**（224254→`0x2e8e10`，301739→`0x2feda7`） |
| 与 DR RVA | — | **全程对齐到 405604**（DR 总长 ≈425181） |

停点 **不是** 又一次 unresolved ret。末尾：

```
[lmlrep] addr=0x403c4a18 cur=0x14014684a
[vip] … target=0x403fccd1 cur=0x404170fa vip=0x403c4a18 repeat=1 exact=0 confirm=1
[vip] … target=0x403f48de cur=0x403fccd1 vip=0x403c4a18 repeat=1 exact=0 confirm=1
```

DR 下一条是 `417112 → 3fccd1 → 3f48de`（同一圈再转）。LF 用假 VIP 触发 `replaceWithGeneralizedLoopBlock`，迭代不再展开。优化 IR 见 §7.12.17 的 `bb1: br bb1`。

真 VIP 本在 `0x14020051d` 一带递减；`noteModule` /「最后一次 module load = VIP」（intel `AddEndHandlerCommands`）在 Ultra 上不成立——handler 里还有原生 RX / 表读，cursor 被 `0x403c4a18` ↔ `0x14014684a` 盖掉。transfer fallback `vmp.vipOffset()` 把假地址送进 `(VIP, native target)` backedge 键。

更早语义偏差（RVA 仍对齐）：循环计数 rcx 在 ≈405536 已是 DR=`0x5` / LF=`0x14`；≈405586 LF rcx 变 SYM。

#### C. 试过的 VIP「收紧」全部撤回（回归 ≈105668）

| 试法 | 结果 |
|---|---|
| PathSolver 对 `backedgeKey` 加 `exact`/bytecode 门闸 | **补丁**（VIP 已错还堵 confirm）；已撤 |
| `noteModule` / `loadProvenance` 一律 `isBytecodeAddress` | insn 掉到 **≈105668**，无 `3ec79e`；路径早分叉 |
| 仅 VIP cursor bytecode / sticky，不动 provenance | 同样 ≈105668 |
| `vipConfirmsBackedge` 默认改 `false` + fallback 只认 bytecode | noseed/rcx 都 ≈105668 |

「正确」sticky VIP 会更早 `confirm=1`，说明还要动 **loop generalize 与状态**，不能只堵 `noteModule`。代码已全部 `git checkout` 回撤；基线仍是 rcx seed → **405604**。

#### D. 一句话与下一步

控制靠 VIP/槽位保持具体，数据（含 RCX）保持符号。当前 VIP cursor 被非 pcode 的 module load 污染 → 无 seed 卡二次 ret；指定 RCX 后假 VIP 触发 generalize。

下一步仍是 **(2) VIP 取回**（数据槽 SSA 时控制槽仍读出具体指针 / 避免 SSA 进 VIP 槽），并审 loop generalize 在 VIP 正确重复时不要收掉仍在推进的具体状态。禁止：unique-fold、VIP overlay、STACKP±8、`GetRFLAGSValue |= 0x202`、把 RCX 具体化当产品解、PathSolver backedgeKey 补丁。

**日志（先分析再改）：** `MERGEN_DIAG_VIP=1`

| 标签 | 含义 |
|---|---|
| `[vipcur]` | `noteModuleLoad` 写 cursor：`load/prev/now` + `loadBc/prevBc/nowBc` + `clobber`（prev 是 bytecode、load 不是且 now==load） |
| `[vipload]` | 即将 `noteModuleLoad` 的 module 读；`=1` 只打「非 bytecode 且 cursor 已是 bytecode」；`=2` 全量 |
| `[vippick]` | transfer（ret/djmp/ijmp）选 VIP：`mod` / `chain` / `cursor` 三源与最终 `src=` |

```
set MERGEN_DIAG_VIP=1
set MERGEN_MAX_BLOCK_BUDGET=131072
set MERGEN_INSN_STREAM_FILE=mix_lift_insn_rcx.csv
lifter.exe … 0x140007450 --mem-dump entry_7450.dmp --reg RCX=0x12345678 2>vip_diag.err 1>vip_diag.out
findstr /C:"clobber=1" /C:"[vippick]" /C:"confirm=1" vip_diag.out
```

先看末段 `clobber=1` 的 insn VA 与随后 `src=cursor pick=0x403c…` / `confirm=1` 是否同一条链；再决定改 cursor 还是改 pick。

**首轮 `MERGEN_DIAG_VIP=1` + `--reg RCX=0x12345678`（`vip_diag.out`）：**

- `clobber=1` 共 29 次；末段决定性一次：
  - `[vipcur] insn=0x403f48ee load=0x403c48fc prev=0x14037d46a now=0x403c48fc loadBc=0 prevBc=1 clobber=1`
  - 紧接着 `[vippick] kind=djmp insn=0x403f48f9 … src=cursor pick=0x403c48fc cursorBc=0`（`mod=0 chain=0`）
  - 再 `[vip] … vip=0x403c48fc confirm=1`（`3fccd1` / `3f48de`）→ 停在 ≈405604
- 说明：**卡住链是 cursor 被非 bytecode load 盖掉 → transfer 只能 `src=cursor` → 假 VIP 进 backedge 键**；不是计数器直接收 worklist。
- `[vipload]` 在 `=1` 下 0 条而 `[vipcur] clobber` 有，说明部分 clobber 来自 **GEPTracker 嵌套 `noteModuleLoad`**（不经 GetMemoryValue）。
- 早期还有多次 `0x1402e47xx` → `0x1400b1xxx`（`loadBc=0`）clobber，同一机制。
- 全量 `[vippick]` 曾把 stdout 打爆（进程 `0xC0000005`）；现 `=1` 只打 `src=cursor && !cursorBc`，`=2` 才全量。

**只挡 clobber（`VmpModel::onModuleLoad`：bytecode cursor 存活时拒非 bytecode load）实测：** `clobber=0`、`skip=174`、末段不再 `pick=0x403c…`，但 insn **105668**、无 `3ec79e`。sticky VIP `0x1402e47e4` 上 `confirm=1`。与 §7.12.19.C 同一回归。单挡不够。

#### E. 落地修（不回退）：cursor 守卫 + exact-only confirm

三处一起改（缺一仍会 105k 或 405604）：

1. **`VmpModel::onModuleLoad`**：bytecode cursor 存活时拒非 bytecode load（挡 `0x403c48fc` clobber）。
2. **`vipModuleOffset`**：只认 `isBytecodeAddress`（transfer DAG 里的 handler RX 不能变 exact VIP）。
3. **`PathSolver`**：`vipConfirmsBackedge = vipRepeat && currentVipIsExact`；无 VIP 时默认 `false`。cursor 启发式（`exact=0`）不得关 loop。
4. **transfer pick**：fallback cursor 仅当 `isBytecodeAddress`；非 bytecode cursor → pick=0。

| | 基线 rcx | 只挡 clobber | **E 全套** |
|---|---|---|---|
| insn | 405604 | 105668 | **≥426929** |
| `405605` | 无（停） | 无 | **`0x3fccd1`（过）** |
| clobber | 有 | 0 | 0 |
| `confirm=1 exact=0` | 有 | 有（sticky） | **0** |
| 无 seed | ≈301739 | 105668 | ≈301739（二次 ret 仍要 VIP 取回） |

`0x403f48ee` 现为 `skip=1`，cursor 留在 `0x14022184c` 并继续推进。诊断日志保留。下一步仍是无 seed 的 VIP 槽取回（RCX 保持 SYM）。

§7.12.19.E 全套后 `--reg RCX` 诊断停点从 405604（假 VIP confirm）前移到 **405644**（`jne` 路径分叉）。槽实验见 **§7.12.20**；后续从 `0xe64`/`rdtsc` 追回后，**对拍层** 405644 可由 TSC 不同解释，**出口层** `ret@0x33ce78` 另论 —— 见 **§7.12.21**。与无 seed 的二次 `ret @0x3ec79e`（≈301739）仍是另一条线。

### 7.12.20 405644：`0x14fcd8` 槽实验与修正后的根因链

> **后续改写（§7.12.21）：** 对「与某一份冻住的 DR insn 对拍」而言，405644/`0x450` 分叉可由 **`rdtsc` TSC 采样不同**充分解释（钉同 TSC 即消）；DR 多跑圈数本身也不固定。真正「出不了客户码」是 **`ret@0x33ce78` 表 load 折不动**。本节 slot 实验仍保留作历史因果记录，勿再当出口主线。

`--reg RCX=0x12345678`，dump `entry_7450.dmp`，`MERGEN_MAX_BLOCK_BUDGET=131072`。对照 DR `vmptest/mix_dr_insn.csv`；LF insn `mix_rcx_insn_wr.csv` / `mix_verify_*_insn.csv`；写流 `mix_rcx_wr.csv` / `mix_verify_*_wr.csv`。一键 relift：`build_msvc_dbg/_relift_verify.cmd`（tag=`baseline|slot|lea|load`）。

#### A. 表观停点（RVA 对齐到 405643）

| seq | RVA | DR | LF（baseline） |
|---|---|---|---|
| 405643 | `0x3fccd1` | `rcx=0`，下一跳 `0x3fccd7` | 同 |
| **405644** | **`0x3fccd7` vs `0x3f48de`** | fallthrough 出圈 | **`jne` 继续转**（`rcx≈0x411`） |

计数来自更早 `0x326e3b` `mov rcx,[r9+8]` 等链；表观是循环计数偏大，lasting 写入在更前。

#### B. Slot 实验证了什么（充分条件，未证错）

**`MERGEN_VERIFY_SLOT_FCD8=1`**（`GEPTracker.ipp` `addValueReference`）：在 rva **`0x2eeeae`**、槽 **`0x14fcd8`** 这一次 store，把 LF 会写的值强行换成 DR 的 **`0x14042b24f`**。

| tag | wr **mem seq** 28489 写入 `0x14fcd8` | seq 405644 |
|---|---|---|
| baseline | `0x14042d0af`（本跑；其它跑次亦见 `0x14042a7db` 等） | **分叉**（LF `0x3f48de`） |
| **slot** | **`0x14042b24f`**（强制） | **对齐**（LF `0x3fccd7`，与 DR 同） |

由此可成立（至少在本 trace 上）：

- **`0x14fcd8` 里的错模块指针，是传到 405644 的 lasting 瓶颈之一**（write stream **mem seq 28489**，insn rva `0x2eeeae`；**≠** insn seq 188789）。
- **修这一下就够消掉 405644 这个分叉**（充分条件）。
- **12407 的 `adc` 不是 lasting 根**：`12407` `mov [r10],rbp` 写 rbp、`movzx` 清 rdx；slot 实验也**不需要**动 adc。
- **这不是说「28489 是唯一毒源」**，而是说：在这条 trace 上，**下游这一槽写错 → 405644 分叉**。

#### C. 之前分析里不严谨 / 说错的地方

1. **「28489 写进去的一定是 +0x120 模块指针」——本 trace 不成立**

   | 跑次 | baseline 写入 `0x14fcd8` | DR @400919 读回 module rva | 差 |
   |---|---|---|---|
   | 早前 relift | `0x14042a7db` | `0x42b24f` | **`0x474`** |
   | verify baseline | `0x14042d0af` | `0x42b24f` | **`0x1e60`** |

   **`0x120` 是 cx / 栈几何层的偏**（12287、12406 仍成立），**不等于**每个模块 store 的 module rva 差都恰好 `0x120`。

2. **「28489 = 毒从 12407 adc 直接传下来」——链断了**

   - `12407`：`mov [r10],rbp` 写 **rbp**；`movzx rdx,r13w` 清 rdx → **adc 的 rdx 毒没从 12407 进内存**。
   - `28489` 的值来自 **另一条 fold 链**（write stream 有具体值；insn 行里 `rdx` 常与 store 值对不上）。
   - **28489 之前具体哪条 fold 算错，尚未钉死**（`MERGEN_DIAG_FCD8_STORE` visit=1：store 已是裸 `ConstantInt`，IR/`output_no_opts.ll` 同形，semantic fold 在 emit 前完成）。

3. **「修 lea cx 就能验证同一根因」——本次 hook 没打上**

   **`MERGEN_VERIFY_LEA_CX=1`**（`Semantics_Arithmetic.ipp` `lift_lea`）：只在 **`Rvalue` 已是 `ConstantInt`** 时把 cx 强制为 `0xfc80`（rva `0x406f2d`）。若 lea 已是 SSA → **hook 不触发**。

   | tag | 405644 |
   |---|---|
   | lea | **仍分叉**（`rcx=0xa`） |

   **lea 实验不能说明「12287 不是根」**，只说明 **当前 patch 没覆盖到**。

4. **「slot 实验 = 根因就是栈几何」——推过头**

   Slot 只证明：**下游这个槽写错 → 405644 分叉**。  
   **为什么** 28489 会 fold 成 `0x14042d0af` 而不是 `0x14042b24f`，仍要往上追（很可能和 cx/伪栈有关，**但 slot 实验本身没证这一点**）。

**`MERGEN_VERIFY_LOAD_FCD8=1`**（`retrieveCombinedValueImpl`，rva `0x3c048f` 读 `0x14fcd8`）：trace **未到 405644**（停点更早），**不能**替代 slot 实验对瓶颈的因果结论。

#### D. 更准确的根因链（两层，勿混为一谈）

**[机制层，仍较可信，未用 slot 闭合因果]**

```
12287  lea rcx,[rsp+0x140]     → cx 差 0x120（DR 0xfc80 vs LF 0xfda0，伪栈 vs 真机）
12406  adc dx,cx               → 演示「栈低16 × 模块指针」会混（寄存器瞬时）
12407  mov [r10],rbp; movzx    → 不写 rdx 毒进槽；lasting 链在此断
```

**[瓶颈层，slot 实验证实]**

```
28489  WR  0x14fcd8 ← 错模块指针（具体 module rva 随 fold 跑次变，非固定 +0x120）
       insn 0x2eeeae  mov [rsp+rbp], rdx
400919 LD  mov rdx,[rsp+r8]    r8=0x78 → 0x14fc60+0x78 = 0x14fcd8
…      → 0x14fe60 / NOR / 计数 …
405644     jne @0x3fccd1        DR rcx=0 出圈，LF 继续
```

**[slot 实验证实的]**

```
在 0x2eeeae 强制写 DR 值 0x14042b24f → 405644 对齐
```

#### E. 一句话

Slot 实验**没证错**「28489 → `0x14fcd8` 是 lasting 瓶颈」。

说错的是：把「瓶颈」说成「**+0x120 写进去**」、把「**12407 adc**」说成「lasting 根」、以及用 slot 结果直接等同「**栈几何根因已因果闭合**」——中间 **28489 的 fold 链**和 **lea 上游**还没用实验钉死。

#### F.2 28489 store 机制：rdx fold 错，不是 slot 地址错

**insn** `mov qword ptr [rsp+rbp], rdx`（rva `0x2eeeae`，LF 模块 VA 前缀 `0x14000000`）：

| | 值 | 模块 rva |
|---|---|---|
| LF（baseline） | `0x14042d0af` | `0x42d0af` |
| DR（slot patch 用） | `0x14042b24f` | `0x42b24f` |
| 差 | **`0x1e60`** | — |

- **slot 地址 `0x14fcd8` 本身没错**（`rsp+rbp` → 伪栈 0x14fcd8 对）；错的 RDX fold 结果被写进去。
- `400919` 读回 `0x14fcd8` → LF `rbx/rdx` 带 `0x14042d0af`，DR 带 `0x7ff7a378b24f` → 传到 `405644`。
- **insn 行里 rdx 列对不上 store 用的值**：写槽用的是 folder 折叠出的 ConstantInt，和 insn 行采样不是同一路径/同一时刻。

**rdx 被算错的机制**（同 handler 前面有典型 VMP 垃圾 ALU）：

```
or r10w, r9w
xor r10d, edx
...
mov [rsp+rbp], rdx    ← 28489，rdx 在这里 first lasting 进槽
```

更早同 handler 内，LF 的 rdx 模块 rva 已比 DR 偏 `0x37`（rva `0x2e6539` 一带）→ **进这个 handler 之前/之中，模块指针已在 ALU 里被污染**。

**lifter 的根因 class**：模块指针 load 和栈几何/伪栈常量走同一套 `createAddFolder` / constant fold，没有「栈几何域 ≠ 模块指针域」的隔离。多步 junk 后，folder 把**错的整数**收成 `rdx = 0x14042d0af`，`store` 第一次把这个 concrete lasting 写进 `0x14fcd8`。

**和 12287/12407 的关系**：

| | 作用 |
|---|---|
| `12287` lea，cx 差 `0x120` | 更早的栈几何污染源之一，会参与后面很多 handler 的 fold |
| `12407` adc | 演示「栈低16 × 模块指针」会混；这次 lasting 写不经过它 |
| `28489` store | 这条 trace 上 lasting 进 `0x14fcd8` 的瓶颈；此时 cx 已同，毒是**累积 fold 结果** |

`0x1e60` ≠ `0x120`：`0x120` 是 cx / 栈几何层的典型偏；`0x1e60` 是这次具体写槽的差，同属「把不该一起 fold 的域揉成一个常数」，不是「这里又 +0x120」。

#### F.3 追 rdx fold 链：下一步

在 `0x2eeeae` store 上对 rdx operand 开 SSA 追溯（`MERGEN_DIAG_SLOTDAG` / `MERGEN_DIAG_FCD8_STORE visit=1`）：insn 行里的 rdx 列对不上 store 值，需在 **fold DAG** 上追 rdx 从哪条指令开始偏成 `0x42d0af`（锚点 wr seq 28489，而非 405644）。`output_no_opts.ll` 在 store 处已是裸 `ConstantInt`，需 semantic 侧或 insn trace，不是 O2 后 IR。

#### F.4 一句话

Slot 实验没证错「28489 → `0x14fcd8` 是 lasting 瓶颈」。

说错的是：把「瓶颈」说成「**+0x120 写进去**」、把「**12407 adc**」说成「lasting 根」、以及用 slot 结果直接等同「**栈几何根因已因果闭合**」——中间 **28489 的 fold 链**和 **lea 上游**还没用实验钉死。

#### G. 若要闭合机制层（下一步；已被 §7.12.21 / §7.12.22 改写）

1. **对拍 405644：** 后续从 `0xe64`/`0x450` 追到 `rdtsc`（§7.12.21）；与某一份 DR 对齐时钉同 TSC 可消该分叉，属预期，**不是**产品修法。slot/`0x14fcd8` 实验仍有效作「充分补丁」演示，但主因口径已转为 TSC。
2. **出口：** 已由 **`memoryPolicyAddress`（§7.12.22）** 闭合；勿再单独 patch `0x3c47d8` 表。
3. **禁止当修法**：`MERGEN_VERIFY_SLOT_FCD8` 作产品解、写死 DR TSC、`STACKP±0x120`、handler 特判 `adc@0x414464`、把 module 差硬减 `0x120`、把「对拍分叉」和「出口解不出」绑成同一修。

### 7.12.21 TSC / `rdtsc` / 出口 `ret@0x33ce78`：对拍分叉 vs 真出不了客户码（两件事）

入口仍 `0x140007450`，`--reg RCX=0x12345678`，dump `entry_7450.dmp`，`MERGEN_MAX_BLOCK_BUDGET=131072`。  
LF：`scripts/dev/run_mix_chase.cmd`（`MERGEN_INSN_STREAM_FILE` / `MERGEN_WRITE_STREAM_FILE`）。  
DR：`vmpdrtrace7` `-entry 0x140007450 -insn <csv>`（见下）。  
一键 chase：`python scripts/dev/chase_mix_diverge.py`。

#### A. 从 405644 往回追到的症状链（与 §7.12.20 并行口径）

对某一趟 DR（`mix_dr_insn.csv`）与某一趟 LF 对拍时：

| 锚点 | 现象 |
|---|---|
| 405644 | 首个 RVA 分叉：`0x3fccd7` vs `0x3f48de`；LF 侧像 `xor …,0x450` 计数偏 |
| 401476 一带 | 最早稳定出现可接到 `0x450` 的 **module Δ=`0xe64`**（`mov r10d,[rbp]` 等） |
| 399914 | `add rcx, rdi`：`rcx` 两边齐，`rdi` 已是 `0x2934` vs `0x3798`（差 `0xe64`） |
| 398562 | `rax` 首次同现 `0x36f`/`0x4a2`；`mul` 把差放大成 `0xe64` |
| 396367 | **`rdtsc` @ `0x37b499`**：两边 `rax/rdx` 低 32 **首次**分叉；仅这两寄存器变 |

**否证：** seq~16348 的 module Δ=`0x120` **不是** 405644 的因（寿命短、量级不是 `0xe64` 的整数倍、当时 CF 仍齐）。  
**否证：** 把「最早任意偏差」当成因果；应对准能造出 `0x450`/`0xe64` 的那条链。

`lift_rdtsc`（`Semantics_Misc.ipp`）：Win32 上 **`__rdtsc()` 真机拍一次**，再冻成 `ConstantInt` 写 EAX/EDX——不是假 stub；和非 Win 的 `tsc=0` 不同。

#### B. 因果实验：钉成「那趟 DR 的 TSC」

临时把 `lift_rdtsc` 写成该趟 DR 的 `EDX:EAX=0x11b2:0xfffc50d7`，重编 + `run_mix_chase.cmd lift-only`：

| 检查 | 活 `__rdtsc` LF vs 该 DR | 钉死同 TSC |
|---|---|---|
| 396367 `rax/rdx` | 不一致 | **一致** |
| 首个 RVA 分叉 | 405644 | **重叠前缀内无** |
| module Δ=`0xe64` / `rcx` 差 `0x450` | 有 | **无** |
| 旧点 405644 | 分叉 | **同 PC，`rcx` 对齐** |

→ **对「和这份 DR insn 金标对拍」而言，TSC 采样不同是 405644/`0x450` 分叉的充分条件。**  
**禁止产品化：** 把某趟 DR 的 TSC 写死进 `lift_rdtsc`（§7.11.14 同禁令）。

#### C. DR 多跑：并非每次都在 seq 407501 回 `0x750c`

```bat
D:\DynamoRIO\bin64\drrun.exe -c D:\sogen\dr\vmpdrtrace7.dll ^
  -entry 0x140007450 -imagebase 0x140000000 ^
  -insn D:\sogen\dr\vmptest\mix_dr_a.csv ^
  -- D:\sogen\dr\vmptest\test_fixed4.exe
```

（再跑一次换 `mix_dr_b.csv`。）五份 mix DR insn（含已有 `mix_dr_insn*.csv` + 新 A/B）：

| trace | 总条数 | 首次 `0x750c` seq | TSC (`eax`,`edx`) | `@0x750c` rax/rcx |
|---|---|---|---|---|
| mix_dr_insn.csv | 425181 | **407501** | `fffc50d7`,`11b2` | `89ca4f1d` / `c029ef1d` |
| mix_dr_a | 425618 | **407938** | `f5ef30e5`,`7f56` | 同上 |
| mix_dr_insn_pre_r12 | 444770 | **427090** | `8be60097`,`359a` | 同上 |
| mix_dr_b | 446157 | **428477** | `bc892c17`,`7f82` | 同上 |
| mix_dr_insn_rerun | 500402 | **482722** | `2a5824fc`,`68b1` | 同上 |

共同点：

- **都会**回到客户码 `0x750c`，再收到 `0x6cd57`
- 回到时 **rax/rcx 固定**；进程打印 `mix(0x12345678) = c5186e29` 固定
- **seq / 圈数随 TSC 变**（与 §7.11.14 `add_only` 的 `dec/jne` 倒计时同一类）

→ **407501 只是某一趟的序号。**  
「DR 每次 TSC 不同但计数器/`mix` 结果仍对」≠「insn 金标圈数不变」；对拍时 TSC 不同导致中途 RVA 分叉是**预期现象**。

#### D. 说错的因果：出口解不出 ret ≠「TSC 导致走错 handler」

| 现象 | 和 TSC 的关系 |
|---|---|
| 与**某一份** DR 在 405644 RVA 对不齐 | **正常**：两边 TSC 不同 → 圈数/路径长度不同 |
| LF 在 `0x33ce78` **解不出 ret、AV、落不到 `0x750c`** | **另一件事**：不是「相对 DR 走错 handler」就能概括 |

**关键证据：** TSC **钉成与 DR 一致**后，405644 分叉消失、RVA 长前缀对齐，但末尾仍出现  
`[rdag] unresolved ret target at 0x4033ce78`（或进 `solvePath` 后 AV）。  
路径已对齐，出口仍折不出来 → **出口具体化失败**，不是对拍分叉本身。

DR 不「解 IR」：任意完整 TSC 自洽跑完，栈上/算完就是 `0x750c`。  
Mergen 必须把同一条 VMP 出口公式在 IR 里折成常数。

#### E. 出口 `ret@0x33ce78`：目标 DAG 与折不动的点

顶层（`[vipret] add-shape`）：

```
ret_target = add i64 %sym, 0x14000750c    ; 0x14000750c == 客户返回 VA
```

要落到 `0x750c`，`%sym` **须为 0**（或等价可折成 0）。  
`%sym` 往下是 `zext/trunc` + `xor/not/add`，最终卡在多次：

```
load i32, gep(%memory, %index*4 + 0x403c47d8)
```

（另有常数址 `0x403c4924` 的 load。）  
`retrieveCombinedValue` 对这些址返回的是 **SSA=`load` 自身**，不是 `ConstantInt`（PE 文件在对应 RVA 上有 dword 表数据）。

`solvePath` 要 `ConstantInt` 目的地 → `PATH_unsolved` / 诊断 `Unresolved ROP chain`；本机还观察到 **AV 发生在 `solvePath` 内部**，事后 `[rdag]` 打不出来。

#### F. 已加诊断（默认开、有上限；定位用）

| 标签 | 位置 | 作用 |
|---|---|---|
| `[vipret]` | `Semantics_ControlFlow.ipp` `lift_ret` | 尤其 `rva=0x33ce78`：是否 CI、buffer、`add-shape` |
| `[rdag] pre-solve` | 同上，**在 `solvePath` 之前** | 防 AV 吞掉事后 dump；LOAD / GEP-idx / `RETRV-*` / `first-blocker` |
| `[ret-tbl]` | `GEPTracker.ipp` `retrieveCombinedValue` | `rva∈[0x3c47d0,0x3c4a00)`：`fileOk`/`promote`/`symRange`/`bufCover`/`mode`/`isCI`（改完后需重跑确认） |

脚本：`scripts/dev/run_mix_chase.cmd`（须保留 `MERGEN_INSN_STREAM_FILE` / `WRITE`）；无这两行则只出 `.out/.err`、无 insn CSV。  
临时分析脚本（勿当产品）：`tmp_compare_fixed_tsc.py`、`tmp_dr_multi_750c.py`、`tmp_run_mix_dr_twice.cmd`、`tmp_chase_*.py`。

#### G. 两层结论（勿混）

1. **对拍层：** LF 活 `__rdtsc` vs 冻住的某趟 DR ⇒ 405644/`0x450` 分叉可由 TSC 不同解释；钉同 TSC 可消该分叉。DR 多跑本身圈数就不固定。  
2. **出口层（已闭合，§7.12.22）：** 根因是 rebased GEP 常数 `0x403c47d8` 查 policy 落在 default SYMBOLIC，不是 PE/overlay 无字节。

#### H. `[ret-tbl]` 钉死的机制（2026-10-08，`mix_ret_tbl_rerun.log` / `mix_policy_fix.log`）

对 `va=0x403c47d8`（`rva=0x3c47d8`）16 次 load，修复前每次：

```
fileOk=1  promote=1  symRange=0  bufCover=0  mode=SYMBOLIC  isCI=0  ir=%… = load i32 …
```

| 字段 | 含义 |
|---|---|
| `fileOk=1` / `promote=1` | 文件/overlay 能读到、`shouldPromoteFileValue` 也会放行 |
| `mode=SYMBOLIC` | **`memoryPolicy.getAccessMode(0x403c47d8)`** 落在 default，不是 `.HjF0` CONCRETE |
| `isCI=0` | `retrieveCombinedValueImpl` 在 `isSymbolic` 分支直接 `extractBytes(Load)`，**从未走进 promote** |

policy 节范围按 **`imageBase + sectionVA` → `0x140…`** 注册；lift 里 GEP 常数在 **rebased `0x40…` 车道**（`LifterDiagHelpers.hpp`）。同一 RVA：

| VA | policy |
|---|---|
| `0x403c47d8` | SYMBOLIC (default) |
| `0x1403c47d8` | CONCRETE (`.HjF0`) |

`normalizeRuntimeTargetAddress(0x403c47d8)` **修不到** `0x1403c47d8`（无 paged 命中则原样返回），所以旧代码在 policy 阶段用错地址。

#### I. 根修（§7.12.22，不是样本 patch）

**`LifterClass.hpp`：`memoryPolicyAddress(addr)`** — rebased `0x40…` → `imageBase + (addr & 0xFFFFFF)`；已在 `imageBase` 上的 VA 不变；栈/堆等其它地址不变。

**`GEPTracker.ipp`：`retrieveCombinedValueImpl` / `createMemcpy`** — 所有 `getAccessMode` / `isSymbolic` / `isRangeFullyCovered` / promote / `isImmutableImageAddress` 均经 `memoryPolicyAddress()`；`readMemory` 先试 policy VA，再 fallback 原地址。`[ret-tbl]` 诊断增加 `policyVa=…`。

**禁止当修法：** 给 `0x3c47d0..0x3c4a00` 特判 CONCRETE、在 `ret@0x33ce78` hook 读表、写死 DR TSC。

#### J. 修复后验证（`vmptest`，`--reg rcx=0x12345678`，`MERGEN_MAX_BLOCK_BUDGET=131072`）

| 检查 | 修复前 | 修复后 |
|---|---|---|
| `[ret-tbl]` | `mode=SYMBOLIC isCI=0` | **`mode=CONCRETE isCI=1`**（表 dword 为 `ConstantInt`） |
| `[vipret] @0x33ce78` | `isCI=0`，`[rdag] first-blocker=load` | **`isCI=1`**，`realval=0x14000750c` |
| 客户出口 | 落不到 `0x750c` / AV | **`[ret] at 0x140007518 rop=1`** |
| `output.ll`（O2） | `bb1: br bb1` 死循环（§7.12.17） | **`ret i64 3306712617`**（`0xc5186e29` = `mix(0x12345678)`） |
| lift 规模 | — | **46044 blocks / 432814 insns**，0 diagnostic error |

日志：`build_msvc_dbg/mix_policy_fix.log`。产物：`output.ll` / `output_no_opts.ll` / `output_diagnostics.json`（2026-10-08 14:08）。

**IR「没还原」的口径：**

| 文件 | 期望 |
|---|---|
| `output_no_opts.ll` | **不会**收成可读 C/ mix 源码；~31MB / 4 万+ block 的 VM handler 图是设计（debug 用） |
| `output.ll`（O2） | **语义还原**看这里；本跑 = `ret i64 3306712617`（`0xc5186e29`） |
| vs §7.12.17 | 修复前 O2 是 `bb1: br bb1` 死循环；修复后是正确常数 ret |

`--reg rcx=0x12345678` 把入口钉死 → O2 **整路径 constant-fold** 成单个 `ret i64`（对比 `add_only` 仍保留 `add %RCX,%RDX; and` 是因为 RCX/RDX 保持符号）。要看带 `%RCX` 的公式形 IR，需**无 `--reg`** 再 lift。

Lift 命令（PowerShell，日志重定向）：

```powershell
$env:MERGEN_MAX_BLOCK_BUDGET='131072'
cd D:\sogen\dr\refs\Mergen\build_msvc_dbg
.\lifter.exe D:\sogen\dr\vmptest\test_fixed4.exe 0x140007450 `
  --mem-dump D:\sogen\dr\vmptest\entry_7450.dmp --reg rcx=0x12345678 `
  *> mix_policy_fix.log
```

或 `scripts\dev\run_mix_chase.cmd lift-only`（会写 insn/wr 流）。

进程 exit code 仍可能为 `0xC0000005`（客户 `ret` 之后的尾巴），与 IR 已写出、诊断 0 error 不矛盾。

### 7.12.22 `memoryPolicyAddress`：rebased 映像 VA 与 MemoryPolicy 对齐（根修）

**问题：** lift 重基到 `0x40000000` 车道（§7.12.8 / `LifterDiagHelpers.hpp`），但 `configureDefaultMemoryPolicy` 把节注册在 `imageBase+RVA`（`0x140…`）。`retrieveCombinedValueImpl` 用 **原始 GEP 地址** 查 `isSymbolic` → rebased `0x403c47d8` 命中 default SYMBOLIC，即使 `file.readMemory`/`promote=1` 仍只回 `LoadInst`（§7.12.21.H–I）。

**修法：** `LifterClass.hpp` 新增 `memoryPolicyAddress()`；`GEPTracker.ipp` 的 policy/promote 路径统一经它。与 `PathSolver.ipp` 里 `file.imageBase + fetchRva(addr)` 多候选读文件同一地址模型，不是 mix 表特判。

**验收：** §7.12.21.J。mix `--reg rcx=0x12345678` 时 `output.ll` = `ret i64 0xc5186e29`。

#### K. §7.12.22 后无 `--reg` 重跑（2026-10-08，验证 §7.12.19 停点是否仍在）

**命令：**

```powershell
$env:MERGEN_MAX_BLOCK_BUDGET='131072'
$env:MERGEN_INSN_STREAM_FILE='D:\sogen\dr\refs\Mergen\build_msvc_dbg\mix_noreg_insn.csv'
cd D:\sogen\dr\refs\Mergen\build_msvc_dbg
.\lifter.exe D:\sogen\dr\vmptest\test_fixed4.exe 0x140007450 `
  --mem-dump D:\sogen\dr\vmptest\entry_7450.dmp *> mix_noreg_lift.log
```

（**不要** `--reg`。DR 金标：`vmptest\mix_dr_insn.csv`。）

| 指标 | LF（无 `--reg`） | DR |
|---|---|---|
| insn 条数 | **301739**（末条 `0x3ec79e`） | 425181 |
| 块 / 指令（diagnostics） | **31336 / 301740** | — |
| 前 301739 RVA | **与 DR 100% 对齐**（`chase_mix_diverge`：`first_rva_diverge: none`） | 同 seq 同 RVA |
| exit | 0 | — |

**两次 `ret @0x3ec79e`（与 §7.12.19 同）：**

| 次序 | insn seq | LF | DR 下一跳 |
|---|---|---|---|
| 第一次 | **224254** | `[dest-dag] const dest=0x402e8e10` **过** | 继续 |
| 第二次 | **301739** | `[rdag] unsolved ret target` / 诊断 **201** `Unresolved ROP chain` | seq 301740 → **`0x2feda7`** |

第二次卡住的 **不是** `0x33ce78` 出口表（那是 `--reg` 路径末段；`memoryPolicyAddress` 已修）。`first-blocker` 是 **栈上 symbolic load**（`select` 控 FLAGS 选槽址），DAG 经 `%RCX` 相关 xorshift/flags 链，与 §7.12.19「第二次 ret 依赖符号 `%RCX`」同线。

**O2 `output.ll`（无 `--reg`）：** 入口 `%RCX` 上折出一段 xorshift/NAND，但 **`ret i64 undef`**——路径在第二次 `0x3ec79e` 未闭合，语义未还原到 `mix(RCX)`。

**结论：** §7.12.22 **不**改变无 `--reg` 的 **≈301739** 停点；出口层 fix 与「产品路径二次 ret + 符号 RCX」是两条线。下一步仍是无 seed 的 VIP/栈槽取回（§7.12.19.D），不是再 patch 表地址。

> **⚠️ 本节结论已被 §7.12.23 取代。** 「二次 `ret@0x3ec79e` 依赖符号 `%RCX`」不成立：派发链内没有 `%RCX`。真实根因是游标 push（rva `0x2e7bb2`）的源操作数 `rbp` 算成两臂 `select`。本节仍然有效的只有：insn/块数基线（301740±1 / 31336±1）、RVA 前缀与 DR 100% 对齐、以及「表读折不动 ≠ 出口层」这个分层的必要性。

日志/产物：`mix_noreg_lift.log`、`mix_noreg_insn.csv`、`output_diagnostics.json`（warning 201 @ `0x403ec79e`）。

### 7.12.23 根因：无 seed 停点是**游标 push 的源操作数 `rbp` 是两臂 `select`**（干预实验已验证）

入口 `0x140007450`，dump `entry_7450.dmp`，`MERGEN_MAX_BLOCK_BUDGET=131072`，**无 `--reg`**。

> **本节推翻 §7.12.19.A / §7.12.22.K 的口径**：那两节把停点归到「二次 `ret@0x3ec79e` 依赖符号 `%RCX`」。
> **实测 `%RCX` 与本停点无关**，详见下面「已否证」表。`%RCX` 是 ABI 第一参，必须保持符号。

#### A. 出口目标的真实公式（纯控制域，两次 visit 逐位验证）

`ret @0x3ec79e`（`push r8 ; ret`）的目标 = `0x39ab25 + sext32(decode(...))`：

```
0x39ab09  mov r9, rbx
0x39ab0f  movabs rbp, 0
0x39ab19  sub r9, rbp
0x39ab25  lea r8, [rip-7]          ; r8 = 0x39ab25（自地址常量，两侧恒等）
0x39ab2c  mov ecx, [rbx]           ; ★ 明文 pcode dword（rbx = 游标，rbx+4 是下一条）
0x39ab2e  add rbx, 4
0x39ab35  xor ecx, r9d             ; r9d = 低32(rbx - rbp)
0x39ab38  dec ecx
0x39ab3a  rol ecx, 0x13
0x3d87c8  dec ecx
0x3d87ca  ror ecx, 0x12
0x395b6e  movsxd rcx, ecx
0x3b046a  add r8, rcx              ; ★ 目标
0x3ec79c  push r8 / 0x3ec79e ret
```

验证：按此式**反向回代** visit1 得 `d = 0xbfdb1c8f`，与 DR 在 `0x39ab2c` 之后实测的 `ecx` **逐位一致**（`r9d = 0x40218df9`）。两次 visit 目标分别 `0x2e8e10` / `0x2feda7`，验算 `0x39ab25-0xB1D15` / `0x39ab25-0x9BD7E` 全中。

**`r8` 不是控制域量**（只是 `lea r8,[rip-7]` 的自地址，两侧全程相等）；控制域量是 `rcx`（解码出的派发偏移）。

#### B. 断链：游标从 native 栈 pop 回来时是符号

游标由 **push** 存、由 dispatcher **pop** 取，是同一槽 `[rsp+rsi]`（`rsp=STACKP-0x240`, `rsi=0xa8`）：

| rva | 指令 | DR | lifter |
|---|---|---|---|
| `0x2e7bb2` | `mov qword ptr [rsp+rsi], rbp` | `rbp` = **游标** rva `0x21ac17` | `rbp` = **`select`** |
| `0x3ead9b` | `mov r10, qword ptr [rsp+rsi]` | `0x7ff7a357ac17` | 符号 |

DR 侧用 `-trackmem` 直接钉死（`vmpdrtrace7 -trackmem`，同一趟还出 `-insn`）：

```
W,26632,300372,0x7ff63d067bb2,0xa80f7bf928,8     映像基址 0x7ff63cd80000 → 写者 rva 0x2e7bb2
R,26632,301660,0x7ff63d1829fd,…                  → pop @ rva 0x3ead9b
```

同趟 `-insn` 流 seq 300372 处 **DR `rbp = 0x7ff63cf9ac17`（rva `0x21ac17`）= 游标**；seq 301661 起 `r10` 取回同一值。

lifter 侧 `MERGEN_DIAG_SLOTSTORE2`（只听 rva `0x2e7bb2` / 槽 `0x14fd08`）实测，该次被存值：

```
isCI=0  peeled=0
value_ir= %lol-274501 = select i1 %188393, i64 5370915863, i64 5370915584   (= 0x14021AC17 / 0x14021AB00)
select cond_ir= %188393 = icmp eq i64 %shr-lshr-1076950142-, 0   cond_peel=0 true_peel=1 false_peel=1
```

`%188393` 同时就是 `[rdag] first-blocker` 里那条 GEP 索引的 select 条件 —— **槽里存的和出口读的是同一个值**，不是两件事。

**因此失效链**：`rbp`（装游标，控制域量）算成两臂 `select` → store 记 SSA → pop 读回符号 → `mov ecx,[rbx]` 地址非常数（**读都没发生**）→ 解码链全符号 → `add r8,rcx` 符号 → `push r8;ret` 交不出目标 → warning 201。

#### C. 干预实验（`MERGEN_VERIFY_SLOT_FD08=<qword>`）

在 rva `0x2e7bb2` / 槽 `0x14fd08`，**当且仅当**被存值是 `SelectInst` 时替换为一个具体 qword。全程只触发 1 次，其余 37 次 visit 不动。

| | 无干预 | 强制 DR 真值 `0x14021ac17` | **负对照**：强制 select 臂 `0x14021ab17` |
|---|---|---|---|
| insns | 301740 | **440111** | 301740 |
| blocks | 31336 | **47197** | 31337 |
| `201 @0x403ec79e` | 有 | **消失** | 无（但走不下去） |
| seq 301736 的 `rcx` | `-` | **`0xfffffffffff64282`** = DR | `0x7d02941b`（具体但错） |
| 派发目标 | 符号 | **`0x402feda7`** = DR | `0xbd3c3f40`（模块外垃圾） |
| 与 DR 的 RVA 前缀 | 301739 | **405643** | 301739 |

- **充分性成立**：只改这一个值 ⇒ +138k insns、warning 201 消失、与 DR 对齐到 405643。
- **唯一分叉在 seq 405644**，即 §7.12.20.A / §7.12.21.B 已钉死的 `rdtsc` 采样差异（钉同 TSC 即消），**不是 lifter 缺陷**。
- **负对照**：塞 select 的臂会让解码器忠实算出**错误但具体**的目标，lift 原地不动 ⇒ 起作用的是**值的正确性**，不是「具体性」。
- **跨趟复现**：6 趟 DR（ASLR/TSC 各不同，`mix_dr_insn{,_a,_b,_rerun,_pre_r12}` + `mix_tm_insn`）中，rva `0x2e7bb2` 各被访问 **38 次**，其中**恰好一次**（都是 seq 300372）`rbp` 是模块内游标、低 32 位全为 `0x21ac17`；其余 37 次都是 FLAGS 族（`0x202/0x206/0x213/0x246/0x257/0x282/0x286/0x292`），与 lifter 写该槽的值谱完全吻合。⇒ 不是 TSC 抖动、不是 ASLR 假象。
- **默认回归**：不带 env 探针输出 0 行，停点不变。

#### D. 附带成果：**无 `--reg` 还原出 `mix(RCX)` 公式**

强制正确值那一趟的 O2 `output.ll`（`%RCX` 保持符号）：

```llvm
%0 = trunc i64 %RCX to i32
  ... 8 轮 xorshift (shl 13 / lshr 17 / shl 5) ...
%realxor = xor i32 %shl-shift380734, %24
%25 = zext i32 %realxor to i64
ret i64 %25
```

`[ret] at 0x4033ce78 disp=-48`（§7.12.21.E 的出口表那一次，现在解析开了）→ `[ret] at 0x140007518 rsp=0x14fea0 disp=0 rop=1`（**客户函数返回**）。

回代验证 IR 公式 = `test.cpp` 的 C 实现 = DR 实跑打印值：`mix(0x12345678) = 0xc5186e29`（另 3 个种子也对上）。

**⇒ §7.12.17 记为「从未达成」的「无 `--reg` 拿到带 `%RCX` 的公式形 IR」已达成。**

#### E. 已否证 / 已撤回（勿重复排查）

| 说法 | 否证方式 |
|---|---|
| 停点根因是 `%RCX` 符号 | **已否证。** 种子化后 lifter 算出的游标与真机逐位一致（`0x14021AC17` = rva `0x21ac17`），且**多个种子给出同一游标** ⇒ 游标是常量。**把符号 DAG 离线求值，5 个种子全部得到 `0x14021AC17`** ⇒ IR 是对的，只是折不出条件。见 §7.12.23.F.1b |
| 明文 pcode 不在 dump / 数据不可得 | 读地址是进入 handler 时的 `rbx`（**不是 `rbx+4`**）：visit1 rva `0x218df9`（明文 `0xbfdb1c8f`）、visit2 rva `0x21ac17`（明文 `0x3fdaed55`），**两处在 `entry_7450.dmp` 里都精确命中**。lifter 对这两个地址 **0 次 store**（不是自己解出来的） |
| `r8` 是控制域量 | 只是 `lea r8,[rip-7]` 的自地址常量，两侧全程相等 |
| `[rdag] first-blocker` 的 `select` 是「可 fork 的虚拟化 dispatch 谓词」，与槽无关 | 它就是槽里存的那个值（同一 `%188393`）；两臂是候选游标，差 `0x17` |
| 「lifter 把游标写进错槽、slot 身份漂移 `0x160`」 | `0x2e7bb2` 用 `[r11+8]`、`0x3ead9b` 用 `[rsp+rsi]`，**在 DR 上也差 `0x160`**（rsp+0x190 vs rsp+0xa8），本就是不同槽、发生在不同时刻。`r11-rsp` 全程恒比 DR **少 `0x8`**（§7.12.5 已否证的那 8 字节伪栈偏移），与本停点无关 |
| 是 `peel`/cast 丢常数（§7.12.9(2)/§7.12.10/§7.12.13 那条路） | 被存值是 `select`，`peelToConstantInt` 拒绝是正确的（条件不唯一）；两臂都已是 `ConstantInt` |
| 是 `MERGEN_DIAG_SLOTSTORE2` 探针本身扰动 | 默认回归：0 行输出、停点不变（301740±1，`rdtsc` 活采样导致 ±1 抖动） |

#### F. 为什么 lifter 的 `rbp` 是 `select`：缺的是**代数化简**（`%RCX` 只是可被消去的叶子）

`MERGEN_DIAG_RBPDAG=1` 打出 `rbp` 在 `0x2e7bb2` 处的完整 use-def（深度放到 3000）：

- **922 个节点，0 个 `load`，外部叶子只有一个：`%RCX`。**
- 链的内部是 `shl/lshr` + `xor -1`（`realnot`）+ `and`（`realand`）+ 一整套 **RFLAGS 重建**（`%creatingrflag*` = `or/shl/zext` 逐位拼 CF/PF/AF/ZF/SF/OF；`%pf*` 用 `mul 72340172838076673` + `urem 511`；`%sub_af*` 来自 `shld`）→ 末端一个 flag 测试 → 两臂 `select`。

**判定（`--reg rcx=0x12345678`，`build_msvc_dbg/rcxseed.log`）：**

| 检查 | 结果 |
|---|---|
| seq 300372 `rbp` | LF `0x14021ac17` = DR rva `0x21ac17`，**逐位一致** |
| seq 301736 `rcx` / `r8` | `0xfffffffffff64282` / rva `0x39ab25`，与 DR 一致 |
| 规模 / 告警 | 53763 blocks / 481701 insns，**0 个 `201`** |

⇒ **那条链（含 RFLAGS 重建）算术完全忠实，没有语义 bug。**

#### F.1 但「符号 `%RCX` 下游标不是常数」是错的 —— 游标是**常量**

用 lifter 自己测（链已证明忠实，所以它算出的就是机器会算的）：

| seed | 游标 `rbp` @`0x2e7bb2` | 派发偏移 `rcx` @`0x3b046a` |
|---|---|---|
| `0x12345678` | `0x14021ac17` | `0xfffffffffff64282` |
| `0xdeadbeef` | `0x14021ac17` | `0xfffffffffff64282` |

（序号不同：300372 vs 300250；**值完全相同**。`0x00000000` 那趟路径不同、36 次 visit，没走到该点。）

⇒ **游标与参数无关。** 那 922 节点链虽然唯一叶子是 `%RCX`，但它的**参数依赖是可代数消去的**（VMP 拿参数做了能抵消的混淆）。所以：

- **不是**数据依赖的控制流，**不是**方法边界，**不需要**控制域枚举，**不需要** seed。
- **是**一个可修的缺陷：**lifter 折不出条件 `%164868`**（F.1b 证明 IR 本身正确、值恒定）。修法见 F.3：**① 自底向上化简后重试**（首选，单路径）或 **② 对「条件符号 + 两臂具体」的 `select` 做 2 路 fork**（通用兜底，§5.5 本来就有这个机制）。

#### F.1b 离线求值证明：**IR 是对的，缺的是折出条件**

把 `MERGEN_DIAG_RBPDAG` 打出的 922 节点锥用 `tmp_eval_dag.py` 离线求值（只代入 `%RCX`，其余按 IR 语义算）：

| seed | 求值出的 `rbp` |
|---|---|
| `0x12345678` / `0xdeadbeef` / `0x00000000` / `0xffffffff` / `0x00000001` | **全部 `0x14021AC17`**（= DR rva `0x21ac17`） |

根节点是

```
%lol-… = select i1 %164868, i64 5370915863, i64 5370915584
                        = 0x14021AC17      = 0x14021AB00
%164868 = icmp eq i64 %shr-lshr-1076950142-, 0        → 5 个种子下恒为 1
```

⇒ **真值就是臂 1。** 两臂都是合法 pcode 游标（`0x21AC17` / `0x21AB00`，后者在 seq 301696 处正是 `rbx`）。

⇒ **这是「折不动」，不是「算错」**：IR 是正确的编码（一个看似依赖 `%RCX`、实则恒定的函数），lifter 只是折不出条件 `%164868`。

⇒ 由此**两条修法都成立**：
- **折叠**（更优）：条件折成常数 ⇒ 直接取臂 1，单路径。离线求值证明了只要做自底向上化简就一定折得出来（对种子不敏感）。
- **fork**（通用兜底）：条件符号、两臂都是具体控制值 ⇒ 按 §1/§5.5 的 `ltJmpWithFlag` 机制分两路。代价是每臂深拷 `buffer`（§7.10 的 OOM 风险），但 2 路是有界的。

**⚠️ 进制错误教训（勿重复）**：`5370915863` 是 **`0x14021AC17`**，不是 `0x14021AB17`。本节此前据手算得出「真值不在两臂里 ⇒ fork 不行 ⇒ 需控制域枚举」，**该结论已作废**。十六进制换算一律用工具，不要手算。

#### F.2 为什么折不动

| 环节 | 行为 |
|---|---|
| `IRBuilder` 用 `ConstantFolder`（§4.6 从 `InstSimplifyFolder` 换掉） | **局部**折叠：只有操作数**已经**是 `ConstantInt` 才折 |
| 这条链 | 中间**没有任何一步是常数**（全是 SSA），从根往下折不动 |
| `PathSolver.cpp` `getConstraintVal` | 已经试了 `ConstantFoldInstruction` + `simplifyInstruction`，但只作用在**根节点**；根是条件为符号的 `select`，操作数还是 SSA ⇒ 产不出常数。**没有自底向上的传播** |

#### F.3 修法（两条，都待实现 / 接通）

**① 折叠（首选，单路径）** —— 在 `lift_ret` 第一次 `PATH_unsolved` 时，对弹出值的**操作数锥**做**自底向上**的 `simplifyInstruction` + `RAUW`（子节点先于父节点，迭代到不动点），把中间节点塌成 `ConstantInt`，重取槽值后重试 `solvePath`。
F.1b 证明**数学上**一定折得出来（离线求值对 5 个种子都给出臂 1）；**但 LLVM 层面的实现尚未打通，见下方尝试记录**。

> **⚠️ 实现尝试记录（2026-10-08，均已回退，`PathSolver.cpp` 回到 HEAD）**
>
> | 尝试 | 结果 |
> |---|---|
> | 自底向上 `simplifyInstruction` + `RAUW`（含自写 `trunc(zext(x))→x` / `zext(trunc(x))→x` 恒等折叠） | 折了 **241 个节点后停滞**在 `%RCX` 处。锥的 80.9%（729/901）是 `zext`/`trunc`，真实算术只有 ~90 个节点，且它们**只能靠重结合消去** —— 逐指令局部折叠做不到。**诊断成立，实现路线不通。** |
> | 直接对活函数跑 `InstCombinePass` | **不安全**：InstCombine 会折掉并 `erase` 根 `select`，而 `solvePath` 仍持有 `simplifyValue` ⇒ use-after-free（§4.6 同类坑）。已放弃。 |
> | 把锥克隆进临时函数做沙箱 `InstCombine` | 能跑，但**结果不可信**：停点反而提前到 221161（比 301740 更差），并产出地址为 `0x140000000` 的伪告警 —— 回读逻辑取到了无关常数。已放弃。 |
>
> **诊断（缺代数化简）成立，但「用 LLVM 做重结合」这条实现路线尚未打通。** 若继续，正确的形态是**在 lift 期间维持常量性**（§4.6 换 `ConstantFolder` 正是因为 `InstSimplifyFolder` 会删指令），而不是在 transfer 失败时补救 —— 后者已被证明既不够又容易踩生命周期问题。

**② fork（通用兜底，2 路）** —— 转移目标是「条件符号 + 两臂都是具体控制地址」的 `select` 时，按 §1/§5.5 的 `ltJmpWithFlag` 机制分两路，而不是要求单值。**这条本来就在设计意图里**（§5.5 虚拟化条件 fork），只是当前没有覆盖「`select` 经栈槽往返后才被 pop」这种形态。**尚未实现**；F.1b 已确认臂 1 就是真值，所以 fork 出的两条路里有一条是真机走的那条。

- 两条都只加在失败路径、可用 env 门控 ⇒ 默认行为不变。
- 与 §7.12.18 的教训一致：`peel` 只修"宽度不够"，缺的是**真正的化简**（①）。
- **验收**：无 `--reg` 的 mix 从 301740 前进（预期到 §7.12.23.D 那一档：`output.ll` = `mix(RCX)` 公式 + `[ret] rop=1`），且 add `0x140007210` 不回归。

**禁令（补）**：不要给 RFLAGS / `shld` 结果做分字节 overlay（§7.12.7 已证明会让 jcc 走错 handler）；不要把 `%RCX` 具体化当修法；**不要**做控制域枚举（游标是常量，枚举无意义且会 OOM，§7.10）；**不要**因为"两臂"就断定 fork 不行——臂 1 就是真值（见 F.1b 的进制教训）。

**禁令（新增）**：写死 `0x14021ac17` 当修法、给 `0x14fd08` / rva `0x2e7bb2` 特判 CONCRETE、在 `ret@0x3ec79e` hook 读槽、把 `%RCX` 具体化、unique-fold、`STACKP±8`、`GetRFLAGSValue |= 0x202`、写死 DR 的 TSC。

日志/产物：`build_msvc_dbg/vfd08_ok.log` + `vfd08_ok_insn.csv`（正确值）、`vfd08_bad.log` + `vfd08_bad_insn.csv`（负对照）、`default_regress.log`、`slotstore2.log`、`cursor.log` + `cursor_wr.csv`、`rcxseed.log`、`rbpdag4.log` + `dag_nodes.txt`；DR 侧 `vmptest/mix_tm_{insn,mem}.csv`。

分析脚本（**勿当产品**）：`tmp_dr_cursor_writer.py`（DR 侧定位 `0x3ead9b` 那个槽的写者）、`tmp_eval_dag.py`（离线求值 `MERGEN_DIAG_RBPDAG` 输出的 DAG；用法 `python tmp_eval_dag.py <dag_nodes.txt>`）。

### 7.12.4 早期 `movabs` / overlay（已否证为「把 PC 拓宽就能修 mix」）

seq 43 `0x3e28a1` `movabs rbx, imm64`：dump 已是 `0x7ff5e0460000`，文件是 0。lift rbx=0。拓宽 PC / 拒 FileReader underflow 后 mix 的 movabs 对了，但 add 从 ~26069 块客户 `ret` 塌成 11 块 Unresolved ROP。已 `git checkout HEAD -- FileReader.hpp LifterClass.hpp LifterStages.hpp`。mix 前 221160 条 PC 仍对齐，停在 7.12.5→7.12.3，不是取指 RVA 分叉。

## 7.8 诊断基础设施（默认关闭，零输出）


| 环境变量 | 产物 | 用途 |
|---|---|---|
| `MERGEN_INSN_STREAM_FILE` | 全指令快照 `I,seq,rva,rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp,r8..r15` | 与 DR `-insn` 按 RVA 对齐；默认关 |
| `MERGEN_REG_STREAM_FILE` | 寄存器写流 `REG,seq,insn,reg,isconst,value` | 查"谁把某寄存器写成某值" |
| `MERGEN_WRITE_STREAM_FILE` | 写流 `W,seq,insn,slot,size,value` | 与 DR `-trackmem` 写侧对齐 |
| `MERGEN_READ_STREAM_FILE` | 读流 `R,insn,addr,size_bits` | 与 DR `-trackmem` 读侧对齐 |
| `MERGEN_DIAG_BYTE` | 单指令字节读 | 只听 `0x14033578E` |
| `MERGEN_DIAG_SSA58` | 真实 SSA use-def 上溯 | 深度 8 / 200 节点上限 |
| `MERGEN_DIAG_RFLAGS` | 哪些 flag 位是符号 + 其 IR | 只听 `pushfq` @`0x396B77` 与 `0x14fe6{0,6,8}` / `0x410840` 几个槽（§7.12.8） |
| `MERGEN_DIAG_SLOTSTORE` | store 操作数的真实 IR 类型 | 只听 `0x14fe68` / `0x14fe70` 两个 qword 槽（§7.12.10、§7.12.12） |
| `MERGEN_DIAG_PEEL` | cast 折叠生效处 | 打印 `peelToConstantInt` 折成的值（§7.12.13；实测在 mix 上触发 0 次） |
| `MERGEN_DIAG_VIP` | VIP cursor / transfer pick | `=1`：`[vipcur]`/`[vippick]` + 可疑 `[vipload]`；`=2`：全量 module 读。见 §7.12.19 |
| `MERGEN_VERIFY_SLOT_FCD8=1` | stderr `[verify-slot-fcd8]` | **因果实验**：rva `0x2eeeae` 写 `0x14fcd8` 强制 `0x14042b24f`；405644 对齐。见 §7.12.20.B |
| `MERGEN_VERIFY_LOAD_FCD8=1` | stderr `[verify-load-fcd8]` | rva `0x3c048f` 读 `0x14fcd8` 强制 DR 值；本 trace 未到 405644。§7.12.20.C |
| `MERGEN_VERIFY_LEA_CX=1` | stderr `[verify-lea-cx]` | rva `0x406f2d` 仅当 lea 已是 `ConstantInt` 时强制 cx=`0xfc80`；SSA 不触发。§7.12.20.C |
| `MERGEN_DIAG_FCD8_STORE=1` | stdout `[fcd8-store]`（≤3 visit） | rva `0x2eeeae` store 的 IR/reg + use-def；visit=1 多为裸常数。§7.12.20.C |
| `MERGEN_DIAG_SLOTSTORE2=1` | stdout `[slotstore2]` | **mix 根因探针**：rva `0x2e7bb2` / 槽 `0x14fd08` 的 store 操作数形态 + `rbp` 形态 + select 三段 peel。§7.12.23.B |
| `MERGEN_DIAG_CURSOR=1` | stdout `[cursor-w]` / `[cursor-r]` | 全部「游标形状」（`0x140…`/`0x40…`）的写 + 槽 `0x14fd08` 的全部读。用来证明「游标从未进过该槽」。§7.12.23.B |
| `MERGEN_VERIFY_SLOT_FD08=<qword>` | stdout `[verify-slot-fd08]` | **因果实验**：rva `0x2e7bb2` / 槽 `0x14fd08` 且被存值是 `select` 时强制写该 qword。传 DR 真值 `0x14021ac17` 验充分性；传 select 臂 `0x14021ab17` 做负对照。**不是修法**。§7.12.23.C |
| `MERGEN_DIAG_RBPDAG=1` | stdout `[rbpdag]` | rva `0x2e7bb2` / 槽 `0x14fd08` 处 `rbp` 的**完整 use-def**（深度 3000 / 60000 节点上限）。用来证明「该 select 的唯一外部叶子是 `%RCX`，链内 0 个 load」。§7.12.23.F |

**两条流共用 `nextMemEventSeq()`（`mergen_events::memEventSeq`）**，
序号在同一执行轴上，可按 seq 合并成一条时间线 —— 这是定位
「某条 store 执行时各寄存器是什么」的唯一手段（源码：`LifterClass.hpp`
的 `SetRegisterValue_internal` 与 `GEPTracker.ipp` 的 `addValueReference`）。

**DR 侧**：`D:\sogen\dr\vmpdrtrace.c` 已加 `-insn <file>`（与 `MERGEN_INSN_STREAM_FILE` 同行格式，指令前快照，RVA 对齐，列含 `r12..r15`）和 `-r8 <file>`，输出
`R8,<rva>,<r8>,<r10>`；探针白名单含 R8 解密链的 5 个站点
（`0x3E957E/0x3E9588/0x3E95A2/0x3E95A9/0x3E95C0`），以及
`0x3B4FF9/0x3B501C`、`0x301D45/0x2E6FF6/0x2E7043`（§7.11）。
构建脚本：`D:\sogen\dr\build_vmpdrtrace7.bat`（输出 `vmpdrtrace7.dll`）。
旧 15 列（止于 `r11`）CSV 仍可被 tracer 读；新抓的 19 列才能直接对 `push r12` 等。

lifter 侧默认会打 `[tramp]` / `[vip] pre`（定位用，未关）。不要开 `MERGEN_DIAG_LIFT_PROGRESS`。

**所有按指令卡点的探针都必须比 `maskedRVA(va)`，不能比裸地址。** lift 把映像重基到
`0x40000000`，写死 `0x140000000` 的探针在重基 lane 上静默不触发——0 命中看起来像
「那段代码没执行」，实际是基址不匹配（§7.12.8 踩过）。`OperandUtils.ipp` 提供了
「怎么修」的当前状态见 §7.12.13（cast 折叠实测无效）、§7.12.15（167342 的 `0x206` 是 shld 在已符号 dword 上的 FLAGS）、§7.12.16（`0x98fb1a05` 是嵌套 32-bit NAND）、§7.12.17（`--reg rcx` 诊断）、§7.12.19（无 `--reg` 卡 ≈301739 二次 `ret@0x3ec79e`）、§7.12.20（`0x14fcd8` slot 实验）、§7.12.21（TSC 对拍 vs 出口层）、§7.12.22（`memoryPolicyAddress` 根修）、**§7.12.23（根因：无 seed 停点是游标 push `0x2e7bb2` 的源操作数 `rbp` 算成两臂 `select`；干预实验已验证充分性 + 负对照 + 6 趟 DR 复现；且已还原出 `mix(RCX)` 公式 —— 与 `%RCX` 无关）**。§7.12.14 的 SSA `%134186`/`%138038` 不是当前主线。

**⚠️ 读 §7.12.19.A / §7.12.22.K 前先读 §7.12.23**：那两节把停点归到「依赖符号 `%RCX`」，已被 §7.12.23.E 实测否证（派发链内没有 `%RCX`）。

**别拿 DR 的寄存器值当基准**：DR 是真机进程状态（入口 `rbx=0x1fc45d23d40`、`rsp=0x11eb8ffe08`），lifter 是空寄存器 + 伪栈 `rsp=0x14fea0`。两条流 RVA 100% 对齐，但寄存器从第 0 条就不同，这是设计如此。「DR 有 X / lift 无」不是缺陷证据（§7.12.11 实测否证）。

**别用正则抽象 IR 形态再分类**：§7.12.12 就是这么错的——`re.sub(r"%?\d+", "N", ir)` 把 SSA 名字和类型宽度一起替换，于是 `trunc i64 %x to i32` 被读成「源操作数是常数」。要按**操作数结构**分类，不是按字符串形状。

`maskedRVA` / `flagBitNames` / `irText` 三个 helper 现在在
`lifter/core/LifterDiagHelpers.hpp`（因为 `OperandUtils.ipp` 与 `GEPTracker.ipp` 互相
include，helper 不能只放在其中任一处）。

## 8. 待清理

- 调试件：`build_msvc_dbg\vipfix*.out`、`run_*.out`（十余个 GB 级）、
  `vmptest\probe_regs.txt`、`vmptest\r8.*`、`vmptest\rstream.*`、`vmptest\wstream.*`
- **已删除**：`dumpFoldOrigin` 函数及其 4 个调用点（它读 `foldOrigin` 记账表，
  与真实 use-def 链不符，且递归无输出预算 —— 实测占日志 97%，单次运行可达 2GB）。
  删后默认运行日志 2.6MB。
- `Semantics_ControlFlow.ipp` 的 `dumpedVipDag < 0` 应还原为原作者的 `< 8`。
- `Includes.h` 的 `STACKP_VALUE` 注释应还原（值已还原 `0x14FEA0`）。
- 收尾按仓库规范：`clang-format` 改动文件；完成后跑 `cmake --build --preset=tidy`。
