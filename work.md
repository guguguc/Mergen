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

## 7.8 诊断基础设施（默认关闭，零输出）

| 环境变量 | 产物 | 用途 |
|---|---|---|
| `MERGEN_INSN_STREAM_FILE` | 全指令快照 `I,seq,rva,rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp,r8,r9,r10,r11` | 与 DR `-insn` 按 RVA 对齐；默认关 |
| `MERGEN_REG_STREAM_FILE` | 寄存器写流 `REG,seq,insn,reg,isconst,value` | 查"谁把某寄存器写成某值" |
| `MERGEN_WRITE_STREAM_FILE` | 写流 `W,seq,insn,slot,size,value` | 与 DR `-trackmem` 写侧对齐 |
| `MERGEN_READ_STREAM_FILE` | 读流 `R,insn,addr,size_bits` | 与 DR `-trackmem` 读侧对齐 |
| `MERGEN_DIAG_BYTE` | 单指令字节读 | 只听 `0x14033578E` |
| `MERGEN_DIAG_SSA58` | 真实 SSA use-def 上溯 | 深度 8 / 200 节点上限 |

**两条流共用 `nextMemEventSeq()`（`mergen_events::memEventSeq`）**，
序号在同一执行轴上，可按 seq 合并成一条时间线 —— 这是定位
「某条 store 执行时各寄存器是什么」的唯一手段（源码：`LifterClass.hpp`
的 `SetRegisterValue_internal` 与 `GEPTracker.ipp` 的 `addValueReference`）。

**DR 侧**：`D:\sogen\dr\vmpdrtrace.c` 已加 `-insn <file>`（与 `MERGEN_INSN_STREAM_FILE` 同行格式，指令前快照，RVA 对齐）和 `-r8 <file>`，输出
`R8,<rva>,<r8>,<r10>`；探针白名单含 R8 解密链的 5 个站点
（`0x3E957E/0x3E9588/0x3E95A2/0x3E95A9/0x3E95C0`），以及
`0x3B4FF9/0x3B501C`、`0x301D45/0x2E6FF6/0x2E7043`（§7.11）。
构建脚本：`D:\sogen\dr\build_vmpdrtrace7.bat`（输出 `vmpdrtrace7.dll`）。

lifter 侧默认会打 `[tramp]` / `[vip] pre`（定位用，未关）。不要开 `MERGEN_DIAG_LIFT_PROGRESS`。

## 8. 待清理

- 调试件：`build_msvc_dbg\vipfix*.out`、`run_*.out`（十余个 GB 级）、
  `vmptest\probe_regs.txt`、`vmptest\r8.*`、`vmptest\rstream.*`、`vmptest\wstream.*`
- **已删除**：`dumpFoldOrigin` 函数及其 4 个调用点（它读 `foldOrigin` 记账表，
  与真实 use-def 链不符，且递归无输出预算 —— 实测占日志 97%，单次运行可达 2GB）。
  删后默认运行日志 2.6MB。
- `Semantics_ControlFlow.ipp` 的 `dumpedVipDag < 0` 应还原为原作者的 `< 8`。
- `Includes.h` 的 `STACKP_VALUE` 注释应还原（值已还原 `0x14FEA0`）。
- 收尾按仓库规范：`clang-format` 改动文件；完成后跑 `cmake --build --preset=tidy`。
