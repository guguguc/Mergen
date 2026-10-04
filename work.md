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
D:\sogen\dr\vmptest\add_test_fixed4.exe       ← 本文分析的二进制（10128 KB）
D:\sogen\dr\vmptest\add_test.cpp               ← 源码（VMProtectBeginUltra("add_only")）
D:\sogen\dr\vmptest\build_add_test.bat         ← 构建 + 保护 + 解包 一条龙
```

`build_add_test.bat` 的链路：

```bat
cl /O2 /GS- /Zi /I D:\sogen\vmp\sdk add_test.cpp /OUT:add_test.exe
D:\sogen\vmp\bin\64\Debug\VMProtectCon.exe add_test.exe add_test_vmp.exe   :: Ultra 保护
D:\sogen\dr\vmptest\VMPStatic.exe add_test_vmp.exe add_test_unpacked.exe     :: 静态解包
D:\vmp-crcfix\saltscan.exe add_test_vmp.exe add_test_unpacked.exe             :: salt 扫描
```

`*_fixed*.exe` 变体由 `D:\sogen\dr\vmptest\crcfix_fixpoint.py`
在解包结果上做定点修复生成（`fixed4` 是第四轮定点）。

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

### 0.4 复现命令（两套）

**A. lifter（静态）**

```powershell
cd D:\sogen\dr\refs\Mergen\build_msvc_dbg
$env:MERGEN_MAX_BLOCK_BUDGET='131072'
cmd /c "lifter.exe D:\sogen\dr\vmptest\add_test_fixed4.exe 0x140007210 > run.out 2> run.err"
# 产物: output.ll / output_no_opts.ll / output_diagnostics.json
```

期望（当前状态）：`13291 blocks (1 completed, 2 unreachable), 128252 instructions (0 unsupported)`，
0 error，但**停在 13291 块**（真机 30270），诊断里两条 warning：
`Unresolved indirect jump @0x140323cc0`、`Unresolved ROP chain @0x1403da685`。

**B. DynamoRIO（真机真值）**

```powershell
cd D:\sogen\dr\vmptest
$DR='D:\DynamoRIO\bin64\drrun.exe'; $DLL='D:\sogen\dr\vmpdrtrace7.dll'
$argl=@('-c',$DLL,'-entry','0x1401f0efb','-imagebase','0x140000000',
        '-o',"$PWD\t.trace",'-regs',"$PWD\t.regs",'-mem',"$PWD\t.mem",'-trackmem',
        '--',"$PWD\add_test_fixed4.exe")
Start-Process -FilePath $DR -ArgumentList $argl -WorkingDirectory $PWD -Wait
```

可选选项：`-r8 <file>`（R8 解密链真值，输出 `R8,<rva>,<r8>,<r10>`）、
`-bc`（字节码）、`-analysis`、`-memval`。
**警告**：`-trackmem` 全量内存流很大（数万行量级）且写探针带值会让 DR 崩，
寄存器/`-r8` 探针安全。

### 0.5 博客与依据

- Aftermath Labs《Static Devirtualization of Themida》2026-05-09
  <https://aftermathlabs.net/blog/09/05/2026/>
  —— 本文的 **lift → concretize → continue**、*Constant Promotion*、
  *configurable range policy*、以及「从跳转目标反向走 IR DAG 找最后一次模块 load」
  这套判据都出自这里。
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
cmd /c "cd D:\sogen\dr\refs\Mergen\build_msvc_dbg && lifter.exe D:\sogen\dr\vmptest\add_test_fixed4.exe 0x140007210"
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
| 客户函数 entry | `0x140007210` |
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

## 5. 现状

- `output_diagnostics.json`：`13291 blocks (1 completed, 2 unreachable), ... 0 unsupported`，**0 error**
- 与 DR **连续一致 13280 块**；唯一地址 3275
- `output_no_opts.ll`：`br i1 = 0`，仍是 1 个函数 + 循环

## 6. 卡点（已定位到 IR 行）

`0x1403b4ff9`（VMP 派发蹦床）解出错误目标 → `pv=0` → 停在 **13291 块**（真机 30270）。

### 6.1 路径对比（严格逐块，同一次运行）

lifter 的块序列相对真机只多一个入口块（`0x7210`），逐块比较：

```
lifter[1..] vs real[0..] 共 13290 块: 一致 13281 (99.93%)
第一个分歧: lifter[13282]

lifter[13281] = 0x3B4FF9   real[13280] = 0x3B4FF9     同一块
lifter[13282] = 0x369063   real[13281] = 0x2D8CD0     ← 分歧
```

`0x3B4FF9` 在真机共出现 5 次（idx 5295/11500/12602/13280/15391），
其中 idx 5295 与 13280 后接 `0x2D8CD0`，idx 15391 后接 `0x369063`。
**两边各自解出的都是真机用过的目标，只是对应不同的 VM 迭代。**

### 6.2 根因：一条栈槽 load 的地址退化成裸偏移

关键槽是 **`0x14FE48`**，它等于 `STACKP_VALUE - 0x58`（`0x14FEA0 - 0x14FE48 = 0x58`）。

IR 中分歧源（`bb_solved_const89166`）：

```llvm
L191419:  %70237 = getelementptr i8, ptr %memory, i64 1375816   ; 0x14FE48  ✓ 栈槽
L191420:  %70238 = getelementptr i8, ptr %memory, i64 88        ; 0x58      ✗
L191421:  %70239 = load i32, ptr %70238
L191424:  %70242 = getelementptr i8, ptr %memory, i64 1375820   ; 0x14FE4C  相邻槽
```

`%memory` 是零基址字节寻址（同一处用完整地址 `1375816` 即为证），所以
**`%memory + 0x58` 读的是地址 `0x58`，而不是那个栈槽**。

`%70239` 沿 169 个节点的 use-def 链到
`%realadd-5372596252- = add i64 …, 0x1402E7026`，即派发目标
（`[halt]` 记录里的 `transfer=%realadd-5372596252-`），目标解不出 → `pv=0`。

**结论：槽地址 `0x14FE48` 与「相对 STACKP_VALUE 的偏移 `0x58`」在这个位置被混用。**

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

### 7.6.1 完整因果闭环（已确证）

`[smalladdr]` 诊断（`getPointer` 里，address 是常量且落在 `0x40..0x80` 时打印）
**只命中 1 次**，内容决定性：

```
[smalladdr] @14034ed0e addr=0x58 mem_base=R11 mem_index=None
            mem_disp=0x0 scale=0
            ops=[0]Register32/ECX [1]Memory32/None
```

即 `0x14034ed0e`（`mov ecx, [r11]`）的**基址寄存器 `R11` 退化成 `0x58`**，
于是有效地址 = `0 + 0x58`，读的是地址 `0x58`。

链路（两侧实测，序号来自统一事件流）：

```
0x1402e17d5  mov rdi,[rsp+r11]   r11=0x30 → 从栈槽读出 0x58    <-- 错误值入口
      ↓
0x1402e17ee  mov [rbx],rdi       seq=102322  把 0x58 写进 VM 槽 0x14FCB8
      ↓
0x14034ecfd  mov r11,[rbx]       seq=102349  读回 0x58 → R11=0x58
      ↓
0x14034ed0e  mov ecx,[r11]       seq=102353  有效地址 0x58 → 读到垃圾(符号)
      ↓
ecx 符号 → 派发目标符号化 → 蹦床 jmp r10 解不出 → pv=0 → 停在 13291 块
```

**真机真值对照**（`site.regs` / `r8.regs`）：

| 位置 | 真机 | lifter |
|---|---|---|
| `0x2e17ee` 的 `RDI`（21 次） | `0x7ff6a5200000`(模块基址) / `0x91cb5c000`(堆) / `0x0` / `0x202` | **`0x58`**（真机从不出现） |
| `0x34ecfd` 的 `R11`（3 次） | `0xfffffffffffb894c` / `0xfffffffffff7edc6` / `0x6d564` | 前两次 `0x1402b2ed0`/`0x1402b2f4c`（正常，seq 53173/76531），第三次 **`0x58`** |

**⇒ 根因是一条指令：`0x1402e17d5`（`mov rdi,[rsp+r11]`，`r11=0x30`）
从栈槽读出了 `0x58`，而真机该槽里是指针。** 错误值由此进入 `RDI`，
经 `[rbx]` 中转后成为 `R11`，使 `[r11]` 读地址 `0x58`。

（这正是本文件 6.1 最初记录的现象 —— `lifter: [rsp+0x58]=88 / 真值: 模块基址类`。）

### 7.6.2 收敛到「第一条读错」的精确帧（seq 102317–102322）

统一事件流（`reg6.csv` + `wr6.csv`）在分歧点附近逐条：

```
seq=102312  R11 = 0x30                                   <- 索引寄存器
seq=102317  0x1402e17d5  mov rdi,[rsp+r11]  -> RDI = 0x58   <- 从 [0x14FC60+0x30]=0x14FC90 读出 0x58
seq=102318  R11 = 0x14fe50
seq=102319  RBX = 0x14fe48
seq=102322  0x1402e17ee  mov [rbx],rdi      -> 写 0x58 到 0x14FE48
seq=102323  R11 = 0x0
seq=102347  R10 = 0x14034ecfd
seq=102349  0x14034ecfd  mov r11,[rbx]      -> R11 = 0x58      <- 退化
seq=102352  RCX = 0x58
seq=102353  0x14034ed0e  mov ecx,[r11]      -> [0x58] 读到符号 <- 派发目标符号化
```

指令编码：

```asm
0x1402e17d5  4a 8b 04 3c     mov rdi, [rsp + r11]     (REX.W + 8B /r, SIB)
```

**结论：第一个错误值出现在 `0x1402e17d5` 这条读上** —— 它从 `[RSP+0x30] = 0x14FC90`
读出 `0x58`，而真机该槽的值域是 模块基址/堆指针/`0x0`/`0x202`（21 次采样，见 7.6.1）。

`0x58` 由此进入 `RDI`，经 `0x2e17ee` 写入 `0x14FE48`，再被 `0x34ecfd` 读成 `R11`，
最终让 `0x34ed0e` 去读地址 `0x58`。

### 7.6.3 0x14FC90 这个槽的写入史（已查到）

`0x14FC90` 的写入者（`wr6.csv`，按 seq）：

| seq | 指令 | 值 |
|---|---|---|
| 38978 | `0x1403e1ad1` | 符号 |
| 41575 | `0x1403750eb` | `0x800800` |
| 44088 | `0x1403e0b7c` | `0x800800` |
| 50515 | `0x1402b8dd0` | `0x4` |
| 50613 | `0x1403690d4` | `0x4` |
| 50853 | `0x1403750eb` | `0x4` |
| 60805 | `0x1402d3889` | 符号 |
| 62244 | `0x1403e9af2` | `0x11` |
| 63235 | `0x1403750eb` | 符号 |

**注意 62244（`0x1403e9af2` 写 `0x11`）早于 102317，而 102322 那次写的是 `0x14FE48`
（另一个槽）** —— 所以 `102317` 读到的 `0x58` **不是** `0x1403e9af2` 在 102322 写的。
**该槽在 102317 之前还有更晚的写入者尚未列出，需要继续用 `wr6.csv` 过滤 `seq ∈ (63235, 102317)`。**

### 7.6.4 真正的第一条错误：`0x14037ebaa` 的 `mov r8,[rbx]`

继续上溯（`wr6.csv` 过滤 `slot == 0x14FC90 && seq < 102317`，共 54 条写入），
**最后一条**就是那条 store：

```
seq=100464  insn=0x1403e9af2  slot=0x14FC90  val=0x58
```

再查这次 store 的源寄存器：

```
seq=100416  0x14037ebaa   R8 = 0x58        <- store 前最后一条 R8 写
seq=100454  0x1403e9ad9   RDI = 0x30       seq=100460  0x1403e9ae5   RSI = 0x14017892d > 同块内
seq=100464  0x1403e9af2   store 0x58 -> 0x14FC90     (RSP=0x14FC60, +0x30 = 0x14FC90 ✓)
```

指令编码（`0x14037EBAA`）：

```asm
0x14037ebaa  4c8b03            mov r8, qword ptr [rbx]   <- R8 = [rbx] = 0x58
0x14037ebad  402aec            sub bpl, spl
0x14037ebb0  40c0fd0f          sar bpl, 0xf
0x14037ebb4  4881c308000000    add rbx, 8                <- 游标步进（与 0x37507a 同模式）
```

**⇒ 根因是这个「从 VM 数据区读 qword 到 R8」的操作**：lifter 读出 `0x58`，
而真机在同一模式（`0x37507a` 的 `mov r8,[rbx]`，45 次采样）读出的值域是
`0x7ff6a5200000`(模块基址) / `0x91c91f7a0`(堆) / `0x213` / `0x202` / `0x2c` 等
—— **从来不是 `0x58`**。

### 7.6.5 完整闭环（一条链，每环均有两侧真值）

```
0x14037ebaa  mov r8,[rbx]        R8 = 0x58            <- 第一个错误值（VM 数据区读）
      ↓ seq 100416
0x1403e9af2  mov [rsp+rdi],r8    rdi=0x30,rsp=0x14FC60 → 写 0x58 到 0x14FC90
      ↓ seq 100464
0x1402e17d5  mov rdi,[rsp+0x30]  读回 0x58            <- 6.1 最初记录的那条
      ↓ seq 102317
0x1402e17ee  mov [rbx],rdi       写 0x58 到 0x14FE48
      ↓ seq 102322
0x14034ecfd  mov r11,[rbx]       R11 = 0x58           <- 退化
      ↓ seq 102349
0x14034ed0e  mov ecx,[r11]       [0x58] → 符号        <- 派发目标符号化
      ↓ seq 102353
0x3B4FF9     jmp r10 解不出 → pv=0 → 停在 13291 块（真机 30270）
```

### 7.6.6 三条链收敛：`R8 = 0x58` 是唯一源头

**链 1（store → 派发）**：见 7.6.5。

**链 2（自循环，已闭合）**：

```asm
0x1403750eb  4c89043c    mov [rsp+rdi], r8     RSP=0x14fc60 RDI=0x40 → 写 0x14FCA0 (R8=0x58)
0x14037990b  4a8b3c1c    mov rdi, [rsp+r11]    RSP=0x14fc60 R11=0x40 → 读 0x14FCA0 = 0x58
0x14037990f  4881eb08..  sub rbx, 8
0x140379916  48893b      mov [rbx], rdi        → 压入 0x14FDC0 (= 0x58)
0x14037ebaa  4c8b03      mov r8, [rbx]         RBX=0x14FDC0 → R8 = 0x58   <- 回到起点
```

**`R8 = 0x58` 被压进 VM 栈、再被 `mov r8,[rbx]` 读回 `R8`，形成自循环** ——
所以 `0x58` 一旦产生就会一直传播下去。

**链 3（诊断直接命中）**：`[smalladdr] @14034ed0e mem_base=R11`，`R11 = 0x58`。

### 7.6.7 唯一源头：`R8 = 0x58` 由 5 条 `rol r8b,1` 产生

lifter 的寄存器流里 `R8 = 0x58` 只在这些指令上出现（每条前一条都是 `R8 = 0x2c`）：

```
0x140376FF7   0x1403CDBB2   0x1403BEAB9   0x14031C1B7   0x1402F2468
（另有 0x1403A85EC / 0x1402E14F3，同型）
```

`0x2C << 1 = 0x58` —— `rol r8b,1` 的语义正确，**但真机在同一条 `0x140376ff7` 上的值是 `0x2c`**
（`r8s.r8` 实测：`0x2c / 0x6c / 0x74`）。

⇒ **lifter 在这个旋转链上多走了一步**（或进入该链时 `R8` 的初值与真机不同）。
这里是「为什么读错」的最上游可定点。

### 7.6.8 分歧的确切指令：`0x140376ff7`（`rol r8b,1`）

**lifter 完整链**（`reg6.csv`，每处三次迭代）：

```
0x140376FCA  adc r8b,0x1f     R8 = 0x88 / 0x68 / 0x21
0x140376FD1  movzx r8d,[r9]   R8 = 0xed / 0x35 / 0xf2
0x140376FDA  xor r8b,sil      R8 = 0x20 / 0xa0 / 0x90
0x140376FDD  sub r8b,0x79     R8 = 0xa7 / 0x27 / 0x17
0x140376FE1  rol r8b,7        R8 = 0xd3 / 0x93 / 0x8b
0x140376FEB  not r8b          R8 = 0x2c / 0x6c / 0x74     <-- 真机同值 ✓
0x140376FF7  rol r8b,1        R8 = 0x58 / 0xd8 / 0xe8     <-- 真机 0x2c/0x6c/0x74 ✗
0x140376FFF  neg r8b          R8 = 0xa8 / 0x28 / 0x18
```

**真机在 `0x376ff7` 处 R8 与上一条 `0x376feb` 完全相同（未变），lifter 翻倍**
（`0x2C<<1 = 0x58`，`rol r8b,1` 语义正确）。

**⇒ 最可能：真机在该轮并未执行到 `0x376ff7`**（该段是 VM handler 尾部，
`0x140376FC0` 是 `jmp rdi` 间接跳转、`0x140376FD1` 是 `movzx r8d,[r9]` 字节码读），
**lifter 把它当作顺序执行过去了** —— 即 **handler 边界 / 间接跳转落点在这一处判断有偏差**。

注意 `0x140376FCA` 的 `adc r8b,0x1f` 是 **CF 依赖**指令，紧邻还有 `sbb`/`setl`/`bt`/`btr`，
与第 4 节记录的「flags 条件选择」改动区域相关，一并存疑。

### 7.6.9 更正 7.6.8 的推断 + 新的精确线索

**7.6.8 里「真机没走到 `0x376FF7`」的推断被否证**：真机与 lifter 在
`0x376FC0`（`jmp rdi`）处的后继块**完全相同**：

```
真机 @0x376FC0 (块 idx 2470) -> 0x3ce9d7, 0x2ba263, 0x3d0ed5
lifter @0x376FC0 (块 idx 2471) -> 0x3ce9d7, 0x2ba263, 0x3d0ed5
```

（lifter 仅多一个入口块，与 6.1 的 13281 块一致。）

**真正的数值关系（更强的线索）**：

```
真机 @0x376FF7   R8 = 0x2c   ==  lifter 在【上一条】0x376FEB 的值
lifter @0x376FF7 R8 = 0x58   ==  0x2c << 1
```

⇒ **lifter 比真机多「做了一次操作」。** 但两边路径与指令序列相同，
所以副作用只能来自 `0x376FEB` 与 `0x376FF7` **之间**那三条指令：

```asm
0x140376fee  480fa3cd   bt  rbp, rcx     ; 只动 CF
0x140376ff2  440fb3cd   btr ebp, r9d     ; 位测试并复位（操作 ebp）
0x140376ff6  f8         clc              ; 只动 CF
```

**嫌疑：`btr ebp, r9d`（`0x140376ff2`）的 lift 语义若错误地写到了 `R8`
（而非 `EBP`），就会造成这个精确的一步偏移。**

### 7.6.10 重要更正：7.6.7 / 7.6.8 / 7.6.9 的「rol 分歧」可能是口径不一致

**7.6.9 的 `btr` 嫌疑已排除**：读 `lift_btr`（`Semantics_Misc.ipp:982-1018`），
它只做 `baseVal = GetIndexValue(0)` → 位复位 → `SetIndexValue(0, baseVal)`，
**只写回操作数 0（`ebp`），不碰 `R8`**。

**新的、更可能的解释**：两侧探针的取值口径不同。

- `reg6.csv`（lifter 的 `MERGEN_REG_STREAM_FILE`）记的是
  `SetRegisterValue_internal` 被调用时的**新值 = 执行后**；
- DR 的 `-r8` 探针用 clean call 插在指令前，**取的是执行前值**
  （第 2 节记录过：`[regs]` 探针从 `0x1f0efb` 的 `push rdi` 校准为「执行前」）。

若 `-r8` 是执行前值，则：

```
真机 @0x376FF7  R8 = 0x2c   = 执行前
lifter @0x376FF7 R8 = 0x58  = 执行后
=> rol r8b,1 在两边的语义一致（0x2c -> 0x58），此处【没有分歧】
```

**⇒ 7.6.7 / 7.6.8 关于「lifter 多旋转一次」的结论未经此口径核对，应视为待验证。**

**核对方法**：取一个 `-r8` 站点，其**前一条指令确定地写该寄存器**，
比较 `-r8` 的值与 lifter 在该前一条的值 —— 若相等则是执行前口径。
`0x3E957E`（`mov r8d,[r11]`，其前为 `0x3E957A` 且 lifter 记 `R8=0x3500`）
正好可用：真机 `0x3E957E` 处 `R8 = 0x3500`，与 lifter 在 `0x3E957A` 的 `0x3500` 相同
（见 7.6 系列数据），**这支持「执行前」口径**。

### 7.6.11 口径校准的结果（重要）

**校准测试（决定性）**：

```
真机 -r8 探针 @0x3E957E : 0x3500 / 0x6c00 / 0xffffffffffffe800 / ...
lifter reg6.csv @0x3E957A: 0x3500          <- 相等（0x3E957A 是 0x3E957E 的前一条）
lifter reg6.csv @0x3E957E: 0x6c9128f2      <- 不等
```

**⇒ DR 的 `-r8` / `[regs]` 探针取「执行前」值；`reg6.csv` 记「执行后」值。**
正确口径：**真机在指令 X 的执行前值 == lifter 在 X 前一条指令的执行后值。**

**因此 7.6.7 / 7.6.8 / 7.6.9 关于「lifter 在 `rol r8b,1` 上多旋转一次」的结论
作废** —— 那是口径不一致造成的假分歧（真机 `0x2c` 是执行前，lifter `0x58` 是执行后，
`rol r8b,1` 两边语义一致）。

### 7.6.12 不受口径影响的结论（最终）

用正确口径重比关键点，结论不变且更硬：

```
真机 @0x2e17ee 的 RDI（执行前，21 次采样）:
   0x7ff565d40000（模块基址）/ 0x7999947000（堆）/ 0x0 / 0x202 / 0x1
lifter RDI 由 0x1402e17d5 写入（执行后）:
   0x0 / 0x0 / 0x7ffd1000 / <符号> / 0x0 / <符号> …（其中某次为 0x58）
```

`0x58` 与 `0x202`/指针**不是「差一条指令」能解释的差异**（量级完全不同），
所以：

**根因：`0x1402e17d5`（`mov rdi,[rsp+r11]`，`r11=0x30`）从栈槽 `0x14FC90`
读出了 `0x58`，而真机该槽里是指针 / flag 族值（`0x202`、`0x1`、模块基址、堆指针）。**

该错误值经 `RDI → 0x2e17ee → [rbx] → 0x34ecfd(R11) → 0x34ed0e([r11])`
传到派发目标，目标符号化 → 蹦床解不出 → 停在 13291 块。

### 7.6.13 最外层产生点：`0x1403C4475`（`movsx r8w, bpl`）

按执行序取**第一次** `R8 = 0x58`（不是自循环里那次）：

```
seq=6257  0x1403c444f   R11 = 0x140175f39        <- 字节码指针
seq=6266  0x1403c4465   R8  = <符号>             (rcl r8w, 0xb8)
seq=6269  0x1403c446d   R8  = <符号>             (btc r8d, ebp)
seq=6270  0x1403c4471   R8  = 0x5f39             (movzx r8d, r11w = R11 低 16 位)
seq=6271  0x1403c4475   R8  = 0x58               (movsx r8w, bpl)
```

对应反汇编：

```asm
0x1403c444b  movzx r9d, byte ptr [r11]   ; 字节码读
0x1403c444f  add   r11, 1                ; 游标前进
0x1403c4456  xor   r9b, r10b             ; rolling key
0x1403c4459  sub   r9b, 0x17
0x1403c445d  rol   r9b, 4
0x1403c4461  sub   r9b, 6
0x1403c4465  rcl   r8w, 0xb8             ; CF 依赖
0x1403c446a  neg   r9b
0x1403c446d  btc   r8d, ebp              ; 位测试并取反（CF 依赖）
0x1403c4471  movzx r8d, r11w             ; R8 = 0x5f39
0x1403c4475  movsx r8w, bpl              ; R8 低字节 = BP 低字节 = 0x58   <-- 首次 0x58
0x1403c4481  movsx r8w, r8b
0x1403c4486  shr   r8w, cl
0x1403c448a  mov   r8, qword ptr [rsp + r9]
```

**⇒ `0x58` 来自 `RBP` 的低字节**（`movsx r8w, bpl`）。
而 `0x1403c4471` 的 `0x5f39` 是 `R11` 的低 16 位（R11 = 字节码指针，其寻址已确认与真机一致）。

**下一步唯一动作**：查 lifter 在 `0x1403c4475` 处的 `RBP` 低字节 ——
若 lifter 是 `0x58` 而真机不是，则上溯到写 `RBP` 的指令；
`RBP` 在 lifter 里常是 `%newreg = or i64 %X, 1375488`（= `0x14FE60` 一类伪栈基址），
**若 `RBP` 被算成了伪栈地址而其低字节恰好是 `0x58`，那就是「伪栈地址低字节被当成数据」**。

### 7.6.14 收束点：`RBP` 的低字节（`0x1403C4475` 的唯一输入）

`RBP` 在 lifter 里的形态（早先 `[stb]` 探针记录）：

```
RBP = %newreg = or i64 %<符号>, 1375488      (1375488 = 0x14FE60，低字节 0x60)
RBP = %newreg = or i64 %<符号>, 1375744      (1375744 = 0x14FE80，低字节 0x80)
```

即 **`RBP` 是「伪栈地址类」值**。注意 `STACKP_VALUE - 0x58 = 0x14FE48`，
低字节 `0x58` 对应 `0x14FE58` 一类的地址。

**但 `RBP` 在真机侧同样是栈指针类值 —— 真机 `RBP` 的低字节完全可能也是 `0x58`。**
所以「`RBP` 低字节 = `0x58`」本身**可能不是错的**，`movsx r8w, bpl` 也可能正确。

**⇒ 最后一层需要对比 `RBP` 的精确值**，而 `RBP` 不在寄存器流白名单里
（与 `RDI` 同样的情况，见 7.8）。这是当前唯一的缺口。

### 7.6.15 本次会话的最终上溯链（一条）

```
RBP 的低字节 = 0x58                       <- 最后的可定点（未与真机核对）
      ↓ 0x1403C4475   movsx r8w, bpl
R8 = 0x58
      ↓ 反复 压栈(0x1403750eb/0x1403e9af2) ↔ 读回(0x14037ebaa)，构成自循环
0x1402e17d5   mov rdi,[rsp+0x30]   读回 0x58              <- work.md 6.1 最初那条
      ↓
0x1402e17ee   mov [rbx],rdi        写 0x58 到 0x14FE48
      ↓
0x14034ecfd   mov r11,[rbx]        R11 = 0x58             <- 退化
      ↓
0x14034ed0e   mov ecx,[r11]        [0x58] -> 符号          <- 派发目标符号化
      ↓
0x3B4FF9      jmp r10 解不出 -> pv=0 -> 停在 13291 块（真机 30270）
```

### 7.6.16 根因确认：`RBP` 被建模成伪栈地址，其低字节漏进数据

DR 探针（`vmpdrtrace8.dll`，新增 `0x3C444F/0x3C4471/0x3C4475/0x3C4481` 站点 + `RBP`/`RSP`）：

```
真机 @0x3C4475 (7 次):
   RBP = 0x17b92ff9b8   R8 = 0x5d94
   RBP = 0x17b92ff9c0   R8 = 0x5f39
   RBP = 0x17b92ff9b6   R8 = 0x60d6
   RBP = 0x17b92ff98c   R8 = 0x636b
   RBP = 0x17b92ff950   R8 = 0x67be
   （低字节 = 0xb8/0xc0/0xb6/0x8c/0x50 —— 从不是 0x58）
```

**口径更正（7.6.11）**：`@0x3C4475` 探针是执行前，此时 `R8` 仍是上一条
`movzx r8d, r11w` 的结果，**不能**说「真机没做 `movsx r8w, bpl`」。
`r8.regs` 里下一条 `0x3C4481` 的执行前 `R8` 就是 `movsx` 之后：
visit2 `BPL=0x90` → `R8=0xff90`；visit1 `0x88` → `0xff88`。
真机**执行了** `movsx`，输入是 `BPL`（7 次都不是 `0x58`）。
lifter 对齐 visit2：`R8` 前值同为 `0x5f39`，之后 lifter 得到 `0x58`（`BPL` 错）。

| | 真机 | lifter |
|---|---|---|
| `0x3C4471` 出的 `R8` | `0x5d94 / 0x5f39 / 0x60d6 / 0x636b / 0x67be` | `0x5d94 / 0x5f39` ✅ |
| `0x3C4475` 出的 `R8` | 保持 `0x5f39`（低字节 `0x39`） | **`0x58`** |
| 该处 `RBP` | `0x17b92ff9c0`（真实栈指针，模块外堆区） | **`0x14fe58`（伪栈地址）** |

`0x3C4471` 两侧一致 ⇒ **字节码读与 `R11` 游标都正确**；
分歧精确发生在 `0x3C4475`。

**⇒ 根因：`RBP` 在 lifter 里被建模成伪栈地址（`0x14FE58`），真机 `RBP` 是真实栈指针
（`0x17b92ff9c0`）。`movsx r8w, bpl` 把「伪造址的低字节 `0x58`」当作 VM 数据搬进 `R8`，
经自循环与中转后成为那个错误的派发目标。**

这条与 6.1 最初记录的 `lifter: [0x14FE48]=88 / 真值: 指针` 现象是同一件事。

### 7.6.17 根因的本质：VM 把「栈指针的低字节」当数据用

`RBP` 在 lifter 里的伪栈赋值来自**标准栈帧建立指令**（lift 本身正确）：

```asm
0x1403d7f88  488dac2440010000   lea rbp, [rsp + 0x140]   ; RBP = 栈上固定偏移（672 次）
0x14036c47a  488bec             mov rbp, rsp             ; RBP = 栈指针
0x14036c47d  4881ec80010000     sub rsp, 0x180
0x1403c1d57  4881c508000000     add rbp, 8               ; 循环步进
```

⇒ **分歧不在指令语义，而在「栈放在哪」**：

| | `RBP` | `bpl`（低字节） |
|---|---|---|
| 真机 | `0x17b92ff9c0`（真实栈，模块外堆区） | `0xc0` |
| lifter | `0x14fe58`（伪栈，`STACKP_VALUE` 附近） | `0x58` |

**而 VM 在 `0x1403c4475` 用 `movsx r8w, bpl` 读取 `RBP` 的低字节并当作 VM 数据使用**
（见 7.6.16 的逐次对照：真机 `R8` 保持 `0x5f39`，lifter 变 `0x58`）。

**⇒ 最终根因：VM 的混淆把「栈指针的一个字节」泄漏进了数据流。
因此 VM 的语义依赖栈的实际落点；lifter 用固定伪栈基址
`STACKP_VALUE = 0x14FEA0`（低字节 `0xA0`），与真机栈（低字节 `0xC0`）不同，
于是 VM 算出的数据与真机不同 —— 该数据最终成为派发目标，导致 `jmp r10` 解不出。**

这也解释了为什么此前所有「寻址/字节码/key/flags」方向都排除了：
**它们全是对的；错的是「栈基址字节」这一个自由度。**

**重要限定（勿据此写死常量）**：真机 `RBP` 的低字节**在不同运行/不同点都不同**：

```
rbp.regs : 0x00 0x16 0x50 0x8c 0x90 0xa8 0xaa 0xb6 0xb8 0xc0 0xdc
r8.regs  : 0x16 0xa8 0xdc
site.regs: 0x20 0x3a 0x90
RSP 低字节（r8.regs）: 0x90(194) 0xb0 0xa8 0xa0 0x38
```

⇒ **「把 `STACKP_VALUE` 低字节改成 `0xC0` 去对齐」是错的**（那只是某一次运行的值）。

**尚未确定的一点**：`0x58` 作为 `R8` 的**最终**值是否有意义。
`0x3C4475` 之后还有 `0x3C4481 movsx r8w, r8b`、`0x3C4486 shr r8w, cl`、
`0x3C448a mov r8, [rsp+r9]` 会继续改写 `R8` ——
所以「`bpl` 的字节泄漏成数据」这一机制**已被证实存在**，
但「它是否就是最终导致派发目标错误的那个值」还需在 `0x3C448a` 处再对照一次
（真机该点可用 `vmpdrtrace8.dll` 的 `poff` 名单加 `0x3C448A` 采集）。

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

### 7.6.29 修复（range policy）

错改：`MERGEN_NO_FILE_PROMOTION` 只挡 SYMBOLIC 早退支路，而 `.rZu0` 当时是 CONCRETE，走 composed → `file.readMemory` → PE 零。

已改（通用，不是灌值）：
1. `MemoryPolicySetup`：**白名单**才 CONCRETE；保护器自创节名一律 SYMBOLIC。
2. `retrieveCombinedValueImpl`：SYMBOLIC 且 buffer 未覆盖时**禁止** file promotion。

不做 `MEM_OVERLAY`：按样本灌堆指针是打补丁，ASLR 一变就废，也不符合「无 handler / 无表」的静态路线。

## 7.7 下一步（按优先级）

**可交接状态：假 `0x58` 的直接原因是对保护器节做了 file promotion；policy 已挡住。
`0xEF850` 的堆指针是 VM 入口前写好的，lift 若从入口才开始，静态侧本来就没有这个值。**

1. 查谁在入口前写 `RVA 0xEF850`：能否把 lift 起点前移覆盖那段 init，让 store 进 concolic buffer。
2. 若写发生在无法静态拿到的外部（堆分配 / 系统调用），再定 range policy：对该槽保持 symbolic，还是另有可具体化来源。
3. 不要灌 overlay，不要再沿 R8 混淆算术往下追。
4. `foldOrigin` 仍不可信（6.4）。

## 7.8 诊断基础设施（默认关闭，零输出）

| 环境变量 | 产物 | 用途 |
|---|---|---|
| `MERGEN_REG_STREAM_FILE` | 寄存器写流 `REG,seq,insn,reg,isconst,value` | 查"谁把某寄存器写成某值" |
| `MERGEN_WRITE_STREAM_FILE` | 写流 `W,seq,insn,slot,size,value` | 与 DR `-trackmem` 写侧对齐 |
| `MERGEN_READ_STREAM_FILE` | 读流 `R,insn,addr,size_bits` | 与 DR `-trackmem` 读侧对齐 |
| `MERGEN_DIAG_BYTE` | 单指令字节读 | 只听 `0x14033578E` |
| `MERGEN_DIAG_SSA58` | 真实 SSA use-def 上溯 | 深度 8 / 200 节点上限 |

**两条流共用 `nextMemEventSeq()`（`mergen_events::memEventSeq`）**，
序号在同一执行轴上，可按 seq 合并成一条时间线 —— 这是定位
「某条 store 执行时各寄存器是什么」的唯一手段（源码：`LifterClass.hpp`
的 `SetRegisterValue_internal` 与 `GEPTracker.ipp` 的 `addValueReference`）。

**DR 侧**：`D:\sogen\dr\vmpdrtrace.c` 已加 `-r8 <file>` 选项，输出
`R8,<rva>,<r8>,<r10>`；探针白名单含 R8 解密链的 5 个站点
（`0x3E957E/0x3E9588/0x3E95A2/0x3E95A9/0x3E95C0`）。
构建脚本：`D:\sogen\dr\build_vmpdrtrace7.bat`（输出 `vmpdrtrace7.dll`）。

## 8. 待清理

- 调试件：`build_msvc_dbg\vipfix*.out`、`run_*.out`（十余个 GB 级）、
  `vmptest\probe_regs.txt`、`vmptest\r8.*`、`vmptest\rstream.*`、`vmptest\wstream.*`
- **已删除**：`dumpFoldOrigin` 函数及其 4 个调用点（它读 `foldOrigin` 记账表，
  与真实 use-def 链不符，且递归无输出预算 —— 实测占日志 97%，单次运行可达 2GB）。
  删后默认运行日志 2.6MB。
- `Semantics_ControlFlow.ipp` 的 `dumpedVipDag < 0` 应还原为原作者的 `< 8`。
- `Includes.h` 的 `STACKP_VALUE` 注释应还原（值已还原 `0x14FEA0`）。
- 收尾按仓库规范：`clang-format` 改动文件；完成后跑 `cmake --build --preset=tidy`。
