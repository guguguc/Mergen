# sample/add

VMProtect Ultra `add_only(a,b)=a+b` sample used by the current devirt work.

| file | role |
|---|---|
| `add_test.cpp` | source (`VMProtectBeginUltra("add_only")`) |
| `build.cmd` | cl → Ultra protect → unpack → saltscan |
| `add_test_fixed4.exe` | lift target (fourth crc fixpoint round, ~10 MB) |
| `entry_7210.dmp` | DynamoRIO dump at customer entry `0x140007210` (~19 MB) |

Customer function: `0x140007210`. ImageBase: `0x140000000`.

## Build from source

Needs VS, VMProtect SDK/Con, `VMPStatic.exe`, `saltscan.exe` on the paths inside `build.cmd`.

```bat
cmd /c sample\add\build.cmd
```

`add_test_fixed4.exe` is the checked-in binary; `build.cmd` does not overwrite it.

## Recapture dump

```powershell
cd D:\sogen\dr\refs\Mergen\sample\add
$DR='D:\DynamoRIO\bin64\drrun.exe'
$DLL='D:\sogen\dr\vmpdrtrace7.dll'
$argl=@('-c',$DLL,'-entry','0x140007210','-imagebase','0x140000000',
        '-dumpmem',"$PWD\entry_7210.dmp",
        '--',"$PWD\add_test_fixed4.exe")
Start-Process -FilePath $DR -ArgumentList $argl -WorkingDirectory $PWD -Wait
```

## Lift

```powershell
cd D:\sogen\dr\refs\Mergen\build_msvc_dbg
$env:MERGEN_MAX_BLOCK_BUDGET='131072'
cmd /c "lifter.exe ..\sample\add\add_test_fixed4.exe 0x140007210 --mem-dump ..\sample\add\entry_7210.dmp"
```
