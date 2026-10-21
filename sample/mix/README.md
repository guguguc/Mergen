# sample/mix

VMProtect Ultra sample with three customer markers (`compute_sum`, `classify`, `mix`). Copied from `D:\sogen\dr\vmptest\`.

| file | role |
|---|---|
| `test.cpp` | source (`VMProtectBeginUltra` on each marker) |
| `build_test.cmd` | cl → `test.exe` + map (protect/unpack/saltscan done out-of-band) |
| `test_fixed4.exe` | lift target (fourth crc fixpoint round, ~10 MB) |
| `entry_7450.dmp` | DynamoRIO dump at `mix` entry `0x140007450` (~20 MB) |

| marker | VA |
|---|---|
| `classify` | `0x140007220` |
| `compute_sum` | `0x1400072d0` |
| `mix` | `0x140007450` |

ImageBase: `0x140000000`. Lift **must** start at the customer VA (not PE AddressOfEntryPoint).

`mix(seed)` runs 8 rounds of xorshift (`^= <<13`, `^= >>17`, `^= <<5`). Expected: `mix(0x12345678) = 0xc5186e29`.

## Build from source

Needs VS and VMProtect SDK paths inside `build_test.cmd`.

```bat
cmd /c sample\mix\build_test.cmd
```

`test_fixed4.exe` is the checked-in binary; `build_test.cmd` does not overwrite it.

## Recapture dump

```powershell
cd D:\sogen\dr\refs\Mergen\sample\mix
$DR='D:\DynamoRIO\bin64\drrun.exe'
$DLL='D:\sogen\dr\vmpdrtrace7.dll'
$argl=@('-c',$DLL,'-entry','0x140007450','-imagebase','0x140000000',
        '-dumpmem',"$PWD\entry_7450.dmp",
        '--',"$PWD\test_fixed4.exe")
Start-Process -FilePath $DR -ArgumentList $argl -WorkingDirectory $PWD -Wait
```

## Lift (`mix`)

```powershell
cd D:\sogen\dr\refs\Mergen\build_msvc
$env:MERGEN_MAX_BLOCK_BUDGET='131072'
cmd /c "lifter.exe ..\sample\mix\test_fixed4.exe 0x140007450 --mem-dump ..\sample\mix\entry_7450.dmp"
```
