# sample/xor

VMProtect Ultra `xor_only(a,b)=a^b` sample.

| file | role |
|---|---|
| `xor_test.cpp` | source (`VMProtectBeginUltra("xor_only")`) |
| `build.cmd` | cl → Ultra protect → unpack → saltscan |
| `xor_test_fixed4.exe` | lift target (fourth crc fixpoint round) |

Customer function: `0x140007210`. ImageBase: `0x140000000`.

## Build from source

```bat
cmd /c sample\xor\build.cmd
```

`xor_test_fixed4.exe` is the checked-in binary; `build.cmd` does not overwrite it.

## Lift

```powershell
cd D:\sogen\dr\refs\Mergen\build_msvc_dbg
$env:MERGEN_MAX_BLOCK_BUDGET='131072'
cmd /c "lifter.exe ..\sample\xor\xor_test_fixed4.exe 0x140007210"
```
