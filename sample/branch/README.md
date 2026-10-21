# sample/branch

VMProtect Ultra `branch_only`: signed `a > b` then `a - b`, else `a ^ b`.

| file | role |
|---|---|
| `branch_test.cpp` | source (`VMProtectBeginUltra("branch_only")`) |
| `build.cmd` | cl → Ultra protect → unpack → saltscan |
| `branch_test_vmp.exe` | protected image |
| `branch_test_unpacked.exe` | unpack output |
| `branch_test_fixed4.exe` | lift target after crc fixpoint |

`branch_only(0x12345678, 0x0F0F0F0F)` takes the true arm: `0x03254769`.

## Build from source

```bat
cmd /c sample\branch\build.cmd
```
