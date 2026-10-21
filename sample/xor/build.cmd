@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

cd /d "%~dp0"

cl /nologo /O2 /GS- /Zi /W3 ^
   /I D:\sogen\vmp\sdk ^
   xor_test.cpp ^
   /link /MAP:xor_test.map /LIBPATH:D:\sogen\vmp\bin\64\Debug ^
   /OUT:xor_test.exe

if errorlevel 1 exit /b 1
echo === built xor_test.exe ===
findstr /C:"xor_only" xor_test.map

echo === protect (Ultra) ===
D:\sogen\vmp\bin\64\Debug\VMProtectCon.exe xor_test.exe xor_test_vmp.exe
if errorlevel 1 exit /b 1

echo === unpack ===
D:\sogen\dr\vmptest\VMPStatic.exe xor_test_vmp.exe xor_test_unpacked.exe
if errorlevel 1 exit /b 1

echo === saltscan ===
D:\vmp-crcfix\saltscan.exe xor_test_vmp.exe xor_test_unpacked.exe

echo Lift target is the checked-in xor_test_fixed4.exe (fourth crc fixpoint round).
