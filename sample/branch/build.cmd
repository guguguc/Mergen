@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

cd /d "%~dp0"

cl /nologo /O2 /GS- /Zi /W3 ^
   /I D:\sogen\vmp\sdk ^
   branch_test.cpp ^
   /link /MAP:branch_test.map /LIBPATH:D:\sogen\vmp\bin\64\Debug ^
   /OUT:branch_test.exe

if errorlevel 1 exit /b 1
echo === built branch_test.exe ===
findstr /C:"branch_only" branch_test.map

echo === protect (Ultra) ===
D:\sogen\vmp\bin\64\Debug\VMProtectCon.exe branch_test.exe branch_test_vmp.exe
if errorlevel 1 exit /b 1

echo === unpack ===
D:\sogen\dr\vmptest\VMPStatic.exe branch_test_vmp.exe branch_test_unpacked.exe
if errorlevel 1 exit /b 1

echo === saltscan ===
D:\vmp-crcfix\saltscan.exe branch_test_vmp.exe branch_test_unpacked.exe

echo Lift target after crc fixpoint is branch_test_fixed4.exe
