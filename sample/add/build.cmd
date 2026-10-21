@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

cd /d "%~dp0"

cl /nologo /O2 /GS- /Zi /W3 ^
   /I D:\sogen\vmp\sdk ^
   add_test.cpp ^
   /link /MAP:add_test.map /LIBPATH:D:\sogen\vmp\bin\64\Debug ^
   /OUT:add_test.exe

if errorlevel 1 exit /b 1
echo === built add_test.exe ===
findstr /C:"add_only" add_test.map

echo === protect (Ultra) ===
D:\sogen\vmp\bin\64\Debug\VMProtectCon.exe add_test.exe add_test_vmp.exe
if errorlevel 1 exit /b 1

echo === unpack ===
D:\sogen\dr\vmptest\VMPStatic.exe add_test_vmp.exe add_test_unpacked.exe
if errorlevel 1 exit /b 1

echo === saltscan ===
D:\vmp-crcfix\saltscan.exe add_test_vmp.exe add_test_unpacked.exe

echo Lift target is the checked-in add_test_fixed4.exe (fourth crc fixpoint round).
