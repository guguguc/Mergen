@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

cd /d "%~dp0"

cl /nologo /O2 /GS- /Zi /W3 ^
   /I D:\sogen\vmp\sdk ^
   test.cpp ^
   /link /MAP:test.map /LIBPATH:D:\sogen\vmp\bin\64\Debug ^
   /OUT:test.exe

if errorlevel 1 exit /b 1
echo === built test.exe ===
findstr /C:"compute_sum" /C:"classify" /C:"mix" test.map | findstr /C:"test.obj"
