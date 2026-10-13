@echo off
setlocal EnableDelayedExpansion

rem ===========================================================================
rem  build_msvc.cmd - one-shot configure + build for the MSVC (cl.exe) lane.
rem
rem  Use this lane when clang-cl is not available. scripts\dev\configure_iced.cmd
rem  and scripts\dev\build_iced.cmd both require clang-cl; this script only needs
rem  a Visual Studio C++ toolset plus an LLVM 18 install.
rem
rem  The Zydis backend is used by default because the Iced backend needs Cargo on
rem  PATH. Pass "iced" as the action to build the Iced backend instead.
rem
rem  Actions:
rem    (none)     configure when needed, then build          [default]
rem    build      same as above
rem    configure  force a reconfigure, then build
rem    clean      wipe the build directory and stop
rem    help       print this text
rem
rem  Overridable environment variables:
rem    LLVM_ROOT            LLVM 18 install root
rem                           (default: Z:\llvm-18.1.8-windows-amd64-msvc17-msvcrt)
rem    LLVM_DIR             LLVM CMake config dir; wins over LLVM_ROOT
rem    MERGEN_VS_DIR        Visual Studio install root (default: vswhere -latest)
rem    MERGEN_BUILD_DIR     build directory (default: <repo>\build_msvc)
rem    MERGEN_BUILD_TYPE    build config (default: Release)
rem    MERGEN_BUILD_JOBS    parallel build jobs (default: %NUMBER_OF_PROCESSORS%)
rem    MERGEN_GENERATOR     CMake generator (default: "Visual Studio 18 2026")
rem    MERGEN_ARCH          toolset architecture (default: x64)
rem    MERGEN_SKIP_CONFIGURE=1   reuse the existing cache without reconfiguring
rem    MERGEN_GENERATOR=Ninja    fall back to Ninja + cl.exe (previous behaviour)
rem
rem  Examples:
rem    scripts\dev\build_msvc.cmd
rem    set MERGEN_BUILD_TYPE=RelWithDebInfo && scripts\dev\build_msvc.cmd
rem    scripts\dev\build_msvc.cmd configure
rem    set MERGEN_GENERATOR=Ninja && scripts\dev\build_msvc.cmd   (Ninja + cl.exe)
rem    set MERGEN_ARCH=ARM64 && scripts\dev\build_msvc.cmd
rem    scripts\dev\build_msvc.cmd clean
rem ===========================================================================

set "ACTION=build"
if not "%~1"=="" set "ACTION=%~1"

if /i "%ACTION%"=="help" goto usage
if /i "%ACTION%"=="--help" goto usage
if /i "%ACTION%"=="/?" goto usage

for %%I in ("%~dp0..\..") do set "REPO_ROOT=%%~fI"

set "BUILD_DIR=%MERGEN_BUILD_DIR%"
if not defined BUILD_DIR set "BUILD_DIR=%REPO_ROOT%\build_msvc"

set "BUILD_TYPE=%MERGEN_BUILD_TYPE%"
if not defined BUILD_TYPE set "BUILD_TYPE=Release"

set "BUILD_JOBS=%MERGEN_BUILD_JOBS%"
if not defined BUILD_JOBS set "BUILD_JOBS=%NUMBER_OF_PROCESSORS%"
if not defined BUILD_JOBS set "BUILD_JOBS=4"

:: Ninja is only needed by the Ninja generator; the Visual Studio generator
:: drives msbuild itself. Keeping the lookup unconditional would fail the script
:: on a VS install that ships CMake but no bundled ninja.exe.
set "USE_NINJA=1"
set "GENERATOR=%MERGEN_GENERATOR%"
if defined GENERATOR if /i "!GENERATOR!"=="Ninja" set "GENERATOR="
if not defined GENERATOR (
    set "GENERATOR=Visual Studio 18 2026"
    set "USE_NINJA=0"
)
set "TOOLSET_ARCH=%MERGEN_ARCH%"
if not defined TOOLSET_ARCH set "TOOLSET_ARCH=x64"

set "BACKEND=zydis"
if /i "%ACTION%"=="iced" set "BACKEND=iced"

:: --- clean ---------------------------------------------------------------
if /i "%ACTION%"=="clean" (
    if exist "%BUILD_DIR%" (
        echo INFO: Removing "%BUILD_DIR%"
        rmdir /s /q "%BUILD_DIR%"
    ) else (
        echo INFO: Nothing to clean at "%BUILD_DIR%"
    )
    exit /b 0
)

:: --- resolve llvm --------------------------------------------------------
set "LLVM_CMAKE_DIR=%LLVM_DIR%"
if defined LLVM_CMAKE_DIR if not exist "%LLVM_CMAKE_DIR%\LLVMConfig.cmake" (
    echo ERROR: LLVM_DIR is set but LLVMConfig.cmake is missing under "%LLVM_CMAKE_DIR%"
    exit /b 1
)
if not defined LLVM_CMAKE_DIR (
    if not defined LLVM_ROOT set "LLVM_ROOT=Z:\Downloads\llvm-18.1.8-windows-amd64-msvc17-msvcrt"
    if not exist "!LLVM_ROOT!\lib\cmake\llvm\LLVMConfig.cmake" (
        echo ERROR: no LLVMConfig.cmake under "!LLVM_ROOT!\lib\cmake\llvm"
        echo        Set LLVM_ROOT or LLVM_DIR to an LLVM 18 install.
        exit /b 1
    )
    set "LLVM_CMAKE_DIR=!LLVM_ROOT!\lib\cmake\llvm"
)

set "LLVM_VERSION="
set "LLVM_CONFIG_EXE="
for %%I in ("%LLVM_CMAKE_DIR%\..\..\..\bin\llvm-config.exe") do if exist "%%~fI" set "LLVM_CONFIG_EXE=%%~fI"
if defined LLVM_CONFIG_EXE for /f "tokens=1" %%V in ('"%LLVM_CONFIG_EXE%" --version') do set "LLVM_VERSION=%%V"
if defined LLVM_VERSION (
    for /f "tokens=1 delims=." %%V in ("%LLVM_VERSION%") do set "LLVM_MAJOR=%%V"
    if not "!LLVM_MAJOR!"=="18" echo WARNING: expected LLVM 18, found %LLVM_VERSION% at "%LLVM_CMAKE_DIR%"
)

:: --- resolve visual studio -----------------------------------------------
set "VSDIR=%MERGEN_VS_DIR%"
if not defined VSDIR (
    set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
    if not exist "!VSWHERE!" set "VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
    if exist "!VSWHERE!" for /f "usebackq delims=" %%I in (`"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do if not defined VSDIR set "VSDIR=%%I"
)
if not defined VSDIR (
    echo ERROR: no Visual Studio install with the C++ toolset was found.
    echo        Install the MSVC toolset, or set MERGEN_VS_DIR to the install root.
    exit /b 1
)

set "VCVARS=%VSDIR%\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
    echo ERROR: vcvars64.bat not found under "%VSDIR%"
    exit /b 1
)

:: --- resolve cmake and ninja ---------------------------------------------
set "CMAKE_BIN="
for /f "usebackq delims=" %%I in (`where cmake 2^>nul`) do (
    set "CMAKE_BIN=%%I"
    goto found_cmake
)
if exist "%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" set "CMAKE_BIN=%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

:found_cmake
if not defined CMAKE_BIN (
    echo ERROR: CMake not found on PATH or under "%VSDIR%".
    exit /b 1
)

set "NINJA_EXE="
for /f "usebackq delims=" %%I in (`where ninja 2^>nul`) do (
    set "NINJA_EXE=%%I"
    goto found_ninja
)
if exist "%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe" set "NINJA_EXE=%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"

:found_ninja
if not defined NINJA_EXE if "!USE_NINJA!"=="1" (
    echo ERROR: Ninja not found on PATH or under "%VSDIR%".
    echo        Use MERGEN_GENERATOR="Visual Studio 18 2026" to build through msbuild instead.
    exit /b 1
)

:: --- activate the msvc toolchain -----------------------------------------
set "VCVARS_LOG=%TEMP%\mergen_vcvars.log"
call "%VCVARS%" > "%VCVARS_LOG%" 2>&1
if errorlevel 1 (
    echo ERROR: "%VCVARS%" failed. Output:
    type "%VCVARS_LOG%"
    exit /b 1
)
if not exist "%VCToolsInstallDir%\bin\Hostx64\x64\cl.exe" (
    echo ERROR: cl.exe was not set up by "%VCVARS%".
    exit /b 1
)

echo INFO: LLVM_DIR      = %LLVM_CMAKE_DIR%
if defined LLVM_VERSION echo INFO: LLVM version  = %LLVM_VERSION%
echo INFO: VS            = %VSDIR%
echo INFO: cl.exe        = %VCToolsInstallDir%\bin\Hostx64\x64\cl.exe
echo INFO: cmake         = %CMAKE_BIN%
if "!USE_NINJA!"=="1" echo INFO: ninja         = %NINJA_EXE%
echo INFO: generator     = !GENERATOR!
echo INFO: arch          = !TOOLSET_ARCH!
echo INFO: backend       = %BACKEND%
echo INFO: build dir     = %BUILD_DIR%
echo INFO: build type    = %BUILD_TYPE%
echo INFO: build jobs    = %BUILD_JOBS%

:: --- drop a stale cache when the requested toolchain no longer matches ----
:: The FetchContent subbuilds also carry absolute paths, so a build tree that
:: was configured under a different repo root or LLVM prefix has to lose those
:: too, not just the top-level cache.
::
:: CMake stores these with forward slashes while the path arguments above use
:: backslashes, so compare normalized forms. Comparing the raw strings would
:: differ on every run and wipe the cache (and every object file under
:: CMakeFiles) on every single invocation.
set "NORMALIZED_LLVM_DIR=%LLVM_CMAKE_DIR:\=/%"
set "NORMALIZED_REPO_ROOT=%REPO_ROOT:\=/%"
if exist "%BUILD_DIR%\CMakeCache.txt" (
    set "CACHED_LLVM_DIR="
    set "CACHED_HOME_DIR="
    for /f "tokens=1,* delims==" %%A in ('findstr /B /R /C:"LLVM_DIR:[^=]*=" "%BUILD_DIR%\CMakeCache.txt"') do set "CACHED_LLVM_DIR=%%B"
    for /f "tokens=1,* delims==" %%A in ('findstr /B /R /C:"CMAKE_HOME_DIRECTORY:[^=]*=" "%BUILD_DIR%\CMakeCache.txt"') do set "CACHED_HOME_DIR=%%B"
    set "STALE_CACHE="
    if defined CACHED_LLVM_DIR (
        set "NORMALIZED_CACHED_LLVM=!CACHED_LLVM_DIR:\=/!"
        if /I not "!NORMALIZED_CACHED_LLVM!"=="%NORMALIZED_LLVM_DIR%" set "STALE_CACHE=1"
    ) else (
        set "STALE_CACHE=1"
    )
    if defined CACHED_HOME_DIR if /I not "!CACHED_HOME_DIR:\=/!"=="%NORMALIZED_REPO_ROOT%" set "STALE_CACHE=1"
    if defined STALE_CACHE (
        echo INFO: Clearing "%BUILD_DIR%" cache because the toolchain or repo root changed
        del /f /q "%BUILD_DIR%\CMakeCache.txt"
        if exist "%BUILD_DIR%\CMakeFiles" rmdir /s /q "%BUILD_DIR%\CMakeFiles"
        if exist "%BUILD_DIR%\_deps" for /d %%D in ("%BUILD_DIR%\_deps\*-subbuild") do (
            if exist "%%D\CMakeCache.txt" del /f /q "%%D\CMakeCache.txt"
            if exist "%%D\CMakeFiles" rmdir /s /q "%%D\CMakeFiles"
        )
    )
)

:: --- git safe.directory ---------------------------------------------------
:: The repo can live on a mapped/network drive (VirtualBox shared folder, SMB),
:: where git cannot resolve the owning uid and refuses every operation with
:: "detected dubious ownership". That breaks FetchContent's clone step.
::
:: Git's own suggested fix (git config --global --add safe.directory '%(prefix)...')
:: only works from an MSYS shell, where %(prefix) expands. Run from cmd it gets
:: stored literally as an unexpanded, non-absolute pattern, which git then warns
:: about and ignores -- so it looks applied but protects nothing.
::
:: Setting the config through the environment scopes the exception to git
:: processes this script spawns, leaving the user's global .gitconfig untouched.
:: GIT_CONFIG_COUNT can hold several KEY_n/VALUE_n pairs, so this composes with
:: any value the caller already exported.
set /a GIT_CONFIG_COUNT+=1
set "GIT_CONFIG_KEY_0=safe.directory"
set "GIT_CONFIG_VALUE_0=*"

:: --- configure -----------------------------------------------------------
if defined MERGEN_SKIP_CONFIGURE goto do_build
if /i "%ACTION%"=="configure" goto do_configure
if exist "%BUILD_DIR%\CMakeCache.txt" goto do_build

:do_configure
set "BACKEND_ARG=-DBUILD_WITH_ZYDIS=ON"
if /i not "%BACKEND%"=="zydis" (
    set "BACKEND_ARG="
    if defined CARGO_EXECUTABLE set "BACKEND_ARG=-DCARGO_EXECUTABLE=%CARGO_EXECUTABLE%"
)
echo INFO: Configuring...
:: The generator is baked into CMakeCache.txt, so switching between Ninja and
:: Visual Studio in the same build directory is rejected by CMake. Wipe the
:: cache (and the FetchContent subbuilds, which carry absolute paths) before
:: reconfiguring whenever the generator differs from the cached one.
if exist "%BUILD_DIR%\CMakeCache.txt" (
    set "CACHED_GENERATOR="
    for /f "tokens=1,* delims==" %%A in ('findstr /B /R /C:"CMAKE_GENERATOR:[^=]*=" "%BUILD_DIR%\CMakeCache.txt"') do set "CACHED_GENERATOR=%%B"
    if defined CACHED_GENERATOR (
        if /I "!CACHED_GENERATOR!"=="!GENERATOR!" goto generator_matches
        echo INFO: Clearing "%BUILD_DIR%" cache: generator "!CACHED_GENERATOR!" -^> "!GENERATOR!"
    ) else (
        echo INFO: Clearing "%BUILD_DIR%" cache: generator could not be determined
    )
    del /f /q "%BUILD_DIR%\CMakeCache.txt"
    if exist "%BUILD_DIR%\CMakeFiles" rmdir /s /q "%BUILD_DIR%\CMakeFiles"
    if exist "%BUILD_DIR%\_deps" for /d %%D in ("%BUILD_DIR%\_deps\*-subbuild") do (
        if exist "%%D\CMakeCache.txt" del /f /q "%%D\CMakeCache.txt"
        if exist "%%D\CMakeFiles" rmdir /s /q "%%D\CMakeFiles"
    )
)
:generator_matches

set "PLATFORM_ARG="
if "!USE_NINJA!"=="0" set "PLATFORM_ARG=-A !TOOLSET_ARCH!"
set "MAKEPROG_ARG="
if "!USE_NINJA!"=="1" set "MAKEPROG_ARG=-DCMAKE_MAKE_PROGRAM="%NINJA_EXE%""
:: The Visual Studio generator locates the compiler through the generator
:: platform/toolset, so the explicit cl overrides are only valid for Ninja.
set "COMPILER_ARG="
if "!USE_NINJA!"=="1" set "COMPILER_ARG=-DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl"


"%CMAKE_BIN%" -S "%REPO_ROOT%" -B "%BUILD_DIR%" ^
  -G "!GENERATOR!" ^
  %PLATFORM_ARG% ^
  %MAKEPROG_ARG% ^
  %COMPILER_ARG% ^
  -DCMAKE_CONFIGURATION_TYPES="%BUILD_TYPE%" ^
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ^
  -DLLVM_DIR="%LLVM_CMAKE_DIR%" ^
  %BACKEND_ARG%
if errorlevel 1 (
    echo ERROR: CMake configure failed.
    exit /b 1
)

:: --- build ---------------------------------------------------------------
:do_build
if not exist "%BUILD_DIR%\CMakeCache.txt" (
    echo ERROR: "%BUILD_DIR%" is not configured. Run scripts\dev\build_msvc.cmd configure
    exit /b 1
)
echo INFO: Building...

:: --config is ignored by Ninja (it is a single-config generator) but required
:: by the Visual Studio generator to pick Debug/Release from the .sln.
if "!USE_NINJA!"=="1" (
    "%CMAKE_BIN%" --build "%BUILD_DIR%" --parallel %BUILD_JOBS%
) else (
    "%CMAKE_BIN%" --build "%BUILD_DIR%" --config "%BUILD_TYPE%" --parallel %BUILD_JOBS%
)
if errorlevel 1 (
    echo ERROR: build failed.
    exit /b 1
)

:: Multi-config generators (Visual Studio) emit into a per-config subdirectory;
:: Ninja writes straight into the build root.
if "!USE_NINJA!"=="1" (
    set "BIN_DIR=%BUILD_DIR%"
) else (
    set "BIN_DIR=%BUILD_DIR%\%BUILD_TYPE%"
)
echo.
rem VS 2026 emits the XML-based .slnx; older generators wrote .sln.
if exist "%BUILD_DIR%\Mergen.slnx" (
    echo INFO: solution           = %BUILD_DIR%\Mergen.slnx
) else (
    echo INFO: solution           = %BUILD_DIR%\Mergen.sln
)
echo INFO: lifter             = !BIN_DIR!\lifter.exe
echo INFO: rewrite_microtests = !BIN_DIR!\rewrite_microtests.exe
:: Re-apply after the build: MSBuild may have rewritten the project files while
:: compiling, dropping anything it does not recognise.
exit /b 0

:usage
echo Usage: scripts\dev\build_msvc.cmd [build^|configure^|clean^|iced^|help]
exit /b 0
