@echo off
rem Build + test on Windows (MSVC + Ninja). Usage: build.bat [Debug|Release]
setlocal

set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=Release
rem Preset names are lowercase; the VS configuration name is not.
set "CFG_PRESET=release"
if /I "%CONFIG%"=="Debug" set "CFG_PRESET=debug"
if /I "%CONFIG%"=="Release" set "CFG_PRESET=release"

rem --- locate Visual Studio (vswhere is installed with every VS 2017+ product) ---
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo [kcp-cpp] vswhere.exe not found at "%VSWHERE%"
  exit /b 1
)

set "VSDIR="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR (
  echo [kcp-cpp] no Visual Studio installation with the MSVC x64 toolset found
  exit /b 1
)

echo [kcp-cpp] Visual Studio: %VSDIR%
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
  echo [kcp-cpp] vcvars64.bat failed
  exit /b 1
)

rem Prefer the CMake + Ninja that ship with VS, so the build works without a separate install.
set "PATH=%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%VSDIR%\VC\Tools\Llvm\x64\bin;%PATH%"

rem --- Windows SDK fallback ---
rem vcvars64.bat locates the SDK through the registry (reg.exe). In restricted shells that lookup
rem can fail, leaving INCLUDE/LIB without ucrt+um and rc.exe/mt.exe off PATH, which then surfaces as
rem "LNK1104: cannot open kernel32.lib". Fall back to the newest SDK under the standard root.
echo "%LIB%" | findstr /i /c:"Windows Kits" >nul
if not errorlevel 1 goto :sdk_ready

set "SDKROOT=%ProgramFiles(x86)%\Windows Kits\10"
set "SDKVER="
for /f "delims=" %%d in ('dir /b /ad /o-n "%SDKROOT%\bin\10.*" 2^>nul') do (
  if not defined SDKVER if exist "%SDKROOT%\Lib\%%d\um\x64\kernel32.lib" set "SDKVER=%%d"
)
if not defined SDKVER (
  echo [kcp-cpp] Windows SDK with x64 libs not found under "%SDKROOT%"
  exit /b 1
)
echo [kcp-cpp] Windows SDK fallback: %SDKVER%
set "SDKINC=%SDKROOT%\Include\%SDKVER%"
set "SDKLIB=%SDKROOT%\Lib\%SDKVER%"
set "INCLUDE=%SDKINC%\ucrt;%SDKINC%\um;%SDKINC%\shared;%SDKINC%\winrt;%INCLUDE%"
set "LIB=%SDKLIB%\ucrt\x64;%SDKLIB%\um\x64;%LIB%"
set "PATH=%SDKROOT%\bin\%SDKVER%\x64;%PATH%"

:sdk_ready
echo [kcp-cpp] configure
cmake --preset windows-x64 || goto :error

echo [kcp-cpp] build (%CONFIG%)
cmake --build --preset windows-x64-%CFG_PRESET% || goto :error

echo [kcp-cpp] header guard check
python tools\check_guard.py || goto :error

echo [kcp-cpp] clang-format check
python tools\check_format.py || goto :error

echo [kcp-cpp] ctest (%CONFIG%)
ctest --preset windows-x64-%CFG_PRESET% || goto :error

echo [kcp-cpp] OK
exit /b 0

:error
echo [kcp-cpp] FAILED with error %errorlevel%
exit /b %errorlevel%
