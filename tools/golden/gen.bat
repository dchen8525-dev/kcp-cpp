@echo off
rem Regenerate the golden vectors from the reference implementation.
rem Requires the kcp-go checkout (default D:\work\kcp-go) and a Go toolchain.
setlocal

set "GOBIN=go"
where go >nul 2>nul || set "GOBIN=C:\Program Files\Go\bin\go.exe"
if not "%GO%"=="" set "GOBIN=%GO%"

if "%GOPROXY%"=="" set "GOPROXY=https://goproxy.cn,direct"
if "%KCP_GO_DIR%"=="" set "KCP_GO_DIR=D:\work\kcp-go"

cd /d "%~dp0"
"%GOBIN%" run gen.go
if errorlevel 1 exit /b 1

echo.
echo Golden vectors written to %~dp0out
