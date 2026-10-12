@echo off
rem Build the SecureKeys workspace with the MSVC toolchain + exploit mitigations.
cd /d "%~dp0"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>nul
set RUSTFLAGS=-C control-flow-guard=yes -C link-arg=/CETCOMPAT -C link-arg=/HIGHENTROPYVA
rem keep build artifacts out of OneDrive
set CARGO_TARGET_DIR=%LOCALAPPDATA%\securekeys-build
set CARGO=%USERPROFILE%\.cargo\bin\cargo.exe
"%CARGO%" +stable-x86_64-pc-windows-msvc build --release %*
echo BUILD_EXIT=%ERRORLEVEL%
echo TARGET_DIR=%CARGO_TARGET_DIR%\release
