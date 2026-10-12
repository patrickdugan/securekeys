@echo off
rem Verify the shipped exploit mitigations in the built binary.
cd /d "%~dp0"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>nul
set T=%LOCALAPPDATA%\securekeys-build\release
echo ===== securekeys.exe DLL characteristics =====
dumpbin /headers "%T%\securekeys.exe" | findstr /C:"DLL characteristics" /C:"Dynamic base" /C:"NX compatible" /C:"High Entropy" /C:"Control Flow Guard" /C:"CET"
