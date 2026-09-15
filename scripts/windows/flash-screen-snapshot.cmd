@echo off
setlocal EnableExtensions

if "%~1"=="" (
    echo Usage: %~nx0 ^<PORT^>
    exit /b 2
)

set "PORT=%~1"
set "SCRIPT_DIR=%~dp0"
set "FIRMWARE_DIR=%SCRIPT_DIR%..\..\firmware"
set "PUSHED=0"

echo [screen-snapshot] Entering firmware directory...
pushd "%FIRMWARE_DIR%"
if errorlevel 1 goto :fail_no_pop
set "PUSHED=1"

if not exist build-screen-snapshot\CMakeCache.txt (
    echo [screen-snapshot] FAIL: diagnostics cache is missing. Run the build helper first.
    goto :fail
)

echo [screen-snapshot] Verifying diagnostics profile flag before flash...
findstr /C:"M5AUTH_TEST_SCREEN_SNAPSHOT:BOOL=ON" build-screen-snapshot\CMakeCache.txt
if errorlevel 1 goto :fail

echo [screen-snapshot] Flashing diagnostics image to %PORT%...
idf.py -B build-screen-snapshot -p "%PORT%" flash
if errorlevel 1 goto :fail

popd
echo [screen-snapshot] PASS: diagnostics image flashed to %PORT%.
exit /b 0

:fail
if "%PUSHED%"=="1" popd
:fail_no_pop
echo [screen-snapshot] FAIL: diagnostics flash did not complete successfully.
exit /b 1
