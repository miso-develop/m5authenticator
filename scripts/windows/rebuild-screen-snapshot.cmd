@echo off
setlocal EnableExtensions

set "SCRIPT_DIR=%~dp0"
set "FIRMWARE_DIR=%SCRIPT_DIR%..\..\firmware"
set "PUSHED=0"

echo [screen-snapshot] Entering firmware directory...
pushd "%FIRMWARE_DIR%"
if errorlevel 1 goto :fail_no_pop
set "PUSHED=1"

echo [screen-snapshot] Repository HEAD:
git rev-parse HEAD
if errorlevel 1 goto :fail

echo [screen-snapshot] ESP-IDF version:
idf.py --version
if errorlevel 1 goto :fail

echo [screen-snapshot] Resetting diagnostics build directory for esp32s3...
idf.py -B build-screen-snapshot set-target esp32s3
if errorlevel 1 goto :fail

echo [screen-snapshot] Building diagnostics profile from the clean target configuration...
idf.py -B build-screen-snapshot -DM5AUTH_TEST_SCREEN_SNAPSHOT=ON build
if errorlevel 1 goto :fail

echo [screen-snapshot] Verifying diagnostics profile flag...
findstr /C:"M5AUTH_TEST_SCREEN_SNAPSHOT:BOOL=ON" build-screen-snapshot\CMakeCache.txt
if errorlevel 1 goto :fail

popd
echo [screen-snapshot] PASS: clean diagnostics rebuild completed with M5AUTH_TEST_SCREEN_SNAPSHOT=ON.
exit /b 0

:fail
if "%PUSHED%"=="1" popd
:fail_no_pop
echo [screen-snapshot] FAIL: clean diagnostics rebuild did not complete successfully.
exit /b 1
