@echo off
rem Load repository-local non-secret tooling settings from .env into cmd.exe.
rem Run with: call scripts\load-env.cmd

set "_M5AUTH_ENV_FILE=%~dp0..\.env"

if not exist "%_M5AUTH_ENV_FILE%" (
  echo [env] Missing %_M5AUTH_ENV_FILE%
  echo [env] Create it with: copy .env.example .env
  exit /b 2
)

set "M5AUTH_IDF_VERSION="
set "M5AUTH_CHIP="
set "M5AUTH_PORT="

for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%_M5AUTH_ENV_FILE%") do (
  if "%%A"=="M5AUTH_IDF_VERSION" (
    set "M5AUTH_IDF_VERSION=%%B"
  ) else if "%%A"=="M5AUTH_CHIP" (
    set "M5AUTH_CHIP=%%B"
  ) else if "%%A"=="M5AUTH_PORT" (
    set "M5AUTH_PORT=%%B"
  ) else (
    echo [env] Unsupported key in .env: %%A
    exit /b 2
  )
)

if not defined M5AUTH_IDF_VERSION (
  echo [env] M5AUTH_IDF_VERSION is required.
  exit /b 2
)
if /i not "%M5AUTH_IDF_VERSION%"=="v5.5.5" (
  echo [env] Expected M5AUTH_IDF_VERSION=v5.5.5 but got %M5AUTH_IDF_VERSION%.
  exit /b 2
)

if not defined M5AUTH_CHIP (
  echo [env] M5AUTH_CHIP is required.
  exit /b 2
)
if /i not "%M5AUTH_CHIP%"=="esp32s3" (
  echo [env] Expected M5AUTH_CHIP=esp32s3 but got %M5AUTH_CHIP%.
  exit /b 2
)

if not defined M5AUTH_PORT (
  echo [env] M5AUTH_PORT is required.
  exit /b 2
)
echo(%M5AUTH_PORT%| findstr /r /i "^COM[1-9][0-9]*$" >nul
if errorlevel 1 (
  echo [env] M5AUTH_PORT must be a Windows COM port such as COM4.
  exit /b 2
)

echo [env] M5AUTH_IDF_VERSION=%M5AUTH_IDF_VERSION%
echo [env] M5AUTH_CHIP=%M5AUTH_CHIP%
echo [env] M5AUTH_PORT=%M5AUTH_PORT%
exit /b 0
