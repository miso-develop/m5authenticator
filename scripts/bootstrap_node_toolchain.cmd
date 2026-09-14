@echo off
setlocal EnableExtensions

set "REPO_ROOT=%~dp0.."
set "NODE_VERSION="
set "NPM_VERSION=11.19.0"

if not exist "%REPO_ROOT%\.node-version" (
  echo ERROR: %REPO_ROOT%\.node-version was not found.
  exit /b 1
)

for /f "usebackq delims=" %%V in ("%REPO_ROOT%\.node-version") do (
  if not defined NODE_VERSION set "NODE_VERSION=%%V"
)

if not defined NODE_VERSION (
  echo ERROR: .node-version is empty.
  exit /b 1
)

where fnm >nul 2>nul
if errorlevel 1 (
  echo ERROR: fnm was not found on PATH.
  exit /b 1
)

echo Installing pinned Node.js %NODE_VERSION% with fnm...
fnm install %NODE_VERSION%
if errorlevel 1 exit /b 1

echo Pinning npm %NPM_VERSION% inside the fnm-managed Node.js %NODE_VERSION% installation...
fnm exec --using=%NODE_VERSION% -- cmd.exe /d /s /c "npm install --global npm@%NPM_VERSION%"
if errorlevel 1 exit /b 1

for /f "delims=" %%V in ('fnm exec --using=%NODE_VERSION% -- node --version') do set "ACTUAL_NODE=%%V"
for /f "delims=" %%V in ('fnm exec --using=%NODE_VERSION% -- cmd.exe /d /s /c "npm --version"') do set "ACTUAL_NPM=%%V"

echo Node.js: %ACTUAL_NODE%
echo npm:     %ACTUAL_NPM%

if /i not "%ACTUAL_NODE%"=="v%NODE_VERSION%" (
  echo ERROR: Node.js version verification failed.
  exit /b 1
)
if /i not "%ACTUAL_NPM%"=="%NPM_VERSION%" (
  echo ERROR: npm version verification failed.
  exit /b 1
)

echo Toolchain bootstrap complete.
echo Configure fnm env --use-on-cd in your shell startup once; after that, cd into this repository will select this Node.js installation and its pinned npm automatically.
exit /b 0
