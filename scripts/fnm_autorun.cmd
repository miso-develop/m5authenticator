@echo off
if defined FNM_AUTORUN_GUARD goto :eof
set "FNM_AUTORUN_GUARD=AutorunGuard"
FOR /f "tokens=*" %%z IN ('fnm env --use-on-cd --version-file-strategy recursive') DO CALL %%z
fnm use --silent-if-unchanged --version-file-strategy recursive >nul 2>nul
exit /b 0
