@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

set "PY="
where python >nul 2>nul
if not errorlevel 1 set "PY=python"
if not defined PY goto trypy
goto ready

:trypy
where py >nul 2>nul
if not errorlevel 1 set "PY=py -3"

:ready
if not defined PY goto nopython
set "FIRST=%~1"
if "%FIRST%"=="" goto ui
set "HEAD=%FIRST:~0,1%"
if "%HEAD%"=="-" goto ui
goto check

:check
echo.
echo   certdiag - checking: %~nx1
echo.
%PY% -m certdiag "%~1"
echo.
echo   Press any key to close...
pause >nul
exit /b 0

:ui
echo.
echo   certdiag - Windows code signing / certificate chain diagnostics
echo   Starting UI, please wait...
echo.
%PY% -m certdiag --ui %*
pause
exit /b 0

:nopython
echo.
echo   [x] Python not found.
echo.
echo   Install Python 3.9+ from https://www.python.org/downloads/
echo   and check "Add Python to PATH" during setup.
echo.
pause
exit /b 1
