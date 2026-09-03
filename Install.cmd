@echo off
setlocal EnableDelayedExpansion
title CE Board setup

echo ==========================================================
echo   Azure DevOps CE Board - setup
echo ==========================================================
echo.

set "ROOT=%~dp0"
set "RUNTIME=%ROOT%runtime"
set "PY="

rem 1. A private runtime, either shipped with this folder or from an earlier run.
if exist "%RUNTIME%\python.exe" set "PY=%RUNTIME%\python.exe"

rem 2. A system Python 3.7+ already on this PC.
if not defined PY (
  for %%C in (python.exe python3.exe) do (
    if not defined PY (
      for %%P in (%%C) do (
        if exist "%%~$PATH:P" (
          "%%~$PATH:P" -c "import sys;sys.exit(0 if sys.version_info>=(3,7) else 1)" >nul 2>&1
          if !errorlevel! equ 0 set "PY=%%~$PATH:P"
        )
      )
    )
  )
)

rem 3. Nothing usable: fetch the official portable build. No admin needed.
if not defined PY (
  echo No suitable Python was found on this PC.
  echo.
  echo Setup can download a private copy of Python 3.11 ^(about 11 MB^) into:
  echo   %RUNTIME%
  echo.
  echo It is the official portable build from python.org. It is NOT installed
  echo system-wide, needs no admin rights, changes no system settings, and is
  echo removed completely by deleting that folder.
  echo.
  set /p GO=Download it now? [Y/n]: 
  if /i "!GO!"=="n" (
    echo Cancelled.
    pause
    exit /b 1
  )
  echo.
  echo Downloading...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; try { [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $u='https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip'; $expect='009d6bf7e3b2ddca3d784fa09f90fe54336d5b60f0e0f305c37f400bf83cfd3b'; $z=Join-Path $env:TEMP 'ceboard-python.zip'; Invoke-WebRequest -Uri $u -OutFile $z -UseBasicParsing -TimeoutSec 300; $got=(Get-FileHash $z -Algorithm SHA256).Hash.ToLower(); if ($got -ne $expect) { Remove-Item $z -Force; Write-Host ('Checksum mismatch: expected ' + $expect + ' got ' + $got); exit 1 }; Write-Host 'Checksum verified.'; if (Test-Path '%RUNTIME%') { Remove-Item -Recurse -Force '%RUNTIME%' }; Expand-Archive -Path $z -DestinationPath '%RUNTIME%' -Force; Remove-Item $z -Force; exit 0 } catch { Write-Host $_.Exception.Message; exit 1 }"
  if errorlevel 1 (
    echo.
    echo The download failed, or the file did not match its expected checksum.
    echo Your network may block python.org, or something modified the download.
    echo Ask whoever shared this tool for the "offline" package, which
    echo already contains the runtime folder.
    echo.
    pause
    exit /b 1
  )
  if not exist "%RUNTIME%\python.exe" (
    echo Download completed but the runtime is not usable.
    pause
    exit /b 1
  )
  set "PY=%RUNTIME%\python.exe"
  echo Python ready.
)

echo.
echo Using: !PY!
echo.

rem Point at an Azure DevOps org/project, defaulting to ours.
set "ORG=ni"
set "PROJECT=DevCentral"
set /p ORG=Azure DevOps organisation [%ORG%]: 
set /p PROJECT=Project [%PROJECT%]: 

echo.
echo Installing for org "!ORG!", project "!PROJECT!"...
echo.
"!PY!" "%ROOT%scripts\install_autostart.py" --org "!ORG!" --project "!PROJECT!"
if errorlevel 1 (
  echo.
  echo Setup failed. See the messages above.
  pause
  exit /b 1
)

echo.
echo Opening the board. Click "Sign in" on the page to connect your account.
"!PY!" "%ROOT%scripts\open_board.py"

echo.
echo Done. Use the "CE Board" shortcut on your Desktop from now on.
pause
