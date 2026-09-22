@echo off
setlocal

set SOLUTION=%~dp0WinDbgLite.sln
set CONFIG=%1
set PLATFORM=%2
set TOOLSET=%3
set TARGET=%4

if "%CONFIG%"=="" set CONFIG=Release
if "%PLATFORM%"=="" set PLATFORM=x64
if "%TOOLSET%"=="" set TOOLSET=v100
if "%TARGET%"=="" set TARGET=Build

if /I "%TOOLSET%"=="v100" (
  echo [INFO] v100 selected: building VS2010 compatibility fallback targets.
  echo [INFO] Win32 UI entrypoint is built from Win32UiMain.cpp with VS2010 compatibility branch.
)

set "MSBUILD_EXE="
if /I "%TOOLSET%"=="v100" (
  if exist "C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" set "MSBUILD_EXE=C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"
)
if not "%MSBUILD_EXE%"=="" goto :build

if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD_EXE=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD_EXE=C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD_EXE=C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe"
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD_EXE=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD_EXE=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if not "%MSBUILD_EXE%"=="" goto :build

set "MSBUILD_EXE=msbuild"
where msbuild >nul 2>nul
if errorlevel 1 (
  echo [ERROR] MSBuild.exe not found.
  exit /b 3
)

:build
echo Building %SOLUTION% [%CONFIG% ^| %PLATFORM% ^| %TOOLSET% ^| %TARGET%]
"%MSBUILD_EXE%" "%SOLUTION%" /t:%TARGET% /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /p:PlatformToolset=%TOOLSET%
exit /b %errorlevel%
