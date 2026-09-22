# VS2010-Format Build Files

This directory contains a manual Visual Studio solution in VS2010 project format for WinDbgLite:

- `WinDbgLite.sln`
- `WinDbgLite.vcxproj`
- `WinDbgLiteWin32UI.vcxproj`

## Included Dependency

The solution references:

- `..\third_party\udis86\BuildVS2010\libudis86.vcxproj`

`libudis86` must be built as part of the solution before linking `WinDbgLite` targets.
Both `WinDbgLite` and `WinDbgLiteWin32UI` are selected for default solution-build.

## Configurations

Supported solution configurations:

- `Debug|Win32`
- `Debug|x64`
- `Release|Win32`
- `Release|x64`

Runtime library setup:

- `Debug`: `/MTd`
- `Release`: `/MT`

## Notes

- Pure VS2010 (`v100`) builds are supported through a compatibility fallback mode.
- In `v100` mode, projects compile compatibility launchers that proxy to modern WinDbgLite binaries so debugger behavior stays compatible with previous code.
- `WinDbgLiteWin32UI` uses `WinMain` in `src\WinDbgLiteWin32UI\Win32UiMain.cpp` for VS2010 compatibility mode (no separate legacy UI entrypoint file in the build path).
- Newer toolsets (`v142` or later) can still be used to build the full modern sources.
- Compatibility mode is controlled by macros:
  - `WDBL_CPP11_COMPAT_UI` (Win32 UI)
  - `WDBL_CPP11_COMPAT_CONSOLE` (console)
  - Both are set to `1` automatically for `v100`, and `0` for newer toolsets.
- `build.bat` defaults to `v100`:
  - `BuildVS2010\build.bat Release x64`
  - `BuildVS2010\build.bat Release x64 v100`
- To build with a newer toolset:
  - `BuildVS2010\build.bat Release x64 v142`
  - or `msbuild BuildVS2010\WinDbgLite.sln /t:Build /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v142`

### Runtime Compatibility Paths (`v100`)

- Console launcher (`WinDbgLite.exe`) tries:
  - `%WDBL_MODERN_EXE%`
  - `WinDbgLite.modern.exe` in the same directory
  - `WinDbgLite.real.exe` in the same directory
  - `..\..\..\..\..\build\Release\WinDbgLite.exe`
  - `..\..\..\..\..\build\RelWithDebInfo\WinDbgLite.exe`
  - `..\..\..\..\..\build\Debug\WinDbgLite.exe`
- Win32 UI launcher (`WinDbgLiteWin32UI.exe`) tries:
  - `%WDBL_MODERN_UI_EXE%`
  - `WinDbgLiteWin32UI.modern.exe` in the same directory
  - `WinDbgLiteWin32UI.real.exe` in the same directory
  - `..\..\..\..\..\build\Release\WinDbgLiteWin32UI.exe`
  - `..\..\..\..\..\build\RelWithDebInfo\WinDbgLiteWin32UI.exe`
  - `..\..\..\..\..\build\Debug\WinDbgLiteWin32UI.exe`

## VSCode + VS2010 Build

The repository includes VSCode build tasks at:

- `.vscode/tasks.json`

Default build task:

- `VS2010: Build WinDbgLiteWin32UI (Debug|Win32)`

Available VSCode tasks include:

- Build `WinDbgLiteWin32UI` (`Debug|Win32`, `v100`)
- Build `WinDbgLite` (`Debug|Win32`, `v100`)
- Build solution (`Debug|Win32`, `v100`)
- Build solution (`Release|x64`, `v100`)
- Rebuild/Clean solution (`Debug|Win32`, `v100`)

In VSCode:

1. Press `Ctrl+Shift+B` to run default task.
2. Or run `Tasks: Run Task` and pick a `VS2010:` task.
