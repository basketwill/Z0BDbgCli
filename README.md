uicli:
<img width="1227" height="773" alt="image" src="https://github.com/user-attachments/assets/9beac98d-4ae3-4bb3-8001-1c0a367c9dbe" />

<img width="1218" height="762" alt="image" src="https://github.com/user-attachments/assets/24b59b1c-9fee-4077-b945-ab4ec75d8d01" />

<img width="1831" height="882" alt="image" src="https://github.com/user-attachments/assets/3ed66497-ec29-4bbb-812d-48857a31e096" />


# WinDbgLite Functional Code Annotations

This document explains the functional structure of the project and the key execution paths for maintenance and extension.

## 1. Module Responsibilities

- `src/Debugger.cpp`
  - Backend debugger engine.
  - Owns process attach/launch, breakpoint handling, memory patching, symbol/source integration, tracing, and command execution.
- `src/main.cpp`
  - Console entry and command loop for backend mode.
- `src/Win32UiMain.cpp`
  - Win32 UI frontend.
  - Owns windows, layout, MDI workspace, status bar custom control, backend pipe I/O, and menu/toolbar command routing.
- `src/WinApiDynamic.h`, `src/WinApiDynamic.cpp`
  - Dynamic system API resolver and macro dispatch layer.
  - Converts most Win32 calls into runtime-resolved invocations (`WDBL_DYN_WINAPI_CALL`).
- `src/CustomListControl.cpp`
  - Custom disassembly/grid-like control behaviors.
- `src/Win32UiMain.cpp` (hex data control logic in-file)
  - Memory/hex visualization control and editing interaction.
- `src/Win32UiMain.cpp` (script code control logic in-file)
  - Script editor text control support.
- `src/Win32UiMain.cpp` (disassembly list manager logic in-file)
  - Disassembly list formatting and style maintenance.

## 2. Win32 UI Execution Flow (`Win32UiMain.cpp`)

### 2.1 Startup and Window Lifetime

- `wWinMain`:
  - Initializes common controls and app state.
  - Registers custom classes (status bar, MDI document, supporting dialogs).
  - Creates main window.
- `MainWindowProc`:
  - `WM_CREATE`: create core controls and initialize fonts/theme/layout.
  - `WM_SIZE`: recalculates layout via `ResizeControls`.
  - `WM_COMMAND`: routes menu/toolbar/button commands to action handlers.
  - `WM_DESTROY`: backend cleanup and process shutdown.

### 2.2 Backend Output Pipeline

- `BackendReaderThreadProc`:
  - Background reader of backend stdout.
- `ProcessBackendChunk`:
  - Buffers incoming chunks into complete logical lines.
- `ProcessBackendLine`:
  - Parses semantic sections (registers, stack, disassembly, memory, etc.).
  - Dispatches data to dashboard panes and output area.
- `AppendOutput`:
  - Rich edit output append with color categories.

### 2.3 Dashboard and MDI Layout Pipeline

- `ResizeControls`:
  - Single source of truth for main window child geometry.
  - Handles both classic dashboard and MDI workspace layouts.
  - In MDI mode, keeps output panel outside MDI and places it above command input.
- `LayoutMdiWorkspaceContent`:
  - Arranges disassembly/stack/memory/context/register panes inside one MDI document.
- Splitter interactions:
  - `HitTestSplitter`: identifies draggable splitter region.
  - `UpdateSplitterDrag`: applies constrained drag math.
  - `DrawSplitterGuides`: paints splitter guides/handles.
  - `ResetSplitterLayout`: double-click reset behavior.

### 2.4 Status Bar Custom Control

- `BottomStatusBarProc`:
  - Custom paint routine for the bottom status bar.
  - Uses light gray background and text colors based on status tone.
- `DetermineBottomStatusTone` + `ResolveBottomStatusTextColor`:
  - Maps status text content to:
    - normal (green),
    - error (red),
    - running (yellow).

## 3. Dynamic WinAPI Layer Notes

- The project uses `#define WDBL_ENABLE_DYNAMIC_WINAPI_MACROS`.
- `WinApiDynamic.h` maps many Win32 APIs to dynamic calls.
- `InvokeDynamic<decltype(&::ApiName)>` resolves procedures by module+name at runtime.
- Missing APIs return safe defaults and set `ERROR_PROC_NOT_FOUND`.

## 4. Recent UI Optimization Notes

- MDI workspace and output panel split are independently resizable.
- Output panel vertical size is draggable and persisted by settings.
- Splitter hit-testing includes an expanded interaction area for easier drag.
- Startup layout guards prevent invalid clamp ranges and initialization-time crashes.

## 5. Extension Guidance

- Add new UI panel:
  - create control in `WM_CREATE`,
  - add placement logic to `ResizeControls`,
  - add localization/theme/font updates in refresh helpers.
- Add new backend section rendering:
  - parse section header in `ProcessBackendLine`,
  - store lines in `viewLines`,
  - rebuild list/control through `RebuildPaneList`.
- Add new splitter:
  - add enum value,
  - add `RECT` state field,
  - implement hit-test + drag update + draw + reset paths consistently.
