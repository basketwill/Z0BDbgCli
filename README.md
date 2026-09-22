uicli:
<img width="1227" height="773" alt="image" src="https://github.com/user-attachments/assets/9beac98d-4ae3-4bb3-8001-1c0a367c9dbe" />

<img width="1218" height="762" alt="image" src="https://github.com/user-attachments/assets/24b59b1c-9fee-4077-b945-ab4ec75d8d01" />

<img width="1831" height="882" alt="image" src="https://github.com/user-attachments/assets/3ed66497-ec29-4bbb-812d-48857a31e096" />

cmdline:
Commands:
  z0dbgcli --py <file>                    Run a Python script after GUI init
  z0dbgcli --pyexec <code>                Run inline Python after GUI init
  launch <exe> [args...]                  Launch and break at main-module entry point
  .attach|attach <pid>                    Attach debugger to process
  .detach|detach                          Detach debugger from attached process
  drv <on|off|status|caps|antidebug|dr|handles|threadinfo|image|mitigations|events|events follow>
  veh <on|off|detach|kill|status> [pid]   Control VEH agent framework
  veh launch <exe> [args...]              Launch a process under VEH agent mode
  veh break                               Interrupt the VEH target process
  veh refresh                             Refresh VEH module/thread snapshot
  veh modules|threads                     Show VEH-synced module/thread cache
  veh read <addr> [size]                  Read memory through VEH agent
  veh write <addr> <byte...>              Write memory through VEH agent
  veh ctx <tid> | setreg <tid> <reg> <v>  Get/set thread context through VEH agent
  veh suspend|resume <tid>                Suspend/resume thread through VEH agent
  veh ex <bp|search|continue> [code]      Set VEH exception forwarding policy
  run | g                                 Continue execution
  step | si | t                           Single instruction step (step into)
  p | stepover | so                       Step over call/rep/loop/int
  gu                                      Go up until current function returns
  wt [max_steps]                          Trace/watch execution timing
  stepback|reverse|sbk [count]            Restore previous paused snapshot(s)
  debugback|dbk [count]                   Alias for stepback
  runtoentry|rte                          Run and break at main-module entry point
  snapshot|snap <save|restore|rerun|list|clear> [name]
  savesnap|snapsave [name]                Save current paused snapshot by name
  rerunsnap|snaprerun [name]              Restore snapshot and continue execution
  flow|cfg [address] [max_blocks]         Show textual control-flow graph
  stepuntil|traceuntil|tu <cond> [max]    Step until condition is met
  rununtil|pauseuntil|ru <cond> [max]     Continue/pause until condition is met
  autostep|astep <count> [delay_ms]       Automatic repeated single-step
  autorun|arun <cycles> [delay_ms]        Automatic repeated continue-to-pause
  break|bp <address|api|module!api|module+offset>
  bu <symbol|module!symbol|module+offset>  Set deferred software breakpoint
  hw|hr|he <addr>                         Set hardware write/read-access/execute breakpoint
  hbreak|hbp <slot> <addr> <type> <len> [tid|all]
                                           type: exec|write|access, len: 1|2|4|8
  hc|hclear <id|*>                        Delete hardware breakpoint(s)
  mbreak|mbp <addr> <size> <access>       Set memory guard breakpoint
                                           access: r|w|x|rw|rx|wx|rwx
  bl                                      List breakpoints
  be <id> | bd <id> | bc <id|*>           Enable/disable/delete breakpoint(s)
  bcond <id> <condition>                  Set breakpoint condition expression
  bcond clear <id>                        Clear breakpoint condition
                                           vars: hit tid ip addr; ops: == != > >= < <=; use &&
  excfg|exshow                            Show exception ignore/run-stop settings
  exignore all <scope> <on|off>           Toggle ignore-all exceptions in scope
  exignore add|del <scope> <code>         Manage ignored exception codes
  exignore clear <scope>                  Clear ignored exception code list
                                           scope: debug|run|step; code: hex or aliases (av,bp,ss,guard)
  exstop add|del|list|clear               Manage run-stop expression breakpoints
  eb|ew|ed|eq <addr> <value>              Write byte/word/dword/qword memory value
  eza|ezu <addr> <string>                 Write null-terminated ASCII/Unicode string
  patch|poke <addr> <byte...>             Patch target process memory bytes
  patch list [max_items]                  Show patch history (latest first)
  patch undo [count|*]                    Revert recent patch operations
  patchstr|ps <addr> <ascii|utf16> <txt>  Patch text bytes into target memory
  patchfile|pf <addr> <file> [off] [sz]   Patch bytes loaded from a file slice
  patchfile|pf preview <file> [off] [sz]  Preview bytes from a file slice
  nop <addr> <count>                      Patch count bytes with 0x90 NOP
  plugin|plug list                        List loaded plugin modules
  plugin|plug autoload                    Load all plugin DLLs from default plugin folders
  plugin|plug load <dll_path>             Load plugin module DLL
  plugin|plug enable <id|name>            Enable a loaded plugin module
  plugin|plug disable <id|name>           Disable a loaded plugin module
  plugin|plug unload <id|name|*>          Unload plugin module(s)
  plugin|plug run <id|name> [args...]     Execute a loaded plugin module
  !process|process                        Show process information
  processes|ps                            List processes
  !thread                                 Show current thread information and stack
  threads                                 Show thread information
  ~ | ~* | ~*s | ~*k | ~<index>s         List/switch threads, show all stacks
  !vm                                     Show virtual memory status
  vmmap|memmap                            Show process memory regions
  vad                                     Scan suspicious VAD-like regions
  vad dump <index|0xaddress> <file>       Dump one committed memory region
  iatcheck [module|all]                   Check imported function pointers
  modifycheck [module|all]                Compare selected module/API bytes
  syscallcheck [module]                   Check ntdll syscall stubs against disk
  threadcheck                             Check thread start/current addresses
  analysis report                         Summarize anti-debug/VAD/thread checks
  timeline [max]                          Show driver events and debugger stop
  timeline follow [interval_ms]           Follow the unified event timeline
  exceptioncheck                          Check SEH and exception dispatcher integrity
  modulecheck                             Check loaded module headers and mappings
  report export <file> [txt|json]         Export an analysis summary
  apitrace [max] [filter]                 Show driver-backed API behavior events
  modules | lm [m <filter>]               Show loaded modules
  .sympath|sympath [path]                 Show/set symbol search path
  symfix [cache_dir] [server_url]         Configure symbol server path
  .reload|symreload [*|module|address]    Reload symbols from path
  symdownload|symdl [*|module|address]    Download and load PDB symbols
  x <module!symbol-mask>                  Examine symbols
  srcroot <add|del|list|clear> [path]     Manage source localization roots
  srcwhere                                Show current IP source location
  srcat <address> [context_lines]         Show source around address
  srcbp <file> <line>                     Set source-level breakpoint
  srcresolve|srcr <file> <line>           Resolve source location to address
  scriptload|sload <file>                 Load custom debugger script
  scriptshow|sshow                         Show script with cursor/breakpoints
  scriptrun|scriptstart|srun              Run script until end/breakpoint
  scriptstep|sstep                         Execute one script line
  scriptuntil|srunto <label>               Run script until label is reached
  scriptbp|sbp <line>                      Set script breakpoint on source line
  scriptbd|sbd <line>                      Remove script breakpoint
  scriptbl|sbl                             List script breakpoints
  scriptset|sset <name> <value>            Set script variable
  scriptunset <name>                       Remove script variable
  scriptvars|svars                         Show script variables
  scriptreset|sreset                       Reset script cursor to start
  scriptclear|sclear                       Clear loaded script state
  envsave|savesettings [file_path]         Save current runtime environment snapshot
  envload|loadsettings [file_path]         Load runtime environment snapshot
  exception                               Show exception information
  r [mmx|float|debug|reg=value] [--ui]    Show or modify CPU registers
  regs                                    Alias for r
  asm color <on|off|status>               Toggle disassembly color output
  disasm|u|uf [address|api|module!api|module+offset] [count]
  pc|pseudoc|decompile [address|symbol] [count] [--ui] [--features]  Minimal pseudo C
  comment|cmt <add|set|del|show|list> ... Manage instruction comments
  k|kb|kv [max_frames] [--ui]             Show stack trace
  stack [max_frames] [--ui]               Show stack contents
  !peb|peb                                Show process environment block details
  !teb|teb                                Show current thread environment block details
  seh                                     Show SEH/exception chain details
  handles [max|all]                       Show process handle information
  memstr [min_len] [max]                  Scan memory strings
  s -a|-u <text> | -b <byte...> | -d <value> | -q <value>
  search                                  Alias for s
  db|dw|dd|dq <addr> [bytes] [per_line] [--ui] Dump memory as byte/word/dword/qword
  da <addr> [bytes] [--ui]                Display ASCII memory
  dt <type|module!type> <addr> [depth]    Display structure fields and values
  dump <file> [base_address length]       Dump current exe or a custom memory range to file
  .writemem <file> <addr> L<size>         Save target memory range to file
  .dvalloc <size>                         Allocate virtual memory in target process
  membin|mbin <address> <size>            Show memory as binary bytes
  context|ctx                             Show key debug context views
  py help                                 Show Python bridge help
  py run <file>                           Run a Python script file
  py exec <code>                          Execute Python code
  help                                    Show this help
  quit|exit                               Exit debugger
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
