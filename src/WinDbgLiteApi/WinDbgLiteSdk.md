# WinDbgLite SDK

## Native entry points

Include `WinDbgLiteSdk.h` when you need the debugger API and plugin ABI in one place.

```cpp
#include "WinDbgLiteSdk.h"

WdblDebuggerHandle handle = nullptr;
if (WdblCreateDebugger(L"trace.log", &handle)) {
    const WdblDebuggerApi* api = WdblGetDebuggerApi(handle);
    WdblDestroyDebugger(handle);
}
```

### Core functions

- `WdblCreateDebugger(tracePath, outHandle)` creates a debugger instance.
- `WdblDestroyDebugger(handle)` releases it.
- `WdblGetDebuggerApi(handle)` returns the debugger API table.

## Python bridge module

The CLI exposes a built-in Python module named `z0dbg`.
There is no separate bridge DLL for script use.

### Common return patterns

- `bool` for success/failure commands.
- `int` for ids, counts, or bytes written.
- `dict` for structured data.
- `bytes` for raw memory.
- `str` for text output.

### Command execution

- `execute(command, capture_output=False)`
  - `command`: debugger command text.
  - `capture_output=False`: only returns `True/False`.
  - `capture_output=True`: returns `{"ok": bool, "output": str}` and still prints in the CLI.
- `execute_capture(command)` is the same as `execute(..., capture_output=True)`.

### Output helpers

- `emit(text)`, `emit_line(text)`
- `emit_color(text, fg)`, `emit_color_bg(text, fg, bg)`
- `emit_info(text)`, `emit_warn(text)`, `emit_error(text)`

### Debugger helpers

- `launch(command_line)`, `attach(pid)`, `detach()`
- `continue_execution()`, `single_step()`, `step_over()`
- `get_stop_info()`, `get_context()`
- `get_thread_count()`, `get_thread_info(index)`
- `get_registers(index=None)`, `get_stack_frames(index=None, max_frames=32)`
- `get_modules()`, `get_breakpoints()`

### Memory and symbols

- `read_memory(address, size) -> bytes`
- `write_memory(address, data) -> int`
- `read_cstr(address, max_bytes=4096) -> str`
- `read_wstr(address, max_chars=2048) -> str`
- `resolve_symbol(address) -> str`
- `resolve_address_expression(expression) -> {"address": int, "text": str}`
- `load_symbols(target='*') -> {"target": str, "pdb_path": str, "downloaded": bool}`
- `download_symbols(target='*', cache_dir=None, server_url=None) -> dict`

### Plugin VM disassembly providers

Native plugins can register a VM/custom instruction decoder through:

```cpp
api->registerVmDisasmProvider(api->context, L"myvm", DecodeVmInstruction, pluginContext);
```

The callback receives `WdblVmDisasmInput`, including the target address, architecture bits, current register snapshot, stack pointer, and nearby raw bytes. It fills `WdblVmDisasmOutput` with `consumedBytes`, `confidence`, `text`, and optional `comment`.

CLI commands:

- `vmprovider list`
- `vmdis [address] [count] [--provider name]`

### Plugin-defined CLI commands

Native plugins can register custom commands through:

```cpp
api->registerPluginCommand(api->context, L"vmpregs", L"Show VM registers", HandleCommand, pluginContext);
```

The callback receives the command name and the remaining command line as one argument string. Built-in debugger commands keep priority; plugin commands are dispatched only when no built-in command matched.

CLI command:

- `plugcmd list`

### Breakpoints

- `add_software_breakpoint(address_expression) -> int`
- `add_hardware_breakpoint(address_expression, access='x', length=1, slot=-1, thread_id=0) -> int`
- `add_memory_breakpoint(address_expression, size, access='rw') -> int`
- `enable_breakpoint(id)`, `disable_breakpoint(id)`, `remove_breakpoint(id)`
- `set_breakpoint_condition(id, expression)`, `clear_breakpoint_condition(id)`

### Example

```python
import z0dbg

print(z0dbg.get_stop_info())
print(z0dbg.execute_capture("k"))
```
