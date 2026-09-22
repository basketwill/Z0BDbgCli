# WinDbgLite Python Bridge

## Entry points

Run Python from the CLI with:

- `py run <file>`
- `py exec <code>`

The script directory is added to `sys.path` before running a file, so sibling imports work.

## Available module: `z0dbg`

Signatures:

- `emit(text) -> None`
- `emit_line(text) -> None`
- `emit_color(text, fg) -> None`
- `emit_color_bg(text, fg, bg) -> None`
- `emit_info(text) -> None`
- `emit_warn(text) -> None`
- `emit_error(text) -> None`
- `launch(command_line) -> bool`
- `attach(pid) -> bool`
- `detach() -> bool`
- `continue_execution() -> bool`
- `single_step() -> bool`
- `step_over() -> bool`
- `execute(command) -> bool`
- `read_memory(address, size) -> bytes`
- `write_memory(address, data) -> int`
- `resolve_symbol(address) -> str`
- `read_cstr(address, max_bytes=4096) -> str`
- `read_wstr(address, max_chars=2048) -> str`
- `get_stop_info() -> dict`
- `print_stop_info() -> None`
- `get_thread_count() -> int`
- `get_thread_info(index) -> dict`
- `print_threads() -> None`
- `print_thread(index) -> None`
- `get_registers(index=None) -> dict`
- `get_context(index=None) -> dict`
- `get_stack_frames(index=None, max_frames=32) -> list[dict]`
- `get_stack(index=None, max_frames=32) -> list[dict]`
- `get_modules() -> list[dict]`
- `get_breakpoints() -> list[dict]`

Output helpers:

- `emit(text)`
- `emit_line(text)`
- `emit_color(text, fg)`
- `emit_color_bg(text, fg, bg)`
- `emit_info(text)`
- `emit_warn(text)`
- `emit_error(text)`

Debugger control:

- `launch(command_line)`
- `attach(pid)`
- `detach()`
- `continue_execution()`
- `single_step()`
- `step_over()`
- `execute(command)`

Memory:

- `read_memory(address, size) -> bytes`
- `write_memory(address, data) -> int`
- `read_cstr(address, max_bytes=4096) -> str`
- `read_wstr(address, max_chars=2048) -> str`

Symbol helpers:

- `resolve_symbol(address) -> str`

State queries:

- `get_stop_info() -> dict`
- `print_stop_info()`
- `get_thread_count() -> int`
- `get_thread_info(index) -> dict`
- `get_registers(index=None) -> dict`
- `get_stack_frames(index=None, max_frames=32) -> list[dict]`
- `get_modules() -> list[dict]`
- `get_breakpoints() -> list[dict]`

Text printers:

- `print_threads()`
- `print_thread(index)`
- `print_modules()`
- `print_breakpoints()`
- `print_registers()`
- `print_stack()`
- `print_context()`

## Argument notes

- `index` is the zero-based thread index from `get_thread_count()` / `get_thread_info()`.
- `pid` is a process id.
- `address` is a 64-bit target virtual address.
- `fg` and `bg` are RGB color values in `0xRRGGBB` form.
- `max_frames` limits stack frame collection.
- `max_bytes` / `max_chars` limit string reads and prevent unbounded scanning.

## Common pattern

```python
import z0dbg

regs = z0dbg.get_registers()
stack = z0dbg.get_stack_frames(max_frames=16)
z0dbg.emit_info(f"rip={regs['rip']:x}")
```
