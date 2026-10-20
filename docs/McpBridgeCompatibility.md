# MCP Bridge 兼容性：CLI(x86) 与 GUI(x64) 的统一修复

本文记录实际调试中暴露的三个 MCP 桥接问题，以及已在源码中统一修复的方式。修复后 x86 与 x64、GUI 与命令行窗口行为一致，不再需要单独维护 `/MD` 的临时构建。

## 1. 症状

| 场景 | 症状 |
| --- | --- |
| x64 `Z0BDbgCli.exe` + `Z0BDbgMcpBridge.dll` | `wdbl_execute` / `wdbl_disasm` 返回 `ok:true`，但 `output` 为空 |
| x86 `WinDbgLiteCli.exe` + 同一插件（x86） | 进程正常，但不创建 `\\.\pipe\Z0BDbgMcpBridge`，MCP 无法连接 |
| 数字地址 | `wdbl_read_memory` 传整数地址（如 `4198721`）读到错误数据或失败，传 `"0x401141"` 才正常 |

## 2. 根因

### 2.1 CRT 不一致导致 `std::wcout` 不是同一个对象

`McpBridgePlugin` 的 `execute_capture` 通过重定向 `std::wcout` 捕获命令输出。原工程：

- `WinDbgLiteCli.vcxproj`（Release/Debug，非 v100）使用静态 CRT：`/MT`、`/MTd`
- `McpBridgePlugin.vcxproj` 使用默认的动态 CRT：`/MD`、`/MDd`
- `Zydis.vcxproj` 也使用 `/MT`

因此 EXE 与 DLL 各自链接了一份 CRT，`std::wcout` 是两个独立对象。插件重定向自己的 `wcout` 捕获不到宿主输出，`output` 恒为空。

### 2.2 x86 的 `__stdcall` 导出名被修饰

插件入口使用 `extern "C" __declspec(dllexport) ... WDBL_CALL`，而 `WDBL_CALL` 在 x86 上是 `__stdcall`。MSVC 在 x86 上导出为：

```text
_WdblPluginGetInfo@4
_WdblPluginInitialize@8
_WdblPluginExecute@8
_WdblPluginShutdown@4
_WdblPluginOnEvent@8
```

宿主 `Debugger::LoadPluginModule` 按未修饰名 `WdblPluginGetInfo` 等查找，`GetProcAddress` 全部返回空，插件因此被判定为“exports are incomplete”而不加载。x64 没有修饰，所以问题只在 x86（CLI 构建）出现。

### 2.3 JSON 数字值被误读成下一个键名

插件的 `ExtractString` 在找到 `"key":` 后直接向后找第一个 `"`，没有确认值本身以引号开头。遇到数字值时会跳到下一个键的引号，把键名当成字符串返回。于是 `ExtractUInt64` 对 `"address": 4198721` 解析出 `0`（或下一个键名的 `_strtoui64` 结果），数字地址因此不可用。

## 3. 修复

### 3.1 统一动态 CRT

- `BuildVS2010\WinDbgLiteCli.vcxproj`
  - Debug（非 v100）：`MultiThreadedDebug` → `MultiThreadedDebugDLL`
  - Release（非 v100）：`MultiThreaded` → `MultiThreadedDLL`
- `BuildVS2010\Zydis.vcxproj`
  - Debug：`MultiThreadedDebug` → `MultiThreadedDebugDLL`
  - Release：`MultiThreaded` → `MultiThreadedDLL`
- `src\WinDbgLiteCli\McpBridgePlugin\McpBridgePlugin.vcxproj`
  - 显式声明 Debug `MultiThreadedDebugDLL`、Release `MultiThreadedDLL`

这样 EXE、Zydis 与插件共享 `msvcp140.dll` / `vcruntime140.dll` 中的同一份 `std::wcout`，`execute_capture` 在 GUI 窗口与命令行窗口中行为一致。

### 3.2 x86 导出未修饰别名

`McpBridgePlugin.cpp` 增加：

```cpp
#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:WdblPluginGetInfo=_WdblPluginGetInfo@4")
#pragma comment(linker, "/EXPORT:WdblPluginInitialize=_WdblPluginInitialize@8")
#pragma comment(linker, "/EXPORT:WdblPluginExecute=_WdblPluginExecute@8")
#pragma comment(linker, "/EXPORT:WdblPluginShutdown=_WdblPluginShutdown@4")
#pragma comment(linker, "/EXPORT:WdblPluginOnEvent=_WdblPluginOnEvent@8")
#endif
```

x86 DLL 同时导出修饰名与未修饰名，宿主按未修饰名即可加载；x64 不受影响。

### 3.3 JSON 解析

`ExtractString` 现在要求冒号后的第一个非空白字符必须是 `"`，否则返回失败，交由 `ExtractUInt64` / `ExtractBool` 按数字或布尔字面量解析。同时数字与布尔解析会跳过 `\r\n`。

`execute_capture` 在重定向前后各调用一次 `std::wcout.flush()`，避免缓冲区中的输出漏捕获。

## 4. 构建与部署

```bat
set MSB=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe

"%MSB%" src\WinDbgLiteCli\McpBridgePlugin\McpBridgePlugin.vcxproj ^
  /t:Rebuild /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143

"%MSB%" BuildVS2010\WinDbgLiteCli.vcxproj ^
  /t:Rebuild /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143

"%MSB%" src\WinDbgLiteCli\McpBridgePlugin\McpBridgePlugin.vcxproj ^
  /t:Rebuild /p:Configuration=Release /p:Platform=Win32 /p:PlatformToolset=v143

"%MSB%" BuildVS2010\WinDbgLiteCli.vcxproj ^
  /t:Rebuild /p:Configuration=Release /p:Platform=Win32 /p:PlatformToolset=v143
```

部署目录：

```text
Build\Bin\Release\x64\Z0BDbgCli.exe
Build\Bin\Release\x64\plugins\Z0BDbgMcpBridge.dll
Build\Bin\Release\x86\WinDbgLiteCli.exe
Build\Bin\Release\x86\plugins\Z0BDbgMcpBridge.dll
```

## 5. 验证

- x64 GUI：`wdbl_ping` 正常；`wdbl_execute "help"` 返回完整命令列表（`output` 非空）；`wdbl_disasm 0x401141 count=5` 返回 5 条指令。
- x64 GUI：`wdbl_disasm` 默认输出不含 ANSI 转义；`structured=true` 返回 5 个 `{address, bytes, text}` 对象。
- x64 GUI：`wdbl_disasm_range start=0x401140 end=0x401180` 返回 16 条指令，最后一条结束地址正好为 `0x401180`。
- x64 GUI：`wdbl_ai_brief` 返回 Markdown，包含停止原因、寄存器、栈、IP 反汇编与模块。
- x64 GUI：`wdbl_read_memory` 使用整数地址 `4198721` 返回 `89E583EC18C7042402000000FF1530EC...`。
- x86 CLI：`wdbl_ping` 正常；`wdbl_execute "help"` 返回完整命令列表，确认 x86 插件已加载且 `execute_capture` 可用；`wdbl_disasm` 结构化输出正常。

## 6. 备注

- GUI 与 CLI 的区分只是同一工程的 x64（`Z0BDbgCli.exe`）与 Win32（`WinDbgLiteCli.exe`）产物；修复位于共享源码，因此两边同时生效。
- 之前为绕过 `/MT` 问题在 `D:\mywork\ai\t2\clibuild` 构建的临时 `/MD` 调试器不再需要；保留仅为历史取证。
- 若加载第三方旧插件，宿主仍按未修饰名查找导出；x86 旧插件需要自行补 `/EXPORT` 别名或重新编译。
