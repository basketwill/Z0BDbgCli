# WinDbgLite SDK

## Headers

- `src\Common\PluginApi.h`
- `src\WinDbgLiteApi\WinDbgLiteApi.h`
- `src\WinDbgLiteApi\WinDbgLiteSdk.h`

## Debugger API

Create a debugger handle with `WdblCreateDebugger`, then fetch the runtime API with `WdblGetDebuggerApi`.

Key `WdblDebuggerApi` calls:

- `launch`
- `attach`
- `detach`
- `continueExecution`
- `singleStep`
- `stepOver`
- `readMemory`
- `writeMemory`
- `resolveSymbol`
- `getStopInfo`
- `getThreadCount`
- `getThreadInfo`
- `getRegisterInfo`
- `getStackFrameInfo`
- `getModuleCount`
- `getModuleInfo`
- `getBreakpointCount`
- `getBreakpointInfo`
- `executeCommand`

## Plugin ABI

Plugins still use:

- `WdblPluginGetInfo`
- `WdblPluginInitialize`
- `WdblPluginExecute`
- `WdblPluginShutdown`
- `WdblPluginOnEvent`

## Notes

- All exported structs are size-tagged. Set `size = sizeof(...)` before calling into the API.
- `WdblDebuggerApi::apiVersion` is currently `4`.
- `WdblPluginInfo::apiVersion` remains `2`.

