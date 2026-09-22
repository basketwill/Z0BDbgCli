# WinDbgLiteMemDrv (Win10/Win11)

This folder contains a Windows kernel driver scaffold for Windows 10 and Windows 11.

## Included files

- `WinDbgLiteMemDrv.c` - non-PnP style driver entry + device/IOCTL dispatch.
- `WinDbgLiteMemDrv.inf` - install metadata targeting `NTamd64.10.0` (Windows 10/11 x64).
- `../../src/Common/WinDbgLiteMemIoctl.h` - shared user/kernel IOCTL contract.

## Device contract

- Device path: `\\.\WinDbgLiteMem`
- Supported test IOCTL:
  - `IOCTL_WDBL_PING` -> returns `ULONG` value `1`
- Supported memory IOCTLs:
  - `IOCTL_WDBL_READ_PROCESS_MEMORY` (input: `WDBL_PROCESS_MEMORY_READ_REQUEST`, output: raw bytes)
  - `IOCTL_WDBL_WRITE_PROCESS_MEMORY` (input: `WDBL_PROCESS_MEMORY_WRITE_REQUEST_HEADER + bytes`, output: `ULONG bytesWritten`)
- Supported thread-context IOCTLs:
  - `IOCTL_WDBL_GET_THREAD_CONTEXT` (input: `WDBL_THREAD_CONTEXT_REQUEST`, output: `CONTEXT`)
  - `IOCTL_WDBL_SET_THREAD_CONTEXT` (input: `WDBL_THREAD_CONTEXT_REQUEST + CONTEXT`)
  - `IOCTL_WDBL_GET_WOW64_THREAD_CONTEXT` (input: `WDBL_WOW64_THREAD_CONTEXT_REQUEST`, output: `WDBL_WOW64_CONTEXT`)
  - `IOCTL_WDBL_SET_WOW64_THREAD_CONTEXT` (input: `WDBL_WOW64_THREAD_CONTEXT_REQUEST + WDBL_WOW64_CONTEXT`)
- Supported virtual-memory IOCTLs:
  - `IOCTL_WDBL_QUERY_VIRTUAL_MEMORY` (input: `WDBL_VIRTUAL_MEMORY_QUERY_REQUEST`, output: `MEMORY_BASIC_INFORMATION`)
  - `IOCTL_WDBL_PROTECT_VIRTUAL_MEMORY` (input: `WDBL_VIRTUAL_MEMORY_PROTECT_REQUEST`, output: `WDBL_VIRTUAL_MEMORY_PROTECT_RESULT`)
  - `IOCTL_WDBL_ALLOCATE_VIRTUAL_MEMORY` (input: `WDBL_VIRTUAL_MEMORY_ALLOCATE_REQUEST`, output: `WDBL_VIRTUAL_MEMORY_ALLOCATE_RESULT`)
  - `IOCTL_WDBL_FREE_VIRTUAL_MEMORY` (input: `WDBL_VIRTUAL_MEMORY_FREE_REQUEST`)
- Supported execution/control IOCTLs:
  - `IOCTL_WDBL_CREATE_USER_THREAD` (input: `WDBL_CREATE_USER_THREAD_REQUEST`, output: `WDBL_CREATE_USER_THREAD_RESULT`)
  - `IOCTL_WDBL_SUSPEND_THREAD` / `IOCTL_WDBL_RESUME_THREAD` (input: `WDBL_THREAD_CONTROL_REQUEST`, output: `WDBL_THREAD_CONTROL_RESULT`)
  - `IOCTL_WDBL_SUSPEND_PROCESS` / `IOCTL_WDBL_RESUME_PROCESS` (input: `WDBL_PROCESS_CONTROL_REQUEST`)
  - `IOCTL_WDBL_TERMINATE_PROCESS` (input: `WDBL_PROCESS_CONTROL_REQUEST`)
- Supported diagnostics IOCTLs:
  - `IOCTL_WDBL_QUERY_DEBUG_API_SUPPORT` (output: `WDBL_DEBUG_API_SUPPORT_RESULT`)
  - `IOCTL_WDBL_QUERY_EPROCESS_IMAGE_NAME_OFFSET` (output: `WDBL_EPROCESS_IMAGE_NAME_OFFSET_RESULT`)
  - `IOCTL_WDBL_QUERY_CAPABILITIES` (output: `WDBL_DRIVER_CAPABILITIES_RESULT`)
  - `IOCTL_WDBL_QUERY_ANTI_DEBUG` (input: `WDBL_ANTI_DEBUG_QUERY_REQUEST`, output: `WDBL_ANTI_DEBUG_QUERY_RESULT`)
  - `IOCTL_WDBL_QUERY_DEBUG_REGISTERS` / `IOCTL_WDBL_SET_DEBUG_REGISTERS` (thread DR0-DR7 access)
  - `IOCTL_WDBL_QUERY_HANDLE_LIST` (input: `WDBL_HANDLE_ENUM_REQUEST`, output: handle entries and best-effort object names)
  - `IOCTL_WDBL_QUERY_THREAD_INFO` (input: `WDBL_THREAD_INFO_REQUEST`, output: TEB/start-address information)
  - `IOCTL_WDBL_QUERY_IMAGE_INFO` (input: `WDBL_IMAGE_INFO_REQUEST`, output: PE image-header information)
  - `IOCTL_WDBL_QUERY_PROCESS_MITIGATIONS` (input: `WDBL_PROCESS_MITIGATIONS_REQUEST`, output: execute/protection policy information)
  - `IOCTL_WDBL_QUERY_DRIVER_EVENTS` (input: `WDBL_DRIVER_EVENT_REQUEST`, output: process/thread/image callback events)
- Extended memory IOCTLs:
  - `IOCTL_WDBL_READ_PROCESS_MEMORY_EX` / `IOCTL_WDBL_WRITE_PROCESS_MEMORY_EX` (byte count, NTSTATUS and fault address)
- Supported debug-event IOCTLs:
  - `IOCTL_WDBL_DEBUG_ACTIVE_PROCESS` (input: `WDBL_DEBUG_ACTIVE_PROCESS_REQUEST`)
  - `IOCTL_WDBL_DEBUG_ACTIVE_PROCESS_STOP` (input: `WDBL_DEBUG_ACTIVE_PROCESS_STOP_REQUEST`)
  - `IOCTL_WDBL_WAIT_FOR_DEBUG_EVENT` (input: `WDBL_WAIT_FOR_DEBUG_EVENT_REQUEST`, output: `WDBL_DEBUG_EVENT_RESULT`)
  - `IOCTL_WDBL_CONTINUE_DEBUG_EVENT` (input: `WDBL_CONTINUE_DEBUG_EVENT_REQUEST`)

Memory operations rely on kernel `MmCopyVirtualMemory`.
Thread context operations rely on kernel `ZwGetContextThread` / `ZwSetContextThread`.
WOW64 context operations rely on `ThreadWow64Context` through `ZwQueryInformationThread` / `ZwSetInformationThread`.
Execution/control operations rely on kernel `ZwCreateThreadEx`, `ZwSuspendThread`, `ZwResumeThread`, `ZwSuspendProcess`, `ZwResumeProcess`, and `ZwTerminateProcess`.
Debug API diagnostics use `MmGetSystemRoutineAddress` to probe `Zw/NtCreateDebugObject`, `Zw/NtDebugActiveProcess`, `Zw/NtWaitForDebugEvent`, `Zw/NtDebugContinue`, and `Zw/NtRemoveProcessDebug`.
EPROCESS ImageFileName offset diagnostics dynamically resolve `PsGetProcessImageFileName` and compute the returned pointer offset from the current `PEPROCESS`.
The extended user-mode wrappers are exposed by `WinApiDynamic` and continue to use the encrypted IOCTL packet protocol. New kernel routines are resolved through the driver's obfuscated dynamic resolver.
Debug-event operations use the same dynamically resolved debug object APIs and are only selected by user mode after `drv on` successfully attaches through the driver.
Release builds define `WDBL_SIGNING_SAFE_DRIVER=1`, which compiles out the debug-object path and EPROCESS ImageFileName offset probe. Those IOCTLs remain in the contract but return not-supported/empty capability results so user mode falls back to WinAPI. Build with `WDBL_SIGNING_SAFE_DRIVER=0` for local test builds that include those paths.
In practice, caller-side suspend/resume policy is still required for deterministic results.

## Build (WDK, Visual Studio)

1. Install Visual Studio 2022 + WDK for Windows 10/11.
2. Open `WinDbgLiteMemDrv.vcxproj`.
3. Build x64 Debug/Release to produce `WinDbgLiteMemDrv.sys`.

## Install (test environment)

Use a signed package in production. For local test signing/dev mode only (run as Administrator):

```powershell
.\Install-WinDbgLiteMemDrv.ps1 -DriverSysPath .\bin\x64\Release\WinDbgLiteMemDrv.sys -StartNow
```

Uninstall helper:

```powershell
.\Uninstall-WinDbgLiteMemDrv.ps1 -RemoveDriverFile
```

Self-test command (ping + memory read/write + thread-context probe):

```powershell
.\Test-WinDbgLiteMemDrv.ps1
```

After service start, the existing WinDbgLite user-mode code can open `\\.\WinDbgLiteMem`.

CLI diagnostics:

- `drv caps` queries the negotiated driver capability mask.
- `drv antidebug` queries PEB `BeingDebugged`/`NtGlobalFlag` and process debug information for the current target.
- `drv dr <tid>` reads DR0-DR3/DR6/DR7 for a target thread.
- `drv handles` lists the current target's kernel handle snapshot.
- `drv threadinfo <tid>` shows TEB, start address, priority and exit status.
- `drv image` parses the current target's main PE header.
- `drv mitigations` shows process execute flags, protection level and break-on-termination state.
- `drv events [max]` drains the lightweight driver event queue for process, thread and image-load events.
- `vad` scans committed regions for RWX, executable private memory and private PE headers.
- `modifycheck [module]` compares selected remote API bytes with a disk-image baseline when available.

The VAD and modification checks are diagnostic heuristics. `vad` uses `VirtualQueryEx`-compatible
region information and does not walk undocumented kernel VAD nodes. `modifycheck` reports
differences for selected ntdll APIs and the module header; review the result before treating
a difference as a confirmed modification.
