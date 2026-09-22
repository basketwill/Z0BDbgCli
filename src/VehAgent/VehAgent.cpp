#include "../WinDbgLiteCli/VehProtocol.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <string>
typedef
VOID
(WINAPI* fn_KiUserExceptionDispatcher)(__in PEXCEPTION_RECORD ExceptionRecord, __in PCONTEXT ContextRecord);

extern "C" fn_KiUserExceptionDispatcher m_KiUserExceptionDispatcher = NULL;
extern "C" void FakeKiUserExceptionDispatcher();
LONG WINAPI VehHandler(PEXCEPTION_POINTERS exceptionInfo);

extern "C" BOOL WINAPI KiUserExceptionDispatcher(__in PEXCEPTION_RECORD ExceptionRecord, __in PCONTEXT ContextRecord)
{
    if (ExceptionRecord && ContextRecord)
    {
       EXCEPTION_POINTERS Exceptions;
       Exceptions.ContextRecord = ContextRecord;
       Exceptions.ExceptionRecord = ExceptionRecord;
       return VehHandler(&Exceptions) == EXCEPTION_CONTINUE_EXECUTION ? TRUE : FALSE;
    }

    return FALSE;
}

HANDLE g_pipe = INVALID_HANDLE_VALUE;
PVOID g_vehHandle = nullptr;
PVOID g_ldrNotificationCookie = nullptr;
HMODULE g_agentModule = nullptr;
CRITICAL_SECTION g_pipeLock;
volatile LONG g_running = 0;
HANDLE g_threadEvent = nullptr;
volatile LONG g_threadEventWrite = 0;
volatile LONG g_threadEventRead = 0;
volatile LONG g_logInitDone = 0;
WCHAR g_logPath[MAX_PATH] = {};
typedef PVOID (WINAPI *RtlAddVectoredExceptionHandlerFn)(ULONG, PVECTORED_EXCEPTION_HANDLER);
typedef ULONG (WINAPI *RtlRemoveVectoredExceptionHandlerFn)(PVOID);

const LONG WDBL_THREAD_EVENT_QUEUE_SIZE = 256;
const int WDBL_MAX_VEH_BREAKPOINTS = 256;
const int WDBL_MAX_VEH_HARDWARE_BREAKPOINTS = 16;
const int WDBL_MAX_VEH_MEMORY_BREAKPOINTS = 64;
const int WDBL_MAX_GUARD_PAGES = 128;
const int WDBL_MAX_PENDING_STEP = 64;
const int WDBL_MAX_EXCEPTION_POLICIES = 64;
const DWORD WDBL_DBG_PRINTEXCEPTION_C = 0x40010006;
const DWORD WDBL_DBG_PRINTEXCEPTION_WIDE_C = 0x4001000A;

struct PendingThreadEvent {
    DWORD type;
    DWORD processId;
    DWORD threadId;
    ULONGLONG tickCount;
};

PendingThreadEvent g_threadEvents[WDBL_THREAD_EVENT_QUEUE_SIZE] = {};
volatile LONG g_exceptionPolicy = WDBL_VEH_EXCEPTION_POLICY_BREAKPOINT_ONLY;

struct ExceptionPolicyEntry {
    DWORD code;
    DWORD policy;
};

ExceptionPolicyEntry g_exceptionPolicies[WDBL_MAX_EXCEPTION_POLICIES] = {};

struct VehSoftwareBreakpoint {
    DWORD id;
    DWORD flags;
    ULONGLONG address;
    BYTE originalByte;
    bool enabled;
};

struct VehHardwareBreakpoint {
    DWORD id;
    DWORD slot;
    DWORD access;
    DWORD length;
    DWORD threadId;
    ULONGLONG address;
    bool enabled;
};

struct VehGuardPage {
    ULONGLONG base;
    SIZE_T size;
    DWORD originalProtect;
};

struct VehMemoryBreakpoint {
    DWORD id;
    DWORD access;
    ULONGLONG address;
    ULONGLONG size;
    bool enabled;
    DWORD pageCount;
    VehGuardPage pages[WDBL_MAX_GUARD_PAGES];
};

struct PendingStepRearm {
    DWORD threadId;
    DWORD breakpointId;
    DWORD stopAfterStep;
    ULONGLONG address;
};

VehSoftwareBreakpoint g_breakpoints[WDBL_MAX_VEH_BREAKPOINTS] = {};
VehHardwareBreakpoint g_hardwareBreakpoints[WDBL_MAX_VEH_HARDWARE_BREAKPOINTS] = {};
VehMemoryBreakpoint g_memoryBreakpoints[WDBL_MAX_VEH_MEMORY_BREAKPOINTS] = {};
PendingStepRearm g_pendingStep[WDBL_MAX_PENDING_STEP] = {};
DWORD g_pendingGuardRearmThreadId = 0;
DWORD g_pendingGuardStepStopThreadId = 0;

typedef struct _WDBL_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} WDBL_UNICODE_STRING;

typedef struct _WDBL_LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;
    const WDBL_UNICODE_STRING* FullDllName;
    const WDBL_UNICODE_STRING* BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} WDBL_LDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _WDBL_LDR_DLL_UNLOADED_NOTIFICATION_DATA {
    ULONG Flags;
    const WDBL_UNICODE_STRING* FullDllName;
    const WDBL_UNICODE_STRING* BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} WDBL_LDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _WDBL_LDR_DLL_NOTIFICATION_DATA {
    WDBL_LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    WDBL_LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} WDBL_LDR_DLL_NOTIFICATION_DATA;

typedef VOID (__stdcall * WDBL_LDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG NotificationReason,
    const WDBL_LDR_DLL_NOTIFICATION_DATA* NotificationData,
    PVOID Context);

typedef LONG (__stdcall * WDBL_LDR_REGISTER_DLL_NOTIFICATION)(
    ULONG Flags,
    WDBL_LDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    PVOID Context,
    PVOID* Cookie);

typedef LONG (__stdcall * WDBL_LDR_UNREGISTER_DLL_NOTIFICATION)(
    PVOID Cookie);

const ULONG WDBL_LDR_DLL_NOTIFICATION_REASON_LOADED = 1;
const ULONG WDBL_LDR_DLL_NOTIFICATION_REASON_UNLOADED = 2;


bool WriteAll(HANDLE handle, const void* data, DWORD size) {
    const BYTE* cursor = static_cast<const BYTE*>(data);
    DWORD remaining = size;
    while (remaining != 0) {
        DWORD written = 0;
        if (!WriteFile(handle, cursor, remaining, &written, nullptr) || written == 0) {
            return false;
        }
        cursor += written;
        remaining -= written;
    }
    return true;
}

bool ReadAll(HANDLE handle, void* data, DWORD size) {
    BYTE* cursor = static_cast<BYTE*>(data);
    DWORD remaining = size;
    while (remaining != 0) {
        DWORD read = 0;
        if (!ReadFile(handle, cursor, remaining, &read, nullptr) || read == 0) {
            return false;
        }
        cursor += read;
        remaining -= read;
    }
    return true;
}

void FillText(WCHAR* target, DWORD targetChars, const WCHAR* text) {
    if (target == nullptr || targetChars == 0) {
        return;
    }
    target[0] = L'\0';
    if (text == nullptr) {
        return;
    }
    lstrcpynW(target, text, static_cast<int>(targetChars));
}

std::wstring BuildPipeName() {
    wchar_t buffer[96] = {};
    wsprintfW(buffer, L"%s%lu", WDBL_VEH_PIPE_PREFIX, GetCurrentProcessId());
    return std::wstring(buffer);
}

bool SendMessageLocked(const void* message, DWORD size) {
    if (g_pipe == INVALID_HANDLE_VALUE) {
        return false;
    }
    EnterCriticalSection(&g_pipeLock);
    const bool ok = WriteAll(g_pipe, message, size);
    LeaveCriticalSection(&g_pipeLock);
    return ok;
}

void SendResponse(DWORD requestId, DWORD status, DWORD errorCode, DWORD value, const WCHAR* text) {
    WdblVehResponseMessage response = {};
    response.header.version = WDBL_VEH_PROTOCOL_VERSION;
    response.header.type = WDBL_VEH_MSG_RESPONSE;
    response.header.size = sizeof(response);
    response.requestId = requestId;
    response.status = status;
    response.errorCode = errorCode;
    response.value = value;
    FillText(response.text, WDBL_VEH_MAX_PATH_CHARS, text);
    SendMessageLocked(&response, sizeof(response));
}

void SendProcessExitMessage(DWORD exitCode) {
    if (g_pipe == INVALID_HANDLE_VALUE) {
        return;
    }
    WdblVehProcessExitMessage message = {};
    message.header.version = WDBL_VEH_PROTOCOL_VERSION;
    message.header.type = WDBL_VEH_MSG_PROCESS_EXIT;
    message.header.size = sizeof(message);
    message.processId = GetCurrentProcessId();
    message.threadId = GetCurrentThreadId();
    message.exitCode = exitCode;
    if (TryEnterCriticalSection(&g_pipeLock)) {
        WriteAll(g_pipe, &message, sizeof(message));
        LeaveCriticalSection(&g_pipeLock);
    }
}

void SendMemoryResponse(DWORD requestId, DWORD status, DWORD errorCode, ULONGLONG address, DWORD bytesTransferred, const BYTE* data) {
    WdblVehMemoryResponse response = {};
    response.header.version = WDBL_VEH_PROTOCOL_VERSION;
    response.header.type = WDBL_VEH_MSG_MEMORY_RESPONSE;
    response.header.size = sizeof(response);
    response.requestId = requestId;
    response.status = status;
    response.errorCode = errorCode;
    response.address = address;
    response.bytesTransferred = bytesTransferred;
    if (data != nullptr && bytesTransferred != 0) {
        if (bytesTransferred > WDBL_VEH_MAX_MEMORY_BYTES) {
            bytesTransferred = WDBL_VEH_MAX_MEMORY_BYTES;
        }
        CopyMemory(response.data, data, bytesTransferred);
    }
    SendMessageLocked(&response, sizeof(response));
}

void FillContextResponseFromContext(WdblVehContextResponse& response, const CONTEXT& ctx) {
#if defined(_M_X64)
    response.ip = ctx.Rip;
    response.sp = ctx.Rsp;
    response.fp = ctx.Rbp;
    response.ax = ctx.Rax;
    response.bx = ctx.Rbx;
    response.cx = ctx.Rcx;
    response.dx = ctx.Rdx;
    response.si = ctx.Rsi;
    response.di = ctx.Rdi;
    response.flags = ctx.EFlags;
#else
    response.ip = ctx.Eip;
    response.sp = ctx.Esp;
    response.fp = ctx.Ebp;
    response.ax = ctx.Eax;
    response.bx = ctx.Ebx;
    response.cx = ctx.Ecx;
    response.dx = ctx.Edx;
    response.si = ctx.Esi;
    response.di = ctx.Edi;
    response.flags = ctx.EFlags;
#endif
}

void ApplyContextRequestToContext(const WdblVehContextRequest& request, CONTEXT& ctx) {
#if defined(_M_X64)
    if ((request.contextFlags & WDBL_VEH_CONTEXT_IP) != 0) ctx.Rip = request.ip;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_SP) != 0) ctx.Rsp = request.sp;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_FP) != 0) ctx.Rbp = request.fp;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_AX) != 0) ctx.Rax = request.ax;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_BX) != 0) ctx.Rbx = request.bx;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_CX) != 0) ctx.Rcx = request.cx;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_DX) != 0) ctx.Rdx = request.dx;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_SI) != 0) ctx.Rsi = request.si;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_DI) != 0) ctx.Rdi = request.di;
    if ((request.contextFlags & WDBL_VEH_CONTEXT_FLAGS) != 0) ctx.EFlags = static_cast<DWORD>(request.flags);
#else
    if ((request.contextFlags & WDBL_VEH_CONTEXT_IP) != 0) ctx.Eip = static_cast<DWORD>(request.ip);
    if ((request.contextFlags & WDBL_VEH_CONTEXT_SP) != 0) ctx.Esp = static_cast<DWORD>(request.sp);
    if ((request.contextFlags & WDBL_VEH_CONTEXT_FP) != 0) ctx.Ebp = static_cast<DWORD>(request.fp);
    if ((request.contextFlags & WDBL_VEH_CONTEXT_AX) != 0) ctx.Eax = static_cast<DWORD>(request.ax);
    if ((request.contextFlags & WDBL_VEH_CONTEXT_BX) != 0) ctx.Ebx = static_cast<DWORD>(request.bx);
    if ((request.contextFlags & WDBL_VEH_CONTEXT_CX) != 0) ctx.Ecx = static_cast<DWORD>(request.cx);
    if ((request.contextFlags & WDBL_VEH_CONTEXT_DX) != 0) ctx.Edx = static_cast<DWORD>(request.dx);
    if ((request.contextFlags & WDBL_VEH_CONTEXT_SI) != 0) ctx.Esi = static_cast<DWORD>(request.si);
    if ((request.contextFlags & WDBL_VEH_CONTEXT_DI) != 0) ctx.Edi = static_cast<DWORD>(request.di);
    if ((request.contextFlags & WDBL_VEH_CONTEXT_FLAGS) != 0) ctx.EFlags = static_cast<DWORD>(request.flags);
#endif
}

void FillContextFields(const CONTEXT* ctx, WdblVehExceptionMessage& message) {
    if (ctx == nullptr) {
        return;
    }
#if defined(_M_X64)
    message.instructionPointer = ctx->Rip;
    message.stackPointer = ctx->Rsp;
    message.framePointer = ctx->Rbp;
#else
    message.instructionPointer = ctx->Eip;
    message.stackPointer = ctx->Esp;
    message.framePointer = ctx->Ebp;
#endif
}

void SetContextInstructionPointer(CONTEXT* ctx, ULONGLONG value) {
    if (ctx == nullptr) {
        return;
    }
#if defined(_M_X64)
    ctx->Rip = value;
#else
    ctx->Eip = static_cast<DWORD>(value);
#endif
}

void EnableTrapFlag(CONTEXT* ctx) {
    if (ctx == nullptr) {
        return;
    }
#if defined(_M_X64)
    ctx->EFlags |= 0x100;
#else
    ctx->EFlags |= 0x100;
#endif
}

void CopyUnicodeString(WCHAR* target, ULONG targetChars, const WDBL_UNICODE_STRING* source, ULONG* outLength) {
    if (outLength != nullptr) {
        *outLength = 0;
    }
    if (target == nullptr || targetChars == 0) {
        return;
    }
    target[0] = L'\0';
    if (source == nullptr || source->Buffer == nullptr || source->Length == 0) {
        return;
    }
    ULONG chars = source->Length / sizeof(WCHAR);
    if (chars >= targetChars) {
        chars = targetChars - 1;
    }
    for (ULONG i = 0; i < chars; ++i) {
        target[i] = source->Buffer[i];
    }
    target[chars] = L'\0';
    if (outLength != nullptr) {
        *outLength = chars;
    }
}

void SendModuleNotification(ULONG reason, const WDBL_LDR_DLL_NOTIFICATION_DATA* data) {
    if (data == nullptr || InterlockedCompareExchange(&g_running, 1, 1) == 0 || g_pipe == INVALID_HANDLE_VALUE) {
        return;
    }

    WdblVehModuleMessage message = {};
    message.header.version = WDBL_VEH_PROTOCOL_VERSION;
    message.header.type = reason == WDBL_LDR_DLL_NOTIFICATION_REASON_UNLOADED
        ? WDBL_VEH_MSG_MODULE_UNLOAD
        : WDBL_VEH_MSG_MODULE_LOAD;
    message.header.size = sizeof(message);
    message.processId = GetCurrentProcessId();
    message.threadId = GetCurrentThreadId();

    if (reason == WDBL_LDR_DLL_NOTIFICATION_REASON_UNLOADED) {
        message.baseAddress = reinterpret_cast<ULONGLONG>(data->Unloaded.DllBase);
        message.sizeOfImage = data->Unloaded.SizeOfImage;
        CopyUnicodeString(message.fullName, WDBL_VEH_MAX_PATH_CHARS, data->Unloaded.FullDllName, &message.fullNameLength);
        CopyUnicodeString(message.baseName, WDBL_VEH_MAX_PATH_CHARS, data->Unloaded.BaseDllName, &message.baseNameLength);
    } else {
        message.baseAddress = reinterpret_cast<ULONGLONG>(data->Loaded.DllBase);
        message.sizeOfImage = data->Loaded.SizeOfImage;
        CopyUnicodeString(message.fullName, WDBL_VEH_MAX_PATH_CHARS, data->Loaded.FullDllName, &message.fullNameLength);
        CopyUnicodeString(message.baseName, WDBL_VEH_MAX_PATH_CHARS, data->Loaded.BaseDllName, &message.baseNameLength);
    }

    SendMessageLocked(&message, sizeof(message));
}

VOID __stdcall LdrDllNotification(ULONG reason, const WDBL_LDR_DLL_NOTIFICATION_DATA* data, PVOID context) {
    UNREFERENCED_PARAMETER(context);
    if (reason == WDBL_LDR_DLL_NOTIFICATION_REASON_LOADED ||
        reason == WDBL_LDR_DLL_NOTIFICATION_REASON_UNLOADED) {
        SendModuleNotification(reason, data);
    }
}

void RegisterLoaderNotifications() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        return;
    }
    WDBL_LDR_REGISTER_DLL_NOTIFICATION registerFn =
        reinterpret_cast<WDBL_LDR_REGISTER_DLL_NOTIFICATION>(GetProcAddress(ntdll, "LdrRegisterDllNotification"));
    if (registerFn == nullptr) {
        return;
    }
    registerFn(0, LdrDllNotification, nullptr, &g_ldrNotificationCookie);
}

void UnregisterLoaderNotifications() {
    if (g_ldrNotificationCookie == nullptr) {
        return;
    }
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    WDBL_LDR_UNREGISTER_DLL_NOTIFICATION unregisterFn = ntdll != nullptr
        ? reinterpret_cast<WDBL_LDR_UNREGISTER_DLL_NOTIFICATION>(GetProcAddress(ntdll, "LdrUnregisterDllNotification"))
        : nullptr;
    if (unregisterFn != nullptr) {
        unregisterFn(g_ldrNotificationCookie);
    }
    g_ldrNotificationCookie = nullptr;
}

int FindBreakpointByAddress(ULONGLONG address) {
    for (int i = 0; i < WDBL_MAX_VEH_BREAKPOINTS; ++i) {
        if (g_breakpoints[i].enabled && g_breakpoints[i].address == address) {
            return i;
        }
    }
    return -1;
}

int FindBreakpointById(DWORD id) {
    for (int i = 0; i < WDBL_MAX_VEH_BREAKPOINTS; ++i) {
        if (g_breakpoints[i].enabled && g_breakpoints[i].id == id) {
            return i;
        }
    }
    return -1;
}

bool WriteTargetByte(ULONGLONG address, BYTE value) {
    DWORD oldProtect = 0;
    BYTE* ptr = reinterpret_cast<BYTE*>(static_cast<ULONG_PTR>(address));
    if (!VirtualProtect(ptr, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    *ptr = value;
    FlushInstructionCache(GetCurrentProcess(), ptr, 1);
    DWORD ignored = 0;
    VirtualProtect(ptr, 1, oldProtect, &ignored);
    return true;
}

ULONGLONG AlignDownToPage(ULONGLONG address) {
    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    const ULONGLONG pageSize = si.dwPageSize != 0 ? si.dwPageSize : 0x1000;
    return address & ~(pageSize - 1);
}

DWORD HardwareAccessToDr7Bits(DWORD access) {
    if (access == 1) {
        return 1;
    }
    if (access == 2) {
        return 3;
    }
    return 0;
}

DWORD HardwareLengthToDr7Bits(DWORD length) {
    if (length == 2) {
        return 1;
    }
    if (length == 4) {
        return 3;
    }
    if (length == 8) {
        return 2;
    }
    return 0;
}

bool ApplyHardwareBreakpointsToThread(DWORD threadId) {
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (thread == nullptr) {
        return false;
    }

    DWORD suspendResult = 0;
    if (threadId != GetCurrentThreadId()) {
        suspendResult = SuspendThread(thread);
        if (suspendResult == static_cast<DWORD>(-1)) {
            CloseHandle(thread);
            return false;
        }
    }

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    bool ok = GetThreadContext(thread, &ctx) == TRUE;
    if (ok) {
        ctx.Dr0 = 0;
        ctx.Dr1 = 0;
        ctx.Dr2 = 0;
        ctx.Dr3 = 0;
        ctx.Dr7 = 0;
        for (int i = 0; i < WDBL_MAX_VEH_HARDWARE_BREAKPOINTS; ++i) {
            const VehHardwareBreakpoint& bp = g_hardwareBreakpoints[i];
            if (!bp.enabled || bp.slot > 3 || (bp.threadId != 0 && bp.threadId != threadId)) {
                continue;
            }
#if defined(_M_X64)
            if (bp.slot == 0) ctx.Dr0 = bp.address;
            if (bp.slot == 1) ctx.Dr1 = bp.address;
            if (bp.slot == 2) ctx.Dr2 = bp.address;
            if (bp.slot == 3) ctx.Dr3 = bp.address;
#else
            if (bp.slot == 0) ctx.Dr0 = static_cast<DWORD>(bp.address);
            if (bp.slot == 1) ctx.Dr1 = static_cast<DWORD>(bp.address);
            if (bp.slot == 2) ctx.Dr2 = static_cast<DWORD>(bp.address);
            if (bp.slot == 3) ctx.Dr3 = static_cast<DWORD>(bp.address);
#endif
            ctx.Dr7 |= (1ull << (bp.slot * 2));
            ctx.Dr7 |= (static_cast<DWORD64>(HardwareAccessToDr7Bits(bp.access)) << (16 + bp.slot * 4));
            ctx.Dr7 |= (static_cast<DWORD64>(HardwareLengthToDr7Bits(bp.length)) << (18 + bp.slot * 4));
        }
        ok = SetThreadContext(thread, &ctx) == TRUE;
    }

    if (threadId != GetCurrentThreadId() && suspendResult != static_cast<DWORD>(-1)) {
        ResumeThread(thread);
    }
    CloseHandle(thread);
    return ok;
}

bool ApplyHardwareBreakpointsToAllThreads() {
    const DWORD pid = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    bool anyOk = false;
    THREADENTRY32 entry = {};
    entry.dwSize = sizeof(entry);
    BOOL ok = Thread32First(snapshot, &entry);
    while (ok) {
        if (entry.th32OwnerProcessID == pid) {
            anyOk = ApplyHardwareBreakpointsToThread(entry.th32ThreadID) || anyOk;
        }
        ok = Thread32Next(snapshot, &entry);
    }
    CloseHandle(snapshot);
    return anyOk;
}

DWORD FindHardwareBreakpointBySlot(DWORD slot, DWORD threadId) {
    for (int i = 0; i < WDBL_MAX_VEH_HARDWARE_BREAKPOINTS; ++i) {
        if (g_hardwareBreakpoints[i].enabled &&
            g_hardwareBreakpoints[i].slot == slot &&
            g_hardwareBreakpoints[i].threadId == threadId) {
            return static_cast<DWORD>(i);
        }
    }
    return static_cast<DWORD>(-1);
}

int FindHardwareBreakpointById(DWORD id) {
    for (int i = 0; i < WDBL_MAX_VEH_HARDWARE_BREAKPOINTS; ++i) {
        if (g_hardwareBreakpoints[i].enabled && g_hardwareBreakpoints[i].id == id) {
            return i;
        }
    }
    return -1;
}

int FindHardwareBreakpointByDr6(DWORD64 dr6) {
    for (int i = 0; i < WDBL_MAX_VEH_HARDWARE_BREAKPOINTS; ++i) {
        const VehHardwareBreakpoint& bp = g_hardwareBreakpoints[i];
        if (bp.enabled && bp.slot < 4 && (dr6 & (1ull << bp.slot)) != 0) {
            return i;
        }
    }
    return -1;
}

bool ProtectGuardPage(VehGuardPage& page) {
    DWORD oldProtect = 0;
    if (!VirtualProtect(
            reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(page.base)),
            page.size,
            page.originalProtect | PAGE_GUARD,
            &oldProtect)) {
        return false;
    }
    return true;
}

bool IsGuardedFaultAddress(ULONGLONG faultAddress) {
    for (int i = 0; i < WDBL_MAX_VEH_MEMORY_BREAKPOINTS; ++i) {
        const VehMemoryBreakpoint& bp = g_memoryBreakpoints[i];
        if (!bp.enabled) {
            continue;
        }
        for (DWORD pageIndex = 0; pageIndex < bp.pageCount && pageIndex < WDBL_MAX_GUARD_PAGES; ++pageIndex) {
            const VehGuardPage& page = bp.pages[pageIndex];
            if (faultAddress >= page.base && faultAddress < page.base + page.size) {
                return true;
            }
        }
    }
    return false;
}

void RestoreMemoryBreakpoint(VehMemoryBreakpoint& bp) {
    for (DWORD i = 0; i < bp.pageCount && i < WDBL_MAX_GUARD_PAGES; ++i) {
        DWORD ignored = 0;
        VirtualProtect(
            reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(bp.pages[i].base)),
            bp.pages[i].size,
            bp.pages[i].originalProtect,
            &ignored);
    }
    bp = VehMemoryBreakpoint();
}

void RearmMemoryBreakpoints() {
    for (int i = 0; i < WDBL_MAX_VEH_MEMORY_BREAKPOINTS; ++i) {
        VehMemoryBreakpoint& bp = g_memoryBreakpoints[i];
        if (!bp.enabled) {
            continue;
        }
        for (DWORD pageIndex = 0; pageIndex < bp.pageCount && pageIndex < WDBL_MAX_GUARD_PAGES; ++pageIndex) {
            ProtectGuardPage(bp.pages[pageIndex]);
        }
    }
}

int FindMemoryBreakpointById(DWORD id) {
    for (int i = 0; i < WDBL_MAX_VEH_MEMORY_BREAKPOINTS; ++i) {
        if (g_memoryBreakpoints[i].enabled && g_memoryBreakpoints[i].id == id) {
            return i;
        }
    }
    return -1;
}

int FindMemoryBreakpointByFault(ULONGLONG faultAddress, DWORD actualAccess) {
    for (int i = 0; i < WDBL_MAX_VEH_MEMORY_BREAKPOINTS; ++i) {
        const VehMemoryBreakpoint& bp = g_memoryBreakpoints[i];
        if (!bp.enabled) {
            continue;
        }
        if (faultAddress >= bp.address &&
            faultAddress < bp.address + bp.size &&
            (bp.access & actualAccess) != 0) {
            return i;
        }
    }
    return -1;
}

void AddPendingStep(DWORD threadId, DWORD breakpointId, ULONGLONG address, DWORD stopAfterStep) {
    for (int i = 0; i < WDBL_MAX_PENDING_STEP; ++i) {
        if (g_pendingStep[i].threadId == 0) {
            g_pendingStep[i].threadId = threadId;
            g_pendingStep[i].breakpointId = breakpointId;
            g_pendingStep[i].stopAfterStep = stopAfterStep;
            g_pendingStep[i].address = address;
            return;
        }
    }
}

void MarkPendingStepStop(DWORD threadId, DWORD breakpointId) {
    for (int i = 0; i < WDBL_MAX_PENDING_STEP; ++i) {
        if (g_pendingStep[i].threadId == threadId &&
            g_pendingStep[i].breakpointId == breakpointId) {
            g_pendingStep[i].stopAfterStep = 1;
            return;
        }
    }
}

bool ConsumePendingStep(DWORD threadId, bool* stopAfterStep) {
    if (stopAfterStep != nullptr) {
        *stopAfterStep = false;
    }
    for (int i = 0; i < WDBL_MAX_PENDING_STEP; ++i) {
        if (g_pendingStep[i].threadId == threadId) {
            const DWORD breakpointId = g_pendingStep[i].breakpointId;
            const DWORD shouldStop = g_pendingStep[i].stopAfterStep;
            const ULONGLONG address = g_pendingStep[i].address;
            g_pendingStep[i] = PendingStepRearm();
            const int bpIndex = FindBreakpointById(breakpointId);
            if (bpIndex >= 0 && g_breakpoints[bpIndex].address == address) {
                WriteTargetByte(address, 0xCC);
            }
            if (stopAfterStep != nullptr) {
                *stopAfterStep = shouldStop != 0;
            }
            return true;
        }
    }
    return false;
}

DWORD LookupExceptionPolicy(DWORD code, bool* matched) {
    if (matched != nullptr) {
        *matched = false;
    }
    for (int i = 0; i < WDBL_MAX_EXCEPTION_POLICIES; ++i) {
        if (g_exceptionPolicies[i].code == code) {
            if (matched != nullptr) {
                *matched = true;
            }
            return g_exceptionPolicies[i].policy;
        }
    }
    return static_cast<DWORD>(InterlockedCompareExchange(&g_exceptionPolicy, 0, 0));
}

void SetExceptionPolicyEntry(DWORD code, DWORD policy) {
    if (code == 0) {
        return;
    }
    for (int i = 0; i < WDBL_MAX_EXCEPTION_POLICIES; ++i) {
        if (g_exceptionPolicies[i].code == code) {
            g_exceptionPolicies[i].policy = policy;
            return;
        }
    }
    for (int i = 0; i < WDBL_MAX_EXCEPTION_POLICIES; ++i) {
        if (g_exceptionPolicies[i].code == 0) {
            g_exceptionPolicies[i].code = code;
            g_exceptionPolicies[i].policy = policy;
            return;
        }
    }
}

bool IsOutputDebugStringException(DWORD code) {
    return code == WDBL_DBG_PRINTEXCEPTION_C || code == WDBL_DBG_PRINTEXCEPTION_WIDE_C;
}

void EnsureVehLogPath() {
    if (InterlockedCompareExchange(&g_logInitDone, 1, 1) != 0) {
        return;
    }
    WCHAR modulePath[MAX_PATH] = {};
    DWORD len = GetModuleFileNameW(g_agentModule, modulePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        WCHAR tempPath[MAX_PATH] = {};
        len = GetTempPathW(MAX_PATH, tempPath);
        if (len == 0 || len >= MAX_PATH) {
            lstrcpynW(g_logPath, L"WinDbgLiteVehAgent.log", MAX_PATH);
            InterlockedExchange(&g_logInitDone, 1);
            return;
        }
        wsprintfW(g_logPath, L"%sWinDbgLiteVehAgent_%lu.log", tempPath, GetCurrentProcessId());
    } else {
        WCHAR* slash = wcsrchr(modulePath, L'\\');
        if (slash != nullptr) {
            *(slash + 1) = L'\0';
            wsprintfW(g_logPath, L"%sWinDbgLiteVehAgent_%lu.log", modulePath, GetCurrentProcessId());
        } else {
            lstrcpynW(g_logPath, L"WinDbgLiteVehAgent.log", MAX_PATH);
        }
    }
    InterlockedExchange(&g_logInitDone, 1);
}

void VehWriteLogLine(const wchar_t* text) {
    EnsureVehLogPath();
    HANDLE file = CreateFileW(
        g_logPath,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD bytesWritten = 0;
    const DWORD bytes = static_cast<DWORD>(lstrlenW(text) * sizeof(wchar_t));
    WriteFile(file, text, bytes, &bytesWritten, nullptr);
    CloseHandle(file);
}

PVOID RegisterVehHandler() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        return nullptr;
    }
    const auto addFn = reinterpret_cast<RtlAddVectoredExceptionHandlerFn>(
        GetProcAddress(ntdll, "RtlAddVectoredExceptionHandler"));
    if (addFn == nullptr) {
        return nullptr;
    }
    return addFn(1, VehHandler);
}

bool UnregisterVehHandler(PVOID handle) {
    if (handle == nullptr) {
        return true;
    }
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        return false;
    }
    const auto removeFn = reinterpret_cast<RtlRemoveVectoredExceptionHandlerFn>(
        GetProcAddress(ntdll, "RtlRemoveVectoredExceptionHandler"));
    if (removeFn == nullptr) {
        return false;
    }
    return removeFn(handle) != 0;
}

void VehTraceLine(
    const wchar_t* stage,
    DWORD exceptionCode,
    DWORD breakpointId,
    ULONGLONG breakpointAddress,
    bool stepCompleteStop,
    bool ok) {
    wchar_t text[256] = {};
    wsprintfW(
        text,
        L"[VEHDBG] %s tid=%lu code=0x%08lX bp=%lu addr=0x%I64X step=%u ok=%u\r\n",
        stage,
        GetCurrentThreadId(),
        exceptionCode,
        breakpointId,
        breakpointAddress,
        stepCompleteStop ? 1u : 0u,
        ok ? 1u : 0u);
    //OutputDebugStringW(text);
    VehWriteLogLine(text);
}

void SetSoftwareBreakpoint(const WdblVehSoftwareBreakpointRequest& request) {
    if (request.address == 0) {
        SendResponse(request.requestId, 0, ERROR_INVALID_ADDRESS, request.breakpointId, L"invalid breakpoint address");
        return;
    }
    if (FindBreakpointByAddress(request.address) >= 0) {
        SendResponse(request.requestId, 1, 0, request.breakpointId, L"breakpoint already exists");
        return;
    }

    int freeIndex = -1;
    for (int i = 0; i < WDBL_MAX_VEH_BREAKPOINTS; ++i) {
        if (!g_breakpoints[i].enabled) {
            freeIndex = i;
            break;
        }
    }
    if (freeIndex < 0) {
        SendResponse(request.requestId, 0, ERROR_NOT_ENOUGH_MEMORY, request.breakpointId, L"breakpoint table full");
        return;
    }

    BYTE* ptr = reinterpret_cast<BYTE*>(static_cast<ULONG_PTR>(request.address));
    BYTE original = 0;
    __try {
        original = *ptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        SendResponse(request.requestId, 0, GetExceptionCode(), request.breakpointId, L"read original byte failed");
        return;
    }

    if (!WriteTargetByte(request.address, 0xCC)) {
        SendResponse(request.requestId, 0, GetLastError(), request.breakpointId, L"write int3 failed");
        return;
    }

    g_breakpoints[freeIndex].id = request.breakpointId;
    g_breakpoints[freeIndex].flags = request.flags;
    g_breakpoints[freeIndex].address = request.address;
    g_breakpoints[freeIndex].originalByte = original;
    g_breakpoints[freeIndex].enabled = true;
    SendResponse(request.requestId, 1, 0, request.breakpointId, L"software breakpoint set");
}

void RemoveSoftwareBreakpoint(const WdblVehSoftwareBreakpointRequest& request) {
    int index = FindBreakpointById(request.breakpointId);
    if (index < 0 && request.address != 0) {
        index = FindBreakpointByAddress(request.address);
    }
    if (index < 0) {
        SendResponse(request.requestId, 0, ERROR_NOT_FOUND, request.breakpointId, L"breakpoint not found");
        return;
    }
    WriteTargetByte(g_breakpoints[index].address, g_breakpoints[index].originalByte);
    g_breakpoints[index] = VehSoftwareBreakpoint();
    SendResponse(request.requestId, 1, 0, request.breakpointId, L"software breakpoint removed");
}

void SetHardwareBreakpoint(const WdblVehHardwareBreakpointRequest& request) {
    if (request.address == 0 || request.slot > 3 || request.length == 0) {
        SendResponse(request.requestId, 0, ERROR_INVALID_PARAMETER, request.breakpointId, L"invalid hardware breakpoint");
        return;
    }
#if !defined(_M_X64)
    if (request.length == 8) {
        SendResponse(request.requestId, 0, ERROR_INVALID_PARAMETER, request.breakpointId, L"x86 hardware breakpoint length cannot be 8");
        return;
    }
#endif
    if (FindHardwareBreakpointBySlot(request.slot, request.threadId) != static_cast<DWORD>(-1)) {
        SendResponse(request.requestId, 0, ERROR_ALREADY_EXISTS, request.breakpointId, L"hardware slot already used");
        return;
    }

    int freeIndex = -1;
    for (int i = 0; i < WDBL_MAX_VEH_HARDWARE_BREAKPOINTS; ++i) {
        if (!g_hardwareBreakpoints[i].enabled) {
            freeIndex = i;
            break;
        }
    }
    if (freeIndex < 0) {
        SendResponse(request.requestId, 0, ERROR_NOT_ENOUGH_MEMORY, request.breakpointId, L"hardware breakpoint table full");
        return;
    }

    g_hardwareBreakpoints[freeIndex].id = request.breakpointId;
    g_hardwareBreakpoints[freeIndex].slot = request.slot;
    g_hardwareBreakpoints[freeIndex].access = request.access;
    g_hardwareBreakpoints[freeIndex].length = request.length;
    g_hardwareBreakpoints[freeIndex].threadId = request.threadId;
    g_hardwareBreakpoints[freeIndex].address = request.address;
    g_hardwareBreakpoints[freeIndex].enabled = true;
    if (!ApplyHardwareBreakpointsToAllThreads()) {
        g_hardwareBreakpoints[freeIndex] = VehHardwareBreakpoint();
        SendResponse(request.requestId, 0, GetLastError(), request.breakpointId, L"apply hardware breakpoint failed");
        return;
    }
    SendResponse(request.requestId, 1, 0, request.breakpointId, L"hardware breakpoint set");
}

void RemoveHardwareBreakpoint(const WdblVehHardwareBreakpointRequest& request) {
    int index = FindHardwareBreakpointById(request.breakpointId);
    if (index < 0) {
        SendResponse(request.requestId, 0, ERROR_NOT_FOUND, request.breakpointId, L"hardware breakpoint not found");
        return;
    }
    g_hardwareBreakpoints[index] = VehHardwareBreakpoint();
    ApplyHardwareBreakpointsToAllThreads();
    SendResponse(request.requestId, 1, 0, request.breakpointId, L"hardware breakpoint removed");
}

void SetMemoryBreakpoint(const WdblVehMemoryBreakpointRequest& request) {
    if (request.address == 0 || request.size == 0 || request.access == 0) {
        SendResponse(request.requestId, 0, ERROR_INVALID_PARAMETER, request.breakpointId, L"invalid memory breakpoint");
        return;
    }

    int freeIndex = -1;
    for (int i = 0; i < WDBL_MAX_VEH_MEMORY_BREAKPOINTS; ++i) {
        if (!g_memoryBreakpoints[i].enabled) {
            freeIndex = i;
            break;
        }
    }
    if (freeIndex < 0) {
        SendResponse(request.requestId, 0, ERROR_NOT_ENOUGH_MEMORY, request.breakpointId, L"memory breakpoint table full");
        return;
    }

    VehMemoryBreakpoint bp = VehMemoryBreakpoint();
    bp.id = request.breakpointId;
    bp.access = request.access;
    bp.address = request.address;
    bp.size = request.size;
    bp.enabled = true;

    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    const ULONGLONG pageSize = si.dwPageSize != 0 ? si.dwPageSize : 0x1000;
    ULONGLONG page = AlignDownToPage(request.address);
    const ULONGLONG end = request.address + request.size;
    while (page < end && bp.pageCount < WDBL_MAX_GUARD_PAGES) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(static_cast<ULONG_PTR>(page)), &mbi, sizeof(mbi)) != sizeof(mbi)) {
            break;
        }
        DWORD protect = mbi.Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
        if (protect != PAGE_NOACCESS && protect != 0) {
            DWORD oldProtect = 0;
            const DWORD originalProtect = mbi.Protect & ~PAGE_GUARD;
            if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize, originalProtect | PAGE_GUARD, &oldProtect)) {
                VehGuardPage& guard = bp.pages[bp.pageCount++];
                guard.base = reinterpret_cast<ULONGLONG>(mbi.BaseAddress);
                guard.size = mbi.RegionSize;
                guard.originalProtect = originalProtect;
            }
        }
        page = reinterpret_cast<ULONGLONG>(mbi.BaseAddress) + mbi.RegionSize;
        if (page == 0) {
            break;
        }
    }

    if (bp.pageCount == 0) {
        SendResponse(request.requestId, 0, ERROR_INVALID_ADDRESS, request.breakpointId, L"no guardable page");
        return;
    }
    g_memoryBreakpoints[freeIndex] = bp;
    SendResponse(request.requestId, 1, 0, request.breakpointId, L"memory breakpoint set");
}

void RemoveMemoryBreakpoint(const WdblVehMemoryBreakpointRequest& request) {
    int index = FindMemoryBreakpointById(request.breakpointId);
    if (index < 0) {
        SendResponse(request.requestId, 0, ERROR_NOT_FOUND, request.breakpointId, L"memory breakpoint not found");
        return;
    }
    RestoreMemoryBreakpoint(g_memoryBreakpoints[index]);
    SendResponse(request.requestId, 1, 0, request.breakpointId, L"memory breakpoint removed");
}

LONG VehHandler(PEXCEPTION_POINTERS exceptionInfo) {

    VehTraceLine(
        L"enter",
        exceptionInfo->ExceptionRecord->ExceptionCode,
        0,
        0,
        false,
        true);

    if (exceptionInfo == nullptr || exceptionInfo->ExceptionRecord == nullptr) {
        VehTraceLine(L"early-null", 0, 0, 0, false, false);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (InterlockedCompareExchange(&g_running, 1, 1) == 0 || g_pipe == INVALID_HANDLE_VALUE) {
        VehTraceLine(
            L"early-state",
            exceptionInfo->ExceptionRecord->ExceptionCode,
            0,
            0,
            false,
            false);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    bool stepCompleteStop = false;
    
    if (exceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if (g_pendingGuardRearmThreadId == GetCurrentThreadId()) {
            g_pendingGuardRearmThreadId = 0;
            RearmMemoryBreakpoints();
            if (g_pendingGuardStepStopThreadId == GetCurrentThreadId()) {
                g_pendingGuardStepStopThreadId = 0;
                stepCompleteStop = true;
            } else {
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        if (!stepCompleteStop) {
            bool stopAfterStep = false;
            if (ConsumePendingStep(GetCurrentThreadId(), &stopAfterStep)) {
                if (!stopAfterStep) {
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
                stepCompleteStop = true;
            }
        }
    }

    DWORD breakpointId = 0;
    DWORD extraExceptionFlags = 0;
    ULONGLONG breakpointAddress = 0;
    if (exceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        WdblVehExceptionMessage probe = {};
        FillContextFields(exceptionInfo->ContextRecord, probe);
        const ULONGLONG candidate = probe.instructionPointer > 0 ? probe.instructionPointer - 1 : 0;
        const int bpIndex = FindBreakpointByAddress(candidate);
        if (bpIndex >= 0) {
            breakpointId = g_breakpoints[bpIndex].id;
            breakpointAddress = g_breakpoints[bpIndex].address;
            const bool temporaryBreakpoint = (g_breakpoints[bpIndex].flags & WDBL_VEH_BREAKPOINT_FLAG_TEMPORARY) != 0;
            WriteTargetByte(breakpointAddress, g_breakpoints[bpIndex].originalByte);
            if (temporaryBreakpoint) {
                g_breakpoints[bpIndex] = VehSoftwareBreakpoint();
            }
            SetContextInstructionPointer(exceptionInfo->ContextRecord, breakpointAddress);
            if (!temporaryBreakpoint) {
                EnableTrapFlag(exceptionInfo->ContextRecord);
                AddPendingStep(GetCurrentThreadId(), breakpointId, breakpointAddress, 0);
            }
        }
    }
    if (breakpointId == 0 && exceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        const int hwIndex = FindHardwareBreakpointByDr6(exceptionInfo->ContextRecord->Dr6);
        if (hwIndex >= 0) {
            breakpointId = g_hardwareBreakpoints[hwIndex].id;
            breakpointAddress = g_hardwareBreakpoints[hwIndex].address;
            extraExceptionFlags |= WDBL_VEH_EXCEPTION_FLAG_HARDWARE_BREAKPOINT;
            exceptionInfo->ContextRecord->Dr6 = 0;
        }
    }
    if (breakpointId == 0 && exceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        const ULONG_PTR accessKind = exceptionInfo->ExceptionRecord->NumberParameters > 0
            ? exceptionInfo->ExceptionRecord->ExceptionInformation[0]
            : 0;
        const ULONGLONG faultAddress = exceptionInfo->ExceptionRecord->NumberParameters > 1
            ? static_cast<ULONGLONG>(exceptionInfo->ExceptionRecord->ExceptionInformation[1])
            : 0;
        DWORD actualAccess = 1;
        if (accessKind == 1) {
            actualAccess = 2;
        } else if (accessKind == 8) {
            actualAccess = 4;
        }
        const int memIndex = FindMemoryBreakpointByFault(faultAddress, actualAccess);
        if (memIndex >= 0) {
            breakpointId = g_memoryBreakpoints[memIndex].id;
            breakpointAddress = faultAddress;
            extraExceptionFlags |= WDBL_VEH_EXCEPTION_FLAG_MEMORY_BREAKPOINT;
            g_pendingGuardRearmThreadId = GetCurrentThreadId();
            EnableTrapFlag(exceptionInfo->ContextRecord);
        } else if (IsGuardedFaultAddress(faultAddress)) {
            g_pendingGuardRearmThreadId = GetCurrentThreadId();
            EnableTrapFlag(exceptionInfo->ContextRecord);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    VehTraceLine(
        L"decide",
        exceptionInfo->ExceptionRecord->ExceptionCode,
        breakpointId,
        breakpointAddress,
        stepCompleteStop,
        true);

    WdblVehExceptionMessage message = {};
    message.header.version = WDBL_VEH_PROTOCOL_VERSION;
    message.header.type = WDBL_VEH_MSG_EXCEPTION;
    message.header.size = sizeof(message);
    message.processId = GetCurrentProcessId();
    message.threadId = GetCurrentThreadId();
    message.exceptionCode = exceptionInfo->ExceptionRecord->ExceptionCode;
    message.exceptionFlags = exceptionInfo->ExceptionRecord->ExceptionFlags;
    message.firstChance = 1;
    if (stepCompleteStop) {
        message.reserved = WDBL_VEH_EXCEPTION_FLAG_STEP_COMPLETE;
    }
    message.reserved |= extraExceptionFlags;
    message.exceptionAddress = reinterpret_cast<ULONGLONG>(exceptionInfo->ExceptionRecord->ExceptionAddress);
    message.breakpointId = breakpointId;
    message.breakpointAddress = breakpointAddress;
    message.parameterCount = exceptionInfo->ExceptionRecord->NumberParameters;
    if (message.parameterCount > EXCEPTION_MAXIMUM_PARAMETERS) {
        message.parameterCount = EXCEPTION_MAXIMUM_PARAMETERS;
    }
    for (DWORD i = 0; i < message.parameterCount; ++i) {
        message.parameters[i] = static_cast<ULONGLONG>(exceptionInfo->ExceptionRecord->ExceptionInformation[i]);
    }
    FillContextFields(exceptionInfo->ContextRecord, message);

    bool policyMatched = false;
    DWORD policy = LookupExceptionPolicy(exceptionInfo->ExceptionRecord->ExceptionCode, &policyMatched);
    const bool outputDebugString = IsOutputDebugStringException(exceptionInfo->ExceptionRecord->ExceptionCode);
    if (outputDebugString) {
        policy = WDBL_VEH_EXCEPTION_POLICY_CONTINUE;
        message.reserved |= WDBL_VEH_EXCEPTION_FLAG_OUTPUT_DEBUG_STRING;
    }
    if (breakpointId == 0 &&
        !stepCompleteStop &&
        !outputDebugString &&
        !policyMatched &&
        policy == WDBL_VEH_EXCEPTION_POLICY_BREAKPOINT_ONLY) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (breakpointId == 0 && !stepCompleteStop && policy == WDBL_VEH_EXCEPTION_POLICY_CONTINUE) {
        message.reserved |= WDBL_VEH_EXCEPTION_FLAG_CONTINUE_EXECUTION;
    }
    if (breakpointId == 0 && !stepCompleteStop && policyMatched && policy == WDBL_VEH_EXCEPTION_POLICY_BREAKPOINT_ONLY) {
        message.reserved |= WDBL_VEH_EXCEPTION_FLAG_POLICY_BREAK;
    }

    WdblVehContinueMessage reply = {};
    EnterCriticalSection(&g_pipeLock);
    const bool ok = WriteAll(g_pipe, &message, sizeof(message)) &&
                    ReadAll(g_pipe, &reply, sizeof(reply));
    LeaveCriticalSection(&g_pipeLock);
    VehTraceLine(
        L"pipe",
        exceptionInfo->ExceptionRecord->ExceptionCode,
        breakpointId,
        breakpointAddress,
        stepCompleteStop,
        ok);

    if (ok &&
        reply.header.version == WDBL_VEH_PROTOCOL_VERSION &&
        reply.header.type == WDBL_VEH_MSG_CONTINUE &&
        reply.header.size == sizeof(reply) &&
        reply.disposition == WDBL_VEH_CONTINUE_EXECUTION) {
        if (reply.contextFlags != 0 &&
            (reply.threadId == 0 || reply.threadId == GetCurrentThreadId())) {
            WdblVehContextRequest request = {};
            request.contextFlags = reply.contextFlags;
            request.ip = reply.ip;
            request.sp = reply.sp;
            request.fp = reply.fp;
            request.ax = reply.ax;
            request.bx = reply.bx;
            request.cx = reply.cx;
            request.dx = reply.dx;
            request.si = reply.si;
            request.di = reply.di;
            request.flags = reply.flags;
            ApplyContextRequestToContext(request, *exceptionInfo->ContextRecord);
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (ok &&
        reply.header.version == WDBL_VEH_PROTOCOL_VERSION &&
        reply.header.type == WDBL_VEH_MSG_CONTINUE &&
        reply.header.size == sizeof(reply) &&
        reply.disposition == WDBL_VEH_CONTINUE_STEP) {
        if (reply.contextFlags != 0 &&
            (reply.threadId == 0 || reply.threadId == GetCurrentThreadId())) {
            WdblVehContextRequest request = {};
            request.contextFlags = reply.contextFlags;
            request.ip = reply.ip;
            request.sp = reply.sp;
            request.fp = reply.fp;
            request.ax = reply.ax;
            request.bx = reply.bx;
            request.cx = reply.cx;
            request.dx = reply.dx;
            request.si = reply.si;
            request.di = reply.di;
            request.flags = reply.flags;
            ApplyContextRequestToContext(request, *exceptionInfo->ContextRecord);
        }
        if (breakpointId != 0) {
            if ((extraExceptionFlags & WDBL_VEH_EXCEPTION_FLAG_MEMORY_BREAKPOINT) != 0) {
                g_pendingGuardStepStopThreadId = GetCurrentThreadId();
            } else {
                MarkPendingStepStop(GetCurrentThreadId(), breakpointId);
                EnableTrapFlag(exceptionInfo->ContextRecord);
            }
        } else {
            AddPendingStep(GetCurrentThreadId(), 0, 0, 1);
            EnableTrapFlag(exceptionInfo->ContextRecord);
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (!ok) {
        if (breakpointId != 0 &&
            (extraExceptionFlags & (WDBL_VEH_EXCEPTION_FLAG_HARDWARE_BREAKPOINT | WDBL_VEH_EXCEPTION_FLAG_MEMORY_BREAKPOINT)) == 0) {
            bool ignored = false;
            ConsumePendingStep(GetCurrentThreadId(), &ignored);
            WriteTargetByte(breakpointAddress, 0xCC);
            VehTraceLine(
                L"pipe-fail",
                exceptionInfo->ExceptionRecord->ExceptionCode,
                breakpointId,
                breakpointAddress,
                stepCompleteStop,
                ok);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    if (breakpointId == 0 && policy == WDBL_VEH_EXCEPTION_POLICY_CONTINUE) {
        VehTraceLine(
            L"policy-continue",
            exceptionInfo->ExceptionRecord->ExceptionCode,
            breakpointId,
            breakpointAddress,
            stepCompleteStop,
            ok);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (breakpointId != 0) {
        if ((extraExceptionFlags & (WDBL_VEH_EXCEPTION_FLAG_HARDWARE_BREAKPOINT | WDBL_VEH_EXCEPTION_FLAG_MEMORY_BREAKPOINT)) == 0) {
            bool ignored = false;
            ConsumePendingStep(GetCurrentThreadId(), &ignored);
            WriteTargetByte(breakpointAddress, 0xCC);
        }
        VehTraceLine(
            L"bp-continue",
            exceptionInfo->ExceptionRecord->ExceptionCode,
            breakpointId,
            breakpointAddress,
            stepCompleteStop,
            ok);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    VehTraceLine(
        L"search",
        exceptionInfo->ExceptionRecord->ExceptionCode,
        breakpointId,
        breakpointAddress,
        stepCompleteStop,
        ok);
    return EXCEPTION_CONTINUE_SEARCH;
}

void QueueThreadNotification(DWORD type, DWORD threadId) {
    if (g_threadEvent == nullptr) {
        return;
    }

    const LONG index = InterlockedIncrement(&g_threadEventWrite) - 1;
    PendingThreadEvent& event = g_threadEvents[index % WDBL_THREAD_EVENT_QUEUE_SIZE];
    event.type = type;
    event.processId = GetCurrentProcessId();
    event.threadId = threadId;
    event.tickCount = GetTickCount();
    SetEvent(g_threadEvent);
}

void DrainThreadNotifications() {
    while (g_threadEventRead < g_threadEventWrite) {
        const LONG index = g_threadEventRead;
        PendingThreadEvent event = g_threadEvents[index % WDBL_THREAD_EVENT_QUEUE_SIZE];
        InterlockedExchange(&g_threadEventRead, index + 1);

        if (event.type != WDBL_VEH_MSG_THREAD_CREATE &&
            event.type != WDBL_VEH_MSG_THREAD_EXIT) {
            continue;
        }
        if (InterlockedCompareExchange(&g_running, 1, 1) == 0 ||
            g_pipe == INVALID_HANDLE_VALUE) {
            continue;
        }

        WdblVehThreadMessage message = {};
        message.header.version = WDBL_VEH_PROTOCOL_VERSION;
        message.header.type = event.type;
        message.header.size = sizeof(message);
        message.processId = event.processId;
        message.threadId = event.threadId;
        message.tickCount = event.tickCount;

        SendMessageLocked(&message, sizeof(message));
        if (event.type == WDBL_VEH_MSG_THREAD_CREATE) {
            ApplyHardwareBreakpointsToThread(event.threadId);
        }
    }
}

void SendSnapshotBoundary(DWORD type) {
    WdblVehMessageHeader message = {};
    message.version = WDBL_VEH_PROTOCOL_VERSION;
    message.type = type;
    message.size = sizeof(message);
    SendMessageLocked(&message, sizeof(message));
}

void SendThreadSnapshot() {
    const DWORD pid = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    THREADENTRY32 entry = {};
    entry.dwSize = sizeof(entry);
    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID != pid) {
                continue;
            }
            WdblVehThreadMessage message = {};
            message.header.version = WDBL_VEH_PROTOCOL_VERSION;
            message.header.type = WDBL_VEH_MSG_THREAD_CREATE;
            message.header.size = sizeof(message);
            message.processId = pid;
            message.threadId = entry.th32ThreadID;
            message.tickCount = GetTickCount();
            SendMessageLocked(&message, sizeof(message));
        } while (Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

void SendModuleSnapshot() {
    const DWORD pid = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            WdblVehModuleMessage message = {};
            message.header.version = WDBL_VEH_PROTOCOL_VERSION;
            message.header.type = WDBL_VEH_MSG_MODULE_LOAD;
            message.header.size = sizeof(message);
            message.processId = pid;
            message.threadId = GetCurrentThreadId();
            message.baseAddress = reinterpret_cast<ULONGLONG>(entry.modBaseAddr);
            message.sizeOfImage = entry.modBaseSize;
            FillText(message.fullName, WDBL_VEH_MAX_PATH_CHARS, entry.szExePath);
            FillText(message.baseName, WDBL_VEH_MAX_PATH_CHARS, entry.szModule);
            message.fullNameLength = lstrlenW(message.fullName);
            message.baseNameLength = lstrlenW(message.baseName);
            SendMessageLocked(&message, sizeof(message));
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

void SendInitialSnapshot() {
    SendSnapshotBoundary(WDBL_VEH_MSG_SNAPSHOT_BEGIN);
    SendThreadSnapshot();
    SendModuleSnapshot();
    SendSnapshotBoundary(WDBL_VEH_MSG_SNAPSHOT_END);
}

void HandleReadMemoryRequest(const WdblVehMemoryRequest& request) {
    if (request.size == 0 || request.size > WDBL_VEH_MAX_MEMORY_BYTES) {
        SendMemoryResponse(request.requestId, 0, ERROR_INVALID_PARAMETER, request.address, 0, nullptr);
        return;
    }
    BYTE buffer[WDBL_VEH_MAX_MEMORY_BYTES] = {};
    __try {
        CopyMemory(buffer, reinterpret_cast<const void*>(static_cast<ULONG_PTR>(request.address)), request.size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        SendMemoryResponse(request.requestId, 0, GetExceptionCode(), request.address, 0, nullptr);
        return;
    }
    SendMemoryResponse(request.requestId, 1, 0, request.address, request.size, buffer);
}

void HandleWriteMemoryRequest(const WdblVehMemoryRequest& request) {
    if (request.size == 0 || request.size > WDBL_VEH_MAX_MEMORY_BYTES) {
        SendMemoryResponse(request.requestId, 0, ERROR_INVALID_PARAMETER, request.address, 0, nullptr);
        return;
    }

    BYTE* ptr = reinterpret_cast<BYTE*>(static_cast<ULONG_PTR>(request.address));
    DWORD oldProtect = 0;
    if (!VirtualProtect(ptr, request.size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        SendMemoryResponse(request.requestId, 0, GetLastError(), request.address, 0, nullptr);
        return;
    }
    __try {
        CopyMemory(ptr, request.data, request.size);
        FlushInstructionCache(GetCurrentProcess(), ptr, request.size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD ignored = 0;
        VirtualProtect(ptr, request.size, oldProtect, &ignored);
        SendMemoryResponse(request.requestId, 0, GetExceptionCode(), request.address, 0, nullptr);
        return;
    }
    DWORD ignored = 0;
    VirtualProtect(ptr, request.size, oldProtect, &ignored);
    SendMemoryResponse(request.requestId, 1, 0, request.address, request.size, nullptr);
}

void HandleGetContextRequest(const WdblVehContextRequest& request) {
    WdblVehContextResponse response = {};
    response.header.version = WDBL_VEH_PROTOCOL_VERSION;
    response.header.type = WDBL_VEH_MSG_CONTEXT_RESPONSE;
    response.header.size = sizeof(response);
    response.requestId = request.requestId;
    response.threadId = request.threadId;

    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, request.threadId);
    if (thread == nullptr) {
        response.status = 0;
        response.errorCode = GetLastError();
        SendMessageLocked(&response, sizeof(response));
        return;
    }

    DWORD suspended = 0;
    if (request.threadId != GetCurrentThreadId()) {
        suspended = SuspendThread(thread);
    }

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(thread, &ctx)) {
        response.status = 1;
        FillContextResponseFromContext(response, ctx);
    } else {
        response.status = 0;
        response.errorCode = GetLastError();
    }
    if (request.threadId != GetCurrentThreadId() && suspended != static_cast<DWORD>(-1)) {
        ResumeThread(thread);
    }
    CloseHandle(thread);
    SendMessageLocked(&response, sizeof(response));
}

void HandleSetContextRequest(const WdblVehContextRequest& request) {
    WdblVehContextResponse response = {};
    response.header.version = WDBL_VEH_PROTOCOL_VERSION;
    response.header.type = WDBL_VEH_MSG_CONTEXT_RESPONSE;
    response.header.size = sizeof(response);
    response.requestId = request.requestId;
    response.threadId = request.threadId;

    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, request.threadId);
    if (thread == nullptr) {
        response.status = 0;
        response.errorCode = GetLastError();
        SendMessageLocked(&response, sizeof(response));
        return;
    }

    DWORD suspended = 0;
    if (request.threadId != GetCurrentThreadId()) {
        suspended = SuspendThread(thread);
    }

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(thread, &ctx)) {
        ApplyContextRequestToContext(request, ctx);
        ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
        if (SetThreadContext(thread, &ctx)) {
            response.status = 1;
            FillContextResponseFromContext(response, ctx);
        } else {
            response.status = 0;
            response.errorCode = GetLastError();
        }
    } else {
        response.status = 0;
        response.errorCode = GetLastError();
    }
    if (request.threadId != GetCurrentThreadId() && suspended != static_cast<DWORD>(-1)) {
        ResumeThread(thread);
    }
    CloseHandle(thread);
    SendMessageLocked(&response, sizeof(response));
}

void HandleThreadControlRequest(DWORD messageType, const WdblVehThreadControlRequest& request) {
    HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, request.threadId);
    if (thread == nullptr) {
        SendResponse(request.requestId, 0, GetLastError(), request.threadId, L"open thread failed");
        return;
    }

    DWORD result = 0;
    if (messageType == WDBL_VEH_MSG_REQ_SUSPEND_THREAD) {
        result = SuspendThread(thread);
    } else {
        result = ResumeThread(thread);
    }
    const DWORD error = result == static_cast<DWORD>(-1) ? GetLastError() : 0;
    CloseHandle(thread);
    SendResponse(request.requestId, error == 0 ? 1 : 0, error, request.threadId,
        messageType == WDBL_VEH_MSG_REQ_SUSPEND_THREAD ? L"suspend thread" : L"resume thread");
}

void HandleExceptionPolicyRequest(const WdblVehExceptionPolicyRequest& request) {
    if (request.policy > WDBL_VEH_EXCEPTION_POLICY_BREAKPOINT_ONLY) {
        SendResponse(request.requestId, 0, ERROR_INVALID_PARAMETER, request.policy, L"invalid exception policy");
        return;
    }
    if (request.exceptionCode == 0) {
        InterlockedExchange(&g_exceptionPolicy, static_cast<LONG>(request.policy));
        SendResponse(request.requestId, 1, 0, request.policy, L"global exception policy updated");
    } else {
        SetExceptionPolicyEntry(request.exceptionCode, request.policy);
        SendResponse(request.requestId, 1, 0, request.policy, L"exception-code policy updated");
    }
}

void PollControlMessages() {
    if (g_pipe == INVALID_HANDLE_VALUE) {
        return;
    }

    EnterCriticalSection(&g_pipeLock);
    DWORD available = 0;
    if (!PeekNamedPipe(g_pipe, nullptr, 0, nullptr, &available, nullptr)) {
        InterlockedExchange(&g_running, 0);
        LeaveCriticalSection(&g_pipeLock);
        return;
    }
    if (available >= sizeof(WdblVehMessageHeader)) {
        WdblVehMessageHeader header = {};
        if (!ReadAll(g_pipe, &header, sizeof(header)) ||
            header.version != WDBL_VEH_PROTOCOL_VERSION ||
            header.size < sizeof(header)) {
            InterlockedExchange(&g_running, 0);
            LeaveCriticalSection(&g_pipeLock);
            return;
        }
        if (header.type == WDBL_VEH_MSG_SHUTDOWN &&
            header.size == sizeof(header)) {
            InterlockedExchange(&g_running, 0);
        }
        if ((header.type == WDBL_VEH_MSG_REQ_SET_SOFTWARE_BREAKPOINT ||
             header.type == WDBL_VEH_MSG_REQ_REMOVE_SOFTWARE_BREAKPOINT) &&
            header.size == sizeof(WdblVehSoftwareBreakpointRequest)) {
            WdblVehSoftwareBreakpointRequest request = {};
            request.header = header;
            if (ReadAll(g_pipe, reinterpret_cast<BYTE*>(&request) + sizeof(header), sizeof(request) - sizeof(header))) {
                LeaveCriticalSection(&g_pipeLock);
                if (header.type == WDBL_VEH_MSG_REQ_SET_SOFTWARE_BREAKPOINT) {
                    SetSoftwareBreakpoint(request);
                } else {
                    RemoveSoftwareBreakpoint(request);
                }
                return;
            }
            InterlockedExchange(&g_running, 0);
        }
        if ((header.type == WDBL_VEH_MSG_REQ_READ_MEMORY ||
             header.type == WDBL_VEH_MSG_REQ_WRITE_MEMORY) &&
            header.size == sizeof(WdblVehMemoryRequest)) {
            WdblVehMemoryRequest request = {};
            request.header = header;
            if (ReadAll(g_pipe, reinterpret_cast<BYTE*>(&request) + sizeof(header), sizeof(request) - sizeof(header))) {
                LeaveCriticalSection(&g_pipeLock);
                if (header.type == WDBL_VEH_MSG_REQ_READ_MEMORY) {
                    HandleReadMemoryRequest(request);
                } else {
                    HandleWriteMemoryRequest(request);
                }
                return;
            }
            InterlockedExchange(&g_running, 0);
        }
        if ((header.type == WDBL_VEH_MSG_REQ_SET_HARDWARE_BREAKPOINT ||
             header.type == WDBL_VEH_MSG_REQ_REMOVE_HARDWARE_BREAKPOINT) &&
            header.size == sizeof(WdblVehHardwareBreakpointRequest)) {
            WdblVehHardwareBreakpointRequest request = {};
            request.header = header;
            if (ReadAll(g_pipe, reinterpret_cast<BYTE*>(&request) + sizeof(header), sizeof(request) - sizeof(header))) {
                LeaveCriticalSection(&g_pipeLock);
                if (header.type == WDBL_VEH_MSG_REQ_SET_HARDWARE_BREAKPOINT) {
                    SetHardwareBreakpoint(request);
                } else {
                    RemoveHardwareBreakpoint(request);
                }
                return;
            }
            InterlockedExchange(&g_running, 0);
        }
        if ((header.type == WDBL_VEH_MSG_REQ_SET_MEMORY_BREAKPOINT ||
             header.type == WDBL_VEH_MSG_REQ_REMOVE_MEMORY_BREAKPOINT) &&
            header.size == sizeof(WdblVehMemoryBreakpointRequest)) {
            WdblVehMemoryBreakpointRequest request = {};
            request.header = header;
            if (ReadAll(g_pipe, reinterpret_cast<BYTE*>(&request) + sizeof(header), sizeof(request) - sizeof(header))) {
                LeaveCriticalSection(&g_pipeLock);
                if (header.type == WDBL_VEH_MSG_REQ_SET_MEMORY_BREAKPOINT) {
                    SetMemoryBreakpoint(request);
                } else {
                    RemoveMemoryBreakpoint(request);
                }
                return;
            }
            InterlockedExchange(&g_running, 0);
        }
        if ((header.type == WDBL_VEH_MSG_REQ_GET_CONTEXT ||
             header.type == WDBL_VEH_MSG_REQ_SET_CONTEXT) &&
            header.size == sizeof(WdblVehContextRequest)) {
            WdblVehContextRequest request = {};
            request.header = header;
            if (ReadAll(g_pipe, reinterpret_cast<BYTE*>(&request) + sizeof(header), sizeof(request) - sizeof(header))) {
                LeaveCriticalSection(&g_pipeLock);
                if (header.type == WDBL_VEH_MSG_REQ_GET_CONTEXT) {
                    HandleGetContextRequest(request);
                } else {
                    HandleSetContextRequest(request);
                }
                return;
            }
            InterlockedExchange(&g_running, 0);
        }
        if ((header.type == WDBL_VEH_MSG_REQ_SUSPEND_THREAD ||
             header.type == WDBL_VEH_MSG_REQ_RESUME_THREAD) &&
            header.size == sizeof(WdblVehThreadControlRequest)) {
            WdblVehThreadControlRequest request = {};
            request.header = header;
            if (ReadAll(g_pipe, reinterpret_cast<BYTE*>(&request) + sizeof(header), sizeof(request) - sizeof(header))) {
                LeaveCriticalSection(&g_pipeLock);
                HandleThreadControlRequest(header.type, request);
                return;
            }
            InterlockedExchange(&g_running, 0);
        }
        if (header.type == WDBL_VEH_MSG_REQ_SET_EXCEPTION_POLICY &&
            header.size == sizeof(WdblVehExceptionPolicyRequest)) {
            WdblVehExceptionPolicyRequest request = {};
            request.header = header;
            if (ReadAll(g_pipe, reinterpret_cast<BYTE*>(&request) + sizeof(header), sizeof(request) - sizeof(header))) {
                LeaveCriticalSection(&g_pipeLock);
                HandleExceptionPolicyRequest(request);
                return;
            }
            InterlockedExchange(&g_running, 0);
        }
        if (header.type == WDBL_VEH_MSG_REQ_REFRESH_SNAPSHOT &&
            header.size == sizeof(WdblVehMessageHeader)) {
            LeaveCriticalSection(&g_pipeLock);
            SendInitialSnapshot();
            SendResponse(0, 1, 0, 0, L"snapshot refreshed");
            return;
        }
    }
    LeaveCriticalSection(&g_pipeLock);
}

DWORD WINAPI VehAgentThread(LPVOID) {
    const std::wstring pipeName = BuildPipeName();
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (DWORD i = 0; i < 100 && pipe == INVALID_HANDLE_VALUE; ++i) {
        pipe = CreateFileW(pipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(50);
        }
    }
    if (pipe == INVALID_HANDLE_VALUE) {
        return 0;
    }

    g_pipe = pipe;
    InterlockedExchange(&g_running, 1);
    VehTraceLine(L"startup", 0, 0, 0, false, true);

    WdblVehHelloMessage hello = {};
    hello.header.version = WDBL_VEH_PROTOCOL_VERSION;
    hello.header.type = WDBL_VEH_MSG_HELLO;
    hello.header.size = sizeof(hello);
    hello.processId = GetCurrentProcessId();
    hello.threadId = GetCurrentThreadId();
    hello.imageBase = reinterpret_cast<ULONGLONG>(g_agentModule);
    WriteAll(g_pipe, &hello, sizeof(hello));

    g_vehHandle = RegisterVehHandler();
    SendInitialSnapshot();
    RegisterLoaderNotifications();
    while (InterlockedCompareExchange(&g_running, 1, 1) != 0) {
        DrainThreadNotifications();
        PollControlMessages();
        if (g_threadEvent != nullptr) {
            WaitForSingleObject(g_threadEvent, 100);
        } else {
            Sleep(100);
        }
    }
    DrainThreadNotifications();
    UnregisterLoaderNotifications();
    for (int i = 0; i < WDBL_MAX_VEH_MEMORY_BREAKPOINTS; ++i) {
        if (g_memoryBreakpoints[i].enabled) {
            RestoreMemoryBreakpoint(g_memoryBreakpoints[i]);
        }
    }
    for (int i = 0; i < WDBL_MAX_VEH_HARDWARE_BREAKPOINTS; ++i) {
        g_hardwareBreakpoints[i] = VehHardwareBreakpoint();
    }
    ApplyHardwareBreakpointsToAllThreads();
    CloseHandle(g_pipe);
    g_pipe = INVALID_HANDLE_VALUE;
    return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {

       // MessageBoxA(NULL, "111111", "dddddd", MB_OK);
        g_agentModule = module;
        InitializeCriticalSection(&g_pipeLock);
        g_threadEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        g_vehHandle = RegisterVehHandler();
        {
            
            wchar_t text[160] = {};
            wsprintfW(
                text,
                L"[VEHDBG] register handle=0x%p\r\n",
                g_vehHandle);
            VehWriteLogLine(text);

            //OutputDebugStringW(text);
        }
        
        HANDLE thread = CreateThread(nullptr, 0, VehAgentThread, nullptr, 0, nullptr);
        if (thread != nullptr) {
            CloseHandle(thread);
        }

       
    } else if (reason == DLL_THREAD_ATTACH) {
        QueueThreadNotification(WDBL_VEH_MSG_THREAD_CREATE, GetCurrentThreadId());
    } else if (reason == DLL_THREAD_DETACH) {
        QueueThreadNotification(WDBL_VEH_MSG_THREAD_EXIT, GetCurrentThreadId());
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_pipe != INVALID_HANDLE_VALUE) {
            SendProcessExitMessage(0);
        }
        if (g_vehHandle != nullptr) {
            UnregisterVehHandler(g_vehHandle);
            g_vehHandle = nullptr;
        }
        InterlockedExchange(&g_running, 0);
        if (g_threadEvent != nullptr) {
            SetEvent(g_threadEvent);
            CloseHandle(g_threadEvent);
            g_threadEvent = nullptr;
        }
        DeleteCriticalSection(&g_pipeLock);
    }
    return TRUE;
}
