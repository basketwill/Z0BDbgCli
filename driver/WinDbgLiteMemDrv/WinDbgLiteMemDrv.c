#include <ntifs.h>

#include "../../src/Common/WinDbgLiteMemIoctl.h"

#define WDBL_MEMDRV_DEVICE_NAME      L"\\Device\\WinDbgLiteMem"
#define WDBL_MEMDRV_DOS_DEVICE_NAME  L"\\DosDevices\\WinDbgLiteMem"

#ifndef WDBL_SIGNING_SAFE_DRIVER
#define WDBL_SIGNING_SAFE_DRIVER 0
#endif
#ifndef WDBL_ENABLE_DRIVER_DEBUG_OBJECT
#define WDBL_ENABLE_DRIVER_DEBUG_OBJECT (!WDBL_SIGNING_SAFE_DRIVER)
#endif
#ifndef WDBL_ENABLE_EPROCESS_IMAGE_NAME_OFFSET
#define WDBL_ENABLE_EPROCESS_IMAGE_NAME_OFFSET (!WDBL_SIGNING_SAFE_DRIVER)
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif
#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION 0x0040
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME 0x0002
#endif
#ifndef DEBUG_OBJECT_ALL_ACCESS
#define DEBUG_OBJECT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x0F)
#endif
#ifndef EXCEPTION_DEBUG_EVENT
#define EXCEPTION_DEBUG_EVENT 1
#endif
#ifndef CREATE_THREAD_DEBUG_EVENT
#define CREATE_THREAD_DEBUG_EVENT 2
#endif
#ifndef CREATE_PROCESS_DEBUG_EVENT
#define CREATE_PROCESS_DEBUG_EVENT 3
#endif
#ifndef EXIT_THREAD_DEBUG_EVENT
#define EXIT_THREAD_DEBUG_EVENT 4
#endif
#ifndef EXIT_PROCESS_DEBUG_EVENT
#define EXIT_PROCESS_DEBUG_EVENT 5
#endif
#ifndef LOAD_DLL_DEBUG_EVENT
#define LOAD_DLL_DEBUG_EVENT 6
#endif
#ifndef UNLOAD_DLL_DEBUG_EVENT
#define UNLOAD_DLL_DEBUG_EVENT 7
#endif

#ifndef PsCreateProcessNotifySubsystems
#define PsCreateProcessNotifySubsystems 0
#endif

#define WDBL_EVENT_QUEUE_CAPACITY 256UL

NTKERNELAPI
NTSTATUS
NTAPI
MmCopyVirtualMemory(
    _In_ PEPROCESS FromProcess,
    _In_ PVOID FromAddress,
    _In_ PEPROCESS ToProcess,
    _Out_ PVOID ToAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T NumberOfBytesCopied);

typedef NTSTATUS (NTAPI* WDBL_MM_COPY_VIRTUAL_MEMORY)(
    _In_ PEPROCESS FromProcess,
    _In_ PVOID FromAddress,
    _In_ PEPROCESS ToProcess,
    _Out_ PVOID ToAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T NumberOfBytesCopied);

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenThread(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PCLIENT_ID ClientId);

typedef NTSTATUS (NTAPI* WDBL_ZW_OPEN_THREAD)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PCLIENT_ID ClientId);

NTSYSAPI
NTSTATUS
NTAPI
ZwProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength);

typedef NTSTATUS (NTAPI* WDBL_ZW_PROTECT_VIRTUAL_MEMORY)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect);

typedef NTSTATUS (NTAPI* WDBL_ZW_QUERY_VIRTUAL_MEMORY)(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength);

typedef NTSTATUS (NTAPI* WDBL_ZW_CLOSE)(
    _In_ HANDLE Handle);

typedef NTSTATUS (NTAPI* WDBL_ZW_OPEN_PROCESS)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PCLIENT_ID ClientId);

typedef NTSTATUS (NTAPI* WDBL_ZW_ALLOCATE_VIRTUAL_MEMORY)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect);

typedef NTSTATUS (NTAPI* WDBL_ZW_FREE_VIRTUAL_MEMORY)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType);

typedef NTSTATUS (NTAPI* WDBL_ZW_GET_CONTEXT_THREAD)(
    _In_ HANDLE ThreadHandle,
    _Inout_ PCONTEXT Context);

typedef NTSTATUS (NTAPI* WDBL_ZW_SET_CONTEXT_THREAD)(
    _In_ HANDLE ThreadHandle,
    _In_ PCONTEXT Context);

typedef NTSTATUS (NTAPI* WDBL_ZW_CREATE_THREAD_EX)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags,
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PVOID AttributeList);

typedef NTSTATUS (NTAPI* WDBL_ZW_QUERY_INFORMATION_THREAD)(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef NTSTATUS (NTAPI* WDBL_ZW_SET_INFORMATION_THREAD)(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG ThreadInformationClass,
    _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength);

typedef NTSTATUS (NTAPI* WDBL_ZW_SUSPEND_THREAD)(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount);

typedef NTSTATUS (NTAPI* WDBL_ZW_RESUME_THREAD)(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount);

typedef NTSTATUS (NTAPI* WDBL_ZW_SUSPEND_PROCESS)(
    _In_ HANDLE ProcessHandle);

typedef NTSTATUS (NTAPI* WDBL_ZW_RESUME_PROCESS)(
    _In_ HANDLE ProcessHandle);

typedef NTSTATUS (NTAPI* WDBL_ZW_TERMINATE_PROCESS)(
    _In_opt_ HANDLE ProcessHandle,
    _In_ NTSTATUS ExitStatus);

typedef NTSTATUS (NTAPI* WDBL_ZW_QUERY_SYSTEM_INFORMATION)(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef NTSTATUS (NTAPI* WDBL_ZW_QUERY_INFORMATION_PROCESS)(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef NTSTATUS (NTAPI* WDBL_PS_LOOKUP_PROCESS_BY_PROCESS_ID)(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process);

typedef LONG_PTR (NTAPI* WDBL_OBF_DEREFERENCE_OBJECT)(
    _In_ PVOID Object);

typedef NTSTATUS (NTAPI* WDBL_OB_QUERY_NAME_STRING)(
    _In_ PVOID Object,
    _Out_writes_bytes_opt_(Length) PVOID ObjectNameInfo,
    _In_ ULONG Length,
    _Out_ PULONG ReturnLength);

typedef NTSTATUS (NTAPI* WDBL_PS_SET_CREATE_PROCESS_NOTIFY_ROUTINE_EX)(
    _In_ PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
    _In_ BOOLEAN Remove);

typedef NTSTATUS (NTAPI* WDBL_PS_SET_CREATE_THREAD_NOTIFY_ROUTINE)(
    _In_ PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine);

typedef NTSTATUS (NTAPI* WDBL_PS_REMOVE_CREATE_THREAD_NOTIFY_ROUTINE)(
    _In_ PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine);

typedef NTSTATUS (NTAPI* WDBL_PS_SET_LOAD_IMAGE_NOTIFY_ROUTINE)(
    _In_ PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine);

typedef NTSTATUS (NTAPI* WDBL_PS_REMOVE_LOAD_IMAGE_NOTIFY_ROUTINE)(
    _In_ PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine);

typedef struct _WDBL_LIST_ENTRY32 {
    ULONG Flink;
    ULONG Blink;
} WDBL_LIST_ENTRY32;

typedef struct _WDBL_LIST_ENTRY64 {
    ULONGLONG Flink;
    ULONGLONG Blink;
} WDBL_LIST_ENTRY64;

typedef struct _WDBL_UNICODE_STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG Buffer;
} WDBL_UNICODE_STRING32;

typedef struct _WDBL_UNICODE_STRING64 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG Padding;
    ULONGLONG Buffer;
} WDBL_UNICODE_STRING64;

typedef struct _WDBL_PROCESS_BASIC_INFORMATION_LOCAL {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} WDBL_PROCESS_BASIC_INFORMATION_LOCAL;

typedef struct _WDBL_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} WDBL_SYSTEM_THREAD_INFORMATION;

typedef struct _WDBL_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    WDBL_SYSTEM_THREAD_INFORMATION Threads[1];
} WDBL_SYSTEM_PROCESS_INFORMATION;

typedef struct _WDBL_PEB32_MIN {
    UCHAR Reserved1[0x0C];
    ULONG Ldr;
} WDBL_PEB32_MIN;

typedef struct _WDBL_PEB64_MIN {
    UCHAR Reserved1[0x18];
    ULONGLONG Ldr;
} WDBL_PEB64_MIN;

typedef struct _WDBL_PEB32_ANTIDEBUG_MIN {
    UCHAR Reserved1[0x18];
    ULONG ProcessHeap;
} WDBL_PEB32_ANTIDEBUG_MIN;

typedef struct _WDBL_PEB64_ANTIDEBUG_MIN {
    UCHAR Reserved1[0x30];
    ULONGLONG ProcessHeap;
} WDBL_PEB64_ANTIDEBUG_MIN;

typedef struct _WDBL_PEB_LDR_DATA32_MIN {
    ULONG Length;
    UCHAR Initialized;
    ULONG SsHandle;
    WDBL_LIST_ENTRY32 InLoadOrderModuleList;
} WDBL_PEB_LDR_DATA32_MIN;

typedef struct _WDBL_PEB_LDR_DATA64_MIN {
    ULONG Length;
    UCHAR Initialized;
    UCHAR Reserved1[3];
    ULONGLONG SsHandle;
    WDBL_LIST_ENTRY64 InLoadOrderModuleList;
} WDBL_PEB_LDR_DATA64_MIN;

typedef struct _WDBL_LDR_DATA_TABLE_ENTRY32_MIN {
    WDBL_LIST_ENTRY32 InLoadOrderLinks;
    WDBL_LIST_ENTRY32 InMemoryOrderLinks;
    WDBL_LIST_ENTRY32 InInitializationOrderLinks;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    WDBL_UNICODE_STRING32 FullDllName;
    WDBL_UNICODE_STRING32 BaseDllName;
} WDBL_LDR_DATA_TABLE_ENTRY32_MIN;

typedef struct _WDBL_LDR_DATA_TABLE_ENTRY64_MIN {
    WDBL_LIST_ENTRY64 InLoadOrderLinks;
    WDBL_LIST_ENTRY64 InMemoryOrderLinks;
    WDBL_LIST_ENTRY64 InInitializationOrderLinks;
    ULONGLONG DllBase;
    ULONGLONG EntryPoint;
    ULONG SizeOfImage;
    ULONG Padding;
    WDBL_UNICODE_STRING64 FullDllName;
    WDBL_UNICODE_STRING64 BaseDllName;
} WDBL_LDR_DATA_TABLE_ENTRY64_MIN;

VOID WdblResolveRuntimeApis(void);
#if WDBL_ENABLE_DRIVER_DEBUG_OBJECT
typedef NTSTATUS (NTAPI* WDBL_ZW_CREATE_DEBUG_OBJECT)(
    _Out_ PHANDLE DebugObjectHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG Flags);

typedef NTSTATUS (NTAPI* WDBL_ZW_DEBUG_ACTIVE_PROCESS)(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE DebugObjectHandle);

typedef NTSTATUS (NTAPI* WDBL_ZW_WAIT_FOR_DEBUG_EVENT)(
    _In_ HANDLE DebugObjectHandle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout,
    _Out_ PVOID WaitStateChange);

typedef NTSTATUS (NTAPI* WDBL_ZW_DEBUG_CONTINUE)(
    _In_ HANDLE DebugObjectHandle,
    _In_ PCLIENT_ID ClientId,
    _In_ NTSTATUS ContinueStatus);

typedef NTSTATUS (NTAPI* WDBL_ZW_REMOVE_PROCESS_DEBUG)(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE DebugObjectHandle);

typedef PCHAR (NTAPI* WDBL_PS_GET_PROCESS_IMAGE_FILE_NAME)(
    _In_ PEPROCESS Process);

typedef enum _WDBL_DBG_STATE {
    WdblDbgIdle = 0,
    WdblDbgReplyPending = 1,
    WdblDbgCreateThreadStateChange = 2,
    WdblDbgCreateProcessStateChange = 3,
    WdblDbgExitThreadStateChange = 4,
    WdblDbgExitProcessStateChange = 5,
    WdblDbgExceptionStateChange = 6,
    WdblDbgBreakpointStateChange = 7,
    WdblDbgSingleStepStateChange = 8,
    WdblDbgLoadDllStateChange = 9,
    WdblDbgUnloadDllStateChange = 10
} WDBL_DBG_STATE;

typedef struct _WDBL_DBGKM_EXCEPTION {
    EXCEPTION_RECORD ExceptionRecord;
    ULONG FirstChance;
} WDBL_DBGKM_EXCEPTION;

typedef struct _WDBL_DBGKM_CREATE_THREAD {
    ULONG SubSystemKey;
    PVOID StartAddress;
} WDBL_DBGKM_CREATE_THREAD;

typedef struct _WDBL_DBGKM_CREATE_PROCESS {
    ULONG SubSystemKey;
    HANDLE FileHandle;
    PVOID BaseOfImage;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    WDBL_DBGKM_CREATE_THREAD InitialThread;
} WDBL_DBGKM_CREATE_PROCESS;

typedef struct _WDBL_DBGKM_EXIT_THREAD {
    NTSTATUS ExitStatus;
} WDBL_DBGKM_EXIT_THREAD;

typedef struct _WDBL_DBGKM_EXIT_PROCESS {
    NTSTATUS ExitStatus;
} WDBL_DBGKM_EXIT_PROCESS;

typedef struct _WDBL_DBGKM_LOAD_DLL {
    HANDLE FileHandle;
    PVOID BaseOfDll;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    PVOID NamePointer;
} WDBL_DBGKM_LOAD_DLL;

typedef struct _WDBL_DBGKM_UNLOAD_DLL {
    PVOID BaseAddress;
} WDBL_DBGKM_UNLOAD_DLL;

typedef struct _WDBL_DBGUI_WAIT_STATE_CHANGE {
    WDBL_DBG_STATE NewState;
    CLIENT_ID AppClientId;
    union {
        WDBL_DBGKM_EXCEPTION Exception;
        WDBL_DBGKM_CREATE_THREAD CreateThread;
        WDBL_DBGKM_CREATE_PROCESS CreateProcessInfo;
        WDBL_DBGKM_EXIT_THREAD ExitThread;
        WDBL_DBGKM_EXIT_PROCESS ExitProcess;
        WDBL_DBGKM_LOAD_DLL LoadDll;
        WDBL_DBGKM_UNLOAD_DLL UnloadDll;
    } StateInfo;
} WDBL_DBGUI_WAIT_STATE_CHANGE;
#endif

typedef struct _WDBL_THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} WDBL_THREAD_BASIC_INFORMATION;

typedef NTSTATUS (NTAPI* WDBL_ZW_QUERY_SYSTEM_INFORMATION)(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef NTSTATUS (NTAPI* WDBL_ZW_QUERY_INFORMATION_PROCESS)(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);


#if WDBL_ENABLE_DRIVER_DEBUG_OBJECT
static WDBL_ZW_CREATE_DEBUG_OBJECT g_WdblZwCreateDebugObject = NULL;
static WDBL_ZW_DEBUG_ACTIVE_PROCESS g_WdblZwDebugActiveProcess = NULL;
static WDBL_ZW_WAIT_FOR_DEBUG_EVENT g_WdblZwWaitForDebugEvent = NULL;
static WDBL_ZW_DEBUG_CONTINUE g_WdblZwDebugContinue = NULL;
static WDBL_ZW_REMOVE_PROCESS_DEBUG g_WdblZwRemoveProcessDebug = NULL;
#endif
static WDBL_MM_COPY_VIRTUAL_MEMORY g_WdblMmCopyVirtualMemory = NULL;
static WDBL_ZW_OPEN_PROCESS g_WdblZwOpenProcess = NULL;
static WDBL_ZW_OPEN_THREAD g_WdblZwOpenThread = NULL;
static WDBL_ZW_ALLOCATE_VIRTUAL_MEMORY g_WdblZwAllocateVirtualMemory = NULL;
static WDBL_ZW_FREE_VIRTUAL_MEMORY g_WdblZwFreeVirtualMemory = NULL;
static WDBL_ZW_PROTECT_VIRTUAL_MEMORY g_WdblZwProtectVirtualMemory = NULL;
static WDBL_ZW_QUERY_VIRTUAL_MEMORY g_WdblZwQueryVirtualMemory = NULL;
static WDBL_ZW_CLOSE g_WdblZwClose = NULL;
static WDBL_ZW_CREATE_THREAD_EX g_WdblZwCreateThreadEx = NULL;
static WDBL_ZW_QUERY_INFORMATION_THREAD g_WdblZwQueryInformationThread = NULL;
static WDBL_ZW_SUSPEND_THREAD g_WdblZwSuspendThread = NULL;
static WDBL_ZW_RESUME_THREAD g_WdblZwResumeThread = NULL;
static WDBL_ZW_SUSPEND_PROCESS g_WdblZwSuspendProcess = NULL;
static WDBL_ZW_RESUME_PROCESS g_WdblZwResumeProcess = NULL;
static WDBL_ZW_TERMINATE_PROCESS g_WdblZwTerminateProcess = NULL;
static WDBL_ZW_QUERY_SYSTEM_INFORMATION g_WdblZwQuerySystemInformation = NULL;
static WDBL_ZW_QUERY_INFORMATION_PROCESS g_WdblZwQueryInformationProcess = NULL;
static WDBL_PS_LOOKUP_PROCESS_BY_PROCESS_ID g_WdblPsLookupProcessByProcessId = NULL;
static WDBL_OBF_DEREFERENCE_OBJECT g_WdblObfDereferenceObject = NULL;
static WDBL_OB_QUERY_NAME_STRING g_WdblObQueryNameString = NULL;
static WDBL_PS_SET_CREATE_PROCESS_NOTIFY_ROUTINE_EX g_WdblPsSetCreateProcessNotifyRoutineEx = NULL;
static WDBL_PS_SET_CREATE_THREAD_NOTIFY_ROUTINE g_WdblPsSetCreateThreadNotifyRoutine = NULL;
static WDBL_PS_REMOVE_CREATE_THREAD_NOTIFY_ROUTINE g_WdblPsRemoveCreateThreadNotifyRoutine = NULL;
static WDBL_PS_SET_LOAD_IMAGE_NOTIFY_ROUTINE g_WdblPsSetLoadImageNotifyRoutine = NULL;
static WDBL_PS_REMOVE_LOAD_IMAGE_NOTIFY_ROUTINE g_WdblPsRemoveLoadImageNotifyRoutine = NULL;
static FAST_MUTEX g_WdblEventLock;
static WDBL_DRIVER_EVENT_ENTRY g_WdblEventQueue[WDBL_EVENT_QUEUE_CAPACITY];
static ULONG g_WdblEventHead = 0;
static ULONG g_WdblEventCount = 0;
static BOOLEAN g_WdblProcessNotifyRegistered = FALSE;
static BOOLEAN g_WdblThreadNotifyRegistered = FALSE;
static BOOLEAN g_WdblImageNotifyRegistered = FALSE;
#ifndef SystemProcessInformation
#define SystemProcessInformation 5UL
#endif

#ifndef ProcessBasicInformation
#define ProcessBasicInformation 0UL
#endif

#ifndef ProcessWow64Information
#define ProcessWow64Information 26UL
#endif

#ifndef ProcessDebugPort
#define ProcessDebugPort 7UL
#endif

#ifndef ProcessDebugObjectHandle
#define ProcessDebugObjectHandle 30UL
#endif

#ifndef ProcessDebugFlags
#define ProcessDebugFlags 31UL
#endif

#ifndef ProcessExecuteFlags
#define ProcessExecuteFlags 34UL
#endif

#ifndef ProcessBreakOnTermination
#define ProcessBreakOnTermination 29UL
#endif

#ifndef ProcessProtectionInformation
#define ProcessProtectionInformation 61UL
#endif

#ifndef ThreadBasicInformation
#define ThreadBasicInformation 0UL
#endif

#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress 9UL
#endif

#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation 64UL
#endif
static NTSTATUS WdblOpenProcessHandle(ULONG processId, ACCESS_MASK desiredAccess, PHANDLE processHandle);
static NTSTATUS WdblCloseHandle(HANDLE handle);
static NTSTATUS WdblOpenThreadHandle(ULONG threadId, ACCESS_MASK desiredAccess, PHANDLE threadHandle);
static VOID WdblDereferenceObject(PVOID object);
static NTSTATUS WdblLookupProcess(ULONG processId, PEPROCESS* process);

#define ZwClose WdblCloseHandle

static VOID* WdblQuerySystemProcessInformationBuffer(ULONG* bufferSize) {
    ULONG size = 0x10000;
    NTSTATUS status;
    PVOID buffer;
    ULONG returned = 0;

    if (bufferSize == NULL || g_WdblZwQuerySystemInformation == NULL) {
        return NULL;
    }

    for (;;) {
        buffer = ExAllocatePoolWithTag(NonPagedPool, size, 'WbDP');
        if (buffer == NULL) {
            return NULL;
        }

        status = g_WdblZwQuerySystemInformation(SystemProcessInformation, buffer, size, &returned);
        if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL) {
            ExFreePool(buffer);
            if (returned > size) {
                size = returned + 0x1000;
            } else {
                size *= 2;
            }
            continue;
        }

        if (!NT_SUCCESS(status)) {
            ExFreePool(buffer);
            return NULL;
        }

        *bufferSize = size;
        return buffer;
    }
}

static BOOLEAN WdblCopyRemoteMemory(PEPROCESS process, ULONG_PTR remoteAddress, PVOID localBuffer, SIZE_T size) {
    SIZE_T copied = 0;
    NTSTATUS status;

    if (process == NULL || localBuffer == NULL || size == 0 || g_WdblMmCopyVirtualMemory == NULL) {
        return FALSE;
    }

    status = g_WdblMmCopyVirtualMemory(
        process,
        (PVOID)remoteAddress,
        PsGetCurrentProcess(),
        localBuffer,
        size,
        KernelMode,
        &copied);
    return NT_SUCCESS(status) && copied == size ? TRUE : FALSE;
}

static BOOLEAN WdblCopyRemoteUnicodeBuffer(PEPROCESS process, ULONG_PTR remoteAddress, USHORT lengthBytes, WCHAR* output, SIZE_T outputChars) {
    SIZE_T copyBytes;

    if (output == NULL || outputChars == 0) {
        return FALSE;
    }

    output[0] = L'\0';
    if (remoteAddress == 0 || lengthBytes == 0) {
        return TRUE;
    }

    copyBytes = lengthBytes;
    if (copyBytes > (outputChars - 1) * sizeof(WCHAR)) {
        copyBytes = (outputChars - 1) * sizeof(WCHAR);
    }
    copyBytes &= ~(SIZE_T)1;
    if (copyBytes == 0) {
        return TRUE;
    }

    if (!WdblCopyRemoteMemory(process, remoteAddress, output, copyBytes)) {
        return FALSE;
    }
    output[copyBytes / sizeof(WCHAR)] = L'\0';
    return TRUE;
}

static BOOLEAN WdblCopyRemoteUnicodeString32(PEPROCESS process, ULONG remoteAddress, WCHAR* output, SIZE_T outputChars) {
    WDBL_UNICODE_STRING32 us;

    if (!WdblCopyRemoteMemory(process, (ULONG_PTR)remoteAddress, &us, sizeof(us))) {
        return FALSE;
    }
    return WdblCopyRemoteUnicodeBuffer(process, (ULONG_PTR)us.Buffer, us.Length, output, outputChars);
}

static BOOLEAN WdblCopyRemoteUnicodeString64(PEPROCESS process, ULONGLONG remoteAddress, WCHAR* output, SIZE_T outputChars) {
    WDBL_UNICODE_STRING64 us;

    if (!WdblCopyRemoteMemory(process, (ULONG_PTR)remoteAddress, &us, sizeof(us))) {
        return FALSE;
    }
    return WdblCopyRemoteUnicodeBuffer(process, (ULONG_PTR)us.Buffer, us.Length, output, outputChars);
}

static VOID WdblCopyKernelUnicodeString(PCUNICODE_STRING source, WCHAR* output, ULONG outputChars) {
    ULONG copyBytes;
    if (output == NULL || outputChars == 0) {
        return;
    }
    output[0] = L'\0';
    if (source == NULL || source->Buffer == NULL || source->Length == 0) {
        return;
    }
    copyBytes = source->Length;
    if (copyBytes > (outputChars - 1) * sizeof(WCHAR)) {
        copyBytes = (outputChars - 1) * sizeof(WCHAR);
    }
    copyBytes &= ~(ULONG)1;
    if (copyBytes == 0) {
        return;
    }
    RtlCopyMemory(output, source->Buffer, copyBytes);
    output[copyBytes / sizeof(WCHAR)] = L'\0';
}

static VOID WdblQueueDriverEvent(const WDBL_DRIVER_EVENT_ENTRY* source) {
    ULONG index;
    if (source == NULL) {
        return;
    }
    ExAcquireFastMutex(&g_WdblEventLock);
    index = (g_WdblEventHead + g_WdblEventCount) % WDBL_EVENT_QUEUE_CAPACITY;
    if (g_WdblEventCount == WDBL_EVENT_QUEUE_CAPACITY) {
        index = g_WdblEventHead;
        g_WdblEventHead = (g_WdblEventHead + 1) % WDBL_EVENT_QUEUE_CAPACITY;
    } else {
        ++g_WdblEventCount;
    }
    g_WdblEventQueue[index] = *source;
    ExReleaseFastMutex(&g_WdblEventLock);
}

static VOID WdblProcessNotifyCallback(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo) {
    WDBL_DRIVER_EVENT_ENTRY event;
    UNREFERENCED_PARAMETER(Process);
    RtlZeroMemory(&event, sizeof(event));
    event.Type = WDBL_DRIVER_EVENT_PROCESS;
    event.ProcessId = (ULONG)(ULONG_PTR)ProcessId;
    if (CreateInfo != NULL) {
        event.Flags = 1;
        event.Status = CreateInfo->CreationStatus;
        WdblCopyKernelUnicodeString(CreateInfo->ImageFileName, event.Name,
            sizeof(event.Name) / sizeof(event.Name[0]));
    }
    WdblQueueDriverEvent(&event);
}

static VOID WdblThreadNotifyCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
    WDBL_DRIVER_EVENT_ENTRY event;
    RtlZeroMemory(&event, sizeof(event));
    event.Type = WDBL_DRIVER_EVENT_THREAD;
    event.Flags = Create ? 1UL : 0UL;
    event.ProcessId = (ULONG)(ULONG_PTR)ProcessId;
    event.ThreadId = (ULONG)(ULONG_PTR)ThreadId;
    WdblQueueDriverEvent(&event);
}

static VOID WdblLoadImageNotifyCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo) {
    WDBL_DRIVER_EVENT_ENTRY event;
    RtlZeroMemory(&event, sizeof(event));
    event.Type = WDBL_DRIVER_EVENT_IMAGE;
    event.Flags = 1;
    event.ProcessId = (ULONG)(ULONG_PTR)ProcessId;
    if (ImageInfo != NULL) {
        event.Address = (ULONGLONG)(ULONG_PTR)ImageInfo->ImageBase;
        event.Size = (ULONGLONG)ImageInfo->ImageSize;
    }
    WdblCopyKernelUnicodeString(FullImageName, event.Name,
        sizeof(event.Name) / sizeof(event.Name[0]));
    WdblQueueDriverEvent(&event);
}

static NTSTATUS WdblRegisterEventCallbacks(void) {
    NTSTATUS status = STATUS_SUCCESS;
    WdblResolveRuntimeApis();
    if (g_WdblPsSetCreateProcessNotifyRoutineEx != NULL) {
        status = g_WdblPsSetCreateProcessNotifyRoutineEx(WdblProcessNotifyCallback, FALSE);
        if (NT_SUCCESS(status)) {
            g_WdblProcessNotifyRegistered = TRUE;
        }
    }
    if (g_WdblPsSetCreateThreadNotifyRoutine != NULL) {
        status = g_WdblPsSetCreateThreadNotifyRoutine(WdblThreadNotifyCallback);
        if (NT_SUCCESS(status)) {
            g_WdblThreadNotifyRegistered = TRUE;
        }
    }
    if (g_WdblPsSetLoadImageNotifyRoutine != NULL) {
        status = g_WdblPsSetLoadImageNotifyRoutine(WdblLoadImageNotifyCallback);
        if (NT_SUCCESS(status)) {
            g_WdblImageNotifyRegistered = TRUE;
        }
    }
    return STATUS_SUCCESS;
}

static VOID WdblUnregisterEventCallbacks(void) {
    WdblResolveRuntimeApis();
    if (g_WdblImageNotifyRegistered && g_WdblPsRemoveLoadImageNotifyRoutine != NULL) {
        g_WdblPsRemoveLoadImageNotifyRoutine(WdblLoadImageNotifyCallback);
        g_WdblImageNotifyRegistered = FALSE;
    }
    if (g_WdblThreadNotifyRegistered && g_WdblPsRemoveCreateThreadNotifyRoutine != NULL) {
        g_WdblPsRemoveCreateThreadNotifyRoutine(WdblThreadNotifyCallback);
        g_WdblThreadNotifyRegistered = FALSE;
    }
    if (g_WdblProcessNotifyRegistered && g_WdblPsSetCreateProcessNotifyRoutineEx != NULL) {
        g_WdblPsSetCreateProcessNotifyRoutineEx(WdblProcessNotifyCallback, TRUE);
        g_WdblProcessNotifyRegistered = FALSE;
    }
}

_Use_decl_annotations_
static NTSTATUS WdblHandleQueryDriverEvents(PIRP irp, PIO_STACK_LOCATION stack) {
    WDBL_DRIVER_EVENT_REQUEST request;
    WDBL_ENUM_RESULT_HEADER* header;
    WDBL_DRIVER_EVENT_ENTRY* entries;
    ULONG maxEntries;
    ULONG returned = 0;
    ULONG sourceIndex;

    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(request) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_ENUM_RESULT_HEADER) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = *(WDBL_DRIVER_EVENT_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    maxEntries = (stack->Parameters.DeviceIoControl.OutputBufferLength -
        sizeof(WDBL_ENUM_RESULT_HEADER)) / sizeof(WDBL_DRIVER_EVENT_ENTRY);
    if (request.MaxEvents != 0 && maxEntries > request.MaxEvents) {
        maxEntries = request.MaxEvents;
    }

    header = (WDBL_ENUM_RESULT_HEADER*)irp->AssociatedIrp.SystemBuffer;
    entries = (WDBL_DRIVER_EVENT_ENTRY*)((UCHAR*)irp->AssociatedIrp.SystemBuffer +
        sizeof(WDBL_ENUM_RESULT_HEADER));

    ExAcquireFastMutex(&g_WdblEventLock);
    while (returned < maxEntries && g_WdblEventCount != 0) {
        WDBL_DRIVER_EVENT_ENTRY* event = &g_WdblEventQueue[g_WdblEventHead];
        const BOOLEAN matches =
            request.ProcessId == 0 ||
            event->ProcessId == request.ProcessId;
        sourceIndex = g_WdblEventHead;
        g_WdblEventHead = (g_WdblEventHead + 1) % WDBL_EVENT_QUEUE_CAPACITY;
        --g_WdblEventCount;
        if (matches) {
            entries[returned] = g_WdblEventQueue[sourceIndex];
            ++returned;
        }
    }
    header->TotalCount = returned;
    header->ReturnedCount = returned;
    ExReleaseFastMutex(&g_WdblEventLock);

    irp->IoStatus.Information = sizeof(*header) + returned * sizeof(WDBL_DRIVER_EVENT_ENTRY);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleQueryProcessList(PIRP irp, PIO_STACK_LOCATION stack) {
    WdblResolveRuntimeApis();
    WDBL_ENUM_RESULT_HEADER* header;
    WDBL_PROCESS_ENUM_ENTRY* entries;
    ULONG bufferSize;
    PVOID systemBuffer;
    WDBL_SYSTEM_PROCESS_INFORMATION* info;
    ULONG total = 0;
    ULONG returned = 0;
    ULONG maxEntries;

    if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_ENUM_RESULT_HEADER) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    maxEntries = (stack->Parameters.DeviceIoControl.OutputBufferLength - sizeof(WDBL_ENUM_RESULT_HEADER)) / sizeof(WDBL_PROCESS_ENUM_ENTRY);
    header = (WDBL_ENUM_RESULT_HEADER*)irp->AssociatedIrp.SystemBuffer;
    entries = (WDBL_PROCESS_ENUM_ENTRY*)((UCHAR*)irp->AssociatedIrp.SystemBuffer + sizeof(WDBL_ENUM_RESULT_HEADER));

    systemBuffer = WdblQuerySystemProcessInformationBuffer(&bufferSize);
    if (systemBuffer == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    info = (WDBL_SYSTEM_PROCESS_INFORMATION*)systemBuffer;
    for (;;) {
        ULONG i;
        WDBL_PROCESS_ENUM_ENTRY* entry;

        ++total;
        if (returned < maxEntries) {
            entry = &entries[returned];
            RtlZeroMemory(entry, sizeof(*entry));
            entry->ProcessId = (ULONG)(ULONG_PTR)info->UniqueProcessId;
            entry->ParentProcessId = (ULONG)(ULONG_PTR)info->InheritedFromUniqueProcessId;
            entry->SessionId = info->SessionId;
            entry->ThreadCount = info->NumberOfThreads;
            if (info->ImageName.Buffer != NULL && info->ImageName.Length > 0) {
                USHORT copyBytes = info->ImageName.Length;
                if (copyBytes > sizeof(entry->ImageName) - sizeof(WCHAR)) {
                    copyBytes = (USHORT)(sizeof(entry->ImageName) - sizeof(WCHAR));
                }
                if (copyBytes > 0) {
                    RtlCopyMemory(entry->ImageName, info->ImageName.Buffer, copyBytes);
                    entry->ImageName[copyBytes / sizeof(WCHAR)] = L'\0';
                }
            }
            ++returned;
        }

        if (info->NextEntryOffset == 0) {
            break;
        }
        info = (WDBL_SYSTEM_PROCESS_INFORMATION*)((UCHAR*)info + info->NextEntryOffset);
    }

    ExFreePool(systemBuffer);
    header->TotalCount = total;
    header->ReturnedCount = returned;
    irp->IoStatus.Information = sizeof(*header) + (returned * sizeof(WDBL_PROCESS_ENUM_ENTRY));
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleQueryThreadList(PIRP irp, PIO_STACK_LOCATION stack) {
    WdblResolveRuntimeApis();
    WDBL_PROCESS_ENUM_REQUEST request;
    WDBL_ENUM_RESULT_HEADER* header;
    WDBL_THREAD_ENUM_ENTRY* entries;
    ULONG bufferSize;
    PVOID systemBuffer;
    WDBL_SYSTEM_PROCESS_INFORMATION* info;
    ULONG total = 0;
    ULONG returned = 0;
    ULONG maxEntries;

    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_PROCESS_ENUM_REQUEST) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_ENUM_RESULT_HEADER) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = *(WDBL_PROCESS_ENUM_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    maxEntries = (stack->Parameters.DeviceIoControl.OutputBufferLength - sizeof(WDBL_ENUM_RESULT_HEADER)) / sizeof(WDBL_THREAD_ENUM_ENTRY);
    header = (WDBL_ENUM_RESULT_HEADER*)irp->AssociatedIrp.SystemBuffer;
    entries = (WDBL_THREAD_ENUM_ENTRY*)((UCHAR*)irp->AssociatedIrp.SystemBuffer + sizeof(WDBL_ENUM_RESULT_HEADER));

    systemBuffer = WdblQuerySystemProcessInformationBuffer(&bufferSize);
    if (systemBuffer == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    info = (WDBL_SYSTEM_PROCESS_INFORMATION*)systemBuffer;
    for (;;) {
        ULONG i;
        if ((ULONG)(ULONG_PTR)info->UniqueProcessId == request.ProcessId) {
            for (i = 0; i < info->NumberOfThreads; ++i) {
                WDBL_SYSTEM_THREAD_INFORMATION* threadInfo = &info->Threads[i];
                WDBL_THREAD_ENUM_ENTRY* entry;

                ++total;
                if (returned >= maxEntries) {
                    continue;
                }

                entry = &entries[returned];
                RtlZeroMemory(entry, sizeof(*entry));
                entry->ProcessId = (ULONG)(ULONG_PTR)threadInfo->ClientId.UniqueProcess;
                entry->ThreadId = (ULONG)(ULONG_PTR)threadInfo->ClientId.UniqueThread;
                entry->StartAddress = (ULONGLONG)(ULONG_PTR)threadInfo->StartAddress;
                entry->Priority = threadInfo->Priority;
                entry->BasePriority = threadInfo->BasePriority;
                entry->ThreadState = threadInfo->ThreadState;
                entry->WaitReason = threadInfo->WaitReason;
                ++returned;
            }
            break;
        }

        if (info->NextEntryOffset == 0) {
            break;
        }
        info = (WDBL_SYSTEM_PROCESS_INFORMATION*)((UCHAR*)info + info->NextEntryOffset);
    }

    ExFreePool(systemBuffer);
    if (total == 0) {
        return STATUS_NOT_FOUND;
    }

    header->TotalCount = total;
    header->ReturnedCount = returned;
    irp->IoStatus.Information = sizeof(*header) + (returned * sizeof(WDBL_THREAD_ENUM_ENTRY));
    return STATUS_SUCCESS;
}

static ULONGLONG WdblGetHighestUserAddress(void) {
#if defined(_WIN64)
    return 0x00007FFFFFFEFFFFULL;
#else
    return 0x7FFEFFFFUL;
#endif
}
_Use_decl_annotations_
static NTSTATUS WdblHandleQueryMemoryMap(PIRP irp, PIO_STACK_LOCATION stack) {
    WdblResolveRuntimeApis();
    WDBL_MEMORY_ENUM_REQUEST request;
    WDBL_ENUM_RESULT_HEADER* header;
    WDBL_MEMORY_ENUM_ENTRY* entries;
    HANDLE processHandle = NULL;
    NTSTATUS status;
    ULONG returned = 0;
    ULONG total = 0;
    ULONG maxEntries;
    ULONGLONG address;
    const ULONGLONG maxAddress = WdblGetHighestUserAddress();

    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_MEMORY_ENUM_REQUEST) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_ENUM_RESULT_HEADER) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = *(WDBL_MEMORY_ENUM_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    maxEntries = (stack->Parameters.DeviceIoControl.OutputBufferLength - sizeof(WDBL_ENUM_RESULT_HEADER)) / sizeof(WDBL_MEMORY_ENUM_ENTRY);
    header = (WDBL_ENUM_RESULT_HEADER*)irp->AssociatedIrp.SystemBuffer;
    entries = (WDBL_MEMORY_ENUM_ENTRY*)((UCHAR*)irp->AssociatedIrp.SystemBuffer + sizeof(WDBL_ENUM_RESULT_HEADER));
    address = request.StartAddress;

    if (g_WdblZwQueryVirtualMemory == NULL) {
        ZwClose(processHandle);
        return STATUS_NOT_SUPPORTED;
    }

    status = WdblOpenProcessHandle(request.ProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &processHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    while (address < maxAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T queryLength = 0;
        ULONGLONG nextAddress;

        RtlZeroMemory(&mbi, sizeof(mbi));
        status = g_WdblZwQueryVirtualMemory(
            processHandle,
            (PVOID)(ULONG_PTR)address,
            MemoryBasicInformation,
            &mbi,
            sizeof(mbi),
            &queryLength);
        if (!NT_SUCCESS(status)) {
            address += 0x1000;
            continue;
        }

        ++total;
        if (returned < maxEntries) {
            WDBL_MEMORY_ENUM_ENTRY* entry = &entries[returned];
            RtlZeroMemory(entry, sizeof(*entry));
            entry->BaseAddress = (ULONGLONG)(ULONG_PTR)mbi.BaseAddress;
            entry->AllocationBase = (ULONGLONG)(ULONG_PTR)mbi.AllocationBase;
            entry->RegionSize = (ULONGLONG)mbi.RegionSize;
            entry->State = mbi.State;
            entry->Protect = mbi.Protect;
            entry->Type = mbi.Type;
            entry->AllocationProtect = mbi.AllocationProtect;
            ++returned;
        }

        nextAddress = (ULONGLONG)(ULONG_PTR)mbi.BaseAddress + (ULONGLONG)mbi.RegionSize;
        if (nextAddress <= address) {
            break;
        }
        address = nextAddress;
    }

    ZwClose(processHandle);
    header->TotalCount = total;
    header->ReturnedCount = returned;
    irp->IoStatus.Information = sizeof(*header) + (returned * sizeof(WDBL_MEMORY_ENUM_ENTRY));
    return STATUS_SUCCESS;
}
#if WDBL_ENABLE_EPROCESS_IMAGE_NAME_OFFSET
static WDBL_PS_GET_PROCESS_IMAGE_FILE_NAME g_WdblPsGetProcessImageFileName = NULL;
#endif
static ULONG g_WdblDebugApiAvailableMask = 0;
static LONG g_WdblDebugApiResolved = 0;
static LONG g_WdblRuntimeApiResolved = 0;
#ifndef SystemProcessInformation
#define SystemProcessInformation 5UL
#endif

#ifndef ProcessBasicInformation
#define ProcessBasicInformation 0UL
#endif

#ifndef ProcessWow64Information
#define ProcessWow64Information 26UL
#endif



#if WDBL_ENABLE_EPROCESS_IMAGE_NAME_OFFSET
static WDBL_EPROCESS_IMAGE_NAME_OFFSET_RESULT g_WdblEprocessImageNameOffset = { 0 };
static LONG g_WdblEprocessImageNameOffsetResolved = 0;
#endif
typedef NTSTATUS (NTAPI* WDBL_ZW_QUERY_SYSTEM_INFORMATION)(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef NTSTATUS (NTAPI* WDBL_ZW_QUERY_INFORMATION_PROCESS)(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);


#if WDBL_ENABLE_DRIVER_DEBUG_OBJECT
static FAST_MUTEX g_WdblDebugSessionLock;
static HANDLE g_WdblDebugObjectHandle = NULL;
static ULONG g_WdblDebugProcessId = 0;
#endif




_Use_decl_annotations_
static PVOID WdblResolveKernelRoutine(PCWSTR name) {
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, name);
    return MmGetSystemRoutineAddress(&routineName);
}

static PVOID WdblResolveKernelRoutineEither(PCWSTR zwName, PCWSTR ntName) {
    PVOID routine = WdblResolveKernelRoutine(zwName);
    if (routine == NULL) {
        routine = WdblResolveKernelRoutine(ntName);
    }
    return routine;
}

static PVOID WdblResolveKernelRoutineXor(const WCHAR* encodedName, SIZE_T encodedChars) {
    WCHAR decoded[64];
    SIZE_T i;
    const WCHAR kXorKey = 0x5A5A;

    if (encodedName == NULL || encodedChars == 0 || encodedChars > (sizeof(decoded) / sizeof(decoded[0]))) {
        return NULL;
    }

    for (i = 0; i < encodedChars; ++i) {
        decoded[i] = (WCHAR)(encodedName[i] ^ kXorKey);
        if (decoded[i] == L'\0') {
            break;
        }
    }
    decoded[(i < (sizeof(decoded) / sizeof(decoded[0]))) ? i : ((sizeof(decoded) / sizeof(decoded[0])) - 1)] = L'\0';
    return WdblResolveKernelRoutine(decoded);
}

static PVOID WdblResolveKernelRoutineXorEither(
    const WCHAR* encodedZwName,
    SIZE_T encodedZwChars,
    const WCHAR* encodedNtName,
    SIZE_T encodedNtChars) {
    PVOID routine = WdblResolveKernelRoutineXor(encodedZwName, encodedZwChars);
    if (routine == NULL) {
        routine = WdblResolveKernelRoutineXor(encodedNtName, encodedNtChars);
    }
    return routine;
}

static const WCHAR g_Obf_ZwCreateDebugObject[] = { 0x5A00, 0x5A2D, 0x5A19, 0x5A28, 0x5A3F, 0x5A3B, 0x5A2E, 0x5A3F, 0x5A1E, 0x5A3F, 0x5A38, 0x5A2F, 0x5A3D, 0x5A15, 0x5A38, 0x5A30, 0x5A3F, 0x5A39, 0x5A2E, 0x0000 };
static const WCHAR g_Obf_NtCreateDebugObject[] = { 0x5A14, 0x5A2E, 0x5A19, 0x5A28, 0x5A3F, 0x5A3B, 0x5A2E, 0x5A3F, 0x5A1E, 0x5A3F, 0x5A38, 0x5A2F, 0x5A3D, 0x5A15, 0x5A38, 0x5A30, 0x5A3F, 0x5A39, 0x5A2E, 0x0000 };
static const WCHAR g_Obf_ZwDebugActiveProcess[] = { 0x5A00, 0x5A2D, 0x5A1E, 0x5A3F, 0x5A38, 0x5A2F, 0x5A3D, 0x5A1B, 0x5A39, 0x5A2E, 0x5A33, 0x5A2C, 0x5A3F, 0x5A0A, 0x5A28, 0x5A35, 0x5A39, 0x5A3F, 0x5A29, 0x5A29, 0x0000 };
static const WCHAR g_Obf_NtDebugActiveProcess[] = { 0x5A14, 0x5A2E, 0x5A1E, 0x5A3F, 0x5A38, 0x5A2F, 0x5A3D, 0x5A1B, 0x5A39, 0x5A2E, 0x5A33, 0x5A2C, 0x5A3F, 0x5A0A, 0x5A28, 0x5A35, 0x5A39, 0x5A3F, 0x5A29, 0x5A29, 0x0000 };
static const WCHAR g_Obf_ZwWaitForDebugEvent[] = { 0x5A00, 0x5A2D, 0x5A0D, 0x5A3B, 0x5A33, 0x5A2E, 0x5A1C, 0x5A35, 0x5A28, 0x5A1E, 0x5A3F, 0x5A38, 0x5A2F, 0x5A3D, 0x5A1F, 0x5A2C, 0x5A3F, 0x5A34, 0x5A2E, 0x0000 };
static const WCHAR g_Obf_NtWaitForDebugEvent[] = { 0x5A14, 0x5A2E, 0x5A0D, 0x5A3B, 0x5A33, 0x5A2E, 0x5A1C, 0x5A35, 0x5A28, 0x5A1E, 0x5A3F, 0x5A38, 0x5A2F, 0x5A3D, 0x5A1F, 0x5A2C, 0x5A3F, 0x5A34, 0x5A2E, 0x0000 };
static const WCHAR g_Obf_ZwDebugContinue[] = { 0x5A00, 0x5A2D, 0x5A1E, 0x5A3F, 0x5A38, 0x5A2F, 0x5A3D, 0x5A19, 0x5A35, 0x5A34, 0x5A2E, 0x5A33, 0x5A34, 0x5A2F, 0x5A3F, 0x0000 };
static const WCHAR g_Obf_NtDebugContinue[] = { 0x5A14, 0x5A2E, 0x5A1E, 0x5A3F, 0x5A38, 0x5A2F, 0x5A3D, 0x5A19, 0x5A35, 0x5A34, 0x5A2E, 0x5A33, 0x5A34, 0x5A2F, 0x5A3F, 0x0000 };
static const WCHAR g_Obf_ZwRemoveProcessDebug[] = { 0x5A00, 0x5A2D, 0x5A08, 0x5A3F, 0x5A37, 0x5A35, 0x5A2C, 0x5A3F, 0x5A0A, 0x5A28, 0x5A35, 0x5A39, 0x5A3F, 0x5A29, 0x5A29, 0x5A1E, 0x5A3F, 0x5A38, 0x5A2F, 0x5A3D, 0x0000 };
static const WCHAR g_Obf_NtRemoveProcessDebug[] = { 0x5A14, 0x5A2E, 0x5A08, 0x5A3F, 0x5A37, 0x5A35, 0x5A2C, 0x5A3F, 0x5A0A, 0x5A28, 0x5A35, 0x5A39, 0x5A3F, 0x5A29, 0x5A29, 0x5A1E, 0x5A3F, 0x5A38, 0x5A2F, 0x5A3D, 0x0000 };
static const WCHAR g_Obf_PsGetProcessImageFileName[] = { 0x5A0A, 0x5A29, 0x5A1D, 0x5A3F, 0x5A2E, 0x5A0A, 0x5A28, 0x5A35, 0x5A39, 0x5A3F, 0x5A29, 0x5A29, 0x5A13, 0x5A37, 0x5A3B, 0x5A3D, 0x5A3F, 0x5A1C, 0x5A33, 0x5A36, 0x5A3F, 0x5A14, 0x5A3B, 0x5A37, 0x5A3F, 0x0000 };
static const WCHAR g_Obf_ZwOpenProcess[] = { 0x5A00, 0x5A2D, 0x5A15, 0x5A2A, 0x5A3F, 0x5A34, 0x5A0A, 0x5A28, 0x5A35, 0x5A39, 0x5A3F, 0x5A29, 0x5A29, 0x0000 };
static const WCHAR g_Obf_ZwOpenThread[] = { 0x5A00, 0x5A2D, 0x5A15, 0x5A2A, 0x5A3F, 0x5A34, 0x5A0E, 0x5A32, 0x5A28, 0x5A3F, 0x5A3B, 0x5A3E, 0x0000 };
static const WCHAR g_Obf_ZwAllocateVirtualMemory[] = { 0x5A00, 0x5A2D, 0x5A1B, 0x5A36, 0x5A36, 0x5A35, 0x5A39, 0x5A3B, 0x5A2E, 0x5A3F, 0x5A0C, 0x5A33, 0x5A28, 0x5A2E, 0x5A2F, 0x5A3B, 0x5A36, 0x5A17, 0x5A3F, 0x5A37, 0x5A35, 0x5A28, 0x5A23, 0x0000 };
static const WCHAR g_Obf_ZwProtectVirtualMemory[] = { 0x5A00, 0x5A2D, 0x5A0A, 0x5A28, 0x5A35, 0x5A2E, 0x5A3F, 0x5A39, 0x5A2E, 0x5A0C, 0x5A33, 0x5A28, 0x5A2E, 0x5A2F, 0x5A3B, 0x5A36, 0x5A17, 0x5A3F, 0x5A37, 0x5A35, 0x5A28, 0x5A23, 0x0000 };
static const WCHAR g_Obf_ZwFreeVirtualMemory[] = { 0x5A00, 0x5A2D, 0x5A1C, 0x5A28, 0x5A3F, 0x5A3F, 0x5A0C, 0x5A33, 0x5A28, 0x5A2E, 0x5A2F, 0x5A3B, 0x5A36, 0x5A17, 0x5A3F, 0x5A37, 0x5A35, 0x5A28, 0x5A23, 0x0000 };
static const WCHAR g_Obf_MmCopyVirtualMemory[] = { 0x5A17, 0x5A37, 0x5A19, 0x5A35, 0x5A2A, 0x5A23, 0x5A0C, 0x5A33, 0x5A28, 0x5A2E, 0x5A2F, 0x5A3B, 0x5A36, 0x5A17, 0x5A3F, 0x5A37, 0x5A35, 0x5A28, 0x5A23, 0x0000 };
static const WCHAR g_Obf_ZwQueryVirtualMemory[] = { 0x5A00, 0x5A2D, 0x5A0B, 0x5A2F, 0x5A3F, 0x5A28, 0x5A23, 0x5A0C, 0x5A33, 0x5A28, 0x5A2E, 0x5A2F, 0x5A3B, 0x5A36, 0x5A17, 0x5A3F, 0x5A37, 0x5A35, 0x5A28, 0x5A23, 0x0000 };
static const WCHAR g_Obf_ZwClose[] = { 0x5A00, 0x5A2D, 0x5A19, 0x5A36, 0x5A35, 0x5A29, 0x5A3F, 0x0000 };
static const WCHAR g_Obf_ZwCreateThreadEx[] = { 0x5A00, 0x5A2D, 0x5A19, 0x5A28, 0x5A3F, 0x5A3B, 0x5A2E, 0x5A3F, 0x5A0E, 0x5A32, 0x5A28, 0x5A3F, 0x5A3B, 0x5A3E, 0x5A1F, 0x5A22, 0x0000 };
static const WCHAR g_Obf_ZwQueryInformationThread[] = { 0x5A00, 0x5A2D, 0x5A0B, 0x5A2F, 0x5A3F, 0x5A28, 0x5A23, 0x5A13, 0x5A34, 0x5A3C, 0x5A35, 0x5A28, 0x5A37, 0x5A3B, 0x5A2E, 0x5A33, 0x5A35, 0x5A34, 0x5A0E, 0x5A32, 0x5A28, 0x5A3F, 0x5A3B, 0x5A3E, 0x0000 };
static const WCHAR g_Obf_ZwSuspendThread[] = { 0x5A00, 0x5A2D, 0x5A09, 0x5A2F, 0x5A29, 0x5A2A, 0x5A3F, 0x5A34, 0x5A3E, 0x5A0E, 0x5A32, 0x5A28, 0x5A3F, 0x5A3B, 0x5A3E, 0x0000 };
static const WCHAR g_Obf_ZwResumeThread[] = { 0x5A00, 0x5A2D, 0x5A08, 0x5A3F, 0x5A29, 0x5A2F, 0x5A37, 0x5A3F, 0x5A0E, 0x5A32, 0x5A28, 0x5A3F, 0x5A3B, 0x5A3E, 0x0000 };
static const WCHAR g_Obf_ZwSuspendProcess[] = { 0x5A00, 0x5A2D, 0x5A09, 0x5A2F, 0x5A29, 0x5A2A, 0x5A3F, 0x5A34, 0x5A3E, 0x5A0A, 0x5A28, 0x5A35, 0x5A39, 0x5A3F, 0x5A29, 0x5A29, 0x0000 };
static const WCHAR g_Obf_ZwResumeProcess[] = { 0x5A00, 0x5A2D, 0x5A08, 0x5A3F, 0x5A29, 0x5A2F, 0x5A37, 0x5A3F, 0x5A0A, 0x5A28, 0x5A35, 0x5A39, 0x5A3F, 0x5A29, 0x5A29, 0x0000 };
static const WCHAR g_Obf_ZwQuerySystemInformation[] = { 0x5A00, 0x5A2D, 0x5A0B, 0x5A2F, 0x5A3F, 0x5A28, 0x5A23, 0x5A09, 0x5A2B, 0x5A29, 0x5A2E, 0x5A3F, 0x5A37, 0x5A13, 0x5A34, 0x5A1C, 0x5A35, 0x5A28, 0x5A37, 0x5A23, 0x5A3C, 0x5A35, 0x5A34, 0x5A1D, 0x5A3F, 0x5A28, 0x5A23, 0x0000 };
static const WCHAR g_Obf_ObQueryNameString[] = { 0x5A15, 0x5A38, 0x5A0B, 0x5A2F, 0x5A3F, 0x5A28, 0x5A23, 0x5A14, 0x5A3B, 0x5A37, 0x5A3F, 0x5A09, 0x5A2E, 0x5A28, 0x5A33, 0x5A34, 0x5A3D, 0x0000 };
static const WCHAR g_Obf_PsSetCreateProcessNotifyRoutineEx[] = { 0x5A0A, 0x5A29, 0x5A09, 0x5A3F, 0x5A2E, 0x5A19, 0x5A28, 0x5A3F, 0x5A3B, 0x5A2E, 0x5A3F, 0x5A0A, 0x5A28, 0x5A35, 0x5A39, 0x5A3F, 0x5A29, 0x5A29, 0x5A14, 0x5A35, 0x5A2E, 0x5A33, 0x5A3C, 0x5A23, 0x5A08, 0x5A35, 0x5A2F, 0x5A2E, 0x5A33, 0x5A34, 0x5A3F, 0x5A1F, 0x5A22, 0x0000 };
static const WCHAR g_Obf_PsSetCreateThreadNotifyRoutine[] = { 0x5A0A, 0x5A29, 0x5A09, 0x5A3F, 0x5A2E, 0x5A19, 0x5A28, 0x5A3F, 0x5A3B, 0x5A2E, 0x5A3F, 0x5A0E, 0x5A32, 0x5A28, 0x5A3F, 0x5A3B, 0x5A3E, 0x5A14, 0x5A35, 0x5A2E, 0x5A33, 0x5A3C, 0x5A23, 0x5A08, 0x5A35, 0x5A2F, 0x5A2E, 0x5A33, 0x5A34, 0x5A3F, 0x0000 };
static const WCHAR g_Obf_PsRemoveCreateThreadNotifyRoutine[] = { 0x5A0A, 0x5A29, 0x5A08, 0x5A3F, 0x5A37, 0x5A35, 0x5A2C, 0x5A3F, 0x5A19, 0x5A28, 0x5A3F, 0x5A3B, 0x5A2E, 0x5A3F, 0x5A0E, 0x5A32, 0x5A28, 0x5A3F, 0x5A3B, 0x5A3E, 0x5A14, 0x5A35, 0x5A2E, 0x5A33, 0x5A3C, 0x5A23, 0x5A08, 0x5A35, 0x5A2F, 0x5A2E, 0x5A33, 0x5A34, 0x5A3F, 0x0000 };
static const WCHAR g_Obf_PsSetLoadImageNotifyRoutine[] = { 0x5A0A, 0x5A29, 0x5A09, 0x5A3F, 0x5A2E, 0x5A16, 0x5A35, 0x5A3B, 0x5A3E, 0x5A13, 0x5A37, 0x5A3B, 0x5A3D, 0x5A3F, 0x5A14, 0x5A35, 0x5A2E, 0x5A33, 0x5A3C, 0x5A23, 0x5A08, 0x5A35, 0x5A2F, 0x5A2E, 0x5A33, 0x5A34, 0x5A3F, 0x0000 };
static const WCHAR g_Obf_PsRemoveLoadImageNotifyRoutine[] = { 0x5A0A, 0x5A29, 0x5A08, 0x5A3F, 0x5A37, 0x5A35, 0x5A2C, 0x5A3F, 0x5A16, 0x5A35, 0x5A3B, 0x5A3E, 0x5A13, 0x5A37, 0x5A3B, 0x5A3D, 0x5A3F, 0x5A14, 0x5A35, 0x5A2E, 0x5A33, 0x5A3C, 0x5A23, 0x5A08, 0x5A35, 0x5A2F, 0x5A2E, 0x5A33, 0x5A34, 0x5A3F, 0x0000 };
static const WCHAR g_Obf_ZwQueryInformationProcess[] = { 0x5A00, 0x5A2D, 0x5A0B, 0x5A2F, 0x5A3F, 0x5A28, 0x5A23, 0x5A13, 0x5A34, 0x5A3C, 0x5A35, 0x5A28, 0x5A37, 0x5A13, 0x5A34, 0x5A1C, 0x5A3F, 0x5A3F, 0x5A39, 0x5A35, 0x5A34, 0x5A1D, 0x5A3F, 0x5A28, 0x5A23, 0x5A09, 0x5A29, 0x0000 };
static const WCHAR g_Obf_ZwTerminateProcess[] = { 0x5A00, 0x5A2D, 0x5A0E, 0x5A3F, 0x5A28, 0x5A37, 0x5A33, 0x5A34, 0x5A3B, 0x5A2E, 0x5A3F, 0x5A0A, 0x5A28, 0x5A35, 0x5A39, 0x5A3F, 0x5A29, 0x5A29, 0x0000 };
static const WCHAR g_Obf_ZwGetContextThread[] = { 0x5A00, 0x5A2D, 0x5A1D, 0x5A3F, 0x5A2E, 0x5A19, 0x5A35, 0x5A34, 0x5A2E, 0x5A3F, 0x5A22, 0x5A2E, 0x5A0E, 0x5A32, 0x5A28, 0x5A3F, 0x5A3B, 0x5A3E, 0x0000 };
static const WCHAR g_Obf_ZwSetContextThread[] = { 0x5A00, 0x5A2D, 0x5A09, 0x5A3F, 0x5A2E, 0x5A19, 0x5A35, 0x5A34, 0x5A2E, 0x5A3F, 0x5A22, 0x5A2E, 0x5A0E, 0x5A32, 0x5A28, 0x5A3F, 0x5A3B, 0x5A3E, 0x0000 };
static const WCHAR g_Obf_ZwSetInformationThread[] = { 0x5A00, 0x5A2D, 0x5A09, 0x5A3F, 0x5A2E, 0x5A13, 0x5A34, 0x5A3C, 0x5A35, 0x5A28, 0x5A37, 0x5A3B, 0x5A2E, 0x5A33, 0x5A35, 0x5A34, 0x5A0E, 0x5A32, 0x5A28, 0x5A3F, 0x5A3B, 0x5A3E, 0x0000 };
static const WCHAR g_Obf_PsLookupProcessByProcessId[] = { 0x5A0A, 0x5A29, 0x5A16, 0x5A35, 0x5A35, 0x5A31, 0x5A2F, 0x5A2A, 0x5A0A, 0x5A28, 0x5A35, 0x5A39, 0x5A3F, 0x5A29, 0x5A29, 0x5A18, 0x5A23, 0x5A0A, 0x5A28, 0x5A35, 0x5A39, 0x5A3F, 0x5A29, 0x5A29, 0x5A13, 0x5A3E, 0x0000 };
static const WCHAR g_Obf_ObfDereferenceObject[] = { 0x5A15, 0x5A38, 0x5A3C, 0x5A1E, 0x5A3F, 0x5A28, 0x5A3F, 0x5A3C, 0x5A3F, 0x5A28, 0x5A3F, 0x5A34, 0x5A39, 0x5A3F, 0x5A15, 0x5A38, 0x5A30, 0x5A3F, 0x5A39, 0x5A2E, 0x0000 };
typedef NTSTATUS (NTAPI* WDBL_ZW_QUERY_SYSTEM_INFORMATION)(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef NTSTATUS (NTAPI* WDBL_ZW_QUERY_INFORMATION_PROCESS)(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);


#if WDBL_ENABLE_DRIVER_DEBUG_OBJECT
static ULONG WdblResolveDebugApis(void) {
    ULONG mask = 0;

    if (InterlockedCompareExchange(&g_WdblDebugApiResolved, 1, 0) == 0) {
        g_WdblZwCreateDebugObject =
            (WDBL_ZW_CREATE_DEBUG_OBJECT)WdblResolveKernelRoutineXorEither(g_Obf_ZwCreateDebugObject, sizeof(g_Obf_ZwCreateDebugObject) / sizeof(g_Obf_ZwCreateDebugObject[0]), g_Obf_NtCreateDebugObject, sizeof(g_Obf_NtCreateDebugObject) / sizeof(g_Obf_NtCreateDebugObject[0]));
        g_WdblZwDebugActiveProcess =
            (WDBL_ZW_DEBUG_ACTIVE_PROCESS)WdblResolveKernelRoutineXorEither(g_Obf_ZwDebugActiveProcess, sizeof(g_Obf_ZwDebugActiveProcess) / sizeof(g_Obf_ZwDebugActiveProcess[0]), g_Obf_NtDebugActiveProcess, sizeof(g_Obf_NtDebugActiveProcess) / sizeof(g_Obf_NtDebugActiveProcess[0]));
        g_WdblZwWaitForDebugEvent =
            (WDBL_ZW_WAIT_FOR_DEBUG_EVENT)WdblResolveKernelRoutineXorEither(g_Obf_ZwWaitForDebugEvent, sizeof(g_Obf_ZwWaitForDebugEvent) / sizeof(g_Obf_ZwWaitForDebugEvent[0]), g_Obf_NtWaitForDebugEvent, sizeof(g_Obf_NtWaitForDebugEvent) / sizeof(g_Obf_NtWaitForDebugEvent[0]));
        g_WdblZwDebugContinue =
            (WDBL_ZW_DEBUG_CONTINUE)WdblResolveKernelRoutineXorEither(g_Obf_ZwDebugContinue, sizeof(g_Obf_ZwDebugContinue) / sizeof(g_Obf_ZwDebugContinue[0]), g_Obf_NtDebugContinue, sizeof(g_Obf_NtDebugContinue) / sizeof(g_Obf_NtDebugContinue[0]));
        g_WdblZwRemoveProcessDebug =
            (WDBL_ZW_REMOVE_PROCESS_DEBUG)WdblResolveKernelRoutineXorEither(g_Obf_ZwRemoveProcessDebug, sizeof(g_Obf_ZwRemoveProcessDebug) / sizeof(g_Obf_ZwRemoveProcessDebug[0]), g_Obf_NtRemoveProcessDebug, sizeof(g_Obf_NtRemoveProcessDebug) / sizeof(g_Obf_NtRemoveProcessDebug[0]));

        if (g_WdblZwCreateDebugObject != NULL) {
            mask |= WDBL_DEBUG_API_CREATE_DEBUG_OBJECT;
        }
        if (g_WdblZwDebugActiveProcess != NULL) {
            mask |= WDBL_DEBUG_API_DEBUG_ACTIVE_PROCESS;
        }
        if (g_WdblZwWaitForDebugEvent != NULL) {
            mask |= WDBL_DEBUG_API_WAIT_FOR_DEBUG_EVENT;
        }
        if (g_WdblZwDebugContinue != NULL) {
            mask |= WDBL_DEBUG_API_DEBUG_CONTINUE;
        }
        if (g_WdblZwRemoveProcessDebug != NULL) {
            mask |= WDBL_DEBUG_API_REMOVE_PROCESS_DEBUG;
        }

        g_WdblDebugApiAvailableMask = mask;
    }

    return g_WdblDebugApiAvailableMask;
}
#else
static ULONG WdblResolveDebugApis(void) {
    return 0;
}
#endif

_Use_decl_annotations_
static NTSTATUS WdblHandleQueryDebugApiSupport(PIRP irp, PIO_STACK_LOCATION stack) {
    WDBL_DEBUG_API_SUPPORT_RESULT* result;

    if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_DEBUG_API_SUPPORT_RESULT) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    result = (WDBL_DEBUG_API_SUPPORT_RESULT*)irp->AssociatedIrp.SystemBuffer;
    result->AvailableMask = WdblResolveDebugApis();
    result->RequiredMask = WDBL_DEBUG_API_REQUIRED;
    irp->IoStatus.Information = sizeof(*result);
    return STATUS_SUCCESS;
}

static VOID WdblResolveRuntimeApis(void) {
    if (InterlockedCompareExchange(&g_WdblRuntimeApiResolved, 1, 0) == 0) {
        g_WdblMmCopyVirtualMemory =
            (WDBL_MM_COPY_VIRTUAL_MEMORY)WdblResolveKernelRoutineXor(
                g_Obf_MmCopyVirtualMemory,
                sizeof(g_Obf_MmCopyVirtualMemory) / sizeof(g_Obf_MmCopyVirtualMemory[0]));
        g_WdblZwOpenProcess =
            (WDBL_ZW_OPEN_PROCESS)WdblResolveKernelRoutineXor(
                g_Obf_ZwOpenProcess,
                sizeof(g_Obf_ZwOpenProcess) / sizeof(g_Obf_ZwOpenProcess[0]));
        g_WdblZwOpenThread =
            (WDBL_ZW_OPEN_THREAD)WdblResolveKernelRoutineXor(
                g_Obf_ZwOpenThread,
                sizeof(g_Obf_ZwOpenThread) / sizeof(g_Obf_ZwOpenThread[0]));
        g_WdblZwAllocateVirtualMemory =
            (WDBL_ZW_ALLOCATE_VIRTUAL_MEMORY)WdblResolveKernelRoutineXor(
                g_Obf_ZwAllocateVirtualMemory,
                sizeof(g_Obf_ZwAllocateVirtualMemory) / sizeof(g_Obf_ZwAllocateVirtualMemory[0]));
        g_WdblZwFreeVirtualMemory =
            (WDBL_ZW_FREE_VIRTUAL_MEMORY)WdblResolveKernelRoutineXor(
                g_Obf_ZwFreeVirtualMemory,
                sizeof(g_Obf_ZwFreeVirtualMemory) / sizeof(g_Obf_ZwFreeVirtualMemory[0]));
        g_WdblZwProtectVirtualMemory =
            (WDBL_ZW_PROTECT_VIRTUAL_MEMORY)WdblResolveKernelRoutineXor(
                g_Obf_ZwProtectVirtualMemory,
                sizeof(g_Obf_ZwProtectVirtualMemory) / sizeof(g_Obf_ZwProtectVirtualMemory[0]));
        g_WdblZwQueryVirtualMemory =
            (WDBL_ZW_QUERY_VIRTUAL_MEMORY)WdblResolveKernelRoutineXor(
                g_Obf_ZwQueryVirtualMemory,
                sizeof(g_Obf_ZwQueryVirtualMemory) / sizeof(g_Obf_ZwQueryVirtualMemory[0]));
        g_WdblZwClose =
            (WDBL_ZW_CLOSE)WdblResolveKernelRoutineXor(
                g_Obf_ZwClose,
                sizeof(g_Obf_ZwClose) / sizeof(g_Obf_ZwClose[0]));
        g_WdblZwCreateThreadEx =
            (WDBL_ZW_CREATE_THREAD_EX)WdblResolveKernelRoutineXor(
                g_Obf_ZwCreateThreadEx,
                sizeof(g_Obf_ZwCreateThreadEx) / sizeof(g_Obf_ZwCreateThreadEx[0]));
        g_WdblZwQueryInformationThread =
            (WDBL_ZW_QUERY_INFORMATION_THREAD)WdblResolveKernelRoutineXor(
                g_Obf_ZwQueryInformationThread,
                sizeof(g_Obf_ZwQueryInformationThread) / sizeof(g_Obf_ZwQueryInformationThread[0]));
        g_WdblZwSuspendThread =
            (WDBL_ZW_SUSPEND_THREAD)WdblResolveKernelRoutineXor(
                g_Obf_ZwSuspendThread,
                sizeof(g_Obf_ZwSuspendThread) / sizeof(g_Obf_ZwSuspendThread[0]));
        g_WdblZwResumeThread =
            (WDBL_ZW_RESUME_THREAD)WdblResolveKernelRoutineXor(
                g_Obf_ZwResumeThread,
                sizeof(g_Obf_ZwResumeThread) / sizeof(g_Obf_ZwResumeThread[0]));
        g_WdblZwSuspendProcess =
            (WDBL_ZW_SUSPEND_PROCESS)WdblResolveKernelRoutineXor(
                g_Obf_ZwSuspendProcess,
                sizeof(g_Obf_ZwSuspendProcess) / sizeof(g_Obf_ZwSuspendProcess[0]));
        g_WdblZwResumeProcess =
            (WDBL_ZW_RESUME_PROCESS)WdblResolveKernelRoutineXor(
                g_Obf_ZwResumeProcess,
                sizeof(g_Obf_ZwResumeProcess) / sizeof(g_Obf_ZwResumeProcess[0]));
        g_WdblZwQuerySystemInformation =
            (WDBL_ZW_QUERY_SYSTEM_INFORMATION)WdblResolveKernelRoutineXor(
                g_Obf_ZwQuerySystemInformation,
                sizeof(g_Obf_ZwQuerySystemInformation) / sizeof(g_Obf_ZwQuerySystemInformation[0]));
        g_WdblZwQueryInformationProcess =
            (WDBL_ZW_QUERY_INFORMATION_PROCESS)WdblResolveKernelRoutineXor(
                g_Obf_ZwQueryInformationProcess,
                sizeof(g_Obf_ZwQueryInformationProcess) / sizeof(g_Obf_ZwQueryInformationProcess[0]));
        g_WdblZwTerminateProcess =
            (WDBL_ZW_TERMINATE_PROCESS)WdblResolveKernelRoutineXor(
                g_Obf_ZwTerminateProcess,
                sizeof(g_Obf_ZwTerminateProcess) / sizeof(g_Obf_ZwTerminateProcess[0]));
        g_WdblPsLookupProcessByProcessId =
            (WDBL_PS_LOOKUP_PROCESS_BY_PROCESS_ID)WdblResolveKernelRoutineXor(
                g_Obf_PsLookupProcessByProcessId,
                sizeof(g_Obf_PsLookupProcessByProcessId) / sizeof(g_Obf_PsLookupProcessByProcessId[0]));
        g_WdblObfDereferenceObject =
            (WDBL_OBF_DEREFERENCE_OBJECT)WdblResolveKernelRoutineXor(
                g_Obf_ObfDereferenceObject,
                sizeof(g_Obf_ObfDereferenceObject) / sizeof(g_Obf_ObfDereferenceObject[0]));
        g_WdblObQueryNameString =
            (WDBL_OB_QUERY_NAME_STRING)WdblResolveKernelRoutineXor(
                g_Obf_ObQueryNameString,
                sizeof(g_Obf_ObQueryNameString) / sizeof(g_Obf_ObQueryNameString[0]));
        g_WdblPsSetCreateProcessNotifyRoutineEx =
            (WDBL_PS_SET_CREATE_PROCESS_NOTIFY_ROUTINE_EX)WdblResolveKernelRoutineXor(
                g_Obf_PsSetCreateProcessNotifyRoutineEx,
                sizeof(g_Obf_PsSetCreateProcessNotifyRoutineEx) / sizeof(g_Obf_PsSetCreateProcessNotifyRoutineEx[0]));
        g_WdblPsSetCreateThreadNotifyRoutine =
            (WDBL_PS_SET_CREATE_THREAD_NOTIFY_ROUTINE)WdblResolveKernelRoutineXor(
                g_Obf_PsSetCreateThreadNotifyRoutine,
                sizeof(g_Obf_PsSetCreateThreadNotifyRoutine) / sizeof(g_Obf_PsSetCreateThreadNotifyRoutine[0]));
        g_WdblPsRemoveCreateThreadNotifyRoutine =
            (WDBL_PS_REMOVE_CREATE_THREAD_NOTIFY_ROUTINE)WdblResolveKernelRoutineXor(
                g_Obf_PsRemoveCreateThreadNotifyRoutine,
                sizeof(g_Obf_PsRemoveCreateThreadNotifyRoutine) / sizeof(g_Obf_PsRemoveCreateThreadNotifyRoutine[0]));
        g_WdblPsSetLoadImageNotifyRoutine =
            (WDBL_PS_SET_LOAD_IMAGE_NOTIFY_ROUTINE)WdblResolveKernelRoutineXor(
                g_Obf_PsSetLoadImageNotifyRoutine,
                sizeof(g_Obf_PsSetLoadImageNotifyRoutine) / sizeof(g_Obf_PsSetLoadImageNotifyRoutine[0]));
        g_WdblPsRemoveLoadImageNotifyRoutine =
            (WDBL_PS_REMOVE_LOAD_IMAGE_NOTIFY_ROUTINE)WdblResolveKernelRoutineXor(
                g_Obf_PsRemoveLoadImageNotifyRoutine,
                sizeof(g_Obf_PsRemoveLoadImageNotifyRoutine) / sizeof(g_Obf_PsRemoveLoadImageNotifyRoutine[0]));
    }
}

static NTSTATUS WdblCloseHandle(HANDLE handle) {
    WdblResolveRuntimeApis();
    if (g_WdblZwClose == NULL) {
        return STATUS_NOT_SUPPORTED;
    }
    return g_WdblZwClose(handle);
}

#ifndef SystemProcessInformation
#define SystemProcessInformation 5UL
#endif

#ifndef ProcessBasicInformation
#define ProcessBasicInformation 0UL
#endif

#ifndef ProcessWow64Information
#define ProcessWow64Information 26UL
#endif


#if WDBL_ENABLE_EPROCESS_IMAGE_NAME_OFFSET
static SIZE_T WdblAnsiStringLengthLimited(const CHAR* text, SIZE_T maxChars) {
    SIZE_T length = 0;
    if (text == NULL) {
        return 0;
    }
    while (length < maxChars && text[length] != '\0') {
        ++length;
    }
    return length;
}

static VOID WdblResolveEprocessImageNameOffset(void) {
    PEPROCESS process;
    PUCHAR processBytes;
    PCHAR imageName;
    SIZE_T nameLength;
    ULONG offset;

    if (InterlockedCompareExchange(&g_WdblEprocessImageNameOffsetResolved, 1, 0) != 0) {
        return;
    }

    process = PsGetCurrentProcess();
    processBytes = (PUCHAR)process;
    RtlZeroMemory(&g_WdblEprocessImageNameOffset, sizeof(g_WdblEprocessImageNameOffset));

    g_WdblPsGetProcessImageFileName =
        (WDBL_PS_GET_PROCESS_IMAGE_FILE_NAME)WdblResolveKernelRoutineXor(g_Obf_PsGetProcessImageFileName, sizeof(g_Obf_PsGetProcessImageFileName) / sizeof(g_Obf_PsGetProcessImageFileName[0]));
    if (g_WdblPsGetProcessImageFileName != NULL) {
        imageName = g_WdblPsGetProcessImageFileName(process);
        if (imageName != NULL && (PUCHAR)imageName >= processBytes) {
            offset = (ULONG)((PUCHAR)imageName - processBytes);
            if (offset < 0x1000) {
                nameLength = WdblAnsiStringLengthLimited(imageName, sizeof(g_WdblEprocessImageNameOffset.ImageName) - 1);
                if (nameLength > 0) {
                    g_WdblEprocessImageNameOffset.Offset = offset;
                    g_WdblEprocessImageNameOffset.NameLength = (ULONG)nameLength;
                    g_WdblEprocessImageNameOffset.Confidence = 100;
                    RtlCopyMemory(g_WdblEprocessImageNameOffset.ImageName, imageName, nameLength);
                    g_WdblEprocessImageNameOffset.ImageName[nameLength] = '\0';
                    return;
                }
            }
        }
    }
}

_Use_decl_annotations_
static NTSTATUS WdblHandleQueryEprocessImageNameOffset(PIRP irp, PIO_STACK_LOCATION stack) {
    WDBL_EPROCESS_IMAGE_NAME_OFFSET_RESULT* result;

    if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_EPROCESS_IMAGE_NAME_OFFSET_RESULT) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    WdblResolveEprocessImageNameOffset();
    if (g_WdblEprocessImageNameOffset.NameLength == 0) {
        return STATUS_NOT_SUPPORTED;
    }

    result = (WDBL_EPROCESS_IMAGE_NAME_OFFSET_RESULT*)irp->AssociatedIrp.SystemBuffer;
    *result = g_WdblEprocessImageNameOffset;
    irp->IoStatus.Information = sizeof(*result);
    return STATUS_SUCCESS;
}
#else
_Use_decl_annotations_
static NTSTATUS WdblHandleQueryEprocessImageNameOffset(PIRP irp, PIO_STACK_LOCATION stack) {
    UNREFERENCED_PARAMETER(irp);
    UNREFERENCED_PARAMETER(stack);
    return STATUS_NOT_SUPPORTED;
}
#endif

_Use_decl_annotations_
static NTSTATUS WdblHandleQueryCapabilities(PIRP irp, PIO_STACK_LOCATION stack) {
    WDBL_DRIVER_CAPABILITIES_RESULT* result;
    ULONG mask = 0;
    ULONG debugMask;
    PVOID getContext;
    PVOID setContext;

    if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_DRIVER_CAPABILITIES_RESULT) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    WdblResolveRuntimeApis();
    debugMask = WdblResolveDebugApis();
    if (g_WdblMmCopyVirtualMemory != NULL) {
        mask |= WDBL_DRIVER_CAP_MEMORY_RW | WDBL_DRIVER_CAP_MEMORY_RW_EX;
    }
    getContext = WdblResolveKernelRoutineXor(
        g_Obf_ZwGetContextThread,
        sizeof(g_Obf_ZwGetContextThread) / sizeof(g_Obf_ZwGetContextThread[0]));
    setContext = WdblResolveKernelRoutineXor(
        g_Obf_ZwSetContextThread,
        sizeof(g_Obf_ZwSetContextThread) / sizeof(g_Obf_ZwSetContextThread[0]));
    if (getContext != NULL && setContext != NULL) {
        mask |= WDBL_DRIVER_CAP_THREAD_CONTEXT | WDBL_DRIVER_CAP_DEBUG_REGISTERS;
    }
    if (g_WdblZwQueryInformationThread != NULL) {
        mask |= WDBL_DRIVER_CAP_WOW64_CONTEXT;
    }
    if (g_WdblZwQueryInformationProcess != NULL && g_WdblMmCopyVirtualMemory != NULL &&
        g_WdblPsLookupProcessByProcessId != NULL) {
        mask |= WDBL_DRIVER_CAP_MODULE_LIST | WDBL_DRIVER_CAP_ANTI_DEBUG;
    }
    if (g_WdblZwQueryVirtualMemory != NULL) {
        mask |= WDBL_DRIVER_CAP_MEMORY_MAP;
    }
    if (g_WdblZwOpenProcess != NULL && g_WdblZwOpenThread != NULL) {
        mask |= WDBL_DRIVER_CAP_PROCESS_CONTROL;
    }
    if (g_WdblZwQuerySystemInformation != NULL) {
        mask |= WDBL_DRIVER_CAP_HANDLE_LIST;
    }
    if (g_WdblZwQueryInformationThread != NULL) {
        mask |= WDBL_DRIVER_CAP_THREAD_INFO;
    }
    if (g_WdblZwQueryInformationProcess != NULL && g_WdblMmCopyVirtualMemory != NULL) {
        mask |= WDBL_DRIVER_CAP_IMAGE_INFO | WDBL_DRIVER_CAP_MITIGATIONS;
    }
    if ((g_WdblProcessNotifyRegistered || g_WdblThreadNotifyRegistered || g_WdblImageNotifyRegistered) ||
        g_WdblPsSetCreateProcessNotifyRoutineEx != NULL ||
        g_WdblPsSetCreateThreadNotifyRoutine != NULL ||
        g_WdblPsSetLoadImageNotifyRoutine != NULL) {
        mask |= WDBL_DRIVER_CAP_EVENTS;
    }
    if ((debugMask & WDBL_DEBUG_API_REQUIRED) == WDBL_DEBUG_API_REQUIRED) {
        mask |= WDBL_DRIVER_CAP_DEBUG_API;
    }

    result = (WDBL_DRIVER_CAPABILITIES_RESULT*)irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(result, sizeof(*result));
    result->Version = WDBL_MEM_DRIVER_CAPABILITY_VERSION;
    result->Size = sizeof(*result);
    result->CapabilityMask = mask;
    result->DebugApiMask = debugMask;
    result->IoctlProtocolVersion = WDBL_IOCTL_PROTOCOL_VERSION;
    irp->IoStatus.Information = sizeof(*result);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleReadProcessMemoryEx(PIRP irp, PIO_STACK_LOCATION stack) {
    WDBL_PROCESS_MEMORY_READ_EX_REQUEST request;
    WDBL_PROCESS_MEMORY_READ_EX_RESULT* result;
    ULONG headerSize = (ULONG)FIELD_OFFSET(WDBL_PROCESS_MEMORY_READ_EX_RESULT, Data);
    PEPROCESS sourceProcess = NULL;
    SIZE_T copied = 0;
    NTSTATUS status;

    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_PROCESS_MEMORY_READ_EX_REQUEST) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < headerSize ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = *(WDBL_PROCESS_MEMORY_READ_EX_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request.Size > stack->Parameters.DeviceIoControl.OutputBufferLength - headerSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    result = (WDBL_PROCESS_MEMORY_READ_EX_RESULT*)irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(result, headerSize);
    if (request.Size == 0) {
        result->KernelStatus = STATUS_SUCCESS;
        irp->IoStatus.Information = headerSize;
        return STATUS_SUCCESS;
    }

    status = WdblLookupProcess(request.ProcessId, &sourceProcess);
    if (!NT_SUCCESS(status)) {
        result->KernelStatus = status;
        irp->IoStatus.Information = headerSize;
        return STATUS_SUCCESS;
    }

    WdblResolveRuntimeApis();
    if (g_WdblMmCopyVirtualMemory == NULL) {
        WdblDereferenceObject(sourceProcess);
        result->KernelStatus = STATUS_NOT_SUPPORTED;
        irp->IoStatus.Information = headerSize;
        return STATUS_SUCCESS;
    }

    status = g_WdblMmCopyVirtualMemory(
        sourceProcess,
        (PVOID)(ULONG_PTR)request.Address,
        PsGetCurrentProcess(),
        result->Data,
        (SIZE_T)request.Size,
        KernelMode,
        &copied);
    WdblDereferenceObject(sourceProcess);

    result->BytesRead = (ULONG)copied;
    result->KernelStatus = status;
    result->FaultAddress = request.Address + (ULONGLONG)copied;
    irp->IoStatus.Information = headerSize + copied;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleWriteProcessMemoryEx(PIRP irp, PIO_STACK_LOCATION stack) {
    const UCHAR* buffer;
    const WDBL_PROCESS_MEMORY_WRITE_EX_REQUEST_HEADER* request;
    WDBL_PROCESS_MEMORY_WRITE_EX_RESULT* result;
    const ULONG headerSize = (ULONG)sizeof(WDBL_PROCESS_MEMORY_WRITE_EX_REQUEST_HEADER);
    PEPROCESS targetProcess = NULL;
    SIZE_T copied = 0;
    NTSTATUS status;

    if (irp->AssociatedIrp.SystemBuffer == NULL ||
        stack->Parameters.DeviceIoControl.InputBufferLength < headerSize ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_PROCESS_MEMORY_WRITE_EX_RESULT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    buffer = (const UCHAR*)irp->AssociatedIrp.SystemBuffer;
    request = (const WDBL_PROCESS_MEMORY_WRITE_EX_REQUEST_HEADER*)buffer;
    if (request->ProcessId == 0 || request->Size > stack->Parameters.DeviceIoControl.InputBufferLength - headerSize) {
        return STATUS_INVALID_PARAMETER;
    }

    result = (WDBL_PROCESS_MEMORY_WRITE_EX_RESULT*)irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(result, sizeof(*result));
    if (request->Size == 0) {
        result->KernelStatus = STATUS_SUCCESS;
        irp->IoStatus.Information = sizeof(*result);
        return STATUS_SUCCESS;
    }

    status = WdblLookupProcess(request->ProcessId, &targetProcess);
    if (!NT_SUCCESS(status)) {
        result->KernelStatus = status;
        irp->IoStatus.Information = sizeof(*result);
        return STATUS_SUCCESS;
    }

    WdblResolveRuntimeApis();
    if (g_WdblMmCopyVirtualMemory == NULL) {
        WdblDereferenceObject(targetProcess);
        result->KernelStatus = STATUS_NOT_SUPPORTED;
        irp->IoStatus.Information = sizeof(*result);
        return STATUS_SUCCESS;
    }

    status = g_WdblMmCopyVirtualMemory(
        PsGetCurrentProcess(),
        (PVOID)(buffer + headerSize),
        targetProcess,
        (PVOID)(ULONG_PTR)request->Address,
        (SIZE_T)request->Size,
        KernelMode,
        &copied);
    WdblDereferenceObject(targetProcess);

    result->BytesWritten = (ULONG)copied;
    result->KernelStatus = status;
    result->FaultAddress = request->Address + (ULONGLONG)copied;
    irp->IoStatus.Information = sizeof(*result);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleQueryAntiDebug(PIRP irp, PIO_STACK_LOCATION stack) {
    WDBL_ANTI_DEBUG_QUERY_REQUEST request;
    WDBL_ANTI_DEBUG_QUERY_RESULT* result;
    WDBL_PROCESS_BASIC_INFORMATION_LOCAL basicInfo;
    HANDLE processHandle = NULL;
    PEPROCESS process = NULL;
    ULONG_PTR wow64Peb = 0;
    UCHAR beingDebugged = 0;
    ULONG ntGlobalFlag = 0;
    NTSTATUS status;

    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_ANTI_DEBUG_QUERY_REQUEST) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_ANTI_DEBUG_QUERY_RESULT) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = *(WDBL_ANTI_DEBUG_QUERY_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    result = (WDBL_ANTI_DEBUG_QUERY_RESULT*)irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(result, sizeof(*result));
    result->ProcessId = request.ProcessId;
    result->PebStatus = STATUS_NOT_SUPPORTED;
    result->DebugPortStatus = STATUS_NOT_SUPPORTED;
    result->DebugObjectStatus = STATUS_NOT_SUPPORTED;
    result->DebugFlagsStatus = STATUS_NOT_SUPPORTED;
    result->HeapStatus = STATUS_NOT_SUPPORTED;

    WdblResolveRuntimeApis();
    status = WdblOpenProcessHandle(request.ProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &processHandle);
    if (!NT_SUCCESS(status)) {
        result->PebStatus = status;
        irp->IoStatus.Information = sizeof(*result);
        return STATUS_SUCCESS;
    }

    status = WdblLookupProcess(request.ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        ZwClose(processHandle);
        result->PebStatus = status;
        irp->IoStatus.Information = sizeof(*result);
        return STATUS_SUCCESS;
    }

    if (g_WdblZwQueryInformationProcess != NULL) {
        RtlZeroMemory(&basicInfo, sizeof(basicInfo));
        status = g_WdblZwQueryInformationProcess(processHandle, ProcessBasicInformation, &basicInfo, sizeof(basicInfo), NULL);
        if (NT_SUCCESS(status)) {
            result->PebAddress = (ULONGLONG)(ULONG_PTR)basicInfo.PebBaseAddress;
            g_WdblZwQueryInformationProcess(processHandle, ProcessWow64Information, &wow64Peb, sizeof(wow64Peb), NULL);
            result->Wow64PebAddress = (ULONGLONG)wow64Peb;
            result->IsWow64 = wow64Peb != 0 ? 1 : 0;

            if (wow64Peb != 0) {
                if (WdblCopyRemoteMemory(process, wow64Peb + 2, &beingDebugged, sizeof(beingDebugged))) {
                    result->BeingDebugged = beingDebugged;
                    WdblCopyRemoteMemory(process, wow64Peb + 0x68, &ntGlobalFlag, sizeof(ntGlobalFlag));
                    result->NtGlobalFlag = ntGlobalFlag;
                    result->PebStatus = STATUS_SUCCESS;
                } else {
                    result->PebStatus = STATUS_UNSUCCESSFUL;
                }
            } else if (basicInfo.PebBaseAddress != NULL) {
                ULONGLONG peb = (ULONGLONG)(ULONG_PTR)basicInfo.PebBaseAddress;
                if (WdblCopyRemoteMemory(process, (ULONG_PTR)(peb + 2), &beingDebugged, sizeof(beingDebugged))) {
                    result->BeingDebugged = beingDebugged;
                    WdblCopyRemoteMemory(process, (ULONG_PTR)(peb + 0xBC), &ntGlobalFlag, sizeof(ntGlobalFlag));
                    result->NtGlobalFlag = ntGlobalFlag;
                    result->PebStatus = STATUS_SUCCESS;
                } else {
                    result->PebStatus = STATUS_UNSUCCESSFUL;
                }
            }
        } else {
            result->PebStatus = status;
        }

        if (result->PebStatus == STATUS_SUCCESS) {
            if (result->IsWow64 != 0 && result->Wow64PebAddress != 0) {
                WDBL_PEB32_ANTIDEBUG_MIN peb32;
                if (WdblCopyRemoteMemory(process, (ULONG_PTR)result->Wow64PebAddress,
                        &peb32, sizeof(peb32)) &&
                    peb32.ProcessHeap != 0 &&
                    WdblCopyRemoteMemory(process, (ULONG_PTR)peb32.ProcessHeap + 0x40,
                        &result->HeapFlags, sizeof(result->HeapFlags)) &&
                    WdblCopyRemoteMemory(process, (ULONG_PTR)peb32.ProcessHeap + 0x44,
                        &result->HeapForceFlags, sizeof(result->HeapForceFlags))) {
                    result->ProcessHeap = peb32.ProcessHeap;
                    result->HeapStatus = STATUS_SUCCESS;
                } else {
                    result->HeapStatus = STATUS_PARTIAL_COPY;
                }
            } else if (basicInfo.PebBaseAddress != NULL) {
                WDBL_PEB64_ANTIDEBUG_MIN peb64;
                if (WdblCopyRemoteMemory(process, (ULONG_PTR)basicInfo.PebBaseAddress,
                        &peb64, sizeof(peb64)) &&
                    peb64.ProcessHeap != 0 &&
                    WdblCopyRemoteMemory(process, (ULONG_PTR)peb64.ProcessHeap + 0x70,
                        &result->HeapFlags, sizeof(result->HeapFlags)) &&
                    WdblCopyRemoteMemory(process, (ULONG_PTR)peb64.ProcessHeap + 0x74,
                        &result->HeapForceFlags, sizeof(result->HeapForceFlags))) {
                    result->ProcessHeap = peb64.ProcessHeap;
                    result->HeapStatus = STATUS_SUCCESS;
                } else {
                    result->HeapStatus = STATUS_PARTIAL_COPY;
                }
            }
        }

        result->DebugPortStatus = g_WdblZwQueryInformationProcess(
            processHandle,
            ProcessDebugPort,
            &result->DebugPort,
            sizeof(result->DebugPort),
            NULL);
        result->DebugObjectStatus = g_WdblZwQueryInformationProcess(
            processHandle,
            ProcessDebugObjectHandle,
            &result->DebugObjectHandle,
            sizeof(result->DebugObjectHandle),
            NULL);
        if (NT_SUCCESS(result->DebugObjectStatus) && result->DebugObjectHandle != 0) {
            ZwClose((HANDLE)(ULONG_PTR)result->DebugObjectHandle);
        }
        result->DebugFlagsStatus = g_WdblZwQueryInformationProcess(
            processHandle,
            ProcessDebugFlags,
            &result->DebugFlags,
            sizeof(result->DebugFlags),
            NULL);
    }

    WdblDereferenceObject(process);
    ZwClose(processHandle);
    irp->IoStatus.Information = sizeof(*result);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleQueryDebugRegisters(PIRP irp, PIO_STACK_LOCATION stack) {
    WDBL_DEBUG_REGISTERS_REQUEST request;
    WDBL_DEBUG_REGISTERS_RESULT* result;
    CONTEXT context;
    HANDLE threadHandle = NULL;
    NTSTATUS status;
    WDBL_ZW_GET_CONTEXT_THREAD getContext;

    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_DEBUG_REGISTERS_REQUEST) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_DEBUG_REGISTERS_RESULT) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = *(WDBL_DEBUG_REGISTERS_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.ThreadId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = WdblOpenThreadHandle(request.ThreadId, THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, &threadHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    getContext = (WDBL_ZW_GET_CONTEXT_THREAD)WdblResolveKernelRoutineXor(
        g_Obf_ZwGetContextThread,
        sizeof(g_Obf_ZwGetContextThread) / sizeof(g_Obf_ZwGetContextThread[0]));
    if (getContext == NULL) {
        ZwClose(threadHandle);
        return STATUS_NOT_SUPPORTED;
    }

    RtlZeroMemory(&context, sizeof(context));
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    status = getContext(threadHandle, &context);
    ZwClose(threadHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    result = (WDBL_DEBUG_REGISTERS_RESULT*)irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(result, sizeof(*result));
    result->Dr0 = context.Dr0;
    result->Dr1 = context.Dr1;
    result->Dr2 = context.Dr2;
    result->Dr3 = context.Dr3;
    result->Dr6 = context.Dr6;
    result->Dr7 = context.Dr7;
    irp->IoStatus.Information = sizeof(*result);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleSetDebugRegisters(PIRP irp, PIO_STACK_LOCATION stack) {
    UCHAR* buffer;
    WDBL_DEBUG_REGISTERS_REQUEST* request;
    WDBL_DEBUG_REGISTERS_RESULT* input;
    CONTEXT context;
    HANDLE threadHandle = NULL;
    NTSTATUS status;
    WDBL_ZW_SET_CONTEXT_THREAD setContext;

    if (stack->Parameters.DeviceIoControl.InputBufferLength <
            sizeof(WDBL_DEBUG_REGISTERS_REQUEST) + sizeof(WDBL_DEBUG_REGISTERS_RESULT) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    buffer = (UCHAR*)irp->AssociatedIrp.SystemBuffer;
    request = (WDBL_DEBUG_REGISTERS_REQUEST*)buffer;
    input = (WDBL_DEBUG_REGISTERS_RESULT*)(buffer + sizeof(WDBL_DEBUG_REGISTERS_REQUEST));
    if (request->ThreadId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = WdblOpenThreadHandle(request->ThreadId, THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, &threadHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    setContext = (WDBL_ZW_SET_CONTEXT_THREAD)WdblResolveKernelRoutineXor(
        g_Obf_ZwSetContextThread,
        sizeof(g_Obf_ZwSetContextThread) / sizeof(g_Obf_ZwSetContextThread[0]));
    if (setContext == NULL) {
        ZwClose(threadHandle);
        return STATUS_NOT_SUPPORTED;
    }

    RtlZeroMemory(&context, sizeof(context));
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    context.Dr0 = (DWORD_PTR)input->Dr0;
    context.Dr1 = (DWORD_PTR)input->Dr1;
    context.Dr2 = (DWORD_PTR)input->Dr2;
    context.Dr3 = (DWORD_PTR)input->Dr3;
    context.Dr6 = (DWORD_PTR)input->Dr6;
    context.Dr7 = (DWORD_PTR)input->Dr7;
    status = setContext(threadHandle, &context);
    ZwClose(threadHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

typedef NTSTATUS (NTAPI* WDBL_ZW_QUERY_SYSTEM_INFORMATION)(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef NTSTATUS (NTAPI* WDBL_ZW_QUERY_INFORMATION_PROCESS)(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);


#if WDBL_ENABLE_DRIVER_DEBUG_OBJECT
static BOOLEAN WdblIsDebugApiReady(void) {
    return (WdblResolveDebugApis() & WDBL_DEBUG_API_REQUIRED) == WDBL_DEBUG_API_REQUIRED ? TRUE : FALSE;
}

static VOID WdblCloseDebugSessionLocked(void) {
    if (g_WdblDebugObjectHandle != NULL) {
        ZwClose(g_WdblDebugObjectHandle);
    }
    g_WdblDebugObjectHandle = NULL;
    g_WdblDebugProcessId = 0;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleDebugActiveProcess(PIRP irp, PIO_STACK_LOCATION stack) {
    WDBL_DEBUG_ACTIVE_PROCESS_REQUEST request;
    OBJECT_ATTRIBUTES attributes;
    HANDLE processHandle = NULL;
    HANDLE debugObjectHandle = NULL;
    NTSTATUS status;

    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_DEBUG_ACTIVE_PROCESS_REQUEST) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    request = *(WDBL_DEBUG_ACTIVE_PROCESS_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!WdblIsDebugApiReady()) {
        return STATUS_NOT_SUPPORTED;
    }

    ExAcquireFastMutex(&g_WdblDebugSessionLock);
    if (g_WdblDebugObjectHandle != NULL) {
        ExReleaseFastMutex(&g_WdblDebugSessionLock);
        return STATUS_DEVICE_BUSY;
    }
    ExReleaseFastMutex(&g_WdblDebugSessionLock);

    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = g_WdblZwCreateDebugObject(&debugObjectHandle, DEBUG_OBJECT_ALL_ACCESS, &attributes, 0);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdblOpenProcessHandle(request.ProcessId, PROCESS_ALL_ACCESS, &processHandle);
    if (NT_SUCCESS(status)) {
        status = g_WdblZwDebugActiveProcess(processHandle, debugObjectHandle);
        ZwClose(processHandle);
    }

    if (!NT_SUCCESS(status)) {
        ZwClose(debugObjectHandle);
        return status;
    }

    ExAcquireFastMutex(&g_WdblDebugSessionLock);
    if (g_WdblDebugObjectHandle != NULL) {
        ExReleaseFastMutex(&g_WdblDebugSessionLock);
        ZwClose(debugObjectHandle);
        return STATUS_DEVICE_BUSY;
    }
    g_WdblDebugObjectHandle = debugObjectHandle;
    g_WdblDebugProcessId = request.ProcessId;
    ExReleaseFastMutex(&g_WdblDebugSessionLock);

    irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleDebugActiveProcessStop(PIRP irp, PIO_STACK_LOCATION stack) {
    WDBL_DEBUG_ACTIVE_PROCESS_STOP_REQUEST request;
    HANDLE debugObjectHandle;
    HANDLE processHandle = NULL;
    NTSTATUS status;

    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_DEBUG_ACTIVE_PROCESS_STOP_REQUEST) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    request = *(WDBL_DEBUG_ACTIVE_PROCESS_STOP_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!WdblIsDebugApiReady()) {
        return STATUS_NOT_SUPPORTED;
    }

    ExAcquireFastMutex(&g_WdblDebugSessionLock);
    debugObjectHandle = g_WdblDebugObjectHandle;
    if (debugObjectHandle == NULL || g_WdblDebugProcessId != request.ProcessId) {
        ExReleaseFastMutex(&g_WdblDebugSessionLock);
        return STATUS_NOT_FOUND;
    }
    ExReleaseFastMutex(&g_WdblDebugSessionLock);

    status = WdblOpenProcessHandle(request.ProcessId, PROCESS_ALL_ACCESS, &processHandle);
    if (NT_SUCCESS(status)) {
        status = g_WdblZwRemoveProcessDebug(processHandle, debugObjectHandle);
        ZwClose(processHandle);
    }

    ExAcquireFastMutex(&g_WdblDebugSessionLock);
    if (g_WdblDebugObjectHandle == debugObjectHandle) {
        WdblCloseDebugSessionLocked();
    }
    ExReleaseFastMutex(&g_WdblDebugSessionLock);

    irp->IoStatus.Information = 0;
    return status;
}

static VOID WdblCopyExceptionRecordResult(WDBL_DEBUG_EVENT_RESULT* result, const EXCEPTION_RECORD* record) {
    ULONG i;

    result->ExceptionCode = record->ExceptionCode;
    result->ExceptionFlags = record->ExceptionFlags;
    result->ExceptionRecord = (ULONGLONG)(ULONG_PTR)record->ExceptionRecord;
    result->ExceptionAddress = (ULONGLONG)(ULONG_PTR)record->ExceptionAddress;
    result->NumberParameters = record->NumberParameters;
    if (result->NumberParameters > 15) {
        result->NumberParameters = 15;
    }
    for (i = 0; i < result->NumberParameters; ++i) {
        result->ExceptionInformation[i] = (ULONGLONG)record->ExceptionInformation[i];
    }
}

static VOID WdblMapDebugEventResult(
    const WDBL_DBGUI_WAIT_STATE_CHANGE* stateChange,
    WDBL_DEBUG_EVENT_RESULT* result) {
    RtlZeroMemory(result, sizeof(*result));
    result->ProcessId = (ULONG)(ULONG_PTR)stateChange->AppClientId.UniqueProcess;
    result->ThreadId = (ULONG)(ULONG_PTR)stateChange->AppClientId.UniqueThread;

    switch (stateChange->NewState) {
        case WdblDbgCreateThreadStateChange:
            result->DebugEventCode = CREATE_THREAD_DEBUG_EVENT;
            result->StartAddress = (ULONGLONG)(ULONG_PTR)stateChange->StateInfo.CreateThread.StartAddress;
            break;

        case WdblDbgCreateProcessStateChange:
            result->DebugEventCode = CREATE_PROCESS_DEBUG_EVENT;
            result->BaseOfImage = (ULONGLONG)(ULONG_PTR)stateChange->StateInfo.CreateProcessInfo.BaseOfImage;
            result->DebugInfoFileOffset = stateChange->StateInfo.CreateProcessInfo.DebugInfoFileOffset;
            result->DebugInfoSize = stateChange->StateInfo.CreateProcessInfo.DebugInfoSize;
            result->StartAddress =
                (ULONGLONG)(ULONG_PTR)stateChange->StateInfo.CreateProcessInfo.InitialThread.StartAddress;
            break;

        case WdblDbgExitThreadStateChange:
            result->DebugEventCode = EXIT_THREAD_DEBUG_EVENT;
            result->ExitCode = (ULONG)stateChange->StateInfo.ExitThread.ExitStatus;
            break;

        case WdblDbgExitProcessStateChange:
            result->DebugEventCode = EXIT_PROCESS_DEBUG_EVENT;
            result->ExitCode = (ULONG)stateChange->StateInfo.ExitProcess.ExitStatus;
            break;

        case WdblDbgExceptionStateChange:
        case WdblDbgBreakpointStateChange:
        case WdblDbgSingleStepStateChange:
            result->DebugEventCode = EXCEPTION_DEBUG_EVENT;
            result->FirstChance = stateChange->StateInfo.Exception.FirstChance;
            WdblCopyExceptionRecordResult(result, &stateChange->StateInfo.Exception.ExceptionRecord);
            break;

        case WdblDbgLoadDllStateChange:
            result->DebugEventCode = LOAD_DLL_DEBUG_EVENT;
            result->BaseOfDll = (ULONGLONG)(ULONG_PTR)stateChange->StateInfo.LoadDll.BaseOfDll;
            result->DebugInfoFileOffset = stateChange->StateInfo.LoadDll.DebugInfoFileOffset;
            result->DebugInfoSize = stateChange->StateInfo.LoadDll.DebugInfoSize;
            result->NamePointer = (ULONGLONG)(ULONG_PTR)stateChange->StateInfo.LoadDll.NamePointer;
            break;

        case WdblDbgUnloadDllStateChange:
            result->DebugEventCode = UNLOAD_DLL_DEBUG_EVENT;
            result->UnloadBaseOfDll = (ULONGLONG)(ULONG_PTR)stateChange->StateInfo.UnloadDll.BaseAddress;
            break;

        default:
            result->DebugEventCode = 0;
            break;
    }
}

_Use_decl_annotations_
static NTSTATUS WdblHandleWaitForDebugEvent(PIRP irp, PIO_STACK_LOCATION stack) {
    WDBL_WAIT_FOR_DEBUG_EVENT_REQUEST request;
    WDBL_DBGUI_WAIT_STATE_CHANGE stateChange;
    WDBL_DEBUG_EVENT_RESULT* result;
    HANDLE debugObjectHandle;
    LARGE_INTEGER timeout;
    PLARGE_INTEGER timeoutPointer = NULL;
    NTSTATUS status;

    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_WAIT_FOR_DEBUG_EVENT_REQUEST) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_DEBUG_EVENT_RESULT) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    request = *(WDBL_WAIT_FOR_DEBUG_EVENT_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (!WdblIsDebugApiReady()) {
        return STATUS_NOT_SUPPORTED;
    }

    ExAcquireFastMutex(&g_WdblDebugSessionLock);
    debugObjectHandle = g_WdblDebugObjectHandle;
    ExReleaseFastMutex(&g_WdblDebugSessionLock);
    if (debugObjectHandle == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (request.TimeoutMilliseconds != 0xFFFFFFFFUL) {
        if (request.TimeoutMilliseconds == 0) {
            timeout.QuadPart = 0;
        } else {
            timeout.QuadPart = -((LONGLONG)request.TimeoutMilliseconds * 10000LL);
        }
        timeoutPointer = &timeout;
    }

    RtlZeroMemory(&stateChange, sizeof(stateChange));
    status = g_WdblZwWaitForDebugEvent(debugObjectHandle, FALSE, timeoutPointer, &stateChange);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    result = (WDBL_DEBUG_EVENT_RESULT*)irp->AssociatedIrp.SystemBuffer;
    WdblMapDebugEventResult(&stateChange, result);
    if (result->DebugEventCode == 0) {
        return STATUS_NOT_SUPPORTED;
    }

    irp->IoStatus.Information = sizeof(*result);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleContinueDebugEvent(PIRP irp, PIO_STACK_LOCATION stack) {
    WDBL_CONTINUE_DEBUG_EVENT_REQUEST request;
    CLIENT_ID clientId;
    HANDLE debugObjectHandle;
    NTSTATUS status;

    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_CONTINUE_DEBUG_EVENT_REQUEST) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    request = *(WDBL_CONTINUE_DEBUG_EVENT_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.ProcessId == 0 || request.ThreadId == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!WdblIsDebugApiReady()) {
        return STATUS_NOT_SUPPORTED;
    }

    ExAcquireFastMutex(&g_WdblDebugSessionLock);
    debugObjectHandle = g_WdblDebugObjectHandle;
    ExReleaseFastMutex(&g_WdblDebugSessionLock);
    if (debugObjectHandle == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)request.ProcessId;
    clientId.UniqueThread = (HANDLE)(ULONG_PTR)request.ThreadId;
    status = g_WdblZwDebugContinue(debugObjectHandle, &clientId, (NTSTATUS)request.ContinueStatus);
    irp->IoStatus.Information = 0;
    return status;
}
#else
static VOID WdblCloseDebugSessionLocked(void) {
}

_Use_decl_annotations_
static NTSTATUS WdblHandleDebugActiveProcess(PIRP irp, PIO_STACK_LOCATION stack) {
    UNREFERENCED_PARAMETER(irp);
    UNREFERENCED_PARAMETER(stack);
    return STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleDebugActiveProcessStop(PIRP irp, PIO_STACK_LOCATION stack) {
    UNREFERENCED_PARAMETER(irp);
    UNREFERENCED_PARAMETER(stack);
    return STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleWaitForDebugEvent(PIRP irp, PIO_STACK_LOCATION stack) {
    UNREFERENCED_PARAMETER(irp);
    UNREFERENCED_PARAMETER(stack);
    return STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleContinueDebugEvent(PIRP irp, PIO_STACK_LOCATION stack) {
    UNREFERENCED_PARAMETER(irp);
    UNREFERENCED_PARAMETER(stack);
    return STATUS_NOT_SUPPORTED;
}
#endif

_Use_decl_annotations_
static NTSTATUS WdblOpenThreadHandle(ULONG threadId, ACCESS_MASK desiredAccess, PHANDLE threadHandle) {
    OBJECT_ATTRIBUTES attributes;
    CLIENT_ID clientId;

    WdblResolveRuntimeApis();
    if (g_WdblZwOpenThread == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = NULL;
    clientId.UniqueThread = (HANDLE)(ULONG_PTR)threadId;
    return g_WdblZwOpenThread(threadHandle, desiredAccess, &attributes, &clientId);
}

static VOID WdblDereferenceObject(PVOID object) {
    WdblResolveRuntimeApis();
    if (g_WdblObfDereferenceObject != NULL && object != NULL) {
        g_WdblObfDereferenceObject(object);
    }
}

_Use_decl_annotations_
static NTSTATUS WdblLookupProcess(ULONG processId, PEPROCESS* process) {
    WdblResolveRuntimeApis();
    if (g_WdblPsLookupProcessByProcessId == NULL) {
        return STATUS_NOT_SUPPORTED;
    }
    return g_WdblPsLookupProcessByProcessId((HANDLE)(ULONG_PTR)processId, process);
}

_Use_decl_annotations_
static NTSTATUS WdblOpenProcessHandle(ULONG processId, ACCESS_MASK desiredAccess, PHANDLE processHandle) {
    OBJECT_ATTRIBUTES attributes;
    CLIENT_ID clientId;

    WdblResolveRuntimeApis();
    if (g_WdblZwOpenProcess == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)processId;
    clientId.UniqueThread = NULL;
    return g_WdblZwOpenProcess(processHandle, desiredAccess, &attributes, &clientId);
}

_Use_decl_annotations_
static NTSTATUS WdblDecodeIoctlInput(PIRP irp, PIO_STACK_LOCATION stack, ULONG ioControlCode) {
    UCHAR* buffer = (UCHAR*)irp->AssociatedIrp.SystemBuffer;
    ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    WDBL_IOCTL_PACKET_HEADER* header;
    UCHAR* payload;

    if (buffer == NULL || inputLength < sizeof(WDBL_IOCTL_PACKET_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }

    header = (WDBL_IOCTL_PACKET_HEADER*)buffer;
    if (header->Magic != WDBL_IOCTL_PROTOCOL_MAGIC ||
        header->Version != WDBL_IOCTL_PROTOCOL_VERSION ||
        header->HeaderSize != sizeof(WDBL_IOCTL_PACKET_HEADER) ||
        header->IoControlCode != ioControlCode ||
        header->HeaderChecksum != WdblIoctlHeaderChecksum(header)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (header->PayloadSize > inputLength - header->HeaderSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    payload = buffer + header->HeaderSize;
    WdblIoctlCryptPayload(payload, header->PayloadSize, ioControlCode);
    if (WdblIoctlPayloadChecksum(payload, header->PayloadSize) != header->PayloadChecksum) {
        RtlZeroMemory(payload, header->PayloadSize);
        return STATUS_DATA_ERROR;
    }

    RtlMoveMemory(buffer, payload, header->PayloadSize);
    stack->Parameters.DeviceIoControl.InputBufferLength = header->PayloadSize;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleReadProcessMemory(PIRP irp, PIO_STACK_LOCATION stack) {
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_PROCESS_MEMORY_READ_REQUEST) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    const WDBL_PROCESS_MEMORY_READ_REQUEST request =
        *(WDBL_PROCESS_MEMORY_READ_REQUEST*)irp->AssociatedIrp.SystemBuffer;

    if (request.Size == 0) {
        irp->IoStatus.Information = 0;
        return STATUS_SUCCESS;
    }
    if (stack->Parameters.DeviceIoControl.OutputBufferLength < request.Size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PEPROCESS sourceProcess = NULL;
    NTSTATUS status = WdblLookupProcess(request.ProcessId, &sourceProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WdblResolveRuntimeApis();
    if (g_WdblMmCopyVirtualMemory == NULL) {
        WdblDereferenceObject(sourceProcess);
        return STATUS_NOT_SUPPORTED;
    }

    SIZE_T copied = 0;
    status = g_WdblMmCopyVirtualMemory(
        sourceProcess,
        (PVOID)(ULONG_PTR)request.Address,
        PsGetCurrentProcess(),
        irp->AssociatedIrp.SystemBuffer,
        (SIZE_T)request.Size,
        KernelMode,
        &copied);
    WdblDereferenceObject(sourceProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    irp->IoStatus.Information = copied;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleWriteProcessMemory(PIRP irp, PIO_STACK_LOCATION stack) {
    if (irp->AssociatedIrp.SystemBuffer == NULL ||
        stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_PROCESS_MEMORY_WRITE_REQUEST_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    const UCHAR* buffer = (const UCHAR*)irp->AssociatedIrp.SystemBuffer;
    const WDBL_PROCESS_MEMORY_WRITE_REQUEST_HEADER* request =
        (const WDBL_PROCESS_MEMORY_WRITE_REQUEST_HEADER*)buffer;
    const ULONG headerSize = (ULONG)sizeof(WDBL_PROCESS_MEMORY_WRITE_REQUEST_HEADER);

    if (request->Size > stack->Parameters.DeviceIoControl.InputBufferLength - headerSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ULONG)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request->Size == 0) {
        *(ULONG*)irp->AssociatedIrp.SystemBuffer = 0;
        irp->IoStatus.Information = sizeof(ULONG);
        return STATUS_SUCCESS;
    }

    PEPROCESS targetProcess = NULL;
    NTSTATUS status = WdblLookupProcess(request->ProcessId, &targetProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WdblResolveRuntimeApis();
    if (g_WdblMmCopyVirtualMemory == NULL) {
        WdblDereferenceObject(targetProcess);
        return STATUS_NOT_SUPPORTED;
    }

    SIZE_T copied = 0;
    status = g_WdblMmCopyVirtualMemory(
        PsGetCurrentProcess(),
        (PVOID)(buffer + headerSize),
        targetProcess,
        (PVOID)(ULONG_PTR)request->Address,
        (SIZE_T)request->Size,
        KernelMode,
        &copied);
    WdblDereferenceObject(targetProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *(ULONG*)irp->AssociatedIrp.SystemBuffer = (ULONG)copied;
    irp->IoStatus.Information = sizeof(ULONG);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleGetThreadContext(PIRP irp, PIO_STACK_LOCATION stack) {
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_THREAD_CONTEXT_REQUEST) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(CONTEXT) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    WDBL_THREAD_CONTEXT_REQUEST* request = (WDBL_THREAD_CONTEXT_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    CONTEXT* context = (CONTEXT*)irp->AssociatedIrp.SystemBuffer;
    HANDLE threadHandle = NULL;

    NTSTATUS status = WdblOpenThreadHandle(
        request->ThreadId,
        THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
        &threadHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(context, sizeof(*context));
    context->ContextFlags = request->ContextFlags;
    WDBL_ZW_GET_CONTEXT_THREAD getContext =
        (WDBL_ZW_GET_CONTEXT_THREAD)WdblResolveKernelRoutineXor(g_Obf_ZwGetContextThread, sizeof(g_Obf_ZwGetContextThread) / sizeof(g_Obf_ZwGetContextThread[0]));
    if (getContext == NULL) {
        ZwClose(threadHandle);
        return STATUS_NOT_SUPPORTED;
    }

    status = getContext(threadHandle, context);
    ZwClose(threadHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    irp->IoStatus.Information = sizeof(*context);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleSetThreadContext(PIRP irp, PIO_STACK_LOCATION stack) {
    const ULONG minInput = sizeof(WDBL_THREAD_CONTEXT_REQUEST) + sizeof(CONTEXT);
    if (stack->Parameters.DeviceIoControl.InputBufferLength < minInput ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    UCHAR* buffer = (UCHAR*)irp->AssociatedIrp.SystemBuffer;
    WDBL_THREAD_CONTEXT_REQUEST* request = (WDBL_THREAD_CONTEXT_REQUEST*)buffer;
    CONTEXT* context = (CONTEXT*)(buffer + sizeof(WDBL_THREAD_CONTEXT_REQUEST));
    HANDLE threadHandle = NULL;

    // ContextFlags from request is authoritative for the driver contract.
    context->ContextFlags = request->ContextFlags;

    NTSTATUS status = WdblOpenThreadHandle(
        request->ThreadId,
        THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
        &threadHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDBL_ZW_SET_CONTEXT_THREAD setContext =
        (WDBL_ZW_SET_CONTEXT_THREAD)WdblResolveKernelRoutineXor(g_Obf_ZwSetContextThread, sizeof(g_Obf_ZwSetContextThread) / sizeof(g_Obf_ZwSetContextThread[0]));
    if (setContext == NULL) {
        ZwClose(threadHandle);
        return STATUS_NOT_SUPPORTED;
    }

    status = setContext(threadHandle, context);
    ZwClose(threadHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleGetWow64ThreadContext(PIRP irp, PIO_STACK_LOCATION stack) {
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_WOW64_THREAD_CONTEXT_REQUEST) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_WOW64_CONTEXT) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    WDBL_WOW64_THREAD_CONTEXT_REQUEST request =
        *(WDBL_WOW64_THREAD_CONTEXT_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.ThreadId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    HANDLE threadHandle = NULL;
    NTSTATUS status = WdblOpenThreadHandle(
        request.ThreadId,
        THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
        &threadHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (g_WdblZwQueryInformationThread == NULL) {
        ZwClose(threadHandle);
        return STATUS_NOT_SUPPORTED;
    }

    WDBL_WOW64_CONTEXT* context = (WDBL_WOW64_CONTEXT*)irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(context, sizeof(*context));
    context->ContextFlags = request.ContextFlags;

    status = g_WdblZwQueryInformationThread(threadHandle, ThreadWow64Context, context, sizeof(*context), NULL);
    ZwClose(threadHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    irp->IoStatus.Information = sizeof(*context);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleSetWow64ThreadContext(PIRP irp, PIO_STACK_LOCATION stack) {
    const ULONG minInput = sizeof(WDBL_WOW64_THREAD_CONTEXT_REQUEST) + sizeof(WDBL_WOW64_CONTEXT);
    if (stack->Parameters.DeviceIoControl.InputBufferLength < minInput ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    UCHAR* buffer = (UCHAR*)irp->AssociatedIrp.SystemBuffer;
    WDBL_WOW64_THREAD_CONTEXT_REQUEST* request = (WDBL_WOW64_THREAD_CONTEXT_REQUEST*)buffer;
    WDBL_WOW64_CONTEXT* context = (WDBL_WOW64_CONTEXT*)(buffer + sizeof(WDBL_WOW64_THREAD_CONTEXT_REQUEST));
    if (request->ThreadId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    context->ContextFlags = request->ContextFlags;

    HANDLE threadHandle = NULL;
    NTSTATUS status = WdblOpenThreadHandle(
        request->ThreadId,
        THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
        &threadHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDBL_ZW_SET_INFORMATION_THREAD setThread =
        (WDBL_ZW_SET_INFORMATION_THREAD)WdblResolveKernelRoutineXor(g_Obf_ZwSetInformationThread, sizeof(g_Obf_ZwSetInformationThread) / sizeof(g_Obf_ZwSetInformationThread[0]));
    if (setThread == NULL) {
        ZwClose(threadHandle);
        return STATUS_NOT_SUPPORTED;
    }

    status = setThread(threadHandle, ThreadWow64Context, context, sizeof(*context));
    ZwClose(threadHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleQueryVirtualMemory(PIRP irp, PIO_STACK_LOCATION stack) {
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_VIRTUAL_MEMORY_QUERY_REQUEST) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MEMORY_BASIC_INFORMATION) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    const WDBL_VIRTUAL_MEMORY_QUERY_REQUEST request =
        *(WDBL_VIRTUAL_MEMORY_QUERY_REQUEST*)irp->AssociatedIrp.SystemBuffer;

    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES attributes;
    CLIENT_ID clientId;
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)request.ProcessId;
    clientId.UniqueThread = NULL;

    WdblResolveRuntimeApis();
    if (g_WdblZwOpenProcess == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS status = g_WdblZwOpenProcess(&processHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &attributes, &clientId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    SIZE_T returned = 0;
    WdblResolveRuntimeApis();
    if (g_WdblZwQueryVirtualMemory == NULL) {
        ZwClose(processHandle);
        return STATUS_NOT_SUPPORTED;
    }

    status = g_WdblZwQueryVirtualMemory(
        processHandle,
        (PVOID)(ULONG_PTR)request.Address,
        MemoryBasicInformation,
        irp->AssociatedIrp.SystemBuffer,
        sizeof(MEMORY_BASIC_INFORMATION),
        &returned);
    ZwClose(processHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    irp->IoStatus.Information = returned;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleProtectVirtualMemory(
    PIRP irp, 
    PIO_STACK_LOCATION stack) {
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_VIRTUAL_MEMORY_PROTECT_REQUEST) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_VIRTUAL_MEMORY_PROTECT_RESULT) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    const WDBL_VIRTUAL_MEMORY_PROTECT_REQUEST request =
        *(WDBL_VIRTUAL_MEMORY_PROTECT_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES attributes;
    CLIENT_ID clientId;
    InitializeObjectAttributes(
        &attributes, 
        NULL, 
        OBJ_KERNEL_HANDLE, 
        NULL,
        NULL);
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)request.ProcessId;
    clientId.UniqueThread = NULL;

    WdblResolveRuntimeApis();
    if (g_WdblZwOpenProcess == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS status = g_WdblZwOpenProcess(
        &processHandle,
        PROCESS_VM_OPERATION, 
        &attributes,
        &clientId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PVOID baseAddress = (PVOID)(ULONG_PTR)request.Address;
    SIZE_T regionSize = (SIZE_T)request.Size;
    ULONG oldProtect = 0;
    WdblResolveRuntimeApis();
    if (g_WdblZwProtectVirtualMemory == NULL) {
        ZwClose(processHandle);
        return STATUS_NOT_SUPPORTED;
    }

    status = g_WdblZwProtectVirtualMemory(processHandle, &baseAddress, &regionSize, request.NewProtect, &oldProtect);
    ZwClose(processHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDBL_VIRTUAL_MEMORY_PROTECT_RESULT* result =
        (WDBL_VIRTUAL_MEMORY_PROTECT_RESULT*)irp->AssociatedIrp.SystemBuffer;
    result->OldProtect = oldProtect;
    {
        WDBL_DRIVER_EVENT_ENTRY event;
        RtlZeroMemory(&event, sizeof(event));
        event.Type = WDBL_DRIVER_EVENT_MEMORY_PROTECT;
        event.Flags = request.NewProtect;
        event.ProcessId = request.ProcessId;
        event.Address = request.Address;
        event.Size = request.Size;
        event.Status = oldProtect;
        WdblQueueDriverEvent(&event);
    }
    irp->IoStatus.Information = sizeof(*result);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleAllocateVirtualMemory(PIRP irp, PIO_STACK_LOCATION stack) {
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_VIRTUAL_MEMORY_ALLOCATE_REQUEST) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_VIRTUAL_MEMORY_ALLOCATE_RESULT) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    const WDBL_VIRTUAL_MEMORY_ALLOCATE_REQUEST request =
        *(WDBL_VIRTUAL_MEMORY_ALLOCATE_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES attributes;
    CLIENT_ID clientId;
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)request.ProcessId;
    clientId.UniqueThread = NULL;

    WdblResolveRuntimeApis();
    if (g_WdblZwOpenProcess == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS status = g_WdblZwOpenProcess(&processHandle, PROCESS_VM_OPERATION, &attributes, &clientId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PVOID baseAddress = (PVOID)(ULONG_PTR)request.BaseAddress;
    SIZE_T regionSize = (SIZE_T)request.Size;
    WdblResolveRuntimeApis();
    if (g_WdblZwAllocateVirtualMemory == NULL) {
        ZwClose(processHandle);
        return STATUS_NOT_SUPPORTED;
    }

    status = g_WdblZwAllocateVirtualMemory(processHandle, &baseAddress, 0, &regionSize, request.AllocationType, request.Protect);
    ZwClose(processHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDBL_VIRTUAL_MEMORY_ALLOCATE_RESULT* result =
        (WDBL_VIRTUAL_MEMORY_ALLOCATE_RESULT*)irp->AssociatedIrp.SystemBuffer;
    result->BaseAddress = (ULONGLONG)(ULONG_PTR)baseAddress;
    result->Size = (ULONGLONG)regionSize;
    irp->IoStatus.Information = sizeof(*result);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleFreeVirtualMemory(PIRP irp, PIO_STACK_LOCATION stack) {
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_VIRTUAL_MEMORY_FREE_REQUEST) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    const WDBL_VIRTUAL_MEMORY_FREE_REQUEST request =
        *(WDBL_VIRTUAL_MEMORY_FREE_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.BaseAddress == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES attributes;
    CLIENT_ID clientId;
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)request.ProcessId;
    clientId.UniqueThread = NULL;

    WdblResolveRuntimeApis();
    if (g_WdblZwOpenProcess == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS status = g_WdblZwOpenProcess(&processHandle, PROCESS_VM_OPERATION, &attributes, &clientId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PVOID baseAddress = (PVOID)(ULONG_PTR)request.BaseAddress;
    SIZE_T regionSize = (SIZE_T)request.Size;
    WdblResolveRuntimeApis();
    if (g_WdblZwFreeVirtualMemory == NULL) {
        ZwClose(processHandle);
        return STATUS_NOT_SUPPORTED;
    }

    status = g_WdblZwFreeVirtualMemory(processHandle, &baseAddress, &regionSize, request.FreeType);
    ZwClose(processHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleCreateUserThread(PIRP irp, PIO_STACK_LOCATION stack) {
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_CREATE_USER_THREAD_REQUEST) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_CREATE_USER_THREAD_RESULT) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    const WDBL_CREATE_USER_THREAD_REQUEST request =
        *(WDBL_CREATE_USER_THREAD_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.ProcessId == 0 || request.StartAddress == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    WdblResolveRuntimeApis();
    if (g_WdblZwCreateThreadEx == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES processAttributes;
    CLIENT_ID processClientId;
    InitializeObjectAttributes(&processAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    processClientId.UniqueProcess = (HANDLE)(ULONG_PTR)request.ProcessId;
    processClientId.UniqueThread = NULL;

    WdblResolveRuntimeApis();
    if (g_WdblZwOpenProcess == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS status = g_WdblZwOpenProcess(
        &processHandle,
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        &processAttributes,
        &processClientId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    HANDLE threadHandle = NULL;
    OBJECT_ATTRIBUTES threadAttributes;
    InitializeObjectAttributes(&threadAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = g_WdblZwCreateThreadEx(
        &threadHandle,
        THREAD_QUERY_INFORMATION | SYNCHRONIZE,
        &threadAttributes,
        processHandle,
        (PVOID)(ULONG_PTR)request.StartAddress,
        (PVOID)(ULONG_PTR)request.Parameter,
        request.CreateFlags,
        0,
        (SIZE_T)request.StackSize,
        (SIZE_T)request.MaximumStackSize,
        NULL);
    ZwClose(processHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDBL_CREATE_USER_THREAD_RESULT* result =
        (WDBL_CREATE_USER_THREAD_RESULT*)irp->AssociatedIrp.SystemBuffer;
    result->ThreadId = 0;

    if (g_WdblZwQueryInformationThread != NULL) {
        WDBL_THREAD_BASIC_INFORMATION basicInfo;
        RtlZeroMemory(&basicInfo, sizeof(basicInfo));
        if (NT_SUCCESS(g_WdblZwQueryInformationThread(threadHandle, 0, &basicInfo, sizeof(basicInfo), NULL))) {
            result->ThreadId = (ULONG)(ULONG_PTR)basicInfo.ClientId.UniqueThread;
        }
    }

    {
        WDBL_DRIVER_EVENT_ENTRY event;
        RtlZeroMemory(&event, sizeof(event));
        event.Type = WDBL_DRIVER_EVENT_REMOTE_THREAD;
        event.Flags = request.CreateFlags;
        event.ProcessId = request.ProcessId;
        event.ThreadId = result->ThreadId;
        event.Address = request.StartAddress;
        event.Size = request.Parameter;
        WdblQueueDriverEvent(&event);
    }

    ZwClose(threadHandle);
    irp->IoStatus.Information = sizeof(*result);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleThreadControl(PIRP irp, PIO_STACK_LOCATION stack, BOOLEAN suspend) {
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_THREAD_CONTROL_REQUEST) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_THREAD_CONTROL_RESULT) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    const WDBL_THREAD_CONTROL_REQUEST request =
        *(WDBL_THREAD_CONTROL_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.ThreadId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    HANDLE threadHandle = NULL;
    NTSTATUS status = WdblOpenThreadHandle(
        request.ThreadId,
        THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
        &threadHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ULONG previousSuspendCount = 0;
    if (suspend) {
        if (g_WdblZwSuspendThread == NULL) {
            ZwClose(threadHandle);
            return STATUS_NOT_SUPPORTED;
        }
        status = g_WdblZwSuspendThread(threadHandle, &previousSuspendCount);
    } else {
        if (g_WdblZwResumeThread == NULL) {
            ZwClose(threadHandle);
            return STATUS_NOT_SUPPORTED;
        }
        status = g_WdblZwResumeThread(threadHandle, &previousSuspendCount);
    }
    ZwClose(threadHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDBL_THREAD_CONTROL_RESULT* result =
        (WDBL_THREAD_CONTROL_RESULT*)irp->AssociatedIrp.SystemBuffer;
    result->PreviousSuspendCount = previousSuspendCount;
    irp->IoStatus.Information = sizeof(*result);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleProcessControl(PIRP irp, PIO_STACK_LOCATION stack, ULONG ioControlCode) {
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_PROCESS_CONTROL_REQUEST) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    const WDBL_PROCESS_CONTROL_REQUEST request =
        *(WDBL_PROCESS_CONTROL_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ACCESS_MASK desiredAccess = PROCESS_QUERY_INFORMATION;
    if (ioControlCode == IOCTL_WDBL_TERMINATE_PROCESS) {
        desiredAccess |= PROCESS_TERMINATE;
    } else {
        desiredAccess |= PROCESS_SUSPEND_RESUME;
    }

    HANDLE processHandle = NULL;
    NTSTATUS status = WdblOpenProcessHandle(request.ProcessId, desiredAccess, &processHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (ioControlCode == IOCTL_WDBL_SUSPEND_PROCESS) {
        if (g_WdblZwSuspendProcess == NULL) {
            ZwClose(processHandle);
            return STATUS_NOT_SUPPORTED;
        }
        status = g_WdblZwSuspendProcess(processHandle);
    } else if (ioControlCode == IOCTL_WDBL_RESUME_PROCESS) {
        if (g_WdblZwResumeProcess == NULL) {
            ZwClose(processHandle);
            return STATUS_NOT_SUPPORTED;
        }
        status = g_WdblZwResumeProcess(processHandle);
    } else {
        if (g_WdblZwTerminateProcess == NULL) {
            ZwClose(processHandle);
            return STATUS_NOT_SUPPORTED;
        }
        status = g_WdblZwTerminateProcess(processHandle, (NTSTATUS)request.ExitStatus);
    }

    ZwClose(processHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleOpenProcessKernelHandle(PIRP irp, PIO_STACK_LOCATION stack) {
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_OPEN_PROCESS_KERNEL_HANDLE_REQUEST) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_OPEN_PROCESS_KERNEL_HANDLE_RESULT) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    const WDBL_OPEN_PROCESS_KERNEL_HANDLE_REQUEST request =
        *(WDBL_OPEN_PROCESS_KERNEL_HANDLE_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.ProcessId == 0 || request.DesiredAccess == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    OBJECT_ATTRIBUTES attributes;
    CLIENT_ID clientId;
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)request.ProcessId;
    clientId.UniqueThread = NULL;

    HANDLE processHandle = NULL;
    WdblResolveRuntimeApis();
    if (g_WdblZwOpenProcess == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS status = g_WdblZwOpenProcess(&processHandle, request.DesiredAccess, &attributes, &clientId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDBL_OPEN_PROCESS_KERNEL_HANDLE_RESULT* result =
        (WDBL_OPEN_PROCESS_KERNEL_HANDLE_RESULT*)irp->AssociatedIrp.SystemBuffer;
    result->KernelHandle = (ULONGLONG)(ULONG_PTR)processHandle;
    irp->IoStatus.Information = sizeof(*result);
    return STATUS_SUCCESS;
}

typedef struct _WDBL_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} WDBL_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL;

typedef struct _WDBL_SYSTEM_HANDLE_INFORMATION_EX_LOCAL {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    WDBL_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL Handles[1];
} WDBL_SYSTEM_HANDLE_INFORMATION_EX_LOCAL;

typedef struct _WDBL_OBJECT_NAME_INFORMATION_LOCAL {
    UNICODE_STRING Name;
    WCHAR Buffer[1];
} WDBL_OBJECT_NAME_INFORMATION_LOCAL;

static VOID WdblQueryObjectName(PVOID object, WCHAR* output, ULONG outputChars) {
    PVOID nameBuffer;
    ULONG nameBufferSize = 0x400;
    ULONG returnedLength = 0;
    NTSTATUS status;

    if (output == NULL || outputChars == 0) {
        return;
    }
    output[0] = L'\0';
    if (object == NULL || g_WdblObQueryNameString == NULL) {
        return;
    }

    for (;;) {
        nameBuffer = ExAllocatePoolWithTag(NonPagedPool, nameBufferSize, 'WbLN');
        if (nameBuffer == NULL) {
            return;
        }
        status = g_WdblObQueryNameString(object, nameBuffer, nameBufferSize, &returnedLength);
        if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL) {
            break;
        }
        ExFreePool(nameBuffer);
        nameBuffer = NULL;
        if (returnedLength > nameBufferSize) {
            nameBufferSize = returnedLength + 0x100;
        } else {
            nameBufferSize *= 2;
        }
        if (nameBufferSize > 0x10000) {
            return;
        }
    }

    if (NT_SUCCESS(status)) {
        WDBL_OBJECT_NAME_INFORMATION_LOCAL* nameInfo =
            (WDBL_OBJECT_NAME_INFORMATION_LOCAL*)nameBuffer;
        ULONG copyBytes = nameInfo->Name.Length;
        ULONG maxBytes = (outputChars - 1) * sizeof(WCHAR);
        ULONG_PTR bufferStart = (ULONG_PTR)nameBuffer;
        ULONG_PTR bufferEnd = bufferStart + nameBufferSize;
        ULONG_PTR nameStart = (ULONG_PTR)nameInfo->Name.Buffer;
        if (copyBytes > maxBytes) {
            copyBytes = maxBytes;
        }
        copyBytes &= ~(ULONG)1;
        if (nameStart >= bufferStart && nameStart <= bufferEnd &&
            copyBytes <= bufferEnd - nameStart) {
            RtlCopyMemory(output, (PVOID)nameStart, copyBytes);
            output[copyBytes / sizeof(WCHAR)] = L'\0';
        }
    }
    ExFreePool(nameBuffer);
}

_Use_decl_annotations_
static NTSTATUS WdblHandleQueryHandleList(PIRP irp, PIO_STACK_LOCATION stack) {
    WDBL_HANDLE_ENUM_REQUEST request;
    WDBL_ENUM_RESULT_HEADER* header;
    WDBL_HANDLE_ENUM_ENTRY* entries;
    WDBL_SYSTEM_HANDLE_INFORMATION_EX_LOCAL* systemInfo;
    ULONG systemInfoSize = 0x100000;
    ULONG maxEntries;
    ULONG total = 0;
    ULONG returned = 0;
    ULONG i;
    NTSTATUS status;

    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(request) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_ENUM_RESULT_HEADER) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = *(WDBL_HANDLE_ENUM_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    WdblResolveRuntimeApis();
    if (g_WdblZwQuerySystemInformation == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    systemInfo = NULL;
    for (;;) {
        ULONG returnedLength = 0;
        systemInfo = (WDBL_SYSTEM_HANDLE_INFORMATION_EX_LOCAL*)ExAllocatePoolWithTag(
            NonPagedPool,
            systemInfoSize,
            'WbLH');
        if (systemInfo == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        status = g_WdblZwQuerySystemInformation(
            SystemExtendedHandleInformation,
            systemInfo,
            systemInfoSize,
            &returnedLength);
        if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL) {
            break;
        }
        ExFreePool(systemInfo);
        systemInfo = NULL;
        if (returnedLength > systemInfoSize) {
            systemInfoSize = returnedLength + 0x10000;
        } else {
            systemInfoSize *= 2;
        }
        if (systemInfoSize > 16 * 1024 * 1024) {
            return STATUS_BUFFER_TOO_SMALL;
        }
    }

    if (!NT_SUCCESS(status)) {
        if (systemInfo != NULL) {
            ExFreePool(systemInfo);
        }
        return status;
    }

    maxEntries = (stack->Parameters.DeviceIoControl.OutputBufferLength -
        sizeof(WDBL_ENUM_RESULT_HEADER)) / sizeof(WDBL_HANDLE_ENUM_ENTRY);
    header = (WDBL_ENUM_RESULT_HEADER*)irp->AssociatedIrp.SystemBuffer;
    entries = (WDBL_HANDLE_ENUM_ENTRY*)((UCHAR*)irp->AssociatedIrp.SystemBuffer +
        sizeof(WDBL_ENUM_RESULT_HEADER));

    for (i = 0; i < (ULONG)systemInfo->NumberOfHandles; ++i) {
        const WDBL_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL* source = &systemInfo->Handles[i];
        if ((ULONG)(ULONG_PTR)source->UniqueProcessId != request.ProcessId) {
            continue;
        }
        ++total;
        if (returned >= maxEntries) {
            continue;
        }
        RtlZeroMemory(&entries[returned], sizeof(entries[returned]));
        entries[returned].ObjectAddress = (ULONGLONG)(ULONG_PTR)source->Object;
        entries[returned].HandleValue = (ULONGLONG)source->HandleValue;
        entries[returned].GrantedAccess = source->GrantedAccess;
        entries[returned].ObjectTypeIndex = source->ObjectTypeIndex;
        entries[returned].Attributes = (USHORT)source->HandleAttributes;
        WdblQueryObjectName(source->Object, entries[returned].ObjectName,
            sizeof(entries[returned].ObjectName) / sizeof(entries[returned].ObjectName[0]));
        ++returned;
    }

    ExFreePool(systemInfo);
    header->TotalCount = total;
    header->ReturnedCount = returned;
    irp->IoStatus.Information = sizeof(*header) + returned * sizeof(WDBL_HANDLE_ENUM_ENTRY);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleQueryThreadInfo(PIRP irp, PIO_STACK_LOCATION stack) {
    WDBL_THREAD_INFO_REQUEST request;
    WDBL_THREAD_INFO_RESULT* result;
    WDBL_THREAD_BASIC_INFORMATION basicInfo;
    HANDLE threadHandle = NULL;
    PVOID startAddress = NULL;
    NTSTATUS status;

    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(request) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_THREAD_INFO_RESULT) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = *(WDBL_THREAD_INFO_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.ThreadId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    result = (WDBL_THREAD_INFO_RESULT*)irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(result, sizeof(*result));
    result->ThreadId = request.ThreadId;
    result->BasicInfoStatus = STATUS_NOT_SUPPORTED;
    result->StartAddressStatus = STATUS_NOT_SUPPORTED;

    WdblResolveRuntimeApis();
    if (g_WdblZwQueryInformationThread == NULL) {
        irp->IoStatus.Information = sizeof(*result);
        return STATUS_SUCCESS;
    }

    status = WdblOpenThreadHandle(
        request.ThreadId,
        THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT,
        &threadHandle);
    if (!NT_SUCCESS(status)) {
        result->BasicInfoStatus = status;
        result->StartAddressStatus = status;
        irp->IoStatus.Information = sizeof(*result);
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&basicInfo, sizeof(basicInfo));
    status = g_WdblZwQueryInformationThread(
        threadHandle,
        ThreadBasicInformation,
        &basicInfo,
        sizeof(basicInfo),
        NULL);
    result->BasicInfoStatus = status;
    if (NT_SUCCESS(status)) {
        result->ProcessId = (ULONG)(ULONG_PTR)basicInfo.ClientId.UniqueProcess;
        result->ThreadId = (ULONG)(ULONG_PTR)basicInfo.ClientId.UniqueThread;
        result->TebBaseAddress = (ULONGLONG)(ULONG_PTR)basicInfo.TebBaseAddress;
        result->AffinityMask = (ULONGLONG)(ULONG_PTR)basicInfo.AffinityMask;
        result->Priority = basicInfo.Priority;
        result->BasePriority = basicInfo.BasePriority;
        result->ExitStatus = basicInfo.ExitStatus;
    }

    status = g_WdblZwQueryInformationThread(
        threadHandle,
        ThreadQuerySetWin32StartAddress,
        &startAddress,
        sizeof(startAddress),
        NULL);
    result->StartAddressStatus = status;
    if (NT_SUCCESS(status)) {
        result->StartAddress = (ULONGLONG)(ULONG_PTR)startAddress;
    }

    ZwClose(threadHandle);
    irp->IoStatus.Information = sizeof(*result);
    return STATUS_SUCCESS;
}

static VOID WdblFillModuleEntry32(PEPROCESS process, const WDBL_LDR_DATA_TABLE_ENTRY32_MIN* ldrEntry, WDBL_MODULE_ENUM_ENTRY* entry) {
    RtlZeroMemory(entry, sizeof(*entry));
    entry->BaseAddress = (ULONGLONG)ldrEntry->DllBase;
    entry->EntryPoint = (ULONGLONG)ldrEntry->EntryPoint;
    entry->SizeOfImage = ldrEntry->SizeOfImage;
    WdblCopyRemoteUnicodeBuffer(
        process,
        (ULONG_PTR)ldrEntry->BaseDllName.Buffer,
        ldrEntry->BaseDllName.Length,
        entry->ModuleName,
        sizeof(entry->ModuleName) / sizeof(entry->ModuleName[0]));
    WdblCopyRemoteUnicodeBuffer(
        process,
        (ULONG_PTR)ldrEntry->FullDllName.Buffer,
        ldrEntry->FullDllName.Length,
        entry->ImagePath,
        sizeof(entry->ImagePath) / sizeof(entry->ImagePath[0]));
}

static VOID WdblFillModuleEntry64(PEPROCESS process, const WDBL_LDR_DATA_TABLE_ENTRY64_MIN* ldrEntry, WDBL_MODULE_ENUM_ENTRY* entry) {
    RtlZeroMemory(entry, sizeof(*entry));
    entry->BaseAddress = ldrEntry->DllBase;
    entry->EntryPoint = ldrEntry->EntryPoint;
    entry->SizeOfImage = ldrEntry->SizeOfImage;
    WdblCopyRemoteUnicodeBuffer(
        process,
        (ULONG_PTR)ldrEntry->BaseDllName.Buffer,
        ldrEntry->BaseDllName.Length,
        entry->ModuleName,
        sizeof(entry->ModuleName) / sizeof(entry->ModuleName[0]));
    WdblCopyRemoteUnicodeBuffer(
        process,
        (ULONG_PTR)ldrEntry->FullDllName.Buffer,
        ldrEntry->FullDllName.Length,
        entry->ImagePath,
        sizeof(entry->ImagePath) / sizeof(entry->ImagePath[0]));
}

static NTSTATUS WdblEnumModuleList32(PEPROCESS process, ULONG pebAddress, WDBL_MODULE_ENUM_ENTRY* entries, ULONG maxEntries, ULONG* total, ULONG* returned) {
    WDBL_PEB32_MIN peb;
    WDBL_PEB_LDR_DATA32_MIN ldr;
    ULONG head;
    ULONG current;
    ULONG guard;

    if (!WdblCopyRemoteMemory(process, (ULONG_PTR)pebAddress, &peb, sizeof(peb)) || peb.Ldr == 0) {
        return STATUS_NOT_FOUND;
    }
    if (!WdblCopyRemoteMemory(process, (ULONG_PTR)peb.Ldr, &ldr, sizeof(ldr))) {
        return STATUS_PARTIAL_COPY;
    }

    head = peb.Ldr + FIELD_OFFSET(WDBL_PEB_LDR_DATA32_MIN, InLoadOrderModuleList);
    current = ldr.InLoadOrderModuleList.Flink;
    for (guard = 0; current != 0 && current != head && guard < 1024; ++guard) {
        WDBL_LDR_DATA_TABLE_ENTRY32_MIN ldrEntry;
        if (!WdblCopyRemoteMemory(process, (ULONG_PTR)current, &ldrEntry, sizeof(ldrEntry))) {
            break;
        }

        ++(*total);
        if (*returned < maxEntries) {
            WdblFillModuleEntry32(process, &ldrEntry, &entries[*returned]);
            ++(*returned);
        }

        if (ldrEntry.InLoadOrderLinks.Flink == current) {
            break;
        }
        current = ldrEntry.InLoadOrderLinks.Flink;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS WdblEnumModuleList64(PEPROCESS process, ULONGLONG pebAddress, WDBL_MODULE_ENUM_ENTRY* entries, ULONG maxEntries, ULONG* total, ULONG* returned) {
    WDBL_PEB64_MIN peb;
    WDBL_PEB_LDR_DATA64_MIN ldr;
    ULONGLONG head;
    ULONGLONG current;
    ULONG guard;

    if (!WdblCopyRemoteMemory(process, (ULONG_PTR)pebAddress, &peb, sizeof(peb)) || peb.Ldr == 0) {
        return STATUS_NOT_FOUND;
    }
    if (!WdblCopyRemoteMemory(process, (ULONG_PTR)peb.Ldr, &ldr, sizeof(ldr))) {
        return STATUS_PARTIAL_COPY;
    }

    head = peb.Ldr + FIELD_OFFSET(WDBL_PEB_LDR_DATA64_MIN, InLoadOrderModuleList);
    current = ldr.InLoadOrderModuleList.Flink;
    for (guard = 0; current != 0 && current != head && guard < 1024; ++guard) {
        WDBL_LDR_DATA_TABLE_ENTRY64_MIN ldrEntry;
        if (!WdblCopyRemoteMemory(process, (ULONG_PTR)current, &ldrEntry, sizeof(ldrEntry))) {
            break;
        }

        ++(*total);
        if (*returned < maxEntries) {
            WdblFillModuleEntry64(process, &ldrEntry, &entries[*returned]);
            ++(*returned);
        }

        if (ldrEntry.InLoadOrderLinks.Flink == current) {
            break;
        }
        current = ldrEntry.InLoadOrderLinks.Flink;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleQueryModuleList(PIRP irp, PIO_STACK_LOCATION stack) {
    WDBL_PROCESS_ENUM_REQUEST request;
    WDBL_ENUM_RESULT_HEADER* header;
    WDBL_MODULE_ENUM_ENTRY* entries;
    WDBL_PROCESS_BASIC_INFORMATION_LOCAL basicInfo;
    HANDLE processHandle = NULL;
    PEPROCESS process = NULL;
    ULONG_PTR wow64Peb = 0;
    ULONG maxEntries;
    ULONG total = 0;
    ULONG returned = 0;
    NTSTATUS status;

    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_PROCESS_ENUM_REQUEST) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_ENUM_RESULT_HEADER) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = *(WDBL_PROCESS_ENUM_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    WdblResolveRuntimeApis();
    if (g_WdblZwQueryInformationProcess == NULL || g_WdblMmCopyVirtualMemory == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    maxEntries = (stack->Parameters.DeviceIoControl.OutputBufferLength - 
        sizeof(WDBL_ENUM_RESULT_HEADER)) / sizeof(WDBL_MODULE_ENUM_ENTRY);

    header = (WDBL_ENUM_RESULT_HEADER*)irp->AssociatedIrp.SystemBuffer;

    entries = (WDBL_MODULE_ENUM_ENTRY*)((UCHAR*)irp->AssociatedIrp.SystemBuffer + 
        sizeof(WDBL_ENUM_RESULT_HEADER));

    status = WdblOpenProcessHandle(request.ProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &processHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdblLookupProcess(request.ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        ZwClose(processHandle);
        return status;
    }

    RtlZeroMemory(&basicInfo, sizeof(basicInfo));
    status = g_WdblZwQueryInformationProcess(processHandle, ProcessBasicInformation, &basicInfo, sizeof(basicInfo), NULL);
    if (NT_SUCCESS(status)) {
        g_WdblZwQueryInformationProcess(processHandle, ProcessWow64Information, &wow64Peb, sizeof(wow64Peb), NULL);
        if (wow64Peb != 0) {
            status = WdblEnumModuleList32(process, (ULONG)wow64Peb, entries, maxEntries, &total, &returned);
        } else {
            status = WdblEnumModuleList64(process, (ULONGLONG)(ULONG_PTR)basicInfo.PebBaseAddress, entries, maxEntries, &total, &returned);
        }
    }

    WdblDereferenceObject(process);
    ZwClose(processHandle);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    header->TotalCount = total;
    header->ReturnedCount = returned;
    irp->IoStatus.Information = sizeof(*header) + (returned * sizeof(WDBL_MODULE_ENUM_ENTRY));
    return STATUS_SUCCESS;
}

typedef struct _WDBL_IMAGE_DOS_HEADER_LOCAL {
    USHORT Magic;
    UCHAR Reserved[58];
    LONG NewHeaderOffset;
} WDBL_IMAGE_DOS_HEADER_LOCAL;

typedef struct _WDBL_IMAGE_FILE_HEADER_LOCAL {
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG TimeDateStamp;
    ULONG PointerToSymbolTable;
    ULONG NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} WDBL_IMAGE_FILE_HEADER_LOCAL;

_Use_decl_annotations_
static NTSTATUS WdblHandleQueryImageInfo(PIRP irp, PIO_STACK_LOCATION stack) {
    WDBL_IMAGE_INFO_REQUEST request;
    WDBL_IMAGE_INFO_RESULT* result;
    WDBL_PROCESS_BASIC_INFORMATION_LOCAL basicInfo;
    HANDLE processHandle = NULL;
    PEPROCESS process = NULL;
    ULONG_PTR wow64Peb = 0;
    ULONGLONG imageBase = 0;
    WDBL_IMAGE_DOS_HEADER_LOCAL dosHeader;
    NTSTATUS status;

    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(request) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_IMAGE_INFO_RESULT) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = *(WDBL_IMAGE_INFO_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    result = (WDBL_IMAGE_INFO_RESULT*)irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(result, sizeof(*result));
    result->ProcessId = request.ProcessId;
    result->PebStatus = STATUS_NOT_SUPPORTED;
    result->HeaderStatus = STATUS_NOT_SUPPORTED;

    WdblResolveRuntimeApis();
    if (g_WdblZwQueryInformationProcess == NULL || g_WdblMmCopyVirtualMemory == NULL) {
        irp->IoStatus.Information = sizeof(*result);
        return STATUS_SUCCESS;
    }

    status = WdblOpenProcessHandle(request.ProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &processHandle);
    if (!NT_SUCCESS(status)) {
        result->PebStatus = status;
        irp->IoStatus.Information = sizeof(*result);
        return STATUS_SUCCESS;
    }
    status = WdblLookupProcess(request.ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        ZwClose(processHandle);
        result->PebStatus = status;
        irp->IoStatus.Information = sizeof(*result);
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&basicInfo, sizeof(basicInfo));
    status = g_WdblZwQueryInformationProcess(
        processHandle,
        ProcessBasicInformation,
        &basicInfo,
        sizeof(basicInfo),
        NULL);
    if (NT_SUCCESS(status)) {
        status = g_WdblZwQueryInformationProcess(
            processHandle,
            ProcessWow64Information,
            &wow64Peb,
            sizeof(wow64Peb),
            NULL);
        if (wow64Peb != 0) {
            ULONG imageBase32 = 0;
            if (WdblCopyRemoteMemory(process, (ULONG_PTR)wow64Peb + 0x10, &imageBase32, sizeof(imageBase32))) {
                imageBase = imageBase32;
                result->PebStatus = STATUS_SUCCESS;
            } else {
                result->PebStatus = STATUS_PARTIAL_COPY;
            }
        } else if (basicInfo.PebBaseAddress != NULL) {
            if (WdblCopyRemoteMemory(
                    process,
                    (ULONG_PTR)basicInfo.PebBaseAddress + 0x10,
                    &imageBase,
                    sizeof(imageBase))) {
                result->PebStatus = STATUS_SUCCESS;
            } else {
                result->PebStatus = STATUS_PARTIAL_COPY;
            }
        } else {
            result->PebStatus = STATUS_NOT_FOUND;
        }
    } else {
        result->PebStatus = status;
    }

    if (imageBase != 0) {
        RtlZeroMemory(&dosHeader, sizeof(dosHeader));
        if (WdblCopyRemoteMemory(process, (ULONG_PTR)imageBase, &dosHeader, sizeof(dosHeader)) &&
            dosHeader.Magic == 0x5A4D &&
            dosHeader.NewHeaderOffset > 0 &&
            dosHeader.NewHeaderOffset < 0x100000) {
            ULONG signature = 0;
            if (WdblCopyRemoteMemory(
                    process,
                    (ULONG_PTR)(imageBase + (ULONGLONG)dosHeader.NewHeaderOffset),
                    &signature,
                    sizeof(signature)) &&
                signature == 0x00004550) {
                WDBL_IMAGE_FILE_HEADER_LOCAL fileHeader;
                RtlZeroMemory(&fileHeader, sizeof(fileHeader));
                if (WdblCopyRemoteMemory(
                        process,
                        (ULONG_PTR)(imageBase + (ULONGLONG)dosHeader.NewHeaderOffset + sizeof(ULONG)),
                        &fileHeader,
                        sizeof(fileHeader))) {
                    result->Machine = fileHeader.Machine;
                    result->Characteristics = fileHeader.Characteristics;
                    result->TimeDateStamp = fileHeader.TimeDateStamp;
                    result->SectionCount = fileHeader.NumberOfSections;

                    USHORT optionalMagic = 0;
                    UCHAR optionalHeader[256];
                    const ULONG_PTR optionalAddress =
                        (ULONG_PTR)(imageBase + (ULONGLONG)dosHeader.NewHeaderOffset +
                            sizeof(ULONG) + sizeof(WDBL_IMAGE_FILE_HEADER_LOCAL));
                    if (WdblCopyRemoteMemory(process, optionalAddress, &optionalMagic, sizeof(optionalMagic))) {
                        RtlZeroMemory(optionalHeader, sizeof(optionalHeader));
                        if (fileHeader.SizeOfOptionalHeader > sizeof(optionalHeader)) {
                            result->HeaderStatus = STATUS_INVALID_IMAGE_FORMAT;
                        } else if (WdblCopyRemoteMemory(
                                       process,
                                       optionalAddress,
                                       optionalHeader,
                                       fileHeader.SizeOfOptionalHeader)) {
                            ULONG addressOfEntryPoint = 0;
                            ULONG sizeOfImage = 0;
                            ULONG sizeOfHeaders = 0;
                            USHORT subsystem = 0;
                            ULONGLONG parsedImageBase = 0;
                            RtlCopyMemory(&addressOfEntryPoint, optionalHeader + 16, sizeof(addressOfEntryPoint));
                            RtlCopyMemory(&sizeOfImage, optionalHeader + 56, sizeof(sizeOfImage));
                            RtlCopyMemory(&sizeOfHeaders, optionalHeader + 60, sizeof(sizeOfHeaders));
                            RtlCopyMemory(&subsystem, optionalHeader + 68, sizeof(subsystem));
                            if (optionalMagic == 0x20B) {
                                RtlCopyMemory(&parsedImageBase, optionalHeader + 24, sizeof(parsedImageBase));
                            } else if (optionalMagic == 0x10B) {
                                ULONG imageBase32 = 0;
                                RtlCopyMemory(&imageBase32, optionalHeader + 28, sizeof(imageBase32));
                                parsedImageBase = imageBase32;
                            } else {
                                result->HeaderStatus = STATUS_INVALID_IMAGE_FORMAT;
                                goto image_info_done;
                            }
                            result->SizeOfHeaders = sizeOfHeaders;
                            result->SizeOfImage = sizeOfImage;
                            result->Subsystem = subsystem;
                            result->ImageBase = parsedImageBase;
                            result->EntryPoint = parsedImageBase + addressOfEntryPoint;
                            result->HeaderStatus = STATUS_SUCCESS;
                        } else {
                            result->HeaderStatus = STATUS_PARTIAL_COPY;
                        }
                    }
                }
            } else {
                result->HeaderStatus = STATUS_INVALID_IMAGE_FORMAT;
            }
        } else {
            result->HeaderStatus = STATUS_INVALID_IMAGE_FORMAT;
        }
    }

image_info_done:
    WdblDereferenceObject(process);
    ZwClose(processHandle);
    irp->IoStatus.Information = sizeof(*result);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblHandleQueryProcessMitigations(PIRP irp, PIO_STACK_LOCATION stack) {
    WDBL_PROCESS_MITIGATIONS_REQUEST request;
    WDBL_PROCESS_MITIGATIONS_RESULT* result;
    HANDLE processHandle = NULL;
    ULONG executeFlags = 0;
    ULONG breakOnTermination = 0;
    UCHAR protectionLevel = 0;
    ULONG_PTR wow64Peb = 0;
    NTSTATUS status;

    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(request) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(WDBL_PROCESS_MITIGATIONS_RESULT) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = *(WDBL_PROCESS_MITIGATIONS_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    result = (WDBL_PROCESS_MITIGATIONS_RESULT*)irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(result, sizeof(*result));
    result->ProcessId = request.ProcessId;
    result->ExecuteFlagsStatus = STATUS_NOT_SUPPORTED;
    result->ProtectionStatus = STATUS_NOT_SUPPORTED;
    result->BreakOnTerminationStatus = STATUS_NOT_SUPPORTED;
    result->Wow64Status = STATUS_NOT_SUPPORTED;

    WdblResolveRuntimeApis();
    if (g_WdblZwQueryInformationProcess == NULL) {
        irp->IoStatus.Information = sizeof(*result);
        return STATUS_SUCCESS;
    }

    status = WdblOpenProcessHandle(request.ProcessId, PROCESS_QUERY_INFORMATION, &processHandle);
    if (!NT_SUCCESS(status)) {
        result->ExecuteFlagsStatus = status;
        result->ProtectionStatus = status;
        result->BreakOnTerminationStatus = status;
        result->Wow64Status = status;
        irp->IoStatus.Information = sizeof(*result);
        return STATUS_SUCCESS;
    }

    result->ExecuteFlagsStatus = g_WdblZwQueryInformationProcess(
        processHandle,
        ProcessExecuteFlags,
        &executeFlags,
        sizeof(executeFlags),
        NULL);
    if (NT_SUCCESS(result->ExecuteFlagsStatus)) {
        result->ExecuteFlags = executeFlags;
    }

    result->ProtectionStatus = g_WdblZwQueryInformationProcess(
        processHandle,
        ProcessProtectionInformation,
        &protectionLevel,
        sizeof(protectionLevel),
        NULL);
    if (NT_SUCCESS(result->ProtectionStatus)) {
        result->ProtectionLevel = protectionLevel;
    }

    result->BreakOnTerminationStatus = g_WdblZwQueryInformationProcess(
        processHandle,
        ProcessBreakOnTermination,
        &breakOnTermination,
        sizeof(breakOnTermination),
        NULL);
    if (NT_SUCCESS(result->BreakOnTerminationStatus)) {
        result->BreakOnTermination = breakOnTermination;
    }

    result->Wow64Status = g_WdblZwQueryInformationProcess(
        processHandle,
        ProcessWow64Information,
        &wow64Peb,
        sizeof(wow64Peb),
        NULL);
    if (NT_SUCCESS(result->Wow64Status)) {
        result->IsWow64 = wow64Peb != 0 ? 1 : 0;
    }

    ZwClose(processHandle);
    irp->IoStatus.Information = sizeof(*result);
    return STATUS_SUCCESS;
}

static NTSTATUS WdblHandleCloseKernelHandle(PIRP irp, PIO_STACK_LOCATION stack) {
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WDBL_CLOSE_KERNEL_HANDLE_REQUEST) ||
        irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    const WDBL_CLOSE_KERNEL_HANDLE_REQUEST request =
        *(WDBL_CLOSE_KERNEL_HANDLE_REQUEST*)irp->AssociatedIrp.SystemBuffer;
    if (request.KernelHandle == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = ZwClose((HANDLE)(ULONG_PTR)request.KernelHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblCreateClose(PDEVICE_OBJECT deviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(deviceObject);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblClose(PDEVICE_OBJECT deviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(deviceObject);
#if WDBL_ENABLE_DRIVER_DEBUG_OBJECT
    ExAcquireFastMutex(&g_WdblDebugSessionLock);
    WdblCloseDebugSessionLocked();
    ExReleaseFastMutex(&g_WdblDebugSessionLock);
#endif

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS WdblDeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(deviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    const ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    if (code != IOCTL_WDBL_PING && code != IOCTL_WDBL_QUERY_PROCESS_LIST) {
        status = WdblDecodeIoctlInput(irp, stack, code);
        if (!NT_SUCCESS(status)) {
            irp->IoStatus.Status = status;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            return status;
        }
    }

    switch (code) {
        case IOCTL_WDBL_PING: {
            if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ULONG)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            *(ULONG*)irp->AssociatedIrp.SystemBuffer = 1;
            information = sizeof(ULONG);
            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_WDBL_QUERY_DEBUG_API_SUPPORT:
            status = WdblHandleQueryDebugApiSupport(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_QUERY_PROCESS_LIST:
            status = WdblHandleQueryProcessList(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_QUERY_THREAD_LIST:
            status = WdblHandleQueryThreadList(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_QUERY_MODULE_LIST:
            status = WdblHandleQueryModuleList(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_QUERY_MEMORY_MAP:
            status = WdblHandleQueryMemoryMap(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_QUERY_CAPABILITIES:
            status = WdblHandleQueryCapabilities(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_READ_PROCESS_MEMORY_EX:
            status = WdblHandleReadProcessMemoryEx(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_WRITE_PROCESS_MEMORY_EX:
            status = WdblHandleWriteProcessMemoryEx(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_QUERY_ANTI_DEBUG:
            status = WdblHandleQueryAntiDebug(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_QUERY_DEBUG_REGISTERS:
            status = WdblHandleQueryDebugRegisters(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_SET_DEBUG_REGISTERS:
            status = WdblHandleSetDebugRegisters(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_QUERY_HANDLE_LIST:
            status = WdblHandleQueryHandleList(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_QUERY_THREAD_INFO:
            status = WdblHandleQueryThreadInfo(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_QUERY_IMAGE_INFO:
            status = WdblHandleQueryImageInfo(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_QUERY_PROCESS_MITIGATIONS:
            status = WdblHandleQueryProcessMitigations(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_QUERY_DRIVER_EVENTS:
            status = WdblHandleQueryDriverEvents(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_QUERY_EPROCESS_IMAGE_NAME_OFFSET:
            status = WdblHandleQueryEprocessImageNameOffset(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_DEBUG_ACTIVE_PROCESS:
            status = WdblHandleDebugActiveProcess(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_DEBUG_ACTIVE_PROCESS_STOP:
            status = WdblHandleDebugActiveProcessStop(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_WAIT_FOR_DEBUG_EVENT:
            status = WdblHandleWaitForDebugEvent(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_CONTINUE_DEBUG_EVENT:
            status = WdblHandleContinueDebugEvent(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_READ_PROCESS_MEMORY:
            status = WdblHandleReadProcessMemory(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_WRITE_PROCESS_MEMORY:
            status = WdblHandleWriteProcessMemory(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_GET_THREAD_CONTEXT:
            status = WdblHandleGetThreadContext(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_SET_THREAD_CONTEXT:
            status = WdblHandleSetThreadContext(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_GET_WOW64_THREAD_CONTEXT:
            status = WdblHandleGetWow64ThreadContext(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_SET_WOW64_THREAD_CONTEXT:
            status = WdblHandleSetWow64ThreadContext(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_QUERY_VIRTUAL_MEMORY:
            status = WdblHandleQueryVirtualMemory(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_PROTECT_VIRTUAL_MEMORY:
            status = WdblHandleProtectVirtualMemory(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_ALLOCATE_VIRTUAL_MEMORY:
            status = WdblHandleAllocateVirtualMemory(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_FREE_VIRTUAL_MEMORY:
            status = WdblHandleFreeVirtualMemory(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_CREATE_USER_THREAD:
            status = WdblHandleCreateUserThread(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_SUSPEND_THREAD:
            status = WdblHandleThreadControl(irp, stack, TRUE);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_RESUME_THREAD:
            status = WdblHandleThreadControl(irp, stack, FALSE);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_SUSPEND_PROCESS:
        case IOCTL_WDBL_RESUME_PROCESS:
        case IOCTL_WDBL_TERMINATE_PROCESS:
            status = WdblHandleProcessControl(irp, stack, code);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_OPEN_PROCESS_KERNEL_HANDLE:
            status = WdblHandleOpenProcessKernelHandle(irp, stack);
            information = irp->IoStatus.Information;
            break;

        case IOCTL_WDBL_CLOSE_KERNEL_HANDLE:
            status = WdblHandleCloseKernelHandle(irp, stack);
            information = irp->IoStatus.Information;
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

_Use_decl_annotations_
void WdblUnload(PDRIVER_OBJECT driverObject) {
    UNICODE_STRING dosName;
    WdblUnregisterEventCallbacks();
    RtlInitUnicodeString(&dosName, WDBL_MEMDRV_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&dosName);
#if WDBL_ENABLE_DRIVER_DEBUG_OBJECT
    ExAcquireFastMutex(&g_WdblDebugSessionLock);
    WdblCloseDebugSessionLocked();
    ExReleaseFastMutex(&g_WdblDebugSessionLock);
#endif

    if (driverObject->DeviceObject != NULL) {
        IoDeleteDevice(driverObject->DeviceObject);
    }
}

_Use_decl_annotations_
NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath) {
    UNREFERENCED_PARAMETER(registryPath);

    UNICODE_STRING deviceName;
    UNICODE_STRING dosName;
    PDEVICE_OBJECT deviceObject = NULL;
#if WDBL_ENABLE_DRIVER_DEBUG_OBJECT
    ExInitializeFastMutex(&g_WdblDebugSessionLock);
#endif
    ExInitializeFastMutex(&g_WdblEventLock);

    RtlInitUnicodeString(&deviceName, WDBL_MEMDRV_DEVICE_NAME);
    RtlInitUnicodeString(&dosName, WDBL_MEMDRV_DOS_DEVICE_NAME);

    NTSTATUS status = IoCreateDevice(
        driverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    status = IoCreateSymbolicLink(&dosName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    driverObject->MajorFunction[IRP_MJ_CREATE] = WdblCreateClose;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = WdblClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = WdblDeviceControl;
    driverObject->DriverUnload = WdblUnload;
    WdblRegisterEventCallbacks();
    return STATUS_SUCCESS;
}














