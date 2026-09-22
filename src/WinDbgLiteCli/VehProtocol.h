#pragma once

#include <Windows.h>

#define WDBL_VEH_PROTOCOL_VERSION 1u
#define WDBL_VEH_PIPE_PREFIX L"\\\\.\\pipe\\WinDbgLiteVeh_"
#define WDBL_VEH_MAX_PATH_CHARS 260u

enum WdblVehMessageType {
    WDBL_VEH_MSG_HELLO = 1,
    WDBL_VEH_MSG_EXCEPTION = 2,
    WDBL_VEH_MSG_CONTINUE = 3,
    WDBL_VEH_MSG_SHUTDOWN = 4,
    WDBL_VEH_MSG_MODULE_LOAD = 5,
    WDBL_VEH_MSG_MODULE_UNLOAD = 6,
    WDBL_VEH_MSG_THREAD_CREATE = 7,
    WDBL_VEH_MSG_THREAD_EXIT = 8,
    WDBL_VEH_MSG_RESPONSE = 9,
    WDBL_VEH_MSG_REQ_SET_SOFTWARE_BREAKPOINT = 10,
    WDBL_VEH_MSG_REQ_REMOVE_SOFTWARE_BREAKPOINT = 11,
    WDBL_VEH_MSG_SNAPSHOT_BEGIN = 12,
    WDBL_VEH_MSG_SNAPSHOT_END = 13,
    WDBL_VEH_MSG_REQ_READ_MEMORY = 14,
    WDBL_VEH_MSG_REQ_WRITE_MEMORY = 15,
    WDBL_VEH_MSG_MEMORY_RESPONSE = 16,
    WDBL_VEH_MSG_REQ_GET_CONTEXT = 17,
    WDBL_VEH_MSG_REQ_SET_CONTEXT = 18,
    WDBL_VEH_MSG_CONTEXT_RESPONSE = 19,
    WDBL_VEH_MSG_REQ_SUSPEND_THREAD = 20,
    WDBL_VEH_MSG_REQ_RESUME_THREAD = 21,
    WDBL_VEH_MSG_REQ_SET_EXCEPTION_POLICY = 22,
    WDBL_VEH_MSG_PROCESS_EXIT = 23,
    WDBL_VEH_MSG_REQ_REFRESH_SNAPSHOT = 24,
    WDBL_VEH_MSG_REQ_SET_HARDWARE_BREAKPOINT = 25,
    WDBL_VEH_MSG_REQ_REMOVE_HARDWARE_BREAKPOINT = 26,
    WDBL_VEH_MSG_REQ_SET_MEMORY_BREAKPOINT = 27,
    WDBL_VEH_MSG_REQ_REMOVE_MEMORY_BREAKPOINT = 28
};

enum WdblVehContinueDisposition {
    WDBL_VEH_CONTINUE_SEARCH = 0,
    WDBL_VEH_CONTINUE_EXECUTION = 1,
    WDBL_VEH_CONTINUE_STEP = 2
};

enum WdblVehExceptionPolicy {
    WDBL_VEH_EXCEPTION_POLICY_SEARCH = 0,
    WDBL_VEH_EXCEPTION_POLICY_CONTINUE = 1,
    WDBL_VEH_EXCEPTION_POLICY_BREAKPOINT_ONLY = 2
};

#define WDBL_VEH_MAX_MEMORY_BYTES 256u
#define WDBL_VEH_CONTEXT_IP    0x00000001u
#define WDBL_VEH_CONTEXT_SP    0x00000002u
#define WDBL_VEH_CONTEXT_FP    0x00000004u
#define WDBL_VEH_CONTEXT_AX    0x00000008u
#define WDBL_VEH_CONTEXT_BX    0x00000010u
#define WDBL_VEH_CONTEXT_CX    0x00000020u
#define WDBL_VEH_CONTEXT_DX    0x00000040u
#define WDBL_VEH_CONTEXT_SI    0x00000080u
#define WDBL_VEH_CONTEXT_DI    0x00000100u
#define WDBL_VEH_CONTEXT_FLAGS 0x00000200u
#define WDBL_VEH_EXCEPTION_FLAG_STEP_COMPLETE 0x00000001u
#define WDBL_VEH_EXCEPTION_FLAG_OUTPUT_DEBUG_STRING 0x00000002u
#define WDBL_VEH_EXCEPTION_FLAG_CONTINUE_EXECUTION 0x00000004u
#define WDBL_VEH_EXCEPTION_FLAG_POLICY_BREAK 0x00000008u
#define WDBL_VEH_EXCEPTION_FLAG_HARDWARE_BREAKPOINT 0x00000010u
#define WDBL_VEH_EXCEPTION_FLAG_MEMORY_BREAKPOINT 0x00000020u
#define WDBL_VEH_BREAKPOINT_FLAG_TEMPORARY 0x00000001u

#pragma pack(push, 1)
struct WdblVehMessageHeader {
    DWORD version;
    DWORD type;
    DWORD size;
};

struct WdblVehHelloMessage {
    WdblVehMessageHeader header;
    DWORD processId;
    DWORD threadId;
    ULONGLONG imageBase;
};

struct WdblVehExceptionMessage {
    WdblVehMessageHeader header;
    DWORD processId;
    DWORD threadId;
    DWORD exceptionCode;
    DWORD exceptionFlags;
    DWORD firstChance;
    DWORD parameterCount;
    ULONGLONG exceptionAddress;
    ULONGLONG instructionPointer;
    ULONGLONG stackPointer;
    ULONGLONG framePointer;
    DWORD breakpointId;
    DWORD reserved;
    ULONGLONG breakpointAddress;
    ULONGLONG parameters[EXCEPTION_MAXIMUM_PARAMETERS];
};

struct WdblVehModuleMessage {
    WdblVehMessageHeader header;
    DWORD processId;
    DWORD threadId;
    ULONGLONG baseAddress;
    ULONG sizeOfImage;
    ULONG fullNameLength;
    ULONG baseNameLength;
    WCHAR fullName[WDBL_VEH_MAX_PATH_CHARS];
    WCHAR baseName[WDBL_VEH_MAX_PATH_CHARS];
};

struct WdblVehThreadMessage {
    WdblVehMessageHeader header;
    DWORD processId;
    DWORD threadId;
    ULONGLONG tickCount;
};

struct WdblVehProcessExitMessage {
    WdblVehMessageHeader header;
    DWORD processId;
    DWORD threadId;
    DWORD exitCode;
    DWORD reserved;
};

struct WdblVehResponseMessage {
    WdblVehMessageHeader header;
    DWORD requestId;
    DWORD status;
    DWORD errorCode;
    DWORD value;
    WCHAR text[WDBL_VEH_MAX_PATH_CHARS];
};

struct WdblVehMemoryRequest {
    WdblVehMessageHeader header;
    DWORD requestId;
    DWORD size;
    ULONGLONG address;
    BYTE data[WDBL_VEH_MAX_MEMORY_BYTES];
};

struct WdblVehMemoryResponse {
    WdblVehMessageHeader header;
    DWORD requestId;
    DWORD status;
    DWORD errorCode;
    DWORD bytesTransferred;
    ULONGLONG address;
    BYTE data[WDBL_VEH_MAX_MEMORY_BYTES];
};

struct WdblVehContextRequest {
    WdblVehMessageHeader header;
    DWORD requestId;
    DWORD threadId;
    DWORD contextFlags;
    ULONGLONG ip;
    ULONGLONG sp;
    ULONGLONG fp;
    ULONGLONG ax;
    ULONGLONG bx;
    ULONGLONG cx;
    ULONGLONG dx;
    ULONGLONG si;
    ULONGLONG di;
    ULONGLONG flags;
};

struct WdblVehContextResponse {
    WdblVehMessageHeader header;
    DWORD requestId;
    DWORD status;
    DWORD errorCode;
    DWORD threadId;
    ULONGLONG ip;
    ULONGLONG sp;
    ULONGLONG fp;
    ULONGLONG ax;
    ULONGLONG bx;
    ULONGLONG cx;
    ULONGLONG dx;
    ULONGLONG si;
    ULONGLONG di;
    ULONGLONG flags;
};

struct WdblVehThreadControlRequest {
    WdblVehMessageHeader header;
    DWORD requestId;
    DWORD threadId;
};

struct WdblVehExceptionPolicyRequest {
    WdblVehMessageHeader header;
    DWORD requestId;
    DWORD policy;
    DWORD exceptionCode;
};

struct WdblVehSoftwareBreakpointRequest {
    WdblVehMessageHeader header;
    DWORD requestId;
    DWORD breakpointId;
    DWORD flags;
    DWORD reserved;
    ULONGLONG address;
};

struct WdblVehHardwareBreakpointRequest {
    WdblVehMessageHeader header;
    DWORD requestId;
    DWORD breakpointId;
    DWORD slot;
    DWORD access;
    DWORD length;
    DWORD threadId;
    DWORD reserved;
    ULONGLONG address;
};

struct WdblVehMemoryBreakpointRequest {
    WdblVehMessageHeader header;
    DWORD requestId;
    DWORD breakpointId;
    DWORD access;
    DWORD reserved;
    ULONGLONG address;
    ULONGLONG size;
};

struct WdblVehContinueMessage {
    WdblVehMessageHeader header;
    DWORD disposition;
    DWORD reserved;
    DWORD contextFlags;
    DWORD threadId;
    ULONGLONG ip;
    ULONGLONG sp;
    ULONGLONG fp;
    ULONGLONG ax;
    ULONGLONG bx;
    ULONGLONG cx;
    ULONGLONG dx;
    ULONGLONG si;
    ULONGLONG di;
    ULONGLONG flags;
};
#pragma pack(pop)
