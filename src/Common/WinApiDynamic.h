#pragma once

#include <Windows.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#include <vector>
#include <type_traits>
#include <utility>

#include "WinDbgLiteMemIoctl.h"

namespace wdbl {
namespace winapi {

BOOL CloseHandle(HANDLE object);
BOOL ContinueDebugEvent(DWORD processId, DWORD threadId, DWORD continueStatus);
BOOL CreateProcessW(
    LPCWSTR applicationName,
    LPWSTR commandLine,
    LPSECURITY_ATTRIBUTES processAttributes,
    LPSECURITY_ATTRIBUTES threadAttributes,
    BOOL inheritHandles,
    DWORD creationFlags,
    LPVOID environment,
    LPCWSTR currentDirectory,
    LPSTARTUPINFOW startupInfo,
    LPPROCESS_INFORMATION processInformation);
HANDLE CreateToolhelp32Snapshot(DWORD flags, DWORD processId);
BOOL DebugActiveProcess(DWORD processId);
BOOL DebugActiveProcessStop(DWORD processId);
BOOL DebugSetProcessKillOnExit(BOOL killOnExit);
BOOL DebugBreakProcess(HANDLE process);
HANDLE CreateEventW(LPSECURITY_ATTRIBUTES eventAttributes, BOOL manualReset, BOOL initialState, LPCWSTR name);
BOOL DuplicateHandle(
    HANDLE sourceProcessHandle,
    HANDLE sourceHandle,
    HANDLE targetProcessHandle,
    LPHANDLE targetHandle,
    DWORD desiredAccess,
    BOOL inheritHandle,
    DWORD options);
BOOL FlushInstructionCache(HANDLE process, LPCVOID baseAddress, SIZE_T size);
BOOL FreeLibrary(HMODULE module);
DWORD GetCurrentDirectoryW(DWORD bufferLength, LPWSTR buffer);
HANDLE GetCurrentProcess();
DWORD GetCurrentProcessId();
HANDLE GetCurrentThread();
DWORD GetEnvironmentVariableW(LPCWSTR name, LPWSTR buffer, DWORD bufferLength);
BOOL GetExitCodeProcess(HANDLE process, LPDWORD exitCode);
BOOL GetExitCodeThread(HANDLE thread, LPDWORD exitCode);
DWORD GetFinalPathNameByHandleW(HANDLE file, LPWSTR filePath, DWORD filePathLength, DWORD flags);
DWORD GetFullPathNameW(LPCWSTR fileName, DWORD bufferLength, LPWSTR buffer, LPWSTR* filePart);
DWORD GetLastError();
DWORD GetModuleFileNameW(HMODULE module, LPWSTR fileName, DWORD size);
HMODULE GetModuleHandleW(LPCWSTR moduleName);
DWORD GetPriorityClass(HANDLE process);
FARPROC GetProcAddress(HMODULE module, LPCSTR procName);
DWORD GetTempFileNameW(LPCWSTR pathName, LPCWSTR prefixString, UINT unique, LPWSTR tempFileName);
DWORD GetTempPathW(DWORD bufferLength, LPWSTR buffer);
void GetSystemInfo(LPSYSTEM_INFO systemInfo);
void GetNativeSystemInfo(LPSYSTEM_INFO systemInfo);
BOOL GetThreadContext(HANDLE thread, LPCONTEXT context);
BOOL IsWow64Process2(HANDLE process, USHORT* processMachine, USHORT* nativeMachine);
HMODULE LoadLibraryW(LPCWSTR fileName);
BOOL Module32FirstW(HANDLE snapshot, LPMODULEENTRY32W moduleEntry);
BOOL Module32NextW(HANDLE snapshot, LPMODULEENTRY32W moduleEntry);
HANDLE OpenProcess(DWORD desiredAccess, BOOL inheritHandle, DWORD processId);
HANDLE OpenThread(DWORD desiredAccess, BOOL inheritHandle, DWORD threadId);
BOOL QueryPerformanceCounter(LARGE_INTEGER* performanceCount);
BOOL QueryPerformanceFrequency(LARGE_INTEGER* frequency);
BOOL QueryFullProcessImageNameW(HANDLE process, DWORD flags, LPWSTR exeName, PDWORD size);
void ConfigureProcessMemoryDriver(BOOL preferDriver, LPCWSTR devicePath);
BOOL IsProcessMemoryDriverPreferred();
BOOL IsProcessMemoryDriverActive();
DWORD GetProcessMemoryDriverLastError();
BOOL PingProcessMemoryDriver();
BOOL QueryDriverCapabilities(WDBL_DRIVER_CAPABILITIES_RESULT* result);
BOOL QueryDriverDebugApiSupport(DWORD* availableMask, DWORD* requiredMask);
BOOL QueryDriverEprocessImageNameOffset(
    DWORD* offset,
    DWORD* nameLength,
    DWORD* confidence,
    char imageName[16]);
BOOL OpenProcessKernelHandle(DWORD processId, DWORD desiredAccess, ULONGLONG* kernelHandle);
BOOL CloseKernelHandle(ULONGLONG kernelHandle);
BOOL DriverCreateUserThread64(
    DWORD processId,
    ULONGLONG startAddress,
    ULONGLONG parameter,
    DWORD createFlags,
    SIZE_T stackSize,
    SIZE_T maximumStackSize,
    DWORD* threadId);
BOOL DriverSuspendThread(DWORD threadId, DWORD* previousSuspendCount);
BOOL DriverResumeThread(DWORD threadId, DWORD* previousSuspendCount);
BOOL DriverSuspendProcess(DWORD processId);
BOOL DriverResumeProcess(DWORD processId);
BOOL DriverTerminateProcess(DWORD processId, DWORD exitStatus);
BOOL DriverGetWow64ThreadContext(DWORD threadId, WOW64_CONTEXT* context);
BOOL DriverSetWow64ThreadContext(DWORD threadId, const WOW64_CONTEXT* context);
BOOL DriverReadProcessMemory64(DWORD processId, ULONGLONG address, LPVOID buffer, SIZE_T size, SIZE_T* bytesRead);
BOOL DriverWriteProcessMemory64(DWORD processId, ULONGLONG address, LPCVOID buffer, SIZE_T size, SIZE_T* bytesWritten);
BOOL DriverReadProcessMemoryEx64(
    DWORD processId,
    ULONGLONG address,
    LPVOID buffer,
    SIZE_T size,
    DWORD flags,
    SIZE_T* bytesRead,
    LONG* kernelStatus,
    ULONGLONG* faultAddress);
BOOL DriverWriteProcessMemoryEx64(
    DWORD processId,
    ULONGLONG address,
    LPCVOID buffer,
    SIZE_T size,
    DWORD flags,
    SIZE_T* bytesWritten,
    LONG* kernelStatus,
    ULONGLONG* faultAddress);
BOOL QueryDriverAntiDebug(DWORD processId, DWORD flags, WDBL_ANTI_DEBUG_QUERY_RESULT* result);
BOOL DriverGetDebugRegisters(DWORD threadId, WDBL_DEBUG_REGISTERS_RESULT* result);
BOOL DriverSetDebugRegisters(DWORD threadId, const WDBL_DEBUG_REGISTERS_RESULT* registers);
SIZE_T DriverVirtualQueryEx64(DWORD processId, ULONGLONG address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length);
BOOL DriverVirtualProtectEx64(DWORD processId, ULONGLONG address, SIZE_T size, DWORD newProtect, PDWORD oldProtect);
ULONGLONG DriverVirtualAllocEx64(DWORD processId, ULONGLONG address, SIZE_T size, DWORD allocationType, DWORD protect);
BOOL DriverVirtualFreeEx64(DWORD processId, ULONGLONG address, SIZE_T size, DWORD freeType);
BOOL ReadProcessMemory(HANDLE process, LPCVOID baseAddress, LPVOID buffer, SIZE_T size, SIZE_T* bytesRead);
BOOL ResetEvent(HANDLE eventHandle);
BOOL SetConsoleOutputCP(UINT codePageId);
BOOL SetEvent(HANDLE eventHandle);
void SetLastError(DWORD error);
BOOL SetThreadContext(HANDLE thread, const CONTEXT* context);
void Sleep(DWORD milliseconds);
BOOL Thread32First(HANDLE snapshot, LPTHREADENTRY32 threadEntry);
BOOL Thread32Next(HANDLE snapshot, LPTHREADENTRY32 threadEntry);
LPVOID VirtualAllocEx(HANDLE process, LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect);
BOOL VirtualFreeEx(HANDLE process, LPVOID address, SIZE_T size, DWORD freeType);
BOOL VirtualProtectEx(HANDLE process, LPVOID address, SIZE_T size, DWORD newProtect, PDWORD oldProtect);
SIZE_T VirtualQueryEx(HANDLE process, LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length);
BOOL WaitForDebugEvent(LPDEBUG_EVENT debugEvent, DWORD milliseconds);
DWORD WaitForSingleObjectEx(HANDLE handle, DWORD milliseconds, BOOL alertable);
BOOL WriteProcessMemory(HANDLE process, LPVOID baseAddress, LPCVOID buffer, SIZE_T size, SIZE_T* bytesWritten);
int MultiByteToWideChar(UINT codePage, DWORD flags, LPCCH multiByteStr, int cbMultiByte, LPWSTR wideCharStr, int cchWideChar);
int WideCharToMultiByte(
    UINT codePage,
    DWORD flags,
    LPCWCH wideCharStr,
    int cchWideChar,
    LPSTR multiByteStr,
    int cbMultiByte,
    LPCCH defaultChar,
    LPBOOL usedDefaultChar);

BOOL StackWalk64(
    DWORD machineType,
    HANDLE process,
    HANDLE thread,
    LPSTACKFRAME64 stackFrame,
    PVOID contextRecord,
    PREAD_PROCESS_MEMORY_ROUTINE64 readMemoryRoutine,
    PFUNCTION_TABLE_ACCESS_ROUTINE64 functionTableAccessRoutine,
    PGET_MODULE_BASE_ROUTINE64 getModuleBaseRoutine,
    PTRANSLATE_ADDRESS_ROUTINE64 translateAddress);
BOOL SymCleanup(HANDLE process);
BOOL SymEnumLinesW(
    HANDLE process,
    ULONG64 base,
    PCWSTR obj,
    PCWSTR file,
    PSYM_ENUMLINES_CALLBACKW callback,
    PVOID userContext);
BOOL SymEnumSymbolsW(HANDLE process, ULONG64 base, PCWSTR mask, PSYM_ENUMERATESYMBOLS_CALLBACKW callback, PVOID userContext);
BOOL SymFromAddr(HANDLE process, DWORD64 address, PDWORD64 displacement, PSYMBOL_INFO symbol);
BOOL SymGetLineFromAddrW64(HANDLE process, DWORD64 address, PDWORD displacement, PIMAGEHLP_LINEW64 line);
BOOL SymGetModuleInfoW64(HANDLE process, DWORD64 address, PIMAGEHLP_MODULEW64 moduleInfo);
DWORD SymGetOptions();
BOOL SymGetSearchPathW(HANDLE process, PWSTR searchPath, DWORD searchPathLength);
BOOL SymGetTypeFromNameW(HANDLE process, ULONG64 base, PCWSTR name, PSYMBOL_INFOW symbol);
BOOL SymGetTypeInfo(HANDLE process, DWORD64 modBase, ULONG typeId, IMAGEHLP_SYMBOL_TYPE_INFO getType, PVOID info);
BOOL SymInitialize(HANDLE process, PCSTR userSearchPath, BOOL invadeProcess);
DWORD64 SymLoadModuleExW(
    HANDLE process,
    HANDLE file,
    PCWSTR imageName,
    PCWSTR moduleName,
    DWORD64 baseOfDll,
    DWORD dllSize,
    PMODLOAD_DATA data,
    DWORD flags);
BOOL SymRefreshModuleList(HANDLE process);
DWORD SymSetOptions(DWORD options);
BOOL SymSetSearchPathW(HANDLE process, PCWSTR searchPath);
BOOL SymUnloadModule64(HANDLE process, DWORD64 baseOfDll);

BOOL QueryDriverProcessList(std::vector<WDBL_PROCESS_ENUM_ENTRY>* entries);
BOOL QueryDriverThreadList(DWORD processId, std::vector<WDBL_THREAD_ENUM_ENTRY>* entries);
BOOL QueryDriverModuleList(DWORD processId, std::vector<WDBL_MODULE_ENUM_ENTRY>* entries);
BOOL QueryDriverMemoryMap(DWORD processId, ULONGLONG startAddress, std::vector<WDBL_MEMORY_ENUM_ENTRY>* entries);
BOOL QueryDriverHandleList(DWORD processId, std::vector<WDBL_HANDLE_ENUM_ENTRY>* entries);
BOOL QueryDriverThreadInfo(DWORD threadId, WDBL_THREAD_INFO_RESULT* result);
BOOL QueryDriverImageInfo(DWORD processId, WDBL_IMAGE_INFO_RESULT* result);
BOOL QueryDriverProcessMitigations(DWORD processId, WDBL_PROCESS_MITIGATIONS_RESULT* result);
BOOL QueryDriverEvents(DWORD processId, DWORD maxEvents, std::vector<WDBL_DRIVER_EVENT_ENTRY>* entries);

FARPROC ResolveDynamicProcAddress(const wchar_t* moduleName, const char* procName);
void SetMissingProcErrorValue();

#if !defined(_MSC_VER) || _MSC_VER > 1600

template <typename ReturnT>
struct DynamicInvokeResult {
    static ReturnT MissingValue() {
        return static_cast<ReturnT>(0);
    }

    template <typename Fn, typename... Args>
    static ReturnT Invoke(Fn fn, Args&&... args) {
        return fn(std::forward<Args>(args)...);
    }
};

template <typename ReturnT>
struct DynamicInvokeResult<ReturnT*> {
    static ReturnT* MissingValue() {
        return nullptr;
    }

    template <typename Fn, typename... Args>
    static ReturnT* Invoke(Fn fn, Args&&... args) {
        return fn(std::forward<Args>(args)...);
    }
};

template <>
struct DynamicInvokeResult<void> {
    static void MissingValue() {
    }

    template <typename Fn, typename... Args>
    static void Invoke(Fn fn, Args&&... args) {
        fn(std::forward<Args>(args)...);
    }
};

template <typename Fn>
struct DynamicInvokeFunctionTraits;

template <typename ReturnT, typename... Args>
struct DynamicInvokeFunctionTraits<ReturnT (*)(Args...)> {
    typedef ReturnT ReturnType;
};

#if defined(_M_IX86)
template <typename ReturnT, typename... Args>
struct DynamicInvokeFunctionTraits<ReturnT(__stdcall*)(Args...)> {
    typedef ReturnT ReturnType;
};

template <typename ReturnT, typename... Args>
struct DynamicInvokeFunctionTraits<ReturnT(__fastcall*)(Args...)> {
    typedef ReturnT ReturnType;
};
#endif

template <typename Fn, typename... Args>
typename DynamicInvokeFunctionTraits<Fn>::ReturnType InvokeDynamic(
    const wchar_t* moduleName,
    const char* procName,
    Args&&... args) {
    typedef typename DynamicInvokeFunctionTraits<Fn>::ReturnType ReturnT;

    FARPROC raw = ResolveDynamicProcAddress(moduleName, procName);
    if (raw == nullptr) {
        SetMissingProcErrorValue();
        return DynamicInvokeResult<ReturnT>::MissingValue();
    }

    Fn fn = reinterpret_cast<Fn>(raw);
    return DynamicInvokeResult<ReturnT>::Invoke(fn, std::forward<Args>(args)...);
}

#endif

}  // namespace winapi
}  // namespace wdbl

#ifdef WDBL_ENABLE_DYNAMIC_WINAPI_MACROS

#if defined(_MSC_VER) && _MSC_VER <= 1600
#define WDBL_DYN_WINAPI_CALL(module_name, api_name, ...) ::api_name(__VA_ARGS__)
#else
#define WDBL_DYN_WINAPI_CALL(module_name, api_name, ...) \
    ::wdbl::winapi::InvokeDynamic<decltype(&::api_name)>(module_name, #api_name, __VA_ARGS__)
#endif

#if !defined(_MSC_VER) || _MSC_VER > 1600
#define CloseHandle ::wdbl::winapi::CloseHandle
#define ContinueDebugEvent ::wdbl::winapi::ContinueDebugEvent
#define CreateProcessW ::wdbl::winapi::CreateProcessW
#define CreateToolhelp32Snapshot ::wdbl::winapi::CreateToolhelp32Snapshot
#define DebugActiveProcess ::wdbl::winapi::DebugActiveProcess
#define DebugActiveProcessStop ::wdbl::winapi::DebugActiveProcessStop
#define DebugSetProcessKillOnExit ::wdbl::winapi::DebugSetProcessKillOnExit
#define DebugBreakProcess ::wdbl::winapi::DebugBreakProcess
#define CreateEventW ::wdbl::winapi::CreateEventW
#define DuplicateHandle ::wdbl::winapi::DuplicateHandle
#define FlushInstructionCache ::wdbl::winapi::FlushInstructionCache
#define FreeLibrary ::wdbl::winapi::FreeLibrary
#define GetCurrentDirectoryW ::wdbl::winapi::GetCurrentDirectoryW
#define GetCurrentProcess ::wdbl::winapi::GetCurrentProcess
#define GetCurrentProcessId ::wdbl::winapi::GetCurrentProcessId
#define GetCurrentThread ::wdbl::winapi::GetCurrentThread
#define GetEnvironmentVariableW ::wdbl::winapi::GetEnvironmentVariableW
#define GetExitCodeProcess ::wdbl::winapi::GetExitCodeProcess
#define GetExitCodeThread ::wdbl::winapi::GetExitCodeThread
#define GetFinalPathNameByHandleW ::wdbl::winapi::GetFinalPathNameByHandleW
#define GetFullPathNameW ::wdbl::winapi::GetFullPathNameW
#define GetLastError ::wdbl::winapi::GetLastError
#define GetModuleFileNameW ::wdbl::winapi::GetModuleFileNameW
#define GetModuleHandleW ::wdbl::winapi::GetModuleHandleW
#define GetPriorityClass ::wdbl::winapi::GetPriorityClass
#define GetProcAddress ::wdbl::winapi::GetProcAddress
#define GetTempFileNameW ::wdbl::winapi::GetTempFileNameW
#define GetTempPathW ::wdbl::winapi::GetTempPathW
#define GetSystemInfo ::wdbl::winapi::GetSystemInfo
#define GetNativeSystemInfo ::wdbl::winapi::GetNativeSystemInfo
#define GetThreadContext ::wdbl::winapi::GetThreadContext
#define IsWow64Process2 ::wdbl::winapi::IsWow64Process2
#define LoadLibraryW ::wdbl::winapi::LoadLibraryW
#define Module32FirstW ::wdbl::winapi::Module32FirstW
#define Module32NextW ::wdbl::winapi::Module32NextW
#define OpenProcess ::wdbl::winapi::OpenProcess
#define OpenThread ::wdbl::winapi::OpenThread
#define QueryPerformanceCounter ::wdbl::winapi::QueryPerformanceCounter
#define QueryPerformanceFrequency ::wdbl::winapi::QueryPerformanceFrequency
#define QueryFullProcessImageNameW ::wdbl::winapi::QueryFullProcessImageNameW
#define ReadProcessMemory ::wdbl::winapi::ReadProcessMemory
#define ResetEvent ::wdbl::winapi::ResetEvent
#define SetConsoleOutputCP ::wdbl::winapi::SetConsoleOutputCP
#define SetEvent ::wdbl::winapi::SetEvent
#define SetLastError ::wdbl::winapi::SetLastError
#define SetThreadContext ::wdbl::winapi::SetThreadContext
#define Sleep ::wdbl::winapi::Sleep
#define Thread32First ::wdbl::winapi::Thread32First
#define Thread32Next ::wdbl::winapi::Thread32Next
#define VirtualAllocEx ::wdbl::winapi::VirtualAllocEx
#define VirtualFreeEx ::wdbl::winapi::VirtualFreeEx
#define VirtualProtectEx ::wdbl::winapi::VirtualProtectEx
#define VirtualQueryEx ::wdbl::winapi::VirtualQueryEx
#define WaitForDebugEvent ::wdbl::winapi::WaitForDebugEvent
#define WaitForSingleObjectEx ::wdbl::winapi::WaitForSingleObjectEx
#define WriteProcessMemory ::wdbl::winapi::WriteProcessMemory
#define MultiByteToWideChar ::wdbl::winapi::MultiByteToWideChar
#define WideCharToMultiByte ::wdbl::winapi::WideCharToMultiByte

#define StackWalk64 ::wdbl::winapi::StackWalk64
#define SymCleanup ::wdbl::winapi::SymCleanup
#define SymEnumLinesW ::wdbl::winapi::SymEnumLinesW
#define SymEnumSymbolsW ::wdbl::winapi::SymEnumSymbolsW
#define SymFromAddr ::wdbl::winapi::SymFromAddr
#define SymGetLineFromAddrW64 ::wdbl::winapi::SymGetLineFromAddrW64
#define SymGetModuleInfoW64 ::wdbl::winapi::SymGetModuleInfoW64
#define SymGetOptions ::wdbl::winapi::SymGetOptions
#define SymGetSearchPathW ::wdbl::winapi::SymGetSearchPathW
#define SymGetTypeFromNameW ::wdbl::winapi::SymGetTypeFromNameW
#define SymGetTypeInfo ::wdbl::winapi::SymGetTypeInfo
#define SymInitialize ::wdbl::winapi::SymInitialize
#define SymLoadModuleExW ::wdbl::winapi::SymLoadModuleExW
#define SymRefreshModuleList ::wdbl::winapi::SymRefreshModuleList
#define SymSetOptions ::wdbl::winapi::SymSetOptions
#define SymSetSearchPathW ::wdbl::winapi::SymSetSearchPathW
#define SymUnloadModule64 ::wdbl::winapi::SymUnloadModule64
#endif

#define AppendMenuW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", AppendMenuW, __VA_ARGS__)
#define BeginPaint(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", BeginPaint, __VA_ARGS__)
#define CallWindowProcW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", CallWindowProcW, __VA_ARGS__)
#define CheckDlgButton(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", CheckDlgButton, __VA_ARGS__)
#define CheckMenuRadioItem(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", CheckMenuRadioItem, __VA_ARGS__)
#define ChooseFontW(...) WDBL_DYN_WINAPI_CALL(L"comdlg32.dll", ChooseFontW, __VA_ARGS__)
#define ClientToScreen(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", ClientToScreen, __VA_ARGS__)
#define CloseClipboard(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", CloseClipboard, __VA_ARGS__)
#define CoTaskMemFree(...) WDBL_DYN_WINAPI_CALL(L"ole32.dll", CoTaskMemFree, __VA_ARGS__)
#define CommandLineToArgvW(...) WDBL_DYN_WINAPI_CALL(L"shell32.dll", CommandLineToArgvW, __VA_ARGS__)
#define CreateDirectoryW(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", CreateDirectoryW, __VA_ARGS__)
#define CreateFileW(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", CreateFileW, __VA_ARGS__)
#define CreateFontW(...) WDBL_DYN_WINAPI_CALL(L"gdi32.dll", CreateFontW, __VA_ARGS__)
#define CreateMenu(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", CreateMenu, __VA_ARGS__)
#define CreatePen(...) WDBL_DYN_WINAPI_CALL(L"gdi32.dll", CreatePen, __VA_ARGS__)
#define CreatePipe(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", CreatePipe, __VA_ARGS__)
#define CreatePopupMenu(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", CreatePopupMenu, __VA_ARGS__)
#define CreateSolidBrush(...) WDBL_DYN_WINAPI_CALL(L"gdi32.dll", CreateSolidBrush, __VA_ARGS__)
#define CreateThread(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", CreateThread, __VA_ARGS__)
#define CreateWindowExW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", CreateWindowExW, __VA_ARGS__)
#define DefFrameProcW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", DefFrameProcW, __VA_ARGS__)
#define DefMDIChildProcW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", DefMDIChildProcW, __VA_ARGS__)
#define DefWindowProcW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", DefWindowProcW, __VA_ARGS__)
#define DeleteMenu(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", DeleteMenu, __VA_ARGS__)
#define DeleteObject(...) WDBL_DYN_WINAPI_CALL(L"gdi32.dll", DeleteObject, __VA_ARGS__)
#define DestroyMenu(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", DestroyMenu, __VA_ARGS__)
#define DestroyWindow(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", DestroyWindow, __VA_ARGS__)
#define DispatchMessageW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", DispatchMessageW, __VA_ARGS__)
#define DragAcceptFiles(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", DragAcceptFiles, __VA_ARGS__)
#define DragFinish(...) WDBL_DYN_WINAPI_CALL(L"shell32.dll", DragFinish, __VA_ARGS__)
#define DragQueryFileW(...) WDBL_DYN_WINAPI_CALL(L"shell32.dll", DragQueryFileW, __VA_ARGS__)
#define DrawFocusRect(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", DrawFocusRect, __VA_ARGS__)
#define DrawMenuBar(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", DrawMenuBar, __VA_ARGS__)
#define DrawTextW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", DrawTextW, __VA_ARGS__)
#define EmptyClipboard(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", EmptyClipboard, __VA_ARGS__)
#define EnableWindow(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", EnableWindow, __VA_ARGS__)
#define EndPaint(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", EndPaint, __VA_ARGS__)
#define EnumWindows(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", EnumWindows, __VA_ARGS__)
#define FillRect(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", FillRect, __VA_ARGS__)
#define FindClose(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", FindClose, __VA_ARGS__)
#define FindFirstFileW(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", FindFirstFileW, __VA_ARGS__)
#define FindNextFileW(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", FindNextFileW, __VA_ARGS__)
#define FlushFileBuffers(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", FlushFileBuffers, __VA_ARGS__)
#define FrameRect(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", FrameRect, __VA_ARGS__)
#define GetClientRect(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetClientRect, __VA_ARGS__)
#define GetCommandLineW(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", GetCommandLineW, __VA_ARGS__)
#define GetCurrentThreadId(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", GetCurrentThreadId, __VA_ARGS__)
#define GetCursorPos(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetCursorPos, __VA_ARGS__)
#define GetDC(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetDC, __VA_ARGS__)
#define GetDlgItem(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetDlgItem, __VA_ARGS__)
#define GetDpiForWindow(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetDpiForWindow, __VA_ARGS__)
#define GetFileAttributesExW(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", GetFileAttributesExW, __VA_ARGS__)
#define GetFileAttributesW(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", GetFileAttributesW, __VA_ARGS__)
#define GetFileVersionInfoSizeW(...) WDBL_DYN_WINAPI_CALL(L"version.dll", GetFileVersionInfoSizeW, __VA_ARGS__)
#define GetFileVersionInfoW(...) WDBL_DYN_WINAPI_CALL(L"version.dll", GetFileVersionInfoW, __VA_ARGS__)
#define GetKeyState(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetKeyState, __VA_ARGS__)
#define GetLocalTime(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", GetLocalTime, __VA_ARGS__)
#define GetMenu(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetMenu, __VA_ARGS__)
#define GetMenuItemCount(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetMenuItemCount, __VA_ARGS__)
#define GetMessagePos(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetMessagePos, __VA_ARGS__)
#define GetMessageW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetMessageW, __VA_ARGS__)
#define GetOpenFileNameW(...) WDBL_DYN_WINAPI_CALL(L"comdlg32.dll", GetOpenFileNameW, __VA_ARGS__)
#define GetParent(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetParent, __VA_ARGS__)
#define GetPrivateProfileIntW(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", GetPrivateProfileIntW, __VA_ARGS__)
#define GetPrivateProfileStringW(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", GetPrivateProfileStringW, __VA_ARGS__)
#define GetPropW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetPropW, __VA_ARGS__)
#define GetSaveFileNameW(...) WDBL_DYN_WINAPI_CALL(L"comdlg32.dll", GetSaveFileNameW, __VA_ARGS__)
#define GetScrollInfo(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetScrollInfo, __VA_ARGS__)
#define GetStockObject(...) WDBL_DYN_WINAPI_CALL(L"gdi32.dll", GetStockObject, __VA_ARGS__)
#define GetSystemMetrics(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetSystemMetrics, __VA_ARGS__)
#define GetTextExtentPoint32W(...) WDBL_DYN_WINAPI_CALL(L"gdi32.dll", GetTextExtentPoint32W, __VA_ARGS__)
#define GetTickCount64(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", GetTickCount64, __VA_ARGS__)
#define GetWindow(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetWindow, __VA_ARGS__)
#ifdef GetWindowLongPtrW
#undef GetWindowLongPtrW
#endif
#if defined(_WIN64)
#define GetWindowLongPtrW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetWindowLongPtrW, __VA_ARGS__)
#else
#define GetWindowLongPtrW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetWindowLongW, __VA_ARGS__)
#endif
#define GetWindowRect(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetWindowRect, __VA_ARGS__)
#define GetWindowTextLengthW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetWindowTextLengthW, __VA_ARGS__)
#define GetWindowTextW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetWindowTextW, __VA_ARGS__)
#define GetWindowThreadProcessId(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", GetWindowThreadProcessId, __VA_ARGS__)
#define GlobalAlloc(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", GlobalAlloc, __VA_ARGS__)
#define GlobalFree(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", GlobalFree, __VA_ARGS__)
#define GlobalLock(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", GlobalLock, __VA_ARGS__)
#define GlobalUnlock(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", GlobalUnlock, __VA_ARGS__)
#define InitCommonControlsEx(...) WDBL_DYN_WINAPI_CALL(L"comctl32.dll", InitCommonControlsEx, __VA_ARGS__)
#define InflateRect(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", InflateRect, __VA_ARGS__)
#define InvalidateRect(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", InvalidateRect, __VA_ARGS__)
#define IsDialogMessageW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", IsDialogMessageW, __VA_ARGS__)
#define IsDlgButtonChecked(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", IsDlgButtonChecked, __VA_ARGS__)
#define IsRectEmpty(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", IsRectEmpty, __VA_ARGS__)
#define IsWindow(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", IsWindow, __VA_ARGS__)
#define IsWindowVisible(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", IsWindowVisible, __VA_ARGS__)
#define LineTo(...) WDBL_DYN_WINAPI_CALL(L"gdi32.dll", LineTo, __VA_ARGS__)
#define LoadCursorA(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", LoadCursorA, __VA_ARGS__)
#define LoadCursorW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", LoadCursorW, __VA_ARGS__)
#ifdef LoadCursor
#undef LoadCursor
#endif
#ifdef UNICODE
#define LoadCursor(...) LoadCursorW(__VA_ARGS__)
#else
#define LoadCursor(...) LoadCursorA(__VA_ARGS__)
#endif
#define LoadIconW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", LoadIconW, __VA_ARGS__)
#define LoadImageW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", LoadImageW, __VA_ARGS__)
#define LocalFree(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", LocalFree, __VA_ARGS__)
#define lstrcpynW(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", lstrcpynW, __VA_ARGS__)
#define MessageBoxW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", MessageBoxW, __VA_ARGS__)
#define MoveToEx(...) WDBL_DYN_WINAPI_CALL(L"gdi32.dll", MoveToEx, __VA_ARGS__)
#define MoveWindow(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", MoveWindow, __VA_ARGS__)
#define MulDiv(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", MulDiv, __VA_ARGS__)
#define OffsetRect(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", OffsetRect, __VA_ARGS__)
#define OpenClipboard(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", OpenClipboard, __VA_ARGS__)
#define Polyline(...) WDBL_DYN_WINAPI_CALL(L"gdi32.dll", Polyline, __VA_ARGS__)
#define PostMessageW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", PostMessageW, __VA_ARGS__)
#define PostQuitMessage(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", PostQuitMessage, __VA_ARGS__)
#define Process32FirstW(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", Process32FirstW, __VA_ARGS__)
#define Process32NextW(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", Process32NextW, __VA_ARGS__)
#define PtInRect(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", PtInRect, __VA_ARGS__)
#define ReadFile(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", ReadFile, __VA_ARGS__)
#define Rectangle(...) WDBL_DYN_WINAPI_CALL(L"gdi32.dll", Rectangle, __VA_ARGS__)
#define RedrawWindow(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", RedrawWindow, __VA_ARGS__)
#define RegisterClassW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", RegisterClassW, __VA_ARGS__)
#define ReleaseCapture(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", ReleaseCapture, __VA_ARGS__)
#define ReleaseDC(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", ReleaseDC, __VA_ARGS__)
#define RemovePropW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", RemovePropW, __VA_ARGS__)
#define ResumeThread(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", ResumeThread, __VA_ARGS__)
#define ScreenToClient(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", ScreenToClient, __VA_ARGS__)
#define SelectObject(...) WDBL_DYN_WINAPI_CALL(L"gdi32.dll", SelectObject, __VA_ARGS__)
#define SendMessageW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", SendMessageW, __VA_ARGS__)
#define SetBkColor(...) WDBL_DYN_WINAPI_CALL(L"gdi32.dll", SetBkColor, __VA_ARGS__)
#define SetBkMode(...) WDBL_DYN_WINAPI_CALL(L"gdi32.dll", SetBkMode, __VA_ARGS__)
#define SetCapture(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", SetCapture, __VA_ARGS__)
#define SetClipboardData(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", SetClipboardData, __VA_ARGS__)
#define SetCursor(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", SetCursor, __VA_ARGS__)
#define SetFocus(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", SetFocus, __VA_ARGS__)
#define SetForegroundWindow(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", SetForegroundWindow, __VA_ARGS__)
#define SetHandleInformation(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", SetHandleInformation, __VA_ARGS__)
#define SetMenu(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", SetMenu, __VA_ARGS__)
#define SetParent(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", SetParent, __VA_ARGS__)
#define SetPropW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", SetPropW, __VA_ARGS__)
#define SetRect(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", SetRect, __VA_ARGS__)
#define SetRectEmpty(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", SetRectEmpty, __VA_ARGS__)
#define SetScrollInfo(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", SetScrollInfo, __VA_ARGS__)
#define SetScrollPos(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", SetScrollPos, __VA_ARGS__)
#define SetTextColor(...) WDBL_DYN_WINAPI_CALL(L"gdi32.dll", SetTextColor, __VA_ARGS__)
#ifdef SetWindowLongPtrW
#undef SetWindowLongPtrW
#endif
#if defined(_WIN64)
#define SetWindowLongPtrW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", SetWindowLongPtrW, __VA_ARGS__)
#else
#define SetWindowLongPtrW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", SetWindowLongW, __VA_ARGS__)
#endif
#define SetWindowPos(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", SetWindowPos, __VA_ARGS__)
#define SetWindowTextW(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", SetWindowTextW, __VA_ARGS__)
#define SHBrowseForFolderW(...) WDBL_DYN_WINAPI_CALL(L"shell32.dll", SHBrowseForFolderW, __VA_ARGS__)
#define ShellExecuteW(...) WDBL_DYN_WINAPI_CALL(L"shell32.dll", ShellExecuteW, __VA_ARGS__)
#define SHGetPathFromIDListW(...) WDBL_DYN_WINAPI_CALL(L"shell32.dll", SHGetPathFromIDListW, __VA_ARGS__)
#define ShowWindow(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", ShowWindow, __VA_ARGS__)
#define SuspendThread(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", SuspendThread, __VA_ARGS__)
#define TerminateProcess(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", TerminateProcess, __VA_ARGS__)
#define TextOutW(...) WDBL_DYN_WINAPI_CALL(L"gdi32.dll", TextOutW, __VA_ARGS__)
#define TrackPopupMenu(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", TrackPopupMenu, __VA_ARGS__)
#define TranslateMessage(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", TranslateMessage, __VA_ARGS__)
#define UpdateWindow(...) WDBL_DYN_WINAPI_CALL(L"user32.dll", UpdateWindow, __VA_ARGS__)
#define VerQueryValueW(...) WDBL_DYN_WINAPI_CALL(L"version.dll", VerQueryValueW, __VA_ARGS__)
#define WaitForSingleObject(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", WaitForSingleObject, __VA_ARGS__)
#define WriteFile(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", WriteFile, __VA_ARGS__)
#define WritePrivateProfileStringW(...) WDBL_DYN_WINAPI_CALL(L"kernel32.dll", WritePrivateProfileStringW, __VA_ARGS__)

#endif

