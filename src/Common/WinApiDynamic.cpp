#include "WinApiDynamic.h"
#include <WinIoCtl.h>
#include "WinDbgLiteMemIoctl.h"

#include <cstring>
#include <limits>
#include "StdCompat.h"
#include <string>
#include <unordered_map>
#include <vector>

namespace {

std::mutex g_dynamicProcCacheMutex;
std::unordered_map<std::wstring, FARPROC> g_dynamicProcCache;

std::wstring MakeProcCacheKey(const wchar_t* moduleName, const char* procName) {
    std::wstring key = moduleName != nullptr ? moduleName : L"";
    key.push_back(L'!');
    if (procName != nullptr) {
        while (*procName != '\0') {
            key.push_back(static_cast<unsigned char>(*procName));
            ++procName;
        }
    }
    return key;
}

template <typename Fn>
Fn ResolveProc(const wchar_t* moduleName, const char* procName) {
    HMODULE module = ::GetModuleHandleW(moduleName);
    if (module == nullptr) {
        module = ::LoadLibraryW(moduleName);
    }
    if (module == nullptr) {
        return nullptr;
    }
    return reinterpret_cast<Fn>(::GetProcAddress(module, procName));
}

void SetMissingProcError() {
    ::SetLastError(ERROR_PROC_NOT_FOUND);
}

std::mutex g_processMemoryDriverMutex;
bool g_processMemoryPreferDriver = false;
std::wstring g_processMemoryDriverDevicePath = WDBL_MEM_DRIVER_DEFAULT_DEVICE_PATH;
HANDLE g_processMemoryDriverHandle = INVALID_HANDLE_VALUE;
bool g_processMemoryDriverOpenAttempted = false;
DWORD g_processMemoryDriverLastError = ERROR_SUCCESS;
bool g_processDebugDriverActive = false;
DWORD g_processDebugDriverProcessId = 0;

bool IsOpenDriverHandle(HANDLE handle) {
    return handle != nullptr && handle != INVALID_HANDLE_VALUE;
}

bool BuildSecureDriverInput(DWORD ioControlCode, const void* payload, DWORD payloadSize, std::vector<BYTE>* input) {
    if (input == nullptr || (payloadSize > 0 && payload == nullptr)) {
        return false;
    }
    if (payloadSize > (std::numeric_limits<DWORD>::max)() - sizeof(WDBL_IOCTL_PACKET_HEADER)) {
        return false;
    }

    const DWORD totalSize = static_cast<DWORD>(sizeof(WDBL_IOCTL_PACKET_HEADER)) + payloadSize;
    input->assign(totalSize, 0);

    WDBL_IOCTL_PACKET_HEADER* header = reinterpret_cast<WDBL_IOCTL_PACKET_HEADER*>(&(*input)[0]);
    header->Magic = WDBL_IOCTL_PROTOCOL_MAGIC;
    header->Version = WDBL_IOCTL_PROTOCOL_VERSION;
    header->HeaderSize = static_cast<ULONG>(sizeof(WDBL_IOCTL_PACKET_HEADER));
    header->PayloadSize = payloadSize;
    header->IoControlCode = ioControlCode;

    if (payloadSize > 0) {
        std::memcpy(&(*input)[sizeof(WDBL_IOCTL_PACKET_HEADER)], payload, payloadSize);
    }
    header->PayloadChecksum = WdblIoctlPayloadChecksum(&(*input)[sizeof(WDBL_IOCTL_PACKET_HEADER)], payloadSize);
    header->HeaderChecksum = WdblIoctlHeaderChecksum(header);
    WdblIoctlCryptPayload(&(*input)[sizeof(WDBL_IOCTL_PACKET_HEADER)], payloadSize, ioControlCode);
    return true;
}

BOOL SendSecureDriverIoctl(
    HANDLE driverHandle,
    DWORD ioControlCode,
    const void* payload,
    DWORD payloadSize,
    void* output,
    DWORD outputSize,
    DWORD* returnedBytes) {
    std::vector<BYTE> input;
    if (!BuildSecureDriverInput(ioControlCode, payload, payloadSize, &input)) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    return ::DeviceIoControl(
        driverHandle,
        ioControlCode,
        input.empty() ? nullptr : &input[0],
        static_cast<DWORD>(input.size()),
        output,
        outputSize,
        returnedBytes,
        nullptr);
}

template <typename TEntry>
BOOL QueryDriverEnumerationResult(DWORD ioControlCode, const void* payload, DWORD payloadSize, std::vector<TEntry>* entries) {
    if (entries == nullptr) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    entries->clear();

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        if (!g_processMemoryPreferDriver) {
            ::SetLastError(ERROR_NOT_SUPPORTED);
            return FALSE;
        }
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    std::vector<BYTE> output(262144);
    for (unsigned int attempt = 0; attempt < 3; ++attempt) {
        DWORD returnedBytes = 0;
        const BOOL ok = SendSecureDriverIoctl(
            driverHandle,
            ioControlCode,
            payload,
            payloadSize,
            output.empty() ? nullptr : &output[0],
            static_cast<DWORD>(output.size()),
            &returnedBytes);
        if (!ok) {
            const DWORD error = ::GetLastError();
            {
                std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
                g_processMemoryDriverLastError = error;
                if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                    CloseProcessMemoryDriverHandleLocked();
                    g_processMemoryDriverOpenAttempted = false;
                }
            }
            return FALSE;
        }

        if (returnedBytes < sizeof(WDBL_ENUM_RESULT_HEADER)) {
            ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }

        const WDBL_ENUM_RESULT_HEADER* header =
            reinterpret_cast<const WDBL_ENUM_RESULT_HEADER*>(&output[0]);
        const size_t payloadBytes = static_cast<size_t>(returnedBytes) - sizeof(WDBL_ENUM_RESULT_HEADER);
        const size_t availableCount = payloadBytes / sizeof(TEntry);
        size_t copyCount = header->ReturnedCount;
        if (copyCount > availableCount) {
            copyCount = availableCount;
        }
        if (copyCount > 0) {
            const TEntry* first =
                reinterpret_cast<const TEntry*>(&output[sizeof(WDBL_ENUM_RESULT_HEADER)]);
            entries->assign(first, first + copyCount);
        }

        if (header->TotalCount <= header->ReturnedCount ||
            header->TotalCount <= availableCount ||
            attempt == 2) {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = ERROR_SUCCESS;
            return TRUE;
        }

        const size_t maxBytes = 16u * 1024u * 1024u;
        const size_t requiredBytes =
            sizeof(WDBL_ENUM_RESULT_HEADER) +
            static_cast<size_t>(header->TotalCount) * sizeof(TEntry);
        size_t nextSize = output.size() * 2;
        if (nextSize < requiredBytes) {
            nextSize = requiredBytes;
        }
        if (nextSize > maxBytes) {
            nextSize = maxBytes;
        }
        if (nextSize <= output.size()) {
            break;
        }
        output.resize(nextSize);
    }

    ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return FALSE;
}

void CloseProcessMemoryDriverHandleLocked() {
    if (IsOpenDriverHandle(g_processMemoryDriverHandle)) {
        ::CloseHandle(g_processMemoryDriverHandle);
    }
    g_processMemoryDriverHandle = INVALID_HANDLE_VALUE;
}

void ResetProcessMemoryDriverStateLocked() {
    CloseProcessMemoryDriverHandleLocked();
    g_processMemoryDriverOpenAttempted = false;
    g_processMemoryDriverLastError = ERROR_SUCCESS;
    g_processDebugDriverActive = false;
    g_processDebugDriverProcessId = 0;
}

HANDLE EnsureProcessMemoryDriverHandleLocked() {
    if (!g_processMemoryPreferDriver) {
        g_processMemoryDriverLastError = ERROR_NOT_SUPPORTED;
        return INVALID_HANDLE_VALUE;
    }
    if (IsOpenDriverHandle(g_processMemoryDriverHandle)) {
        return g_processMemoryDriverHandle;
    }
    if (g_processMemoryDriverOpenAttempted) {
        return INVALID_HANDLE_VALUE;
    }

    g_processMemoryDriverOpenAttempted = true;
    const std::wstring path = g_processMemoryDriverDevicePath.empty()
                                  ? std::wstring(WDBL_MEM_DRIVER_DEFAULT_DEVICE_PATH)
                                  : g_processMemoryDriverDevicePath;
    g_processMemoryDriverHandle = ::CreateFileW(
        path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (!IsOpenDriverHandle(g_processMemoryDriverHandle)) {
        g_processMemoryDriverLastError = ::GetLastError();
        g_processMemoryDriverHandle = INVALID_HANDLE_VALUE;
        return INVALID_HANDLE_VALUE;
    }

    g_processMemoryDriverLastError = ERROR_SUCCESS;
    return g_processMemoryDriverHandle;
}

DWORD ResolveProcessIdFromHandle(HANDLE process) {
    if (process == nullptr || process == INVALID_HANDLE_VALUE) {
        return 0;
    }
    typedef decltype(&::GetProcessId) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetProcessId");
    if (fn == nullptr) {
        return 0;
    }
    return fn(process);
}

DWORD ResolveThreadIdFromHandle(HANDLE thread) {
    if (thread == nullptr || thread == INVALID_HANDLE_VALUE) {
        return 0;
    }
    typedef decltype(&::GetThreadId) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetThreadId");
    if (fn == nullptr) {
        return 0;
    }
    return fn(thread);
}

bool DriverReadProcessMemoryById(DWORD processId, ULONGLONG address, LPVOID buffer, SIZE_T size, SIZE_T* bytesRead) {
    if (bytesRead != nullptr) {
        *bytesRead = 0;
    }
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        if (!g_processMemoryPreferDriver) {
            return false;
        }
    }
    if (size > static_cast<SIZE_T>((std::numeric_limits<DWORD>::max)()) || (size > 0 && buffer == nullptr)) {
        return false;
    }

    if (processId == 0) {
        return false;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return false;
    }

    WDBL_PROCESS_MEMORY_READ_REQUEST request = WDBL_PROCESS_MEMORY_READ_REQUEST();
    request.ProcessId = static_cast<ULONG>(processId);
    request.Address = address;
    request.Size = static_cast<ULONG>(size);

    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_READ_PROCESS_MEMORY,
        &request,
        static_cast<DWORD>(sizeof(request)),
        buffer,
        request.Size,
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return false;
    }

    if (bytesRead != nullptr) {
        *bytesRead = static_cast<SIZE_T>(returnedBytes);
    }
    if (returnedBytes != request.Size) {
        ::SetLastError(ERROR_PARTIAL_COPY);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    return true;
}

bool TryDriverReadProcessMemory(HANDLE process, LPCVOID baseAddress, LPVOID buffer, SIZE_T size, SIZE_T* bytesRead) {
    return DriverReadProcessMemoryById(
        ResolveProcessIdFromHandle(process),
        static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(baseAddress)),
        buffer,
        size,
        bytesRead);
}

bool DriverWriteProcessMemoryById(DWORD processId, ULONGLONG address, LPCVOID buffer, SIZE_T size, SIZE_T* bytesWritten) {
    if (bytesWritten != nullptr) {
        *bytesWritten = 0;
    }
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        if (!g_processMemoryPreferDriver) {
            return false;
        }
    }
    if (size > static_cast<SIZE_T>((std::numeric_limits<DWORD>::max)()) || (size > 0 && buffer == nullptr)) {
        return false;
    }

    if (processId == 0) {
        return false;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return false;
    }

    const size_t headerSize = sizeof(WDBL_PROCESS_MEMORY_WRITE_REQUEST_HEADER);
    if (size > static_cast<SIZE_T>((std::numeric_limits<DWORD>::max)()) - headerSize) {
        return false;
    }
    const size_t inputSize = headerSize + size;
    std::vector<BYTE> input(inputSize);
    WDBL_PROCESS_MEMORY_WRITE_REQUEST_HEADER* request =
        reinterpret_cast<WDBL_PROCESS_MEMORY_WRITE_REQUEST_HEADER*>(input.data());
    request->ProcessId = static_cast<ULONG>(processId);
    request->Address = address;
    request->Size = static_cast<ULONG>(size);
    if (size > 0) {
        std::memcpy(input.data() + headerSize, buffer, size);
    }

    DWORD returnedBytes = 0;
    DWORD kernelBytesWritten = static_cast<DWORD>(size);
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_WRITE_PROCESS_MEMORY,
        &input[0],
        static_cast<DWORD>(inputSize),
        &kernelBytesWritten,
        static_cast<DWORD>(sizeof(kernelBytesWritten)),
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return false;
    }

    const SIZE_T effectiveWritten =
        returnedBytes >= sizeof(kernelBytesWritten) ? static_cast<SIZE_T>(kernelBytesWritten) : size;
    if (bytesWritten != nullptr) {
        *bytesWritten = effectiveWritten;
    }
    if (effectiveWritten != size) {
        ::SetLastError(ERROR_WRITE_FAULT);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    return true;
}

bool TryDriverWriteProcessMemory(HANDLE process, LPVOID baseAddress, LPCVOID buffer, SIZE_T size, SIZE_T* bytesWritten) {
    return DriverWriteProcessMemoryById(
        ResolveProcessIdFromHandle(process),
        static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(baseAddress)),
        buffer,
        size,
        bytesWritten);
}

bool TryDriverGetThreadContext(HANDLE thread, LPCONTEXT context) {
    if (context == nullptr) {
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        if (!g_processMemoryPreferDriver) {
            return false;
        }
    }

    const DWORD threadId = ResolveThreadIdFromHandle(thread);
    if (threadId == 0) {
        return false;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return false;
    }

    WDBL_THREAD_CONTEXT_REQUEST request = WDBL_THREAD_CONTEXT_REQUEST();
    request.ThreadId = static_cast<ULONG>(threadId);
    request.ContextFlags = context->ContextFlags;

    CONTEXT kernelContext = CONTEXT();
    kernelContext.ContextFlags = request.ContextFlags;
    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_GET_THREAD_CONTEXT,
        &request,
        static_cast<DWORD>(sizeof(request)),
        &kernelContext,
        static_cast<DWORD>(sizeof(kernelContext)),
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return false;
    }

    if (returnedBytes < sizeof(CONTEXT)) {
        ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return false;
    }

    *context = kernelContext;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    return true;
}

bool TryDriverSetThreadContext(HANDLE thread, const CONTEXT* context) {
    if (context == nullptr) {
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        if (!g_processMemoryPreferDriver) {
            return false;
        }
    }

    const DWORD threadId = ResolveThreadIdFromHandle(thread);
    if (threadId == 0) {
        return false;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return false;
    }

    const size_t inputSize = sizeof(WDBL_THREAD_CONTEXT_REQUEST) + sizeof(CONTEXT);
    std::vector<BYTE> input(inputSize);
    WDBL_THREAD_CONTEXT_REQUEST* request = reinterpret_cast<WDBL_THREAD_CONTEXT_REQUEST*>(input.data());
    request->ThreadId = static_cast<ULONG>(threadId);
    request->ContextFlags = context->ContextFlags;
    std::memcpy(input.data() + sizeof(WDBL_THREAD_CONTEXT_REQUEST), context, sizeof(CONTEXT));

    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_SET_THREAD_CONTEXT,
        &input[0],
        static_cast<DWORD>(inputSize),
        nullptr,
        0,
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    return true;
}

bool DriverVirtualQueryExById(DWORD processId, ULONGLONG address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length, SIZE_T* bytesReturned) {
    if (bytesReturned != nullptr) {
        *bytesReturned = 0;
    }
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        if (!g_processMemoryPreferDriver) {
            return false;
        }
    }
    if (buffer == nullptr || length < sizeof(MEMORY_BASIC_INFORMATION)) {
        return false;
    }

    if (processId == 0) {
        return false;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return false;
    }

    WDBL_VIRTUAL_MEMORY_QUERY_REQUEST request = WDBL_VIRTUAL_MEMORY_QUERY_REQUEST();
    request.ProcessId = static_cast<ULONG>(processId);
    request.Address = address;

    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_QUERY_VIRTUAL_MEMORY,
        &request,
        static_cast<DWORD>(sizeof(request)),
        buffer,
        static_cast<DWORD>(sizeof(MEMORY_BASIC_INFORMATION)),
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return false;
    }

    if (returnedBytes < sizeof(MEMORY_BASIC_INFORMATION)) {
        ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return false;
    }

    if (bytesReturned != nullptr) {
        *bytesReturned = static_cast<SIZE_T>(returnedBytes);
    }
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    return true;
}

bool TryDriverVirtualQueryEx(HANDLE process, LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length, SIZE_T* bytesReturned) {
    return DriverVirtualQueryExById(
        ResolveProcessIdFromHandle(process),
        static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(address)),
        buffer,
        length,
        bytesReturned);
}

bool DriverVirtualProtectExById(DWORD processId, ULONGLONG address, SIZE_T size, DWORD newProtect, PDWORD oldProtect) {
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        if (!g_processMemoryPreferDriver) {
            return false;
        }
    }
    if (size == 0) {
        return false;
    }

    if (processId == 0) {
        return false;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return false;
    }

    WDBL_VIRTUAL_MEMORY_PROTECT_REQUEST request = WDBL_VIRTUAL_MEMORY_PROTECT_REQUEST();
    request.ProcessId = static_cast<ULONG>(processId);
    request.Address = address;
    request.Size = static_cast<ULONGLONG>(size);
    request.NewProtect = newProtect;

    WDBL_VIRTUAL_MEMORY_PROTECT_RESULT result = WDBL_VIRTUAL_MEMORY_PROTECT_RESULT();
    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_PROTECT_VIRTUAL_MEMORY,
        &request,
        static_cast<DWORD>(sizeof(request)),
        &result,
        static_cast<DWORD>(sizeof(result)),
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return false;
    }

    if (oldProtect != nullptr) {
        *oldProtect = result.OldProtect;
    }
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    return true;
}

bool TryDriverVirtualProtectEx(HANDLE process, LPVOID address, SIZE_T size, DWORD newProtect, PDWORD oldProtect) {
    return DriverVirtualProtectExById(
        ResolveProcessIdFromHandle(process),
        static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(address)),
        size,
        newProtect,
        oldProtect);
}

ULONGLONG DriverVirtualAllocExById(DWORD processId, ULONGLONG address, SIZE_T size, DWORD allocationType, DWORD protect) {
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        if (!g_processMemoryPreferDriver) {
            return 0;
        }
    }
    if (size == 0) {
        return 0;
    }

    if (processId == 0) {
        return 0;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return 0;
    }

    WDBL_VIRTUAL_MEMORY_ALLOCATE_REQUEST request = WDBL_VIRTUAL_MEMORY_ALLOCATE_REQUEST();
    request.ProcessId = static_cast<ULONG>(processId);
    request.BaseAddress = address;
    request.Size = static_cast<ULONGLONG>(size);
    request.AllocationType = allocationType;
    request.Protect = protect;

    WDBL_VIRTUAL_MEMORY_ALLOCATE_RESULT result = WDBL_VIRTUAL_MEMORY_ALLOCATE_RESULT();
    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_ALLOCATE_VIRTUAL_MEMORY,
        &request,
        static_cast<DWORD>(sizeof(request)),
        &result,
        static_cast<DWORD>(sizeof(result)),
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return 0;
    }

    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    return result.BaseAddress;
}

LPVOID TryDriverVirtualAllocEx(HANDLE process, LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect) {
    const ULONGLONG result = DriverVirtualAllocExById(
        ResolveProcessIdFromHandle(process),
        static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(address)),
        size,
        allocationType,
        protect);
    return result == 0 ? nullptr : reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(result));
}

bool DriverVirtualFreeExById(DWORD processId, ULONGLONG address, SIZE_T size, DWORD freeType) {
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        if (!g_processMemoryPreferDriver) {
            return false;
        }
    }

    if (processId == 0 || address == 0) {
        return false;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return false;
    }

    WDBL_VIRTUAL_MEMORY_FREE_REQUEST request = WDBL_VIRTUAL_MEMORY_FREE_REQUEST();
    request.ProcessId = static_cast<ULONG>(processId);
    request.BaseAddress = address;
    request.Size = static_cast<ULONGLONG>(size);
    request.FreeType = freeType;

    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_FREE_VIRTUAL_MEMORY,
        &request,
        static_cast<DWORD>(sizeof(request)),
        nullptr,
        0,
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    return true;
}

bool TryDriverVirtualFreeEx(HANDLE process, LPVOID address, SIZE_T size, DWORD freeType) {
    return DriverVirtualFreeExById(
        ResolveProcessIdFromHandle(process),
        static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(address)),
        size,
        freeType);
}

void MarkDriverDebugSession(bool active, DWORD processId) {
    std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
    g_processDebugDriverActive = active;
    g_processDebugDriverProcessId = active ? processId : 0;
}

bool IsDriverDebugSessionActive() {
    std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
    return g_processDebugDriverActive;
}

bool SendDriverDebugIoctl(
    DWORD ioControlCode,
    const void* input,
    DWORD inputSize,
    void* output,
    DWORD outputSize,
    DWORD* returnedBytes) {
    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return false;
    }

    DWORD localReturnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        ioControlCode,
        input,
        inputSize,
        output,
        outputSize,
        returnedBytes != nullptr ? returnedBytes : &localReturnedBytes);
    if (!ok) {
        DWORD error = ::GetLastError();
        if (error == ERROR_TIMEOUT) {
            error = ERROR_SEM_TIMEOUT;
            ::SetLastError(error);
        }
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
                g_processDebugDriverActive = false;
                g_processDebugDriverProcessId = 0;
            }
        }
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    return true;
}

bool TryDriverDebugActiveProcess(DWORD processId) {
    if (processId == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    WDBL_DEBUG_ACTIVE_PROCESS_REQUEST request = WDBL_DEBUG_ACTIVE_PROCESS_REQUEST();
    request.ProcessId = processId;
    if (!SendDriverDebugIoctl(
            IOCTL_WDBL_DEBUG_ACTIVE_PROCESS,
            &request,
            static_cast<DWORD>(sizeof(request)),
            nullptr,
            0,
            nullptr)) {
        return false;
    }

    MarkDriverDebugSession(true, processId);
    return true;
}

bool TryDriverDebugActiveProcessStop(DWORD processId) {
    WDBL_DEBUG_ACTIVE_PROCESS_STOP_REQUEST request = WDBL_DEBUG_ACTIVE_PROCESS_STOP_REQUEST();
    request.ProcessId = processId;
    if (!SendDriverDebugIoctl(
            IOCTL_WDBL_DEBUG_ACTIVE_PROCESS_STOP,
            &request,
            static_cast<DWORD>(sizeof(request)),
            nullptr,
            0,
            nullptr)) {
        return false;
    }

    MarkDriverDebugSession(false, 0);
    return true;
}

void FillDebugEventFromDriverResult(const WDBL_DEBUG_EVENT_RESULT& source, LPDEBUG_EVENT target) {
    std::memset(target, 0, sizeof(*target));
    target->dwDebugEventCode = source.DebugEventCode;
    target->dwProcessId = source.ProcessId;
    target->dwThreadId = source.ThreadId;

    if (source.DebugEventCode == EXCEPTION_DEBUG_EVENT) {
        target->u.Exception.dwFirstChance = source.FirstChance;
        target->u.Exception.ExceptionRecord.ExceptionCode = source.ExceptionCode;
        target->u.Exception.ExceptionRecord.ExceptionFlags = source.ExceptionFlags;
        target->u.Exception.ExceptionRecord.ExceptionRecord =
            reinterpret_cast<PEXCEPTION_RECORD>(static_cast<ULONG_PTR>(source.ExceptionRecord));
        target->u.Exception.ExceptionRecord.ExceptionAddress =
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(source.ExceptionAddress));
        target->u.Exception.ExceptionRecord.NumberParameters = source.NumberParameters;
        if (target->u.Exception.ExceptionRecord.NumberParameters > EXCEPTION_MAXIMUM_PARAMETERS) {
            target->u.Exception.ExceptionRecord.NumberParameters = EXCEPTION_MAXIMUM_PARAMETERS;
        }
        for (DWORD i = 0; i < target->u.Exception.ExceptionRecord.NumberParameters; ++i) {
            target->u.Exception.ExceptionRecord.ExceptionInformation[i] =
                static_cast<ULONG_PTR>(source.ExceptionInformation[i]);
        }
    } else if (source.DebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
        target->u.CreateThread.hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, source.ThreadId);
        target->u.CreateThread.lpStartAddress =
            reinterpret_cast<LPTHREAD_START_ROUTINE>(static_cast<ULONG_PTR>(source.StartAddress));
    } else if (source.DebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
        target->u.CreateProcessInfo.hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, source.ProcessId);
        target->u.CreateProcessInfo.hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, source.ThreadId);
        target->u.CreateProcessInfo.lpBaseOfImage =
            reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(source.BaseOfImage));
        target->u.CreateProcessInfo.dwDebugInfoFileOffset = source.DebugInfoFileOffset;
        target->u.CreateProcessInfo.nDebugInfoSize = source.DebugInfoSize;
        target->u.CreateProcessInfo.lpStartAddress =
            reinterpret_cast<LPTHREAD_START_ROUTINE>(static_cast<ULONG_PTR>(source.StartAddress));
    } else if (source.DebugEventCode == EXIT_THREAD_DEBUG_EVENT) {
        target->u.ExitThread.dwExitCode = source.ExitCode;
    } else if (source.DebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
        target->u.ExitProcess.dwExitCode = source.ExitCode;
    } else if (source.DebugEventCode == LOAD_DLL_DEBUG_EVENT) {
        target->u.LoadDll.lpBaseOfDll = reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(source.BaseOfDll));
        target->u.LoadDll.dwDebugInfoFileOffset = source.DebugInfoFileOffset;
        target->u.LoadDll.nDebugInfoSize = source.DebugInfoSize;
        target->u.LoadDll.lpImageName = nullptr;
        target->u.LoadDll.fUnicode = TRUE;
    } else if (source.DebugEventCode == UNLOAD_DLL_DEBUG_EVENT) {
        target->u.UnloadDll.lpBaseOfDll =
            reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(source.UnloadBaseOfDll));
    }
}

bool TryDriverWaitForDebugEvent(LPDEBUG_EVENT debugEvent, DWORD milliseconds) {
    if (debugEvent == nullptr) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    if (!IsDriverDebugSessionActive()) {
        ::SetLastError(ERROR_NOT_SUPPORTED);
        return false;
    }

    WDBL_WAIT_FOR_DEBUG_EVENT_REQUEST request = WDBL_WAIT_FOR_DEBUG_EVENT_REQUEST();
    request.TimeoutMilliseconds = milliseconds;
    WDBL_DEBUG_EVENT_RESULT result = WDBL_DEBUG_EVENT_RESULT();
    DWORD returnedBytes = 0;
    if (!SendDriverDebugIoctl(
            IOCTL_WDBL_WAIT_FOR_DEBUG_EVENT,
            &request,
            static_cast<DWORD>(sizeof(request)),
            &result,
            static_cast<DWORD>(sizeof(result)),
            &returnedBytes)) {
        return false;
    }
    if (returnedBytes < sizeof(result) || result.DebugEventCode == 0) {
        ::SetLastError(ERROR_NOT_SUPPORTED);
        return false;
    }

    FillDebugEventFromDriverResult(result, debugEvent);
    return true;
}

bool TryDriverContinueDebugEvent(DWORD processId, DWORD threadId, DWORD continueStatus) {
    if (!IsDriverDebugSessionActive()) {
        ::SetLastError(ERROR_NOT_SUPPORTED);
        return false;
    }

    WDBL_CONTINUE_DEBUG_EVENT_REQUEST request = WDBL_CONTINUE_DEBUG_EVENT_REQUEST();
    request.ProcessId = processId;
    request.ThreadId = threadId;
    request.ContinueStatus = continueStatus;
    return SendDriverDebugIoctl(
        IOCTL_WDBL_CONTINUE_DEBUG_EVENT,
        &request,
        static_cast<DWORD>(sizeof(request)),
        nullptr,
        0,
        nullptr);
}

}  // namespace

namespace wdbl {
namespace winapi {

FARPROC ResolveDynamicProcAddress(const wchar_t* moduleName, const char* procName) {
    if (moduleName == nullptr || procName == nullptr || *procName == '\0') {
        SetMissingProcError();
        return nullptr;
    }

    const std::wstring key = MakeProcCacheKey(moduleName, procName);
    {
        std::lock_guard<std::mutex> lock(g_dynamicProcCacheMutex);
        std::unordered_map<std::wstring, FARPROC>::const_iterator it = g_dynamicProcCache.find(key);
        if (it != g_dynamicProcCache.end()) {
            return it->second;
        }
    }

    HMODULE module = ::GetModuleHandleW(moduleName);
    if (module == nullptr) {
        module = ::LoadLibraryW(moduleName);
    }

    FARPROC proc = nullptr;
    if (module != nullptr) {
        proc = ::GetProcAddress(module, procName);
    }

    {
        std::lock_guard<std::mutex> lock(g_dynamicProcCacheMutex);
        g_dynamicProcCache.insert(std::make_pair(key, proc));
    }
    return proc;
}

void SetMissingProcErrorValue() {
    SetMissingProcError();
}

BOOL CloseHandle(HANDLE object) {
    typedef decltype(&::CloseHandle) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "CloseHandle");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(object);
}

BOOL ContinueDebugEvent(DWORD processId, DWORD threadId, DWORD continueStatus) {
    if (IsDriverDebugSessionActive()) {
        return TryDriverContinueDebugEvent(processId, threadId, continueStatus) ? TRUE : FALSE;
    }

    typedef decltype(&::ContinueDebugEvent) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "ContinueDebugEvent");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(processId, threadId, continueStatus);
}

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
    LPPROCESS_INFORMATION processInformation) {
    typedef decltype(&::CreateProcessW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "CreateProcessW");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(
        applicationName,
        commandLine,
        processAttributes,
        threadAttributes,
        inheritHandles,
        creationFlags,
        environment,
        currentDirectory,
        startupInfo,
        processInformation);
}

HANDLE CreateToolhelp32Snapshot(DWORD flags, DWORD processId) {
    typedef decltype(&::CreateToolhelp32Snapshot) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "CreateToolhelp32Snapshot");
    if (fn == nullptr) {
        SetMissingProcError();
        return INVALID_HANDLE_VALUE;
    }
    return fn(flags, processId);
}

BOOL DebugActiveProcess(DWORD processId) {
    if (TryDriverDebugActiveProcess(processId)) {
        return TRUE;
    }

    typedef decltype(&::DebugActiveProcess) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "DebugActiveProcess");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    const BOOL ok = fn(processId);
    if (ok) {
        MarkDriverDebugSession(false, 0);
    }
    return ok;
}

BOOL DebugActiveProcessStop(DWORD processId) {
    if (IsDriverDebugSessionActive()) {
        const BOOL ok = TryDriverDebugActiveProcessStop(processId) ? TRUE : FALSE;
        if (ok) {
            MarkDriverDebugSession(false, 0);
        }
        return ok;
    }

    typedef decltype(&::DebugActiveProcessStop) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "DebugActiveProcessStop");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(processId);
}

BOOL DebugSetProcessKillOnExit(BOOL killOnExit) {
    typedef decltype(&::DebugSetProcessKillOnExit) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "DebugSetProcessKillOnExit");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(killOnExit);
}

BOOL DebugBreakProcess(HANDLE process) {
    typedef decltype(&::DebugBreakProcess) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "DebugBreakProcess");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process);
}

HANDLE CreateEventW(LPSECURITY_ATTRIBUTES eventAttributes, BOOL manualReset, BOOL initialState, LPCWSTR name) {
    typedef decltype(&::CreateEventW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "CreateEventW");
    if (fn == nullptr) {
        SetMissingProcError();
        return nullptr;
    }
    return fn(eventAttributes, manualReset, initialState, name);
}

BOOL DuplicateHandle(
    HANDLE sourceProcessHandle,
    HANDLE sourceHandle,
    HANDLE targetProcessHandle,
    LPHANDLE targetHandle,
    DWORD desiredAccess,
    BOOL inheritHandle,
    DWORD options) {
    typedef decltype(&::DuplicateHandle) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "DuplicateHandle");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(
        sourceProcessHandle,
        sourceHandle,
        targetProcessHandle,
        targetHandle,
        desiredAccess,
        inheritHandle,
        options);
}

BOOL FlushInstructionCache(HANDLE process, LPCVOID baseAddress, SIZE_T size) {
    typedef decltype(&::FlushInstructionCache) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "FlushInstructionCache");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, baseAddress, size);
}

BOOL FreeLibrary(HMODULE module) {
    typedef decltype(&::FreeLibrary) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "FreeLibrary");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(module);
}

DWORD GetCurrentDirectoryW(DWORD bufferLength, LPWSTR buffer) {
    typedef decltype(&::GetCurrentDirectoryW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetCurrentDirectoryW");
    if (fn == nullptr) {
        SetMissingProcError();
        return 0;
    }
    return fn(bufferLength, buffer);
}

HANDLE GetCurrentProcess() {
    typedef decltype(&::GetCurrentProcess) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetCurrentProcess");
    if (fn == nullptr) {
        SetMissingProcError();
        return nullptr;
    }
    return fn();
}

DWORD GetCurrentProcessId() {
    typedef decltype(&::GetCurrentProcessId) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetCurrentProcessId");
    if (fn == nullptr) {
        SetMissingProcError();
        return 0;
    }
    return fn();
}

HANDLE GetCurrentThread() {
    typedef decltype(&::GetCurrentThread) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetCurrentThread");
    if (fn == nullptr) {
        SetMissingProcError();
        return nullptr;
    }
    return fn();
}

DWORD GetEnvironmentVariableW(LPCWSTR name, LPWSTR buffer, DWORD bufferLength) {
    typedef decltype(&::GetEnvironmentVariableW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetEnvironmentVariableW");
    if (fn == nullptr) {
        SetMissingProcError();
        return 0;
    }
    return fn(name, buffer, bufferLength);
}

DWORD GetFinalPathNameByHandleW(HANDLE file, LPWSTR filePath, DWORD filePathLength, DWORD flags) {
    typedef decltype(&::GetFinalPathNameByHandleW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetFinalPathNameByHandleW");
    if (fn == nullptr) {
        SetMissingProcError();
        return 0;
    }
    return fn(file, filePath, filePathLength, flags);
}

DWORD GetFullPathNameW(LPCWSTR fileName, DWORD bufferLength, LPWSTR buffer, LPWSTR* filePart) {
    typedef decltype(&::GetFullPathNameW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetFullPathNameW");
    if (fn == nullptr) {
        SetMissingProcError();
        return 0;
    }
    return fn(fileName, bufferLength, buffer, filePart);
}

BOOL GetExitCodeProcess(HANDLE process, LPDWORD exitCode) {
    typedef decltype(&::GetExitCodeProcess) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetExitCodeProcess");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, exitCode);
}

BOOL GetExitCodeThread(HANDLE thread, LPDWORD exitCode) {
    typedef decltype(&::GetExitCodeThread) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetExitCodeThread");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(thread, exitCode);
}

DWORD GetLastError() {
    typedef decltype(&::GetLastError) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetLastError");
    if (fn == nullptr) {
        return ERROR_PROC_NOT_FOUND;
    }
    return fn();
}

DWORD GetModuleFileNameW(HMODULE module, LPWSTR fileName, DWORD size) {
    typedef decltype(&::GetModuleFileNameW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetModuleFileNameW");
    if (fn == nullptr) {
        SetMissingProcError();
        return 0;
    }
    return fn(module, fileName, size);
}

HMODULE GetModuleHandleW(LPCWSTR moduleName) {
    typedef decltype(&::GetModuleHandleW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetModuleHandleW");
    if (fn == nullptr) {
        SetMissingProcError();
        return nullptr;
    }
    return fn(moduleName);
}

DWORD GetPriorityClass(HANDLE process) {
    typedef decltype(&::GetPriorityClass) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetPriorityClass");
    if (fn == nullptr) {
        SetMissingProcError();
        return 0;
    }
    return fn(process);
}

FARPROC GetProcAddress(HMODULE module, LPCSTR procName) {
    typedef decltype(&::GetProcAddress) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetProcAddress");
    if (fn == nullptr) {
        SetMissingProcError();
        return nullptr;
    }
    return fn(module, procName);
}

DWORD GetTempFileNameW(LPCWSTR pathName, LPCWSTR prefixString, UINT unique, LPWSTR tempFileName) {
    typedef decltype(&::GetTempFileNameW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetTempFileNameW");
    if (fn == nullptr) {
        SetMissingProcError();
        return 0;
    }
    return fn(pathName, prefixString, unique, tempFileName);
}

DWORD GetTempPathW(DWORD bufferLength, LPWSTR buffer) {
    typedef decltype(&::GetTempPathW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetTempPathW");
    if (fn == nullptr) {
        SetMissingProcError();
        return 0;
    }
    return fn(bufferLength, buffer);
}

void GetSystemInfo(LPSYSTEM_INFO systemInfo) {
    typedef decltype(&::GetSystemInfo) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetSystemInfo");
    if (fn == nullptr) {
        if (systemInfo != nullptr) {
            std::memset(systemInfo, 0, sizeof(*systemInfo));
        }
        SetMissingProcError();
        return;
    }
    fn(systemInfo);
}

void GetNativeSystemInfo(LPSYSTEM_INFO systemInfo) {
    typedef decltype(&::GetNativeSystemInfo) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetNativeSystemInfo");
    if (fn == nullptr) {
        if (systemInfo != nullptr) {
            std::memset(systemInfo, 0, sizeof(*systemInfo));
        }
        SetMissingProcError();
        return;
    }
    fn(systemInfo);
}

BOOL GetThreadContext(HANDLE thread, LPCONTEXT context) {
    if (TryDriverGetThreadContext(thread, context)) {
        return TRUE;
    }

    typedef decltype(&::GetThreadContext) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "GetThreadContext");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(thread, context);
}

BOOL IsWow64Process2(HANDLE process, USHORT* processMachine, USHORT* nativeMachine) {
    typedef decltype(&::IsWow64Process) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "IsWow64Process");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, (PBOOL)processMachine);
}

HMODULE LoadLibraryW(LPCWSTR fileName) {
    typedef decltype(&::LoadLibraryW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "LoadLibraryW");
    if (fn == nullptr) {
        SetMissingProcError();
        return nullptr;
    }
    return fn(fileName);
}

BOOL Module32FirstW(HANDLE snapshot, LPMODULEENTRY32W moduleEntry) {
    typedef decltype(&::Module32FirstW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "Module32FirstW");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(snapshot, moduleEntry);
}

BOOL Module32NextW(HANDLE snapshot, LPMODULEENTRY32W moduleEntry) {
    typedef decltype(&::Module32NextW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "Module32NextW");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(snapshot, moduleEntry);
}

HANDLE OpenProcess(DWORD desiredAccess, BOOL inheritHandle, DWORD processId) {
    typedef decltype(&::OpenProcess) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "OpenProcess");
    if (fn == nullptr) {
        SetMissingProcError();
        return nullptr;
    }
    return fn(desiredAccess, inheritHandle, processId);
}

HANDLE OpenThread(DWORD desiredAccess, BOOL inheritHandle, DWORD threadId) {
    typedef decltype(&::OpenThread) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "OpenThread");
    if (fn == nullptr) {
        SetMissingProcError();
        return nullptr;
    }
    return fn(desiredAccess, inheritHandle, threadId);
}

BOOL QueryPerformanceCounter(LARGE_INTEGER* performanceCount) {
    typedef decltype(&::QueryPerformanceCounter) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "QueryPerformanceCounter");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(performanceCount);
}

BOOL QueryPerformanceFrequency(LARGE_INTEGER* frequency) {
    typedef decltype(&::QueryPerformanceFrequency) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "QueryPerformanceFrequency");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(frequency);
}

BOOL QueryFullProcessImageNameW(HANDLE process, DWORD flags, LPWSTR exeName, PDWORD size) {
    typedef decltype(&::QueryFullProcessImageNameW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "QueryFullProcessImageNameW");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, flags, exeName, size);
}

void ConfigureProcessMemoryDriver(BOOL preferDriver, LPCWSTR devicePath) {
    std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
    g_processMemoryPreferDriver = preferDriver != FALSE;
    if (devicePath == nullptr || *devicePath == L'\0') {
        g_processMemoryDriverDevicePath = WDBL_MEM_DRIVER_DEFAULT_DEVICE_PATH;
    } else {
        g_processMemoryDriverDevicePath = devicePath;
    }
    ResetProcessMemoryDriverStateLocked();
}

BOOL IsProcessMemoryDriverActive() {
    std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
    return g_processMemoryPreferDriver && IsOpenDriverHandle(g_processMemoryDriverHandle) ? TRUE : FALSE;
}

BOOL IsProcessMemoryDriverPreferred() {
    std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
    return g_processMemoryPreferDriver ? TRUE : FALSE;
}

DWORD GetProcessMemoryDriverLastError() {
    std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
    return g_processMemoryDriverLastError;
}

BOOL PingProcessMemoryDriver() {
    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    ULONG pong = 0;
    DWORD returnedBytes = 0;
    const BOOL ok = ::DeviceIoControl(
        driverHandle,
        IOCTL_WDBL_PING,
        nullptr,
        0,
        &pong,
        static_cast<DWORD>(sizeof(pong)),
        &returnedBytes,
        nullptr);
    if (!ok) {
        const DWORD error = ::GetLastError();
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = error;
        if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
            CloseProcessMemoryDriverHandleLocked();
            g_processMemoryDriverOpenAttempted = false;
        }
        return FALSE;
    }

    std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
    g_processMemoryDriverLastError = ERROR_SUCCESS;
    return TRUE;
}

BOOL QueryDriverCapabilities(WDBL_DRIVER_CAPABILITIES_RESULT* result) {
    if (result == nullptr) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    std::memset(result, 0, sizeof(*result));

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_QUERY_CAPABILITIES,
        nullptr,
        0,
        result,
        static_cast<DWORD>(sizeof(*result)),
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = error;
        if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
            CloseProcessMemoryDriverHandleLocked();
            g_processMemoryDriverOpenAttempted = false;
        }
        return FALSE;
    }
    if (returnedBytes < sizeof(*result)) {
        ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
    g_processMemoryDriverLastError = ERROR_SUCCESS;
    return TRUE;
}

BOOL QueryDriverDebugApiSupport(DWORD* availableMask, DWORD* requiredMask) {
    if (availableMask != nullptr) {
        *availableMask = 0;
    }
    if (requiredMask != nullptr) {
        *requiredMask = WDBL_DEBUG_API_REQUIRED;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    WDBL_DEBUG_API_SUPPORT_RESULT result = WDBL_DEBUG_API_SUPPORT_RESULT();
    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_QUERY_DEBUG_API_SUPPORT,
        nullptr,
        0,
        &result,
        static_cast<DWORD>(sizeof(result)),
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return FALSE;
    }
    if (returnedBytes < sizeof(result)) {
        ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    if (availableMask != nullptr) {
        *availableMask = result.AvailableMask;
    }
    if (requiredMask != nullptr) {
        *requiredMask = result.RequiredMask;
    }
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    return TRUE;
}

BOOL DriverReadProcessMemoryEx64(
    DWORD processId,
    ULONGLONG address,
    LPVOID buffer,
    SIZE_T size,
    DWORD flags,
    SIZE_T* bytesRead,
    LONG* kernelStatus,
    ULONGLONG* faultAddress) {
    if (bytesRead != nullptr) {
        *bytesRead = 0;
    }
    if (kernelStatus != nullptr) {
        *kernelStatus = 0;
    }
    if (faultAddress != nullptr) {
        *faultAddress = address;
    }
    if (size > static_cast<SIZE_T>((std::numeric_limits<DWORD>::max)()) ||
        (size > 0 && buffer == nullptr) ||
        processId == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        if (!g_processMemoryPreferDriver) {
            ::SetLastError(ERROR_NOT_SUPPORTED);
            return FALSE;
        }
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    WDBL_PROCESS_MEMORY_READ_EX_REQUEST request = WDBL_PROCESS_MEMORY_READ_EX_REQUEST();
    request.ProcessId = processId;
    request.Address = address;
    request.Size = static_cast<ULONG>(size);
    request.Flags = flags;

    const DWORD resultHeaderSize = static_cast<DWORD>(FIELD_OFFSET(WDBL_PROCESS_MEMORY_READ_EX_RESULT, Data));
    std::vector<BYTE> output(resultHeaderSize + static_cast<size_t>(size));
    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_READ_PROCESS_MEMORY_EX,
        &request,
        static_cast<DWORD>(sizeof(request)),
        output.empty() ? nullptr : &output[0],
        static_cast<DWORD>(output.size()),
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = error;
        if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
            CloseProcessMemoryDriverHandleLocked();
            g_processMemoryDriverOpenAttempted = false;
        }
        return FALSE;
    }
    if (returnedBytes < resultHeaderSize) {
        ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    const WDBL_PROCESS_MEMORY_READ_EX_RESULT* result =
        reinterpret_cast<const WDBL_PROCESS_MEMORY_READ_EX_RESULT*>(&output[0]);
    SIZE_T copied = result->BytesRead;
    const SIZE_T available = static_cast<SIZE_T>(returnedBytes - resultHeaderSize);
    if (copied > available) {
        copied = available;
    }
    if (copied > size) {
        copied = size;
    }
    if (buffer != nullptr && copied > 0) {
        std::memcpy(buffer, result->Data, copied);
    }
    if (bytesRead != nullptr) {
        *bytesRead = copied;
    }
    if (kernelStatus != nullptr) {
        *kernelStatus = result->KernelStatus;
    }
    if (faultAddress != nullptr) {
        *faultAddress = result->FaultAddress;
    }
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    if (result->KernelStatus != 0 || copied != size) {
        ::SetLastError(ERROR_PARTIAL_COPY);
        return FALSE;
    }
    return TRUE;
}

BOOL DriverWriteProcessMemoryEx64(
    DWORD processId,
    ULONGLONG address,
    LPCVOID buffer,
    SIZE_T size,
    DWORD flags,
    SIZE_T* bytesWritten,
    LONG* kernelStatus,
    ULONGLONG* faultAddress) {
    if (bytesWritten != nullptr) {
        *bytesWritten = 0;
    }
    if (kernelStatus != nullptr) {
        *kernelStatus = 0;
    }
    if (faultAddress != nullptr) {
        *faultAddress = address;
    }
    if (size > static_cast<SIZE_T>((std::numeric_limits<DWORD>::max)()) ||
        (size > 0 && buffer == nullptr) ||
        processId == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        if (!g_processMemoryPreferDriver) {
            ::SetLastError(ERROR_NOT_SUPPORTED);
            return FALSE;
        }
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    const size_t requestHeaderSize = sizeof(WDBL_PROCESS_MEMORY_WRITE_EX_REQUEST_HEADER);
    if (size > static_cast<SIZE_T>((std::numeric_limits<DWORD>::max)()) - requestHeaderSize) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    std::vector<BYTE> input(requestHeaderSize + size);
    WDBL_PROCESS_MEMORY_WRITE_EX_REQUEST_HEADER* request =
        reinterpret_cast<WDBL_PROCESS_MEMORY_WRITE_EX_REQUEST_HEADER*>(&input[0]);
    request->ProcessId = processId;
    request->Address = address;
    request->Size = static_cast<ULONG>(size);
    request->Flags = flags;
    if (size > 0) {
        std::memcpy(&input[requestHeaderSize], buffer, size);
    }

    WDBL_PROCESS_MEMORY_WRITE_EX_RESULT result = WDBL_PROCESS_MEMORY_WRITE_EX_RESULT();
    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_WRITE_PROCESS_MEMORY_EX,
        &input[0],
        static_cast<DWORD>(input.size()),
        &result,
        static_cast<DWORD>(sizeof(result)),
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = error;
        if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
            CloseProcessMemoryDriverHandleLocked();
            g_processMemoryDriverOpenAttempted = false;
        }
        return FALSE;
    }
    if (returnedBytes < sizeof(result)) {
        ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (bytesWritten != nullptr) {
        *bytesWritten = result.BytesWritten;
    }
    if (kernelStatus != nullptr) {
        *kernelStatus = result.KernelStatus;
    }
    if (faultAddress != nullptr) {
        *faultAddress = result.FaultAddress;
    }
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    if (result.KernelStatus != 0 || result.BytesWritten != size) {
        ::SetLastError(ERROR_WRITE_FAULT);
        return FALSE;
    }
    return TRUE;
}

BOOL QueryDriverAntiDebug(DWORD processId, DWORD flags, WDBL_ANTI_DEBUG_QUERY_RESULT* result) {
    if (result == nullptr || processId == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    std::memset(result, 0, sizeof(*result));
    WDBL_ANTI_DEBUG_QUERY_REQUEST request = WDBL_ANTI_DEBUG_QUERY_REQUEST();
    request.ProcessId = processId;
    request.Flags = flags;

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_QUERY_ANTI_DEBUG,
        &request,
        static_cast<DWORD>(sizeof(request)),
        result,
        static_cast<DWORD>(sizeof(*result)),
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = error;
        return FALSE;
    }
    if (returnedBytes < sizeof(*result)) {
        ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return TRUE;
}

BOOL DriverGetDebugRegisters(DWORD threadId, WDBL_DEBUG_REGISTERS_RESULT* result) {
    if (result == nullptr || threadId == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    std::memset(result, 0, sizeof(*result));
    WDBL_DEBUG_REGISTERS_REQUEST request = WDBL_DEBUG_REGISTERS_REQUEST();
    request.ThreadId = threadId;

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }
    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_QUERY_DEBUG_REGISTERS,
        &request,
        static_cast<DWORD>(sizeof(request)),
        result,
        static_cast<DWORD>(sizeof(*result)),
        &returnedBytes);
    if (!ok || returnedBytes < sizeof(*result)) {
        if (ok) {
            ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        }
        return FALSE;
    }
    return TRUE;
}

BOOL DriverSetDebugRegisters(DWORD threadId, const WDBL_DEBUG_REGISTERS_RESULT* registers) {
    if (registers == nullptr || threadId == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    std::vector<BYTE> input(sizeof(WDBL_DEBUG_REGISTERS_REQUEST) + sizeof(WDBL_DEBUG_REGISTERS_RESULT));
    WDBL_DEBUG_REGISTERS_REQUEST* request =
        reinterpret_cast<WDBL_DEBUG_REGISTERS_REQUEST*>(&input[0]);
    request->ThreadId = threadId;
    std::memcpy(
        &input[sizeof(WDBL_DEBUG_REGISTERS_REQUEST)],
        registers,
        sizeof(*registers));

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }
    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_SET_DEBUG_REGISTERS,
        &input[0],
        static_cast<DWORD>(input.size()),
        nullptr,
        0,
        &returnedBytes);
    return ok;
}

BOOL QueryDriverEprocessImageNameOffset(
    DWORD* offset,
    DWORD* nameLength,
    DWORD* confidence,
    char imageName[16]) {
    if (offset != nullptr) {
        *offset = 0;
    }
    if (nameLength != nullptr) {
        *nameLength = 0;
    }
    if (confidence != nullptr) {
        *confidence = 0;
    }
    if (imageName != nullptr) {
        std::memset(imageName, 0, 16);
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    WDBL_EPROCESS_IMAGE_NAME_OFFSET_RESULT result = WDBL_EPROCESS_IMAGE_NAME_OFFSET_RESULT();
    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_QUERY_EPROCESS_IMAGE_NAME_OFFSET,
        nullptr,
        0,
        &result,
        static_cast<DWORD>(sizeof(result)),
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return FALSE;
    }
    if (returnedBytes < sizeof(result)) {
        ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    if (offset != nullptr) {
        *offset = result.Offset;
    }
    if (nameLength != nullptr) {
        *nameLength = result.NameLength;
    }
    if (confidence != nullptr) {
        *confidence = result.Confidence;
    }
    if (imageName != nullptr) {
        std::memcpy(imageName, result.ImageName, 16);
        imageName[15] = '\0';
    }
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    return TRUE;
}

BOOL QueryDriverProcessList(std::vector<WDBL_PROCESS_ENUM_ENTRY>* entries) {
    return QueryDriverEnumerationResult<WDBL_PROCESS_ENUM_ENTRY>(IOCTL_WDBL_QUERY_PROCESS_LIST, nullptr, 0, entries);
}

BOOL QueryDriverThreadList(DWORD processId, std::vector<WDBL_THREAD_ENUM_ENTRY>* entries) {
    WDBL_PROCESS_ENUM_REQUEST request = WDBL_PROCESS_ENUM_REQUEST();
    request.ProcessId = processId;
    return QueryDriverEnumerationResult<WDBL_THREAD_ENUM_ENTRY>(
        IOCTL_WDBL_QUERY_THREAD_LIST,
        &request,
        static_cast<DWORD>(sizeof(request)),
        entries);
}

BOOL QueryDriverModuleList(DWORD processId, std::vector<WDBL_MODULE_ENUM_ENTRY>* entries) {
    WDBL_PROCESS_ENUM_REQUEST request = WDBL_PROCESS_ENUM_REQUEST();
    request.ProcessId = processId;
    return QueryDriverEnumerationResult<WDBL_MODULE_ENUM_ENTRY>(
        IOCTL_WDBL_QUERY_MODULE_LIST,
        &request,
        static_cast<DWORD>(sizeof(request)),
        entries);
}

BOOL QueryDriverMemoryMap(DWORD processId, ULONGLONG startAddress, std::vector<WDBL_MEMORY_ENUM_ENTRY>* entries) {
    WDBL_MEMORY_ENUM_REQUEST request = WDBL_MEMORY_ENUM_REQUEST();
    request.ProcessId = processId;
    request.StartAddress = startAddress;
    return QueryDriverEnumerationResult<WDBL_MEMORY_ENUM_ENTRY>(
        IOCTL_WDBL_QUERY_MEMORY_MAP,
        &request,
        static_cast<DWORD>(sizeof(request)),
        entries);
}

BOOL QueryDriverHandleList(DWORD processId, std::vector<WDBL_HANDLE_ENUM_ENTRY>* entries) {
    WDBL_HANDLE_ENUM_REQUEST request = WDBL_HANDLE_ENUM_REQUEST();
    request.ProcessId = processId;
    return QueryDriverEnumerationResult<WDBL_HANDLE_ENUM_ENTRY>(
        IOCTL_WDBL_QUERY_HANDLE_LIST,
        &request,
        static_cast<DWORD>(sizeof(request)),
        entries);
}

BOOL QueryDriverThreadInfo(DWORD threadId, WDBL_THREAD_INFO_RESULT* result) {
    if (result == nullptr || threadId == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    std::memset(result, 0, sizeof(*result));
    WDBL_THREAD_INFO_REQUEST request = WDBL_THREAD_INFO_REQUEST();
    request.ThreadId = threadId;

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_QUERY_THREAD_INFO,
        &request,
        static_cast<DWORD>(sizeof(request)),
        result,
        static_cast<DWORD>(sizeof(*result)),
        &returnedBytes);
    if (!ok || returnedBytes < sizeof(*result)) {
        if (ok) {
            ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        }
        return FALSE;
    }
    return TRUE;
}

BOOL QueryDriverImageInfo(DWORD processId, WDBL_IMAGE_INFO_RESULT* result) {
    if (result == nullptr || processId == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    std::memset(result, 0, sizeof(*result));
    WDBL_IMAGE_INFO_REQUEST request = WDBL_IMAGE_INFO_REQUEST();
    request.ProcessId = processId;

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_QUERY_IMAGE_INFO,
        &request,
        static_cast<DWORD>(sizeof(request)),
        result,
        static_cast<DWORD>(sizeof(*result)),
        &returnedBytes);
    if (!ok || returnedBytes < sizeof(*result)) {
        if (ok) {
            ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        }
        return FALSE;
    }
    return TRUE;
}

BOOL QueryDriverProcessMitigations(DWORD processId, WDBL_PROCESS_MITIGATIONS_RESULT* result) {
    if (result == nullptr || processId == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    std::memset(result, 0, sizeof(*result));
    WDBL_PROCESS_MITIGATIONS_REQUEST request = WDBL_PROCESS_MITIGATIONS_REQUEST();
    request.ProcessId = processId;

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_QUERY_PROCESS_MITIGATIONS,
        &request,
        static_cast<DWORD>(sizeof(request)),
        result,
        static_cast<DWORD>(sizeof(*result)),
        &returnedBytes);
    if (!ok || returnedBytes < sizeof(*result)) {
        if (ok) {
            ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        }
        return FALSE;
    }
    return TRUE;
}

BOOL QueryDriverEvents(DWORD processId, DWORD maxEvents, std::vector<WDBL_DRIVER_EVENT_ENTRY>* entries) {
    if (entries == nullptr || maxEvents == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    WDBL_DRIVER_EVENT_REQUEST request = WDBL_DRIVER_EVENT_REQUEST();
    request.ProcessId = processId;
    request.MaxEvents = maxEvents;
    return QueryDriverEnumerationResult<WDBL_DRIVER_EVENT_ENTRY>(
        IOCTL_WDBL_QUERY_DRIVER_EVENTS,
        &request,
        static_cast<DWORD>(sizeof(request)),
        entries);
}

BOOL OpenProcessKernelHandle(DWORD processId, DWORD desiredAccess, ULONGLONG* kernelHandle) {
    if (kernelHandle == nullptr) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *kernelHandle = 0;

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    WDBL_OPEN_PROCESS_KERNEL_HANDLE_REQUEST request = WDBL_OPEN_PROCESS_KERNEL_HANDLE_REQUEST();
    request.ProcessId = static_cast<ULONG>(processId);
    request.DesiredAccess = desiredAccess;

    WDBL_OPEN_PROCESS_KERNEL_HANDLE_RESULT result = WDBL_OPEN_PROCESS_KERNEL_HANDLE_RESULT();
    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_OPEN_PROCESS_KERNEL_HANDLE,
        &request,
        static_cast<DWORD>(sizeof(request)),
        &result,
        static_cast<DWORD>(sizeof(result)),
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return FALSE;
    }

    *kernelHandle = result.KernelHandle;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    return TRUE;
}

BOOL CloseKernelHandle(ULONGLONG kernelHandle) {
    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    WDBL_CLOSE_KERNEL_HANDLE_REQUEST request = WDBL_CLOSE_KERNEL_HANDLE_REQUEST();
    request.KernelHandle = kernelHandle;

    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_CLOSE_KERNEL_HANDLE,
        &request,
        static_cast<DWORD>(sizeof(request)),
        nullptr,
        0,
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return FALSE;
    }

    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    return TRUE;
}

BOOL DriverCreateUserThread64(
    DWORD processId,
    ULONGLONG startAddress,
    ULONGLONG parameter,
    DWORD createFlags,
    SIZE_T stackSize,
    SIZE_T maximumStackSize,
    DWORD* threadId) {
    if (threadId != nullptr) {
        *threadId = 0;
    }
    if (processId == 0 || startAddress == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    WDBL_CREATE_USER_THREAD_REQUEST request = WDBL_CREATE_USER_THREAD_REQUEST();
    request.ProcessId = static_cast<ULONG>(processId);
    request.StartAddress = startAddress;
    request.Parameter = parameter;
    request.CreateFlags = createFlags;
    request.StackSize = static_cast<ULONGLONG>(stackSize);
    request.MaximumStackSize = static_cast<ULONGLONG>(maximumStackSize);

    WDBL_CREATE_USER_THREAD_RESULT result = WDBL_CREATE_USER_THREAD_RESULT();
    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_CREATE_USER_THREAD,
        &request,
        static_cast<DWORD>(sizeof(request)),
        &result,
        static_cast<DWORD>(sizeof(result)),
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return FALSE;
    }

    if (threadId != nullptr) {
        *threadId = result.ThreadId;
    }
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    return TRUE;
}

BOOL DriverSuspendThread(DWORD threadId, DWORD* previousSuspendCount) {
    if (previousSuspendCount != nullptr) {
        *previousSuspendCount = 0;
    }
    if (threadId == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    WDBL_THREAD_CONTROL_REQUEST request = WDBL_THREAD_CONTROL_REQUEST();
    request.ThreadId = static_cast<ULONG>(threadId);
    WDBL_THREAD_CONTROL_RESULT result = WDBL_THREAD_CONTROL_RESULT();
    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_SUSPEND_THREAD,
        &request,
        static_cast<DWORD>(sizeof(request)),
        &result,
        static_cast<DWORD>(sizeof(result)),
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return FALSE;
    }

    if (previousSuspendCount != nullptr && returnedBytes >= sizeof(result)) {
        *previousSuspendCount = result.PreviousSuspendCount;
    }
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    return TRUE;
}

BOOL DriverResumeThread(DWORD threadId, DWORD* previousSuspendCount) {
    if (previousSuspendCount != nullptr) {
        *previousSuspendCount = 0;
    }
    if (threadId == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    WDBL_THREAD_CONTROL_REQUEST request = WDBL_THREAD_CONTROL_REQUEST();
    request.ThreadId = static_cast<ULONG>(threadId);
    WDBL_THREAD_CONTROL_RESULT result = WDBL_THREAD_CONTROL_RESULT();
    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_RESUME_THREAD,
        &request,
        static_cast<DWORD>(sizeof(request)),
        &result,
        static_cast<DWORD>(sizeof(result)),
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return FALSE;
    }

    if (previousSuspendCount != nullptr && returnedBytes >= sizeof(result)) {
        *previousSuspendCount = result.PreviousSuspendCount;
    }
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    return TRUE;
}

BOOL DriverSuspendProcess(DWORD processId) {
    if (processId == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    WDBL_PROCESS_CONTROL_REQUEST request = WDBL_PROCESS_CONTROL_REQUEST();
    request.ProcessId = static_cast<ULONG>(processId);
    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_SUSPEND_PROCESS,
        &request,
        static_cast<DWORD>(sizeof(request)),
        nullptr,
        0,
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return FALSE;
    }

    std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
    g_processMemoryDriverLastError = ERROR_SUCCESS;
    return TRUE;
}

BOOL DriverResumeProcess(DWORD processId) {
    if (processId == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    WDBL_PROCESS_CONTROL_REQUEST request = WDBL_PROCESS_CONTROL_REQUEST();
    request.ProcessId = static_cast<ULONG>(processId);
    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_RESUME_PROCESS,
        &request,
        static_cast<DWORD>(sizeof(request)),
        nullptr,
        0,
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return FALSE;
    }

    std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
    g_processMemoryDriverLastError = ERROR_SUCCESS;
    return TRUE;
}

BOOL DriverTerminateProcess(DWORD processId, DWORD exitStatus) {
    if (processId == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    WDBL_PROCESS_CONTROL_REQUEST request = WDBL_PROCESS_CONTROL_REQUEST();
    request.ProcessId = static_cast<ULONG>(processId);
    request.ExitStatus = exitStatus;
    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_TERMINATE_PROCESS,
        &request,
        static_cast<DWORD>(sizeof(request)),
        nullptr,
        0,
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return FALSE;
    }

    std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
    g_processMemoryDriverLastError = ERROR_SUCCESS;
    return TRUE;
}

BOOL DriverGetWow64ThreadContext(DWORD threadId, WOW64_CONTEXT* context) {
    if (context == nullptr || threadId == 0 || sizeof(WDBL_WOW64_CONTEXT) != sizeof(WOW64_CONTEXT)) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    WDBL_WOW64_THREAD_CONTEXT_REQUEST request = WDBL_WOW64_THREAD_CONTEXT_REQUEST();
    request.ThreadId = static_cast<ULONG>(threadId);
    request.ContextFlags = context->ContextFlags;

    WDBL_WOW64_CONTEXT driverContext = WDBL_WOW64_CONTEXT();
    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_GET_WOW64_THREAD_CONTEXT,
        &request,
        static_cast<DWORD>(sizeof(request)),
        &driverContext,
        static_cast<DWORD>(sizeof(driverContext)),
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return FALSE;
    }
    if (returnedBytes < sizeof(driverContext)) {
        ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    std::memcpy(context, &driverContext, sizeof(driverContext));
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        g_processMemoryDriverLastError = ERROR_SUCCESS;
    }
    return TRUE;
}

BOOL DriverSetWow64ThreadContext(DWORD threadId, const WOW64_CONTEXT* context) {
    if (context == nullptr || threadId == 0 || sizeof(WDBL_WOW64_CONTEXT) != sizeof(WOW64_CONTEXT)) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    HANDLE driverHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
        driverHandle = EnsureProcessMemoryDriverHandleLocked();
    }
    if (!IsOpenDriverHandle(driverHandle)) {
        return FALSE;
    }

    const size_t requestSize = sizeof(WDBL_WOW64_THREAD_CONTEXT_REQUEST);
    const size_t contextSize = sizeof(WDBL_WOW64_CONTEXT);
    if (requestSize > (std::numeric_limits<DWORD>::max)() - contextSize) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    std::vector<BYTE> input(requestSize + contextSize);
    WDBL_WOW64_THREAD_CONTEXT_REQUEST* request =
        reinterpret_cast<WDBL_WOW64_THREAD_CONTEXT_REQUEST*>(&input[0]);
    request->ThreadId = static_cast<ULONG>(threadId);
    request->ContextFlags = context->ContextFlags;

    WDBL_WOW64_CONTEXT* driverContext =
        reinterpret_cast<WDBL_WOW64_CONTEXT*>(&input[requestSize]);
    std::memcpy(driverContext, context, contextSize);

    DWORD returnedBytes = 0;
    const BOOL ok = SendSecureDriverIoctl(
        driverHandle,
        IOCTL_WDBL_SET_WOW64_THREAD_CONTEXT,
        &input[0],
        static_cast<DWORD>(input.size()),
        nullptr,
        0,
        &returnedBytes);
    if (!ok) {
        const DWORD error = ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
            g_processMemoryDriverLastError = error;
            if (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_GEN_FAILURE) {
                CloseProcessMemoryDriverHandleLocked();
                g_processMemoryDriverOpenAttempted = false;
            }
        }
        return FALSE;
    }

    std::lock_guard<std::mutex> lock(g_processMemoryDriverMutex);
    g_processMemoryDriverLastError = ERROR_SUCCESS;
    return TRUE;
}

BOOL DriverReadProcessMemory64(DWORD processId, ULONGLONG address, LPVOID buffer, SIZE_T size, SIZE_T* bytesRead) {
    return DriverReadProcessMemoryById(processId, address, buffer, size, bytesRead) ? TRUE : FALSE;
}

BOOL DriverWriteProcessMemory64(DWORD processId, ULONGLONG address, LPCVOID buffer, SIZE_T size, SIZE_T* bytesWritten) {
    return DriverWriteProcessMemoryById(processId, address, buffer, size, bytesWritten) ? TRUE : FALSE;
}

SIZE_T DriverVirtualQueryEx64(DWORD processId, ULONGLONG address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length) {
    SIZE_T bytesReturned = 0;
    return DriverVirtualQueryExById(processId, address, buffer, length, &bytesReturned) ? bytesReturned : 0;
}

BOOL DriverVirtualProtectEx64(DWORD processId, ULONGLONG address, SIZE_T size, DWORD newProtect, PDWORD oldProtect) {
    return DriverVirtualProtectExById(processId, address, size, newProtect, oldProtect) ? TRUE : FALSE;
}

ULONGLONG DriverVirtualAllocEx64(DWORD processId, ULONGLONG address, SIZE_T size, DWORD allocationType, DWORD protect) {
    return DriverVirtualAllocExById(processId, address, size, allocationType, protect);
}

BOOL DriverVirtualFreeEx64(DWORD processId, ULONGLONG address, SIZE_T size, DWORD freeType) {
    return DriverVirtualFreeExById(processId, address, size, freeType) ? TRUE : FALSE;
}

BOOL ReadProcessMemory(HANDLE process, LPCVOID baseAddress, LPVOID buffer, SIZE_T size, SIZE_T* bytesRead) {
    if (TryDriverReadProcessMemory(process, baseAddress, buffer, size, bytesRead)) {
        return TRUE;
    }

    typedef decltype(&::ReadProcessMemory) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "ReadProcessMemory");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, baseAddress, buffer, size, bytesRead);
}

BOOL ResetEvent(HANDLE eventHandle) {
    typedef decltype(&::ResetEvent) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "ResetEvent");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(eventHandle);
}

BOOL SetConsoleOutputCP(UINT codePageId) {
    typedef decltype(&::SetConsoleOutputCP) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "SetConsoleOutputCP");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(codePageId);
}

BOOL SetEvent(HANDLE eventHandle) {
    typedef decltype(&::SetEvent) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "SetEvent");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(eventHandle);
}

void SetLastError(DWORD error) {
    typedef decltype(&::SetLastError) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "SetLastError");
    if (fn == nullptr) {
        return;
    }
    fn(error);
}

BOOL SetThreadContext(HANDLE thread, const CONTEXT* context) {
    if (TryDriverSetThreadContext(thread, context)) {
        return TRUE;
    }

    typedef decltype(&::SetThreadContext) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "SetThreadContext");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(thread, context);
}

void Sleep(DWORD milliseconds) {
    typedef decltype(&::Sleep) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "Sleep");
    if (fn == nullptr) {
        SetMissingProcError();
        return;
    }
    fn(milliseconds);
}

BOOL Thread32First(HANDLE snapshot, LPTHREADENTRY32 threadEntry) {
    typedef decltype(&::Thread32First) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "Thread32First");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(snapshot, threadEntry);
}

BOOL Thread32Next(HANDLE snapshot, LPTHREADENTRY32 threadEntry) {
    typedef decltype(&::Thread32Next) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "Thread32Next");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(snapshot, threadEntry);
}

LPVOID VirtualAllocEx(HANDLE process, LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect) {
    LPVOID driverResult = TryDriverVirtualAllocEx(process, address, size, allocationType, protect);
    if (driverResult != nullptr) {
        return driverResult;
    }

    typedef decltype(&::VirtualAllocEx) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "VirtualAllocEx");
    if (fn == nullptr) {
        SetMissingProcError();
        return nullptr;
    }
    return fn(process, address, size, allocationType, protect);
}

BOOL VirtualFreeEx(HANDLE process, LPVOID address, SIZE_T size, DWORD freeType) {
    if (TryDriverVirtualFreeEx(process, address, size, freeType)) {
        return TRUE;
    }

    typedef decltype(&::VirtualFreeEx) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "VirtualFreeEx");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, address, size, freeType);
}

BOOL VirtualProtectEx(HANDLE process, LPVOID address, SIZE_T size, DWORD newProtect, PDWORD oldProtect) {
    if (TryDriverVirtualProtectEx(process, address, size, newProtect, oldProtect)) {
        return TRUE;
    }

    typedef decltype(&::VirtualProtectEx) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "VirtualProtectEx");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, address, size, newProtect, oldProtect);
}

SIZE_T VirtualQueryEx(HANDLE process, LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length) {
    SIZE_T bytesReturned = 0;
    if (TryDriverVirtualQueryEx(process, address, buffer, length, &bytesReturned)) {
        return bytesReturned;
    }

    typedef decltype(&::VirtualQueryEx) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "VirtualQueryEx");
    if (fn == nullptr) {
        SetMissingProcError();
        return 0;
    }
    return fn(process, address, buffer, length);
}

BOOL WaitForDebugEvent(LPDEBUG_EVENT debugEvent, DWORD milliseconds) {
    if (IsDriverDebugSessionActive()) {
        return TryDriverWaitForDebugEvent(debugEvent, milliseconds) ? TRUE : FALSE;
    }

    typedef decltype(&::WaitForDebugEvent) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "WaitForDebugEvent");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(debugEvent, milliseconds);
}

DWORD WaitForSingleObjectEx(HANDLE handle, DWORD milliseconds, BOOL alertable) {
    typedef decltype(&::WaitForSingleObjectEx) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "WaitForSingleObjectEx");
    if (fn == nullptr) {
        SetMissingProcError();
        return WAIT_FAILED;
    }
    return fn(handle, milliseconds, alertable);
}

BOOL WriteProcessMemory(HANDLE process, LPVOID baseAddress, LPCVOID buffer, SIZE_T size, SIZE_T* bytesWritten) {
    if (TryDriverWriteProcessMemory(process, baseAddress, buffer, size, bytesWritten)) {
        return TRUE;
    }

    typedef decltype(&::WriteProcessMemory) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "WriteProcessMemory");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, baseAddress, buffer, size, bytesWritten);
}

int MultiByteToWideChar(
    UINT codePage,
    DWORD flags,
    LPCCH multiByteStr,
    int cbMultiByte,
    LPWSTR wideCharStr,
    int cchWideChar) {
    typedef decltype(&::MultiByteToWideChar) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "MultiByteToWideChar");
    if (fn == nullptr) {
        SetMissingProcError();
        return 0;
    }
    return fn(codePage, flags, multiByteStr, cbMultiByte, wideCharStr, cchWideChar);
}

int WideCharToMultiByte(
    UINT codePage,
    DWORD flags,
    LPCWCH wideCharStr,
    int cchWideChar,
    LPSTR multiByteStr,
    int cbMultiByte,
    LPCCH defaultChar,
    LPBOOL usedDefaultChar) {
    typedef decltype(&::WideCharToMultiByte) Fn;
    static const Fn fn = ResolveProc<Fn>(L"kernel32.dll", "WideCharToMultiByte");
    if (fn == nullptr) {
        SetMissingProcError();
        return 0;
    }
    return fn(
        codePage,
        flags,
        wideCharStr,
        cchWideChar,
        multiByteStr,
        cbMultiByte,
        defaultChar,
        usedDefaultChar);
}

BOOL StackWalk64(
    DWORD machineType,
    HANDLE process,
    HANDLE thread,
    LPSTACKFRAME64 stackFrame,
    PVOID contextRecord,
    PREAD_PROCESS_MEMORY_ROUTINE64 readMemoryRoutine,
    PFUNCTION_TABLE_ACCESS_ROUTINE64 functionTableAccessRoutine,
    PGET_MODULE_BASE_ROUTINE64 getModuleBaseRoutine,
    PTRANSLATE_ADDRESS_ROUTINE64 translateAddress) {
    typedef decltype(&::StackWalk64) Fn;
    static const Fn fn = ResolveProc<Fn>(L"dbghelp.dll", "StackWalk64");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(
        machineType,
        process,
        thread,
        stackFrame,
        contextRecord,
        readMemoryRoutine,
        functionTableAccessRoutine,
        getModuleBaseRoutine,
        translateAddress);
}

BOOL SymCleanup(HANDLE process) {
    typedef decltype(&::SymCleanup) Fn;
    static const Fn fn = ResolveProc<Fn>(L"dbghelp.dll", "SymCleanup");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process);
}

BOOL SymEnumLinesW(
    HANDLE process,
    ULONG64 base,
    PCWSTR obj,
    PCWSTR file,
    PSYM_ENUMLINES_CALLBACKW callback,
    PVOID userContext) {
    typedef decltype(&::SymEnumLinesW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"dbghelp.dll", "SymEnumLinesW");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, base, obj, file, callback, userContext);
}

BOOL SymEnumSymbolsW(HANDLE process, ULONG64 base, PCWSTR mask, PSYM_ENUMERATESYMBOLS_CALLBACKW callback, PVOID userContext) {
    typedef decltype(&::SymEnumSymbolsW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"dbghelp.dll", "SymEnumSymbolsW");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, base, mask, callback, userContext);
}

BOOL SymFromAddr(HANDLE process, DWORD64 address, PDWORD64 displacement, PSYMBOL_INFO symbol) {
    typedef decltype(&::SymFromAddr) Fn;
    static const Fn fn = ResolveProc<Fn>(L"dbghelp.dll", "SymFromAddr");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, address, displacement, symbol);
}

BOOL SymGetLineFromAddrW64(HANDLE process, DWORD64 address, PDWORD displacement, PIMAGEHLP_LINEW64 line) {
    typedef decltype(&::SymGetLineFromAddrW64) Fn;
    static const Fn fn = ResolveProc<Fn>(L"dbghelp.dll", "SymGetLineFromAddrW64");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, address, displacement, line);
}

BOOL SymGetModuleInfoW64(HANDLE process, DWORD64 address, PIMAGEHLP_MODULEW64 moduleInfo) {
    typedef decltype(&::SymGetModuleInfoW64) Fn;
    static const Fn fn = ResolveProc<Fn>(L"dbghelp.dll", "SymGetModuleInfoW64");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, address, moduleInfo);
}

DWORD SymGetOptions() {
    typedef decltype(&::SymGetOptions) Fn;
    static const Fn fn = ResolveProc<Fn>(L"dbghelp.dll", "SymGetOptions");
    if (fn == nullptr) {
        SetMissingProcError();
        return 0;
    }
    return fn();
}

BOOL SymGetSearchPathW(HANDLE process, PWSTR searchPath, DWORD searchPathLength) {
    typedef decltype(&::SymGetSearchPathW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"dbghelp.dll", "SymGetSearchPathW");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, searchPath, searchPathLength);
}

BOOL SymGetTypeFromNameW(HANDLE process, ULONG64 base, PCWSTR name, PSYMBOL_INFOW symbol) {
    typedef decltype(&::SymGetTypeFromNameW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"dbghelp.dll", "SymGetTypeFromNameW");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, base, name, symbol);
}

BOOL SymGetTypeInfo(HANDLE process, DWORD64 modBase, ULONG typeId, IMAGEHLP_SYMBOL_TYPE_INFO getType, PVOID info) {
    typedef decltype(&::SymGetTypeInfo) Fn;
    static const Fn fn = ResolveProc<Fn>(L"dbghelp.dll", "SymGetTypeInfo");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, modBase, typeId, getType, info);
}

BOOL SymInitialize(HANDLE process, PCSTR userSearchPath, BOOL invadeProcess) {
    typedef decltype(&::SymInitialize) Fn;
    static const Fn fn = ResolveProc<Fn>(L"dbghelp.dll", "SymInitialize");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, userSearchPath, invadeProcess);
}

DWORD64 SymLoadModuleExW(
    HANDLE process,
    HANDLE file,
    PCWSTR imageName,
    PCWSTR moduleName,
    DWORD64 baseOfDll,
    DWORD dllSize,
    PMODLOAD_DATA data,
    DWORD flags) {
    typedef decltype(&::SymLoadModuleExW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"dbghelp.dll", "SymLoadModuleExW");
    if (fn == nullptr) {
        SetMissingProcError();
        return 0;
    }
    return fn(process, file, imageName, moduleName, baseOfDll, dllSize, data, flags);
}

BOOL SymRefreshModuleList(HANDLE process) {
    typedef decltype(&::SymRefreshModuleList) Fn;
    static const Fn fn = ResolveProc<Fn>(L"dbghelp.dll", "SymRefreshModuleList");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process);
}

DWORD SymSetOptions(DWORD options) {
    typedef decltype(&::SymSetOptions) Fn;
    static const Fn fn = ResolveProc<Fn>(L"dbghelp.dll", "SymSetOptions");
    if (fn == nullptr) {
        SetMissingProcError();
        return 0;
    }
    return fn(options);
}

BOOL SymSetSearchPathW(HANDLE process, PCWSTR searchPath) {
    typedef decltype(&::SymSetSearchPathW) Fn;
    static const Fn fn = ResolveProc<Fn>(L"dbghelp.dll", "SymSetSearchPathW");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, searchPath);
}

BOOL SymUnloadModule64(HANDLE process, DWORD64 baseOfDll) {
    typedef decltype(&::SymUnloadModule64) Fn;
    static const Fn fn = ResolveProc<Fn>(L"dbghelp.dll", "SymUnloadModule64");
    if (fn == nullptr) {
        SetMissingProcError();
        return FALSE;
    }
    return fn(process, baseOfDll);
}

}  // namespace winapi
}  // namespace wdbl



