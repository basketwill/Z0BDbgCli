#include "WinDbgLiteApi.h"

#include "../WinDbgLite/Debugger.h"

#include <new>

struct WdblDebuggerHandleImpl {
    Debugger* debugger;

    WdblDebuggerHandleImpl()
        : debugger(nullptr) {
    }
};

int32_t WDBL_CALL WdblCreateDebugger(const wchar_t* tracePath, WdblDebuggerHandle* outHandle) {
    if (outHandle == nullptr) {
        return 0;
    }
    *outHandle = nullptr;

    const std::wstring path = (tracePath != nullptr && tracePath[0] != L'\0')
        ? std::wstring(tracePath)
        : std::wstring(L"wdbl_api_trace.log");

    WdblDebuggerHandleImpl* handle = new (std::nothrow) WdblDebuggerHandleImpl();
    if (handle == nullptr) {
        return 0;
    }

    try {
        handle->debugger = new Debugger(path);
    } catch (...) {
        delete handle;
        return 0;
    }

    *outHandle = handle;
    return 1;
}

void WDBL_CALL WdblDestroyDebugger(WdblDebuggerHandle handle) {
    WdblDebuggerHandleImpl* impl = static_cast<WdblDebuggerHandleImpl*>(handle);
    if (impl == nullptr) {
        return;
    }
    delete impl->debugger;
    impl->debugger = nullptr;
    delete impl;
}

const WdblDebuggerApi* WDBL_CALL WdblGetDebuggerApi(WdblDebuggerHandle handle) {
    const WdblDebuggerHandleImpl* impl = static_cast<const WdblDebuggerHandleImpl*>(handle);
    if (impl == nullptr || impl->debugger == nullptr) {
        return nullptr;
    }
    return impl->debugger->GetDebuggerApi();
}
