#pragma once

#include "../Common/PluginApi.h"

#if defined(_WIN32)
#if defined(WinDbgLiteApi_EXPORTS)
#define WDBL_API extern "C" __declspec(dllexport)
#else
#define WDBL_API extern "C" __declspec(dllimport)
#endif
#else
#define WDBL_API extern "C"
#endif

typedef void* WdblDebuggerHandle;

WDBL_API int32_t WDBL_CALL WdblCreateDebugger(const wchar_t* tracePath, WdblDebuggerHandle* outHandle);
WDBL_API void WDBL_CALL WdblDestroyDebugger(WdblDebuggerHandle handle);
WDBL_API const WdblDebuggerApi* WDBL_CALL WdblGetDebuggerApi(WdblDebuggerHandle handle);

#undef WDBL_API
