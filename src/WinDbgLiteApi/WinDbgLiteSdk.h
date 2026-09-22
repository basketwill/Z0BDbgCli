#pragma once

// WinDbgLite SDK umbrella header.
// Include this file from tools, plugins, or external integrations when you
// want both the debugger API and the plugin ABI definitions in one place.

#include "WinDbgLiteApi.h"
#include "../Common/PluginApi.h"

// Common debugger-side helpers.
typedef const WdblDebuggerApi* WdblDebuggerApiPtr;
typedef const WdblHostApi* WdblHostApiPtr;

