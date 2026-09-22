#include "../src/Common/PluginApi.h"

#include <cwctype>
#include <sstream>
#include <string>

namespace {

struct PluginContext {
    WdblHostApi host{};
};

std::wstring Trim(const std::wstring& value) {
    size_t begin = 0;
    while (begin < value.size() && std::iswspace(value[begin])) {
        ++begin;
    }
    size_t end = value.size();
    while (end > begin && std::iswspace(value[end - 1])) {
        --end;
    }
    return value.substr(begin, end - begin);
}

void HostLog(const PluginContext* ctx, const std::wstring& message) {
    if (ctx == nullptr || ctx->host.log == nullptr) {
        return;
    }
    ctx->host.log(ctx->host.context, message.c_str());
}

int32_t HostExecute(const PluginContext* ctx, const std::wstring& command) {
    if (ctx == nullptr || ctx->host.execute == nullptr) {
        return 0;
    }
    return ctx->host.execute(ctx->host.context, command.c_str());
}

} // namespace

extern "C" __declspec(dllexport) int32_t WDBL_CALL WdblPluginGetInfo(WdblPluginInfo* outInfo) {
    if (outInfo == nullptr || outInfo->size < sizeof(WdblPluginInfo)) {
        return 0;
    }
    *outInfo = {};
    outInfo->size = sizeof(WdblPluginInfo);
    outInfo->apiVersion = WDBL_PLUGIN_API_VERSION;
    wcsncpy_s(outInfo->name, L"SamplePlugin", _TRUNCATE);
    wcsncpy_s(outInfo->version, L"1.0", _TRUNCATE);
    wcsncpy_s(outInfo->description, L"Example plugin: reads stop info, controls stepping, and prints output.", _TRUNCATE);
    return 1;
}

extern "C" __declspec(dllexport) int32_t WDBL_CALL WdblPluginInitialize(const WdblHostApi* hostApi, void** pluginContext) {
    if (hostApi == nullptr || pluginContext == nullptr) {
        return 0;
    }
    if (hostApi->apiVersion != WDBL_PLUGIN_API_VERSION ||
        hostApi->execute == nullptr ||
        hostApi->log == nullptr ||
        hostApi->getStopInfo == nullptr) {
        return 0;
    }

    auto* ctx = new PluginContext();
    ctx->host = *hostApi;
    *pluginContext = ctx;
    if (ctx->host.subscribeEvents != nullptr) {
        ctx->host.subscribeEvents(ctx->host.context, 1);
    }
    HostLog(ctx, L"[SamplePlugin] Initialized. Run with: plugin run SamplePlugin info|step|breaks");
    return 1;
}

extern "C" __declspec(dllexport) int32_t WDBL_CALL WdblPluginExecute(void* pluginContext, const wchar_t* args) {
    auto* ctx = static_cast<PluginContext*>(pluginContext);
    if (ctx == nullptr) {
        return 0;
    }

    const std::wstring action = Trim(args == nullptr ? L"" : args);
    if (action.empty() || action == L"help") {
        HostLog(ctx, L"[SamplePlugin] Actions: info | step | run | breaks");
        return 1;
    }
    if (action == L"info") {
        WdblStopInfo info{};
        info.size = sizeof(WdblStopInfo);
        if (ctx->host.getStopInfo(ctx->host.context, &info) == 0 || info.paused == 0) {
            HostLog(ctx, L"[SamplePlugin] Debuggee is not paused.");
            return 1;
        }
        std::wstringstream ss;
        ss << L"[SamplePlugin] paused pid=" << info.processId
           << L" tid=" << info.threadId
           << L" ip=0x" << std::hex << info.instructionPointer
           << L" reason=" << info.reason;
        HostLog(ctx, ss.str());
        return 1;
    }
    if (action == L"step") {
        HostLog(ctx, L"[SamplePlugin] Executing step...");
        return HostExecute(ctx, L"step");
    }
    if (action == L"run") {
        HostLog(ctx, L"[SamplePlugin] Executing run...");
        return HostExecute(ctx, L"run");
    }
    if (action == L"breaks") {
        return HostExecute(ctx, L"bl");
    }

    HostLog(ctx, L"[SamplePlugin] Unknown action. Use: info | step | run | breaks");
    return 0;
}

extern "C" __declspec(dllexport) void WDBL_CALL WdblPluginShutdown(void* pluginContext) {
    auto* ctx = static_cast<PluginContext*>(pluginContext);
    if (ctx == nullptr) {
        return;
    }
    HostLog(ctx, L"[SamplePlugin] Shutdown.");
    delete ctx;
}

extern "C" __declspec(dllexport) void WDBL_CALL WdblPluginOnEvent(void* pluginContext, const WdblPluginEvent* eventData) {
    auto* ctx = static_cast<PluginContext*>(pluginContext);
    if (ctx == nullptr || eventData == nullptr) {
        return;
    }
    if (eventData->type == WDBL_PLUGIN_EVENT_PAUSED) {
        std::wstringstream ss;
        ss << L"[SamplePlugin] Paused event: ip=0x" << std::hex << eventData->stopInfo.instructionPointer
           << L" reason=" << eventData->stopInfo.reason;
        HostLog(ctx, ss.str());
    } else if (eventData->type == WDBL_PLUGIN_EVENT_MODULE_LOADED) {
        std::wstringstream ss;
        ss << L"[SamplePlugin] Module loaded @0x" << std::hex << eventData->address
           << L": " << eventData->modulePath;
        HostLog(ctx, ss.str());
    }
}
