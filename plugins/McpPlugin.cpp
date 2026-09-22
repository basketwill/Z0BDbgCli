#include "../src/Common/PluginApi.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cwctype>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

struct PluginContext {
    WdblHostApi host{};
    PROCESS_INFORMATION process{};
    HANDLE stdinWrite = nullptr;
    HANDLE stdoutRead = nullptr;
    bool connected = false;
    bool initialized = false;
    uint64_t nextRequestId = 1;
    std::string readBuffer;
    std::wstring serverCommandLine;
};

std::wstring Trim(const std::wstring& value) {
    size_t begin = 0;
    while (begin < value.size() && std::iswspace(static_cast<unsigned short>(value[begin])) != 0) {
        ++begin;
    }
    size_t end = value.size();
    while (end > begin && std::iswspace(static_cast<unsigned short>(value[end - 1])) != 0) {
        --end;
    }
    return value.substr(begin, end - begin);
}

std::wstring ToLower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (size <= 0) {
        return {};
    }
    std::string out(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        out.data(),
        size,
        nullptr,
        nullptr);
    return out;
}

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    const int size = MultiByteToWideChar(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0);
    if (size <= 0) {
        return {};
    }
    std::wstring out(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        out.data(),
        size);
    return out;
}

std::string EscapeJsonStringUtf8(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (unsigned char ch : value) {
        switch (ch) {
        case '\"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (ch < 0x20) {
                wchar_t tmp[8] = {};
                swprintf_s(tmp, L"\\u%04x", static_cast<unsigned int>(ch));
                out += WideToUtf8(tmp);
            } else {
                out.push_back(static_cast<char>(ch));
            }
            break;
        }
    }
    return out;
}

std::string EscapeJsonString(const std::wstring& value) {
    return EscapeJsonStringUtf8(WideToUtf8(value));
}

void HostLog(const PluginContext* ctx, const std::wstring& message) {
    if (ctx == nullptr || ctx->host.log == nullptr) {
        return;
    }
    ctx->host.log(ctx->host.context, message.c_str());
}

void CloseConnection(PluginContext& ctx) {
    if (ctx.stdinWrite != nullptr) {
        CloseHandle(ctx.stdinWrite);
        ctx.stdinWrite = nullptr;
    }
    if (ctx.stdoutRead != nullptr) {
        CloseHandle(ctx.stdoutRead);
        ctx.stdoutRead = nullptr;
    }
    if (ctx.process.hProcess != nullptr) {
        const DWORD waitResult = WaitForSingleObject(ctx.process.hProcess, 1500);
        if (waitResult == WAIT_TIMEOUT) {
            TerminateProcess(ctx.process.hProcess, 1);
            WaitForSingleObject(ctx.process.hProcess, 1500);
        }
        CloseHandle(ctx.process.hProcess);
        ctx.process.hProcess = nullptr;
    }
    if (ctx.process.hThread != nullptr) {
        CloseHandle(ctx.process.hThread);
        ctx.process.hThread = nullptr;
    }
    ctx.connected = false;
    ctx.initialized = false;
    ctx.readBuffer.clear();
}

bool StartServerProcess(PluginContext& ctx, const std::wstring& commandLine) {
    CloseConnection(ctx);

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE childStdoutRead = nullptr;
    HANDLE childStdoutWrite = nullptr;
    HANDLE childStdinRead = nullptr;
    HANDLE childStdinWrite = nullptr;

    if (!CreatePipe(&childStdoutRead, &childStdoutWrite, &sa, 0)) {
        return false;
    }
    if (!SetHandleInformation(childStdoutRead, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(childStdoutRead);
        CloseHandle(childStdoutWrite);
        return false;
    }

    if (!CreatePipe(&childStdinRead, &childStdinWrite, &sa, 0)) {
        CloseHandle(childStdoutRead);
        CloseHandle(childStdoutWrite);
        return false;
    }
    if (!SetHandleInformation(childStdinWrite, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(childStdoutRead);
        CloseHandle(childStdoutWrite);
        CloseHandle(childStdinRead);
        CloseHandle(childStdinWrite);
        return false;
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = childStdinRead;
    si.hStdOutput = childStdoutWrite;
    si.hStdError = childStdoutWrite;

    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> mutableCmd(commandLine.begin(), commandLine.end());
    mutableCmd.push_back(L'\0');
    const BOOL created = CreateProcessW(
        nullptr,
        mutableCmd.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi);

    CloseHandle(childStdinRead);
    CloseHandle(childStdoutWrite);

    if (!created) {
        CloseHandle(childStdoutRead);
        CloseHandle(childStdinWrite);
        return false;
    }

    ctx.process = pi;
    ctx.stdinWrite = childStdinWrite;
    ctx.stdoutRead = childStdoutRead;
    ctx.connected = true;
    ctx.initialized = false;
    ctx.readBuffer.clear();
    ctx.serverCommandLine = commandLine;
    ctx.nextRequestId = 1;
    return true;
}

bool WriteUtf8ToServer(PluginContext& ctx, const std::string& utf8) {
    if (!ctx.connected || ctx.stdinWrite == nullptr) {
        return false;
    }
    const std::string header = "Content-Length: " + std::to_string(utf8.size()) + "\r\n\r\n";
    DWORD written = 0;
    if (!WriteFile(ctx.stdinWrite, header.data(), static_cast<DWORD>(header.size()), &written, nullptr) ||
        written != header.size()) {
        return false;
    }
    if (!WriteFile(ctx.stdinWrite, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr) ||
        written != utf8.size()) {
        return false;
    }
    FlushFileBuffers(ctx.stdinWrite);
    return true;
}

bool TryExtractFramedMessage(std::string& buffer, std::string& outMessage) {
    const size_t headerEnd = buffer.find("\r\n\r\n");
    if (headerEnd == std::string::npos) {
        return false;
    }

    std::string headerBlock = buffer.substr(0, headerEnd);
    std::istringstream headerStream(headerBlock);
    std::string line;
    size_t contentLength = 0;
    bool haveLength = false;

    while (std::getline(headerStream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        std::string lower = line;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        static constexpr char kLengthPrefix[] = "content-length:";
        if (lower.rfind(kLengthPrefix, 0) == 0) {
            std::string value = line.substr(sizeof(kLengthPrefix) - 1);
            size_t begin = 0;
            while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin])) != 0) {
                ++begin;
            }
            try {
                contentLength = static_cast<size_t>(std::stoull(value.substr(begin)));
                haveLength = true;
            } catch (...) {
                return false;
            }
            break;
        }
    }

    if (!haveLength) {
        return false;
    }

    const size_t bodyOffset = headerEnd + 4;
    if (buffer.size() < bodyOffset + contentLength) {
        return false;
    }

    outMessage = buffer.substr(bodyOffset, contentLength);
    buffer.erase(0, bodyOffset + contentLength);
    return true;
}

// Returns: 1=data read, 0=timeout/no data, -1=pipe/error.
int ReadPipeChunkWithTimeout(HANDLE pipe, std::string& appendTo, uint32_t timeoutMs) {
    if (pipe == nullptr) {
        return -1;
    }
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    std::array<char, 4096> chunk{};

    while (std::chrono::steady_clock::now() < deadline) {
        DWORD available = 0;
        if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) {
            return -1;
        }
        if (available == 0) {
            Sleep(10);
            continue;
        }

        const DWORD toRead = std::min<DWORD>(available, static_cast<DWORD>(chunk.size()));
        DWORD bytesRead = 0;
        if (!ReadFile(pipe, chunk.data(), toRead, &bytesRead, nullptr)) {
            return -1;
        }
        if (bytesRead == 0) {
            Sleep(10);
            continue;
        }
        appendTo.append(chunk.data(), chunk.data() + bytesRead);
        return 1;
    }
    return 0;
}

bool IsResponseForId(const std::string& json, uint64_t requestId) {
    static const std::regex idRegex(R"("id"\s*:\s*([0-9]+))");
    std::smatch match;
    if (!std::regex_search(json, match, idRegex)) {
        return false;
    }
    if (match.size() < 2) {
        return false;
    }
    try {
        return std::stoull(match[1].str()) == requestId;
    } catch (...) {
        return false;
    }
}

std::wstring PreviewUtf8(const std::string& json, size_t maxChars = 220) {
    std::wstring wide = Utf8ToWide(json);
    for (wchar_t& ch : wide) {
        if (ch == L'\r' || ch == L'\n' || ch == L'\t') {
            ch = L' ';
        }
    }
    if (wide.size() > maxChars) {
        wide.resize(maxChars);
        wide += L"...";
    }
    return wide;
}

bool WaitForResponse(PluginContext& ctx, uint64_t requestId, std::string& outJson, uint32_t timeoutMs) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        std::string message;
        while (TryExtractFramedMessage(ctx.readBuffer, message)) {
            if (IsResponseForId(message, requestId)) {
                outJson = std::move(message);
                return true;
            }
            HostLog(&ctx, L"[McpPlugin] notification: " + PreviewUtf8(message));
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            break;
        }
        const auto remaining = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
        const int readResult = ReadPipeChunkWithTimeout(ctx.stdoutRead, ctx.readBuffer, std::min<uint32_t>(200, remaining));
        if (readResult < 0) {
            return false;
        }
    }
    return false;
}

std::string BuildRequestJson(uint64_t id, const std::wstring& method, const std::string& paramsJson) {
    std::ostringstream ss;
    ss << "{\"jsonrpc\":\"2.0\",\"id\":" << id
       << ",\"method\":\"" << EscapeJsonString(method) << "\",\"params\":" << paramsJson << "}";
    return ss.str();
}

std::string BuildNotificationJson(const std::wstring& method, const std::string& paramsJson) {
    std::ostringstream ss;
    ss << "{\"jsonrpc\":\"2.0\",\"method\":\"" << EscapeJsonString(method) << "\",\"params\":" << paramsJson << "}";
    return ss.str();
}

bool SendRequestAndWait(
    PluginContext& ctx,
    const std::wstring& method,
    const std::string& paramsJson,
    std::string& responseJson,
    uint32_t timeoutMs) {
    if (!ctx.connected) {
        return false;
    }
    const uint64_t id = ctx.nextRequestId++;
    const std::string requestJson = BuildRequestJson(id, method, paramsJson);
    if (!WriteUtf8ToServer(ctx, requestJson)) {
        return false;
    }
    if (!WaitForResponse(ctx, id, responseJson, timeoutMs)) {
        return false;
    }
    return true;
}

std::vector<std::wstring> ExtractJsonStringFieldValues(const std::string& json, const char* fieldName) {
    std::vector<std::wstring> values;
    if (fieldName == nullptr || *fieldName == '\0') {
        return values;
    }
    const std::string pattern = std::string("\"") + fieldName + "\"\\s*:\\s*\"([^\"]+)\"";
    const std::regex fieldRegex(pattern);
    for (std::sregex_iterator it(json.begin(), json.end(), fieldRegex), end; it != end; ++it) {
        if ((*it).size() >= 2) {
            values.push_back(Utf8ToWide((*it)[1].str()));
        }
    }
    return values;
}

bool ResponseContainsError(const std::string& responseJson) {
    return responseJson.find("\"error\"") != std::string::npos;
}

std::wstring ExtractErrorMessage(const std::string& responseJson) {
    static const std::regex messageRegex("\"message\"\\s*:\\s*\"([^\"]*)\"");
    std::smatch match;
    if (!std::regex_search(responseJson, match, messageRegex) || match.size() < 2) {
        return L"Unknown MCP error";
    }
    return Utf8ToWide(match[1].str());
}

bool InitializeMcpSession(PluginContext& ctx) {
    if (!ctx.connected) {
        HostLog(&ctx, L"[McpPlugin] Not connected. Use: plugin run McpPlugin start <mcp-server-command>");
        return false;
    }
    if (ctx.initialized) {
        return true;
    }

    const std::string paramsJson =
        "{\"protocolVersion\":\"2024-11-05\","
        "\"capabilities\":{\"tools\":{},\"prompts\":{},\"resources\":{}},"
        "\"clientInfo\":{\"name\":\"WinDbgLiteMcpPlugin\",\"version\":\"1.0\"}}";
    std::string response;
    if (!SendRequestAndWait(ctx, L"initialize", paramsJson, response, 15000)) {
        HostLog(&ctx, L"[McpPlugin] initialize request timed out or failed.");
        return false;
    }
    if (ResponseContainsError(response)) {
        HostLog(&ctx, L"[McpPlugin] initialize error: " + ExtractErrorMessage(response));
        return false;
    }
    if (!WriteUtf8ToServer(ctx, BuildNotificationJson(L"notifications/initialized", "{}"))) {
        HostLog(&ctx, L"[McpPlugin] initialized notification failed to send.");
        return false;
    }

    ctx.initialized = true;
    HostLog(&ctx, L"[McpPlugin] MCP initialized.");
    return true;
}

void SplitFirstToken(const std::wstring& input, std::wstring& first, std::wstring& rest) {
    const std::wstring trimmed = Trim(input);
    if (trimmed.empty()) {
        first.clear();
        rest.clear();
        return;
    }
    size_t i = 0;
    while (i < trimmed.size() && std::iswspace(static_cast<unsigned short>(trimmed[i])) == 0) {
        ++i;
    }
    first = trimmed.substr(0, i);
    rest = i < trimmed.size() ? Trim(trimmed.substr(i)) : L"";
}

void LogUsage(const PluginContext* ctx) {
    HostLog(ctx, L"[McpPlugin] Usage:");
    HostLog(ctx, L"  plugin run McpPlugin start <mcp_server_command_line>");
    HostLog(ctx, L"  plugin run McpPlugin init");
    HostLog(ctx, L"  plugin run McpPlugin tools");
    HostLog(ctx, L"  plugin run McpPlugin call <tool_name> <json_arguments>");
    HostLog(ctx, L"  plugin run McpPlugin skills [list]");
    HostLog(ctx, L"  plugin run McpPlugin skills run <skill_name> <json_arguments>");
    HostLog(ctx, L"  plugin run McpPlugin skill <skill_name> <json_arguments>");
    HostLog(ctx, L"  plugin run McpPlugin stop");
    HostLog(ctx, L"  plugin run McpPlugin status");
}

bool HandleToolsList(PluginContext& ctx) {
    if (!InitializeMcpSession(ctx)) {
        return false;
    }

    std::string response;
    if (!SendRequestAndWait(ctx, L"tools/list", "{}", response, 15000)) {
        HostLog(&ctx, L"[McpPlugin] tools/list request failed.");
        return false;
    }
    if (ResponseContainsError(response)) {
        HostLog(&ctx, L"[McpPlugin] tools/list error: " + ExtractErrorMessage(response));
        return false;
    }

    const std::vector<std::wstring> toolNames = ExtractJsonStringFieldValues(response, "name");

    if (toolNames.empty()) {
        HostLog(&ctx, L"[McpPlugin] tools/list response: " + PreviewUtf8(response, 400));
        return true;
    }

    HostLog(&ctx, L"[McpPlugin] Available tools:");
    for (const auto& name : toolNames) {
        HostLog(&ctx, L"  - " + name);
    }
    return true;
}

bool CallTool(PluginContext& ctx, const std::wstring& toolName, const std::string& argsJsonUtf8, std::string& response) {
    const std::string paramsJson =
        std::string("{\"name\":\"") + EscapeJsonString(toolName) + "\",\"arguments\":" + argsJsonUtf8 + "}";
    return SendRequestAndWait(ctx, L"tools/call", paramsJson, response, 20000);
}

bool GetPrompt(PluginContext& ctx, const std::wstring& promptName, const std::string& argsJsonUtf8, std::string& response) {
    const std::string paramsJson =
        std::string("{\"name\":\"") + EscapeJsonString(promptName) + "\",\"arguments\":" + argsJsonUtf8 + "}";
    return SendRequestAndWait(ctx, L"prompts/get", paramsJson, response, 20000);
}

bool ReadResource(PluginContext& ctx, const std::wstring& uri, std::string& response) {
    const std::string paramsJson =
        std::string("{\"uri\":\"") + EscapeJsonString(uri) + "\"}";
    return SendRequestAndWait(ctx, L"resources/read", paramsJson, response, 20000);
}

bool HandleToolCall(PluginContext& ctx, const std::wstring& input) {
    if (!InitializeMcpSession(ctx)) {
        return false;
    }

    std::wstring toolName;
    std::wstring argJsonWide;
    SplitFirstToken(input, toolName, argJsonWide);
    if (toolName.empty()) {
        HostLog(&ctx, L"[McpPlugin] call requires a tool name.");
        return false;
    }

    const std::string argsJsonUtf8 = argJsonWide.empty() ? "{}" : WideToUtf8(argJsonWide);
    std::string response;
    if (!CallTool(ctx, toolName, argsJsonUtf8, response)) {
        HostLog(&ctx, L"[McpPlugin] tools/call request failed.");
        return false;
    }
    if (ResponseContainsError(response)) {
        HostLog(&ctx, L"[McpPlugin] tools/call error: " + ExtractErrorMessage(response));
        return false;
    }

    HostLog(&ctx, L"[McpPlugin] tools/call response: " + PreviewUtf8(response, 700));
    return true;
}

bool HandleSkillsList(PluginContext& ctx) {
    if (!InitializeMcpSession(ctx)) {
        return false;
    }

    std::vector<std::wstring> skillLines;
    std::unordered_set<std::wstring> seen;
    auto addUnique = [&](const std::wstring& text) {
        if (text.empty()) {
            return;
        }
        const std::wstring key = ToLower(text);
        if (seen.insert(key).second) {
            skillLines.push_back(text);
        }
    };

    std::string toolsResponse;
    if (SendRequestAndWait(ctx, L"tools/list", "{}", toolsResponse, 15000) && !ResponseContainsError(toolsResponse)) {
        for (const auto& name : ExtractJsonStringFieldValues(toolsResponse, "name")) {
            addUnique(L"tool/" + name);
        }
    }

    std::string promptsResponse;
    if (SendRequestAndWait(ctx, L"prompts/list", "{}", promptsResponse, 15000) && !ResponseContainsError(promptsResponse)) {
        for (const auto& name : ExtractJsonStringFieldValues(promptsResponse, "name")) {
            addUnique(L"prompt/" + name);
        }
    }

    std::string resourcesResponse;
    if (SendRequestAndWait(ctx, L"resources/list", "{}", resourcesResponse, 15000) && !ResponseContainsError(resourcesResponse)) {
        for (const auto& uri : ExtractJsonStringFieldValues(resourcesResponse, "uri")) {
            addUnique(L"resource/" + uri);
        }
    }

    if (skillLines.empty()) {
        HostLog(&ctx, L"[McpPlugin] No skills discovered from tools/prompts/resources.");
        return true;
    }

    HostLog(&ctx, L"[McpPlugin] Skills:");
    for (const auto& line : skillLines) {
        HostLog(&ctx, L"  - " + line);
    }
    return true;
}

bool HandleSkillsRun(PluginContext& ctx, const std::wstring& input) {
    if (!InitializeMcpSession(ctx)) {
        return false;
    }

    std::wstring skillName;
    std::wstring argsWide;
    SplitFirstToken(input, skillName, argsWide);
    if (skillName.empty()) {
        HostLog(&ctx, L"[McpPlugin] skills run requires a skill name.");
        return false;
    }

    const std::string argsJsonUtf8 = argsWide.empty() ? "{}" : WideToUtf8(argsWide);
    std::string response;
    const std::wstring lowerName = ToLower(skillName);

    auto logResponse = [&](const std::wstring& prefix) -> bool {
        if (ResponseContainsError(response)) {
            HostLog(&ctx, prefix + L" error: " + ExtractErrorMessage(response));
            return false;
        }
        HostLog(&ctx, prefix + L" response: " + PreviewUtf8(response, 700));
        return true;
    };

    if (lowerName.rfind(L"tool/", 0) == 0) {
        const std::wstring toolName = skillName.substr(5);
        if (!CallTool(ctx, toolName, argsJsonUtf8, response)) {
            HostLog(&ctx, L"[McpPlugin] tool skill request failed.");
            return false;
        }
        return logResponse(L"[McpPlugin] tool skill");
    }

    if (lowerName.rfind(L"prompt/", 0) == 0) {
        const std::wstring promptName = skillName.substr(7);
        if (!GetPrompt(ctx, promptName, argsJsonUtf8, response)) {
            HostLog(&ctx, L"[McpPlugin] prompt skill request failed.");
            return false;
        }
        return logResponse(L"[McpPlugin] prompt skill");
    }

    if (lowerName.rfind(L"resource/", 0) == 0) {
        const std::wstring uri = skillName.substr(9);
        if (!ReadResource(ctx, uri, response)) {
            HostLog(&ctx, L"[McpPlugin] resource skill request failed.");
            return false;
        }
        return logResponse(L"[McpPlugin] resource skill");
    }

    if (GetPrompt(ctx, skillName, argsJsonUtf8, response) && !ResponseContainsError(response)) {
        return logResponse(L"[McpPlugin] skill(prompt)");
    }
    if (CallTool(ctx, skillName, argsJsonUtf8, response) && !ResponseContainsError(response)) {
        return logResponse(L"[McpPlugin] skill(tool)");
    }

    if (ResponseContainsError(response)) {
        HostLog(&ctx, L"[McpPlugin] skill run error: " + ExtractErrorMessage(response));
    } else {
        HostLog(&ctx, L"[McpPlugin] skill run failed for name: " + skillName);
    }
    return false;
}

} // namespace

extern "C" __declspec(dllexport) int32_t WDBL_CALL WdblPluginGetInfo(WdblPluginInfo* outInfo) {
    if (outInfo == nullptr || outInfo->size < sizeof(WdblPluginInfo)) {
        return 0;
    }
    *outInfo = {};
    outInfo->size = sizeof(WdblPluginInfo);
    outInfo->apiVersion = WDBL_PLUGIN_API_VERSION;
    wcsncpy_s(outInfo->name, L"McpPlugin", _TRUNCATE);
    wcsncpy_s(outInfo->version, L"1.0", _TRUNCATE);
    wcsncpy_s(outInfo->description, L"MCP stdio client plugin with tools and skills commands.", _TRUNCATE);
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
    HostLog(ctx, L"[McpPlugin] Initialized. Run 'plugin run McpPlugin help' for commands.");
    return 1;
}

extern "C" __declspec(dllexport) int32_t WDBL_CALL WdblPluginExecute(void* pluginContext, const wchar_t* args) {
    auto* ctx = static_cast<PluginContext*>(pluginContext);
    if (ctx == nullptr) {
        return 0;
    }

    std::wstring action;
    std::wstring rest;
    SplitFirstToken(args == nullptr ? L"" : args, action, rest);
    action = ToLower(action);

    if (action.empty() || action == L"help") {
        LogUsage(ctx);
        return 1;
    }

    if (action == L"start") {
        if (rest.empty()) {
            HostLog(ctx, L"[McpPlugin] Missing server command line.");
            LogUsage(ctx);
            return 0;
        }
        if (!StartServerProcess(*ctx, rest)) {
            HostLog(ctx, L"[McpPlugin] Failed to start MCP server process.");
            return 0;
        }
        HostLog(ctx, L"[McpPlugin] MCP server started: " + rest);
        return 1;
    }

    if (action == L"stop") {
        if (!ctx->connected) {
            HostLog(ctx, L"[McpPlugin] No active MCP server.");
            return 1;
        }
        CloseConnection(*ctx);
        HostLog(ctx, L"[McpPlugin] MCP server stopped.");
        return 1;
    }

    if (action == L"status") {
        if (!ctx->connected) {
            HostLog(ctx, L"[McpPlugin] Status: disconnected.");
            return 1;
        }
        HostLog(ctx, std::wstring(L"[McpPlugin] Status: connected, initialized=") + (ctx->initialized ? L"yes" : L"no"));
        if (!ctx->serverCommandLine.empty()) {
            HostLog(ctx, L"[McpPlugin] Server: " + ctx->serverCommandLine);
        }
        return 1;
    }

    if (action == L"init") {
        return InitializeMcpSession(*ctx) ? 1 : 0;
    }

    if (action == L"tools" || action == L"list") {
        return HandleToolsList(*ctx) ? 1 : 0;
    }

    if (action == L"call") {
        return HandleToolCall(*ctx, rest) ? 1 : 0;
    }

    if (action == L"skills") {
        std::wstring subAction;
        std::wstring subRest;
        SplitFirstToken(rest, subAction, subRest);
        subAction = ToLower(subAction);
        if (subAction.empty() || subAction == L"list") {
            return HandleSkillsList(*ctx) ? 1 : 0;
        }
        if (subAction == L"run") {
            return HandleSkillsRun(*ctx, subRest) ? 1 : 0;
        }
        HostLog(ctx, L"[McpPlugin] Unknown skills action: " + subAction);
        return 0;
    }

    if (action == L"skill") {
        return HandleSkillsRun(*ctx, rest) ? 1 : 0;
    }

    HostLog(ctx, L"[McpPlugin] Unknown command: " + action);
    LogUsage(ctx);
    return 0;
}

extern "C" __declspec(dllexport) void WDBL_CALL WdblPluginShutdown(void* pluginContext) {
    auto* ctx = static_cast<PluginContext*>(pluginContext);
    if (ctx == nullptr) {
        return;
    }
    CloseConnection(*ctx);
    HostLog(ctx, L"[McpPlugin] Shutdown.");
    delete ctx;
}
