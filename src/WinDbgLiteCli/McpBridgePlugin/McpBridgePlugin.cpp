#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <stdint.h>
#include <stdio.h>
#include <deque>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "..\..\Common\PluginApi.h"

#pragma comment(lib, "bcrypt.lib")

namespace {

const wchar_t kPipeName[] = L"\\\\.\\pipe\\Z0BDbgMcpBridge";
const char kProtocolName[] = "Z0BDbgMcpBridge-v1";

enum SecurityMode {
    SecurityPlain,
    SecurityOptional,
    SecurityStrict
};

struct SecureSession {
    SecurityMode mode;
    std::string secret;
    bool encrypted;
    std::string clientNonce;
    std::string serverNonce;

    SecureSession()
        : mode(SecurityPlain), encrypted(false) {
    }
};

struct BridgeContext {
    BridgeContext()
        : host(),
          thread(NULL),
          stopEvent(NULL),
          events(),
          stopping(0) {
    }

    WdblHostApi host;
    HANDLE thread;
    HANDLE stopEvent;
    CRITICAL_SECTION apiLock;
    CRITICAL_SECTION eventLock;
    std::deque<std::string> events;
    volatile LONG stopping;
};

BridgeContext* g_context = NULL;

bool ExtractString(const std::string& json, const char* key, std::string& out);
std::string ToLowerAscii(std::string text);

std::string GetEnvironmentValue(const char* name) {
    char buffer[256] = {};
    DWORD length = GetEnvironmentVariableA(name, buffer, sizeof(buffer));
    if (length == 0 || length >= sizeof(buffer)) {
        return std::string();
    }
    return std::string(buffer, length);
}

SecurityMode ReadSecurityMode() {
    const std::string value = GetEnvironmentValue("Z0BDBG_MCP_SECURITY_MODE");
    if (_stricmp(value.c_str(), "strict") == 0 ||
        _stricmp(value.c_str(), "encrypted") == 0) {
        return SecurityStrict;
    }
    if (_stricmp(value.c_str(), "optional") == 0 ||
        _stricmp(value.c_str(), "auto") == 0) {
        return SecurityOptional;
    }
    return SecurityPlain;
}

std::string HexEncode(const std::vector<unsigned char>& data) {
    static const char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (size_t i = 0; i < data.size(); ++i) {
        result.push_back(digits[(data[i] >> 4) & 0x0f]);
        result.push_back(digits[data[i] & 0x0f]);
    }
    return result;
}

bool HexDecode(const std::string& text, std::vector<unsigned char>& data) {
    data.clear();
    if ((text.size() & 1) != 0) {
        return false;
    }
    for (size_t i = 0; i < text.size(); i += 2) {
        const char a = text[i];
        const char b = text[i + 1];
        const int high = a >= '0' && a <= '9' ? a - '0'
            : a >= 'a' && a <= 'f' ? a - 'a' + 10
            : a >= 'A' && a <= 'F' ? a - 'A' + 10 : -1;
        const int low = b >= '0' && b <= '9' ? b - '0'
            : b >= 'a' && b <= 'f' ? b - 'a' + 10
            : b >= 'A' && b <= 'F' ? b - 'A' + 10 : -1;
        if (high < 0 || low < 0) {
            return false;
        }
        data.push_back(static_cast<unsigned char>((high << 4) | low));
    }
    return true;
}

bool HmacSha256(
    const std::string& key,
    const std::string& input,
    std::vector<unsigned char>& digest) {
    digest.assign(32, 0);
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    DWORD objectLength = 0;
    DWORD resultLength = 0;
    PUCHAR object = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status < 0) {
        return false;
    }
    status = BCryptGetProperty(
        algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength),
        sizeof(objectLength), &resultLength, 0);
    if (status >= 0) {
        object = new unsigned char[objectLength];
        status = BCryptCreateHash(
            algorithm, &hash, object, objectLength,
            reinterpret_cast<PUCHAR>(const_cast<char*>(key.data())),
            static_cast<ULONG>(key.size()), 0);
    }
    if (status >= 0) {
        status = BCryptHashData(
            hash, reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
            static_cast<ULONG>(input.size()), 0);
    }
    if (status >= 0) {
        status = BCryptFinishHash(hash, &digest[0], 32, 0);
    }
    if (hash != NULL) {
        BCryptDestroyHash(hash);
    }
    if (algorithm != NULL) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    delete[] object;
    return status >= 0;
}

bool ConstantTimeEqual(
    const std::vector<unsigned char>& left,
    const std::vector<unsigned char>& right) {
    if (left.size() != right.size()) {
        return false;
    }
    unsigned char difference = 0;
    for (size_t i = 0; i < left.size(); ++i) {
        difference = static_cast<unsigned char>(difference | (left[i] ^ right[i]));
    }
    return difference == 0;
}

std::string SecurityModeName(SecurityMode mode) {
    if (mode == SecurityStrict) {
        return "strict";
    }
    if (mode == SecurityOptional) {
        return "optional";
    }
    return "plain";
}

std::string RandomNonce() {
    unsigned char bytes[16] = {};
    if (BCryptGenRandom(NULL, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        return std::string();
    }
    std::vector<unsigned char> value(bytes, bytes + sizeof(bytes));
    return HexEncode(value);
}

bool HmacHex(
    const std::string& key,
    const std::string& input,
    std::string& output) {
    std::vector<unsigned char> digest;
    if (!HmacSha256(key, input, digest)) {
        output.clear();
        return false;
    }
    output = HexEncode(digest);
    return true;
}

std::string XorCrypt(
    const std::string& key,
    const std::string& nonce,
    const std::string& input) {
    std::string output(input.size(), '\0');
    size_t offset = 0;
    unsigned int counter = 0;
    while (offset < input.size()) {
        char counterText[32] = {};
        sprintf_s(counterText, "%u", counter++);
        std::vector<unsigned char> block;
        if (!HmacSha256(
                key,
                std::string("stream|") + nonce + "|" + counterText,
                block) ||
            block.empty()) {
            return std::string();
        }
        const size_t count = std::min<size_t>(block.size(), input.size() - offset);
        for (size_t i = 0; i < count; ++i) {
            output[offset + i] = static_cast<char>(
                static_cast<unsigned char>(input[offset + i]) ^ block[i]);
        }
        offset += count;
    }
    return output;
}

bool EncryptPayload(
    const SecureSession& session,
    const std::string& plain,
    std::string& envelope) {
    if (session.secret.empty()) {
        return false;
    }
    const std::string nonce = RandomNonce();
    const std::string cipher = XorCrypt(session.secret, nonce, plain);
    if (nonce.empty() || cipher.size() != plain.size()) {
        return false;
    }
    const std::string cipherHex = HexEncode(
        std::vector<unsigned char>(
            reinterpret_cast<const unsigned char*>(cipher.data()),
            reinterpret_cast<const unsigned char*>(cipher.data()) + cipher.size()));
    std::string tag;
    if (!HmacHex(session.secret, "packet|" + nonce + "|" + cipherHex, tag)) {
        return false;
    }
    char header[256] = {};
    sprintf_s(
        header,
        "{\"secure\":1,\"nonce\":\"%s\",\"data\":\"%s\",\"tag\":\"%s\"}",
        nonce.c_str(), cipherHex.c_str(), tag.c_str());
    envelope = header;
    return true;
}

bool DecryptPayload(
    const SecureSession& session,
    const std::string& envelope,
    std::string& plain) {
    std::string nonce;
    std::string dataHex;
    std::string tag;
    if (!ExtractString(envelope, "nonce", nonce) ||
        !ExtractString(envelope, "data", dataHex) ||
        !ExtractString(envelope, "tag", tag)) {
        return false;
    }
    std::vector<unsigned char> cipherBytes;
    if (!HexDecode(dataHex, cipherBytes)) {
        return false;
    }
    std::string expected;
    if (!HmacHex(session.secret, "packet|" + nonce + "|" + dataHex, expected)) {
        return false;
    }
    std::vector<unsigned char> expectedBytes;
    std::vector<unsigned char> actualBytes;
    if (!HexDecode(expected, expectedBytes) || !HexDecode(tag, actualBytes) ||
        !ConstantTimeEqual(expectedBytes, actualBytes)) {
        return false;
    }
    const std::string cipher(
        reinterpret_cast<const char*>(cipherBytes.data()), cipherBytes.size());
    plain = XorCrypt(session.secret, nonce, cipher);
    return plain.size() == cipher.size();
}

void CopyText(wchar_t* dst, size_t count, const wchar_t* src) {
    if (dst == NULL || count == 0) {
        return;
    }
    dst[0] = L'\0';
    if (src == NULL) {
        return;
    }
    wcsncpy_s(dst, count, src, _TRUNCATE);
}

std::wstring Utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return std::wstring();
    }
    int chars = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), NULL, 0);
    if (chars <= 0) {
        return std::wstring();
    }
    std::wstring out;
    out.resize((size_t)chars);
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), &out[0], chars);
    return out;
}

std::string WideToUtf8(const wchar_t* text) {
    if (text == NULL || text[0] == L'\0') {
        return std::string();
    }
    int bytes = WideCharToMultiByte(CP_UTF8, 0, text, -1, NULL, 0, NULL, NULL);
    if (bytes <= 1) {
        return std::string();
    }
    std::string out;
    out.resize((size_t)bytes - 1);
    WideCharToMultiByte(CP_UTF8, 0, text, -1, &out[0], bytes, NULL, NULL);
    return out;
}

std::string JsonEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (size_t i = 0; i < value.size(); ++i) {
        unsigned char ch = (unsigned char)value[i];
        switch (ch) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (ch < 0x20) {
                char buf[8];
                sprintf_s(buf, "\\u%04x", (unsigned int)ch);
                out += buf;
            } else {
                out.push_back((char)ch);
            }
            break;
        }
    }
    return out;
}

std::string HexBytes(const BYTE* data, DWORD size) {
    static const char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve((size_t)size * 2);
    for (DWORD i = 0; i < size; ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0xF]);
        out.push_back(kHex[data[i] & 0xF]);
    }
    return out;
}

bool ExtractString(const std::string& json, const char* key, std::string& out) {
    out.clear();
    std::string token = std::string("\"") + key + "\"";
    size_t p = json.find(token);
    if (p == std::string::npos) {
        return false;
    }
    p = json.find(':', p + token.size());
    if (p == std::string::npos) {
        return false;
    }
    p = json.find('"', p + 1);
    if (p == std::string::npos) {
        return false;
    }
    ++p;
    while (p < json.size()) {
        char ch = json[p++];
        if (ch == '"') {
            return true;
        }
        if (ch == '\\' && p < json.size()) {
            char esc = json[p++];
            switch (esc) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            default: out.push_back(esc); break;
            }
        } else {
            out.push_back(ch);
        }
    }
    return false;
}

bool ExtractUInt64(const std::string& json, const char* key, uint64_t& out) {
    out = 0;
    std::string raw;
    if (ExtractString(json, key, raw)) {
        int base = 10;
        const char* start = raw.c_str();
        if (raw.size() > 2 && raw[0] == '0' && (raw[1] == 'x' || raw[1] == 'X')) {
            base = 16;
            start += 2;
        }
        out = _strtoui64(start, NULL, base);
        return true;
    }

    std::string token = std::string("\"") + key + "\"";
    size_t p = json.find(token);
    if (p == std::string::npos) {
        return false;
    }
    p = json.find(':', p + token.size());
    if (p == std::string::npos) {
        return false;
    }
    ++p;
    while (p < json.size() && (json[p] == ' ' || json[p] == '\t')) {
        ++p;
    }
    size_t start = p;
    while (p < json.size() && ((json[p] >= '0' && json[p] <= '9') || json[p] == 'x' || json[p] == 'X' ||
        (json[p] >= 'a' && json[p] <= 'f') || (json[p] >= 'A' && json[p] <= 'F'))) {
        ++p;
    }
    if (p == start) {
        return false;
    }
    std::string rawNumber = json.substr(start, p - start);
    int base = 10;
    const char* startNumber = rawNumber.c_str();
    if (rawNumber.size() > 2 && rawNumber[0] == '0' && (rawNumber[1] == 'x' || rawNumber[1] == 'X')) {
        base = 16;
        startNumber += 2;
    }
    out = _strtoui64(startNumber, NULL, base);
    return true;
}

bool ExtractBool(const std::string& json, const char* key, bool& out) {
    std::string raw;
    if (ExtractString(json, key, raw)) {
        out = raw == "1" || raw == "true" || raw == "TRUE" || raw == "yes" || raw == "on";
        return true;
    }

    std::string token = std::string("\"") + key + "\"";
    size_t p = json.find(token);
    if (p == std::string::npos) {
        return false;
    }
    p = json.find(':', p + token.size());
    if (p == std::string::npos) {
        return false;
    }
    ++p;
    while (p < json.size() && (json[p] == ' ' || json[p] == '\t')) {
        ++p;
    }
    if (json.compare(p, 4, "true") == 0) {
        out = true;
        return true;
    }
    if (json.compare(p, 5, "false") == 0) {
        out = false;
        return true;
    }
    if (p < json.size() && (json[p] == '0' || json[p] == '1')) {
        out = json[p] == '1';
        return true;
    }
    return false;
}

bool ResolveExpression(const WdblDebuggerApi* api, const std::string& request, const char* key, uint64_t& address, wchar_t* text, uint32_t textChars) {
    std::string expression;
    if (!ExtractString(request, key, expression)) {
        uint64_t numeric = 0;
        if (!ExtractUInt64(request, key, numeric)) {
            return false;
        }
        address = numeric;
        if (text != NULL && textChars != 0 && api->resolveSymbol != NULL) {
            api->resolveSymbol(api->context, address, text, textChars);
        }
        return true;
    }
    std::wstring wide = Utf8ToWide(expression);
    return api->resolveAddressExpression != NULL &&
        api->resolveAddressExpression(api->context, wide.c_str(), &address, text, textChars) != 0;
}

bool ParseHexBytes(const std::string& hex, std::vector<BYTE>& bytes) {
    bytes.clear();
    if ((hex.size() % 2) != 0 || hex.empty() || hex.size() > 8192) {
        return false;
    }
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        char pair[3] = { hex[i], hex[i + 1], 0 };
        char* end = NULL;
        unsigned long value = strtoul(pair, &end, 16);
        if (end == NULL || *end != '\0' || value > 0xFF) {
            return false;
        }
        bytes.push_back((BYTE)value);
    }
    return true;
}

std::string ToLowerAscii(std::string text) {
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] >= 'A' && text[i] <= 'Z') {
            text[i] = (char)(text[i] - 'A' + 'a');
        }
    }
    return text;
}

int32_t ParseHardwareAccess(const std::string& text) {
    const std::string lower = ToLowerAscii(text);
    if (lower == "w" || lower == "write") {
        return 1;
    }
    if (lower == "rw" || lower == "access" || lower == "readwrite") {
        return 2;
    }
    return 0;
}

uint32_t ParseMemoryAccess(const std::string& text) {
    const std::string lower = ToLowerAscii(text);
    if (lower.empty()) {
        return 3;
    }
    uint32_t mask = 0;
    if (lower.find('r') != std::string::npos || lower.find("read") != std::string::npos) {
        mask |= 1;
    }
    if (lower.find('w') != std::string::npos || lower.find("write") != std::string::npos) {
        mask |= 2;
    }
    if (lower.find('x') != std::string::npos || lower.find("exec") != std::string::npos) {
        mask |= 4;
    }
    return mask != 0 ? mask : 3;
}

int32_t ParseExceptionScope(const std::string& text) {
    const std::string lower = ToLowerAscii(text);
    if (lower == "runtime") {
        return 1;
    }
    if (lower == "stepping" || lower == "step") {
        return 2;
    }
    return 0;
}

std::string Ok(const std::string& body) {
    return std::string("{\"ok\":true") + (body.empty() ? "}" : "," + body + "}");
}

std::string Error(const char* message) {
    return std::string("{\"ok\":false,\"error\":\"") + JsonEscape(message != NULL ? message : "error") + "\"}";
}

struct ScopedWcoutRedirect {
    explicit ScopedWcoutRedirect(std::wstreambuf* newBuffer)
        : oldBuffer(std::wcout.rdbuf(newBuffer)) {
    }
    ~ScopedWcoutRedirect() {
        std::wcout.rdbuf(oldBuffer);
    }
    std::wstreambuf* oldBuffer;
private:
    ScopedWcoutRedirect(const ScopedWcoutRedirect&);
    ScopedWcoutRedirect& operator=(const ScopedWcoutRedirect&);
};

const char* EventTypeName(uint32_t type) {
    switch (type) {
    case WDBL_PLUGIN_EVENT_CONTINUE_REQUESTED: return "continue_requested";
    case WDBL_PLUGIN_EVENT_SINGLE_STEP_REQUESTED: return "single_step_requested";
    case WDBL_PLUGIN_EVENT_PAUSED: return "paused";
    case WDBL_PLUGIN_EVENT_MODULE_LOADED: return "module_loaded";
    default: return "unknown";
    }
}

std::string StopInfoFieldsJson(const WdblStopInfo& info) {
    char buf[1200];
    sprintf_s(
        buf,
        "\"paused\":%d,\"processId\":%u,\"threadId\":%u,\"exceptionCode\":%u,"
        "\"firstChance\":%d,\"exceptionAddress\":%llu,\"instructionPointer\":%llu,\"reason\":\"%s\"",
        info.paused,
        info.processId,
        info.threadId,
        info.exceptionCode,
        info.firstChance,
        (unsigned long long)info.exceptionAddress,
        (unsigned long long)info.instructionPointer,
        JsonEscape(WideToUtf8(info.reason)).c_str());
    return std::string(buf);
}

std::string EventJson(const WdblPluginEvent& eventData) {
    char head[512];
    sprintf_s(
        head,
        "{\"type\":%u,\"typeName\":\"%s\",\"processId\":%u,\"threadId\":%u,"
        "\"debugEventCode\":%u,\"address\":%llu",
        eventData.type,
        EventTypeName(eventData.type),
        eventData.processId,
        eventData.threadId,
        eventData.debugEventCode,
        (unsigned long long)eventData.address);
    std::string out = head;
    out += ",\"modulePath\":\"";
    out += JsonEscape(WideToUtf8(eventData.modulePath));
    out += "\",\"message\":\"";
    out += JsonEscape(WideToUtf8(eventData.message));
    out += "\",\"stopInfo\":{";
    out += StopInfoFieldsJson(eventData.stopInfo);
    out += "}}";
    return out;
}

void QueueEvent(BridgeContext* ctx, const WdblPluginEvent& eventData) {
    if (ctx == NULL) {
        return;
    }
    EnterCriticalSection(&ctx->eventLock);
    ctx->events.push_back(EventJson(eventData));
    while (ctx->events.size() > 256) {
        ctx->events.pop_front();
    }
    LeaveCriticalSection(&ctx->eventLock);
}

std::string DrainEventsJson(BridgeContext* ctx) {
    std::string body = "\"events\":[";
    EnterCriticalSection(&ctx->eventLock);
    bool first = true;
    while (!ctx->events.empty()) {
        if (!first) {
            body += ",";
        }
        first = false;
        body += ctx->events.front();
        ctx->events.pop_front();
    }
    LeaveCriticalSection(&ctx->eventLock);
    body += "]";
    return Ok(body);
}

const WdblDebuggerApi* Api(BridgeContext* ctx) {
    return ctx != NULL ? ctx->host.debuggerApi : NULL;
}

std::string StopInfoJson(BridgeContext* ctx) {
    WdblStopInfo info = WdblStopInfo();
    int32_t ok = 0;
    if (ctx->host.getStopInfo != NULL) {
        ok = ctx->host.getStopInfo(ctx->host.context, &info);
    }
    if (!ok) {
        return Error("getStopInfo failed");
    }
    char buf[1024];
    sprintf_s(
        buf,
        "\"paused\":%d,\"processId\":%u,\"threadId\":%u,\"exceptionCode\":%u,"
        "\"firstChance\":%d,\"exceptionAddress\":%llu,\"instructionPointer\":%llu,\"reason\":\"%s\"",
        info.paused,
        info.processId,
        info.threadId,
        info.exceptionCode,
        info.firstChance,
        (unsigned long long)info.exceptionAddress,
        (unsigned long long)info.instructionPointer,
        JsonEscape(WideToUtf8(info.reason)).c_str());
    return Ok(buf);
}

std::string HandleRequest(BridgeContext* ctx, const std::string& request) {
    EnterCriticalSection(&ctx->apiLock);
    struct LeaveApiLock {
        BridgeContext* ctx;
        ~LeaveApiLock() { LeaveCriticalSection(&ctx->apiLock); }
    } leaveApiLock = { ctx };

    std::string cmd;
    if (!ExtractString(request, "cmd", cmd)) {
        return Error("missing cmd");
    }

    const WdblDebuggerApi* api = Api(ctx);
    if (api == NULL) {
        return Error("debugger api unavailable");
    }

    if (cmd == "ping") {
        return Ok("\"pipe\":\"\\\\\\\\.\\\\pipe\\\\Z0BDbgMcpBridge\"");
    }
    if (cmd == "execute") {
        std::string command;
        if (!ExtractString(request, "command", command)) {
            return Error("missing command");
        }
        std::wstring wide = Utf8ToWide(command);
        int32_t rc = 0;
        if (api->executeCommand != NULL) {
            rc = api->executeCommand(api->context, wide.c_str());
        } else if (ctx->host.execute != NULL) {
            rc = ctx->host.execute(ctx->host.context, wide.c_str());
        }
        char buf[64];
        sprintf_s(buf, "\"value\":%d", rc);
        return rc ? Ok(buf) : Error("execute failed");
    }
    if (cmd == "execute_capture") {
        std::string command;
        if (!ExtractString(request, "command", command)) {
            return Error("missing command");
        }
        std::wstring wide = Utf8ToWide(command);
        std::wstringstream capture;
        int32_t rc = 0;
        {
            ScopedWcoutRedirect redirect(capture.rdbuf());
            if (api->executeCommand != NULL) {
                rc = api->executeCommand(api->context, wide.c_str());
            } else if (ctx->host.execute != NULL) {
                rc = ctx->host.execute(ctx->host.context, wide.c_str());
            }
        }
        std::wstring output = capture.str();
        const size_t maxChars = 32768;
        bool truncated = false;
        if (output.size() > maxChars) {
            output.resize(maxChars);
            truncated = true;
        }
        char prefix[128];
        sprintf_s(prefix, "\"value\":%d,\"truncated\":%s,\"output\":\"", rc, truncated ? "true" : "false");
        std::string body = prefix;
        body += JsonEscape(WideToUtf8(output.c_str()));
        body += "\"";
        return rc ? Ok(body) : (std::string("{\"ok\":false,\"error\":\"execute failed\",\"value\":0,\"output\":\"") +
            JsonEscape(WideToUtf8(output.c_str())) + "\"}");
    }
    if (cmd == "poll_events") {
        return DrainEventsJson(ctx);
    }
    if (cmd == "launch") {
        std::string commandLine;
        if (!ExtractString(request, "commandLine", commandLine)) {
            return Error("missing commandLine");
        }
        std::wstring wide = Utf8ToWide(commandLine);
        return (api->launch != NULL && api->launch(api->context, wide.c_str())) ? Ok("\"value\":1") : Error("launch failed");
    }
    if (cmd == "attach") {
        uint64_t pid = 0;
        if (!ExtractUInt64(request, "pid", pid)) {
            return Error("missing pid");
        }
        return (api->attach != NULL && api->attach(api->context, (uint32_t)pid)) ? Ok("\"value\":1") : Error("attach failed");
    }
    if (cmd == "detach") {
        return (api->detach != NULL && api->detach(api->context)) ? Ok("\"value\":1") : Error("detach failed");
    }
    if (cmd == "continue") {
        return (api->continueExecution != NULL && api->continueExecution(api->context)) ? Ok("\"value\":1") : Error("continue failed");
    }
    if (cmd == "step") {
        return (api->singleStep != NULL && api->singleStep(api->context)) ? Ok("\"value\":1") : Error("step failed");
    }
    if (cmd == "step_over") {
        return (api->stepOver != NULL && api->stepOver(api->context)) ? Ok("\"value\":1") : Error("step_over failed");
    }
    if (cmd == "stop_info") {
        return StopInfoJson(ctx);
    }
    if (cmd == "set_breakpoint") {
        std::string expression;
        if (!ExtractString(request, "expression", expression)) {
            return Error("missing expression");
        }
        uint64_t address = 0;
        wchar_t text[512] = {};
        std::wstring wide = Utf8ToWide(expression);
        if (api->resolveAddressExpression == NULL ||
            !api->resolveAddressExpression(api->context, wide.c_str(), &address, text, _countof(text))) {
            return Error("resolveAddressExpression failed");
        }
        int32_t bp = 0;
        if (api->addSoftwareBreakpoint == NULL ||
            !api->addSoftwareBreakpoint(api->context, address, &bp)) {
            return Error("addSoftwareBreakpoint failed");
        }
        char buf[1024];
        sprintf_s(
            buf,
            "\"breakpointId\":%d,\"address\":%llu,\"symbol\":\"%s\"",
            bp,
            (unsigned long long)address,
            JsonEscape(WideToUtf8(text)).c_str());
        return Ok(buf);
    }
    if (cmd == "set_hardware_breakpoint") {
        uint64_t address = 0;
        wchar_t text[512] = {};
        if (!ResolveExpression(api, request, "expression", address, text, _countof(text))) {
            return Error("resolveAddressExpression failed");
        }
        uint64_t length = 1;
        uint64_t slot = 0;
        uint64_t threadId = 0;
        std::string accessText;
        ExtractUInt64(request, "length", length);
        ExtractUInt64(request, "slot", slot);
        ExtractUInt64(request, "threadId", threadId);
        ExtractString(request, "access", accessText);
        int32_t bp = 0;
        if (api->addHardwareBreakpoint == NULL ||
            !api->addHardwareBreakpoint(api->context, (int32_t)slot, address, ParseHardwareAccess(accessText), (int32_t)length, (uint32_t)threadId, &bp)) {
            return Error("addHardwareBreakpoint failed");
        }
        char buf[1024];
        sprintf_s(
            buf,
            "\"breakpointId\":%d,\"address\":%llu,\"symbol\":\"%s\"",
            bp,
            (unsigned long long)address,
            JsonEscape(WideToUtf8(text)).c_str());
        return Ok(buf);
    }
    if (cmd == "set_memory_breakpoint") {
        uint64_t address = 0;
        uint64_t size = 1;
        wchar_t text[512] = {};
        std::string accessText;
        if (!ResolveExpression(api, request, "expression", address, text, _countof(text)) ||
            !ExtractUInt64(request, "size", size)) {
            return Error("missing expression or size");
        }
        ExtractString(request, "access", accessText);
        int32_t bp = 0;
        if (api->addMemoryBreakpoint == NULL ||
            !api->addMemoryBreakpoint(api->context, address, size, ParseMemoryAccess(accessText), &bp)) {
            return Error("addMemoryBreakpoint failed");
        }
        char buf[1024];
        sprintf_s(
            buf,
            "\"breakpointId\":%d,\"address\":%llu,\"size\":%llu,\"symbol\":\"%s\"",
            bp,
            (unsigned long long)address,
            (unsigned long long)size,
            JsonEscape(WideToUtf8(text)).c_str());
        return Ok(buf);
    }
    if (cmd == "set_breakpoint_condition") {
        uint64_t id = 0;
        std::string condition;
        if (!ExtractUInt64(request, "breakpointId", id) || !ExtractString(request, "condition", condition)) {
            return Error("missing breakpointId or condition");
        }
        std::wstring wide = Utf8ToWide(condition);
        return (api->setBreakpointCondition != NULL &&
            api->setBreakpointCondition(api->context, (int32_t)id, wide.c_str())) ? Ok("\"value\":1") : Error("setBreakpointCondition failed");
    }
    if (cmd == "clear_breakpoint_condition") {
        uint64_t id = 0;
        if (!ExtractUInt64(request, "breakpointId", id)) {
            return Error("missing breakpointId");
        }
        return (api->clearBreakpointCondition != NULL &&
            api->clearBreakpointCondition(api->context, (int32_t)id)) ? Ok("\"value\":1") : Error("clearBreakpointCondition failed");
    }
    if (cmd == "resolve") {
        std::string expression;
        if (!ExtractString(request, "expression", expression)) {
            return Error("missing expression");
        }
        uint64_t address = 0;
        wchar_t text[512] = {};
        std::wstring wide = Utf8ToWide(expression);
        if (api->resolveAddressExpression == NULL ||
            !api->resolveAddressExpression(api->context, wide.c_str(), &address, text, _countof(text))) {
            return Error("resolveAddressExpression failed");
        }
        char buf[1024];
        sprintf_s(
            buf,
            "\"address\":%llu,\"symbol\":\"%s\"",
            (unsigned long long)address,
            JsonEscape(WideToUtf8(text)).c_str());
        return Ok(buf);
    }
    if (cmd == "symbol") {
        uint64_t address = 0;
        if (!ExtractUInt64(request, "address", address)) {
            return Error("missing address");
        }
        wchar_t text[512] = {};
        if (api->resolveSymbol == NULL ||
            !api->resolveSymbol(api->context, address, text, _countof(text))) {
            return Error("resolveSymbol failed");
        }
        char buf[1024];
        sprintf_s(
            buf,
            "\"address\":%llu,\"symbol\":\"%s\"",
            (unsigned long long)address,
            JsonEscape(WideToUtf8(text)).c_str());
        return Ok(buf);
    }
    if (cmd == "load_symbols" || cmd == "download_symbols") {
        std::string target;
        std::string cacheDir;
        std::string serverUrl;
        ExtractString(request, "target", target);
        ExtractString(request, "cacheDir", cacheDir);
        ExtractString(request, "serverUrl", serverUrl);
        std::wstring targetWide = Utf8ToWide(target.empty() ? "*" : target);
        wchar_t pdbPath[1024] = {};
        int32_t ok = 0;
        if (cmd == "load_symbols" && api->loadSymbols != NULL) {
            ok = api->loadSymbols(api->context, targetWide.c_str(), pdbPath, _countof(pdbPath));
        } else if (cmd == "download_symbols" && api->downloadSymbols != NULL) {
            std::wstring cacheWide = Utf8ToWide(cacheDir);
            std::wstring serverWide = Utf8ToWide(serverUrl);
            ok = api->downloadSymbols(api->context, targetWide.c_str(), cacheWide.c_str(), serverWide.c_str(), pdbPath, _countof(pdbPath));
        }
        char buf[1400];
        sprintf_s(buf, "\"pdbPath\":\"%s\"", JsonEscape(WideToUtf8(pdbPath)).c_str());
        return ok ? Ok(buf) : Error(cmd == "load_symbols" ? "loadSymbols failed" : "downloadSymbols failed");
    }
    if (cmd == "set_symbol_path") {
        std::string path;
        if (!ExtractString(request, "path", path)) {
            return Error("missing path");
        }
        std::wstring wide = Utf8ToWide(path);
        return (api->setSymbolSearchPath != NULL &&
            api->setSymbolSearchPath(api->context, wide.c_str())) ? Ok("\"value\":1") : Error("setSymbolSearchPath failed");
    }
    if (cmd == "get_symbol_path") {
        wchar_t path[2048] = {};
        if (api->getSymbolSearchPath == NULL ||
            !api->getSymbolSearchPath(api->context, path, _countof(path))) {
            return Error("getSymbolSearchPath failed");
        }
        return Ok(std::string("\"path\":\"") + JsonEscape(WideToUtf8(path)) + "\"");
    }
    if (cmd == "enable_breakpoint" || cmd == "disable_breakpoint" || cmd == "remove_breakpoint") {
        uint64_t id = 0;
        if (!ExtractUInt64(request, "breakpointId", id)) {
            return Error("missing breakpointId");
        }
        int32_t ok = 0;
        if (cmd == "enable_breakpoint" && api->enableBreakpoint != NULL) {
            ok = api->enableBreakpoint(api->context, (int32_t)id);
        } else if (cmd == "disable_breakpoint" && api->disableBreakpoint != NULL) {
            ok = api->disableBreakpoint(api->context, (int32_t)id);
        } else if (cmd == "remove_breakpoint" && api->removeBreakpoint != NULL) {
            ok = api->removeBreakpoint(api->context, (int32_t)id);
        }
        char buf[64];
        sprintf_s(buf, "\"breakpointId\":%d", (int32_t)id);
        return ok ? Ok(buf) : Error("breakpoint operation failed");
    }
    if (cmd == "select_thread") {
        uint64_t index = 0;
        if (!ExtractUInt64(request, "index", index)) {
            return Error("missing index");
        }
        return (api->selectThread != NULL && api->selectThread(api->context, (uint32_t)index)) ? Ok("\"value\":1") : Error("selectThread failed");
    }
    if (cmd == "threads") {
        uint32_t count = 0;
        if (api->getThreadCount == NULL || !api->getThreadCount(api->context, &count)) {
            return Error("getThreadCount failed");
        }
        std::string body = "\"threads\":[";
        for (uint32_t i = 0; i < count; ++i) {
            WdblThreadInfo info = WdblThreadInfo();
            if (api->getThreadInfo(api->context, i, &info)) {
                char buf[512];
                sprintf_s(
                    buf,
                    "%s{\"index\":%u,\"processId\":%u,\"threadId\":%u,\"current\":%u,"
                    "\"ip\":%llu,\"sp\":%llu,\"symbol\":\"%s\"}",
                    (body[body.size() - 1] == '[') ? "" : ",",
                    info.index,
                    info.processId,
                    info.threadId,
                    info.isCurrent,
                    (unsigned long long)info.instructionPointer,
                    (unsigned long long)info.stackPointer,
                    JsonEscape(WideToUtf8(info.symbol)).c_str());
                body += buf;
            }
        }
        body += "]";
        return Ok(body);
    }
    if (cmd == "modules") {
        uint32_t count = 0;
        if (api->getModuleCount == NULL || !api->getModuleCount(api->context, &count)) {
            return Error("getModuleCount failed");
        }
        std::string body = "\"modules\":[";
        for (uint32_t i = 0; i < count; ++i) {
            WdblModuleInfo info = WdblModuleInfo();
            if (api->getModuleInfo(api->context, i, &info)) {
                char buf[1024];
                sprintf_s(
                    buf,
                    "%s{\"index\":%u,\"base\":%llu,\"size\":%u,\"name\":\"%s\",\"path\":\"%s\"}",
                    (body[body.size() - 1] == '[') ? "" : ",",
                    i,
                    (unsigned long long)info.baseAddress,
                    info.imageSize,
                    JsonEscape(WideToUtf8(info.moduleName)).c_str(),
                    JsonEscape(WideToUtf8(info.imagePath)).c_str());
                body += buf;
            }
        }
        body += "]";
        return Ok(body);
    }
    if (cmd == "breakpoints") {
        uint32_t count = 0;
        if (api->getBreakpointCount == NULL || !api->getBreakpointCount(api->context, &count)) {
            return Error("getBreakpointCount failed");
        }
        std::string body = "\"breakpoints\":[";
        for (uint32_t i = 0; i < count; ++i) {
            WdblBreakpointInfo info = WdblBreakpointInfo();
            if (api->getBreakpointInfo(api->context, i, &info)) {
                char buf[512];
                sprintf_s(
                    buf,
                    "%s{\"index\":%u,\"id\":%d,\"kind\":%u,\"address\":%llu,\"enabled\":%d,\"hitCount\":%llu}",
                    (body[body.size() - 1] == '[') ? "" : ",",
                    i,
                    info.id,
                    info.kind,
                    (unsigned long long)info.address,
                    info.enabled,
                    (unsigned long long)info.hitCount);
                body += buf;
            }
        }
        body += "]";
        return Ok(body);
    }
    if (cmd == "registers") {
        uint64_t index64 = 0;
        ExtractUInt64(request, "index", index64);
        WdblRegisterInfo info = WdblRegisterInfo();
        if (api->getRegisterInfo == NULL || !api->getRegisterInfo(api->context, (uint32_t)index64, &info)) {
            return Error("getRegisterInfo failed");
        }
        char buf[2048];
        sprintf_s(
            buf,
            "\"threadId\":%u,\"bits\":%u,\"ip\":%llu,\"sp\":%llu,\"fp\":%llu,"
            "\"rax\":%llu,\"rbx\":%llu,\"rcx\":%llu,\"rdx\":%llu,\"rsi\":%llu,\"rdi\":%llu,"
            "\"rip\":%llu,\"rsp\":%llu,\"r8\":%llu,\"r9\":%llu,\"r10\":%llu,\"r11\":%llu,"
            "\"r12\":%llu,\"r13\":%llu,\"r14\":%llu,\"r15\":%llu",
            info.threadId,
            info.architectureBits,
            (unsigned long long)info.instructionPointer,
            (unsigned long long)info.stackPointer,
            (unsigned long long)info.framePointer,
            (unsigned long long)info.rax,
            (unsigned long long)info.rbx,
            (unsigned long long)info.rcx,
            (unsigned long long)info.rdx,
            (unsigned long long)info.rsi,
            (unsigned long long)info.rdi,
            (unsigned long long)info.rip,
            (unsigned long long)info.rsp,
            (unsigned long long)info.r8,
            (unsigned long long)info.r9,
            (unsigned long long)info.r10,
            (unsigned long long)info.r11,
            (unsigned long long)info.r12,
            (unsigned long long)info.r13,
            (unsigned long long)info.r14,
            (unsigned long long)info.r15);
        return Ok(buf);
    }
    if (cmd == "stack") {
        uint64_t threadIndex = 0;
        uint64_t maxFrames = 16;
        ExtractUInt64(request, "threadIndex", threadIndex);
        ExtractUInt64(request, "maxFrames", maxFrames);
        if (maxFrames == 0 || maxFrames > 64) {
            return Error("maxFrames must be 1..64");
        }
        if (api->getStackFrameInfo == NULL) {
            return Error("getStackFrameInfo unavailable");
        }
        std::string body = "\"frames\":[";
        for (uint32_t frame = 0; frame < (uint32_t)maxFrames; ++frame) {
            WdblStackFrameInfo info = WdblStackFrameInfo();
            if (!api->getStackFrameInfo(api->context, (uint32_t)threadIndex, frame, &info)) {
                break;
            }
            char buf[1200];
            sprintf_s(
                buf,
                "%s{\"index\":%u,\"threadId\":%u,\"ip\":%llu,\"sp\":%llu,\"fp\":%llu,"
                "\"returnAddress\":%llu,\"symbol\":\"%s\",\"sourcePath\":\"%s\",\"sourceLine\":%u}",
                (body[body.size() - 1] == '[') ? "" : ",",
                info.index,
                info.threadId,
                (unsigned long long)info.instructionPointer,
                (unsigned long long)info.stackPointer,
                (unsigned long long)info.framePointer,
                (unsigned long long)info.returnAddress,
                JsonEscape(WideToUtf8(info.symbol)).c_str(),
                JsonEscape(WideToUtf8(info.sourcePath)).c_str(),
                info.sourceLine);
            body += buf;
        }
        body += "]";
        return Ok(body);
    }
    if (cmd == "read_memory") {
        uint64_t address = 0;
        uint64_t size64 = 0;
        if (!ExtractUInt64(request, "address", address) || !ExtractUInt64(request, "size", size64)) {
            return Error("missing address or size");
        }
        if (size64 == 0 || size64 > 4096) {
            return Error("size must be 1..4096");
        }
        std::vector<BYTE> bytes((size_t)size64);
        uint32_t read = 0;
        if (api->readMemory == NULL || !api->readMemory(api->context, address, &bytes[0], (uint32_t)bytes.size(), &read)) {
            return Error("readMemory failed");
        }
        char prefix[128];
        sprintf_s(prefix, "\"address\":%llu,\"bytesRead\":%u,\"data\":\"", (unsigned long long)address, read);
        return Ok(std::string(prefix) + HexBytes(&bytes[0], read) + "\"");
    }
    if (cmd == "write_memory") {
        uint64_t address = 0;
        std::string hex;
        if (!ExtractUInt64(request, "address", address) || !ExtractString(request, "data", hex)) {
            return Error("missing address or data");
        }
        std::vector<BYTE> bytes;
        if (!ParseHexBytes(hex, bytes)) {
            return Error("data must be even-length hex up to 4096 bytes");
        }
        uint32_t written = 0;
        if (api->writeMemory == NULL || !api->writeMemory(api->context, address, &bytes[0], (uint32_t)bytes.size(), &written)) {
            return Error("writeMemory failed");
        }
        char buf[128];
        sprintf_s(buf, "\"address\":%llu,\"bytesWritten\":%u", (unsigned long long)address, written);
        return Ok(buf);
    }
    if (cmd == "set_register") {
        std::string assignment;
        if (!ExtractString(request, "assignment", assignment) || assignment.empty()) {
            std::string name;
            std::string value;
            if (!ExtractString(request, "name", name)) {
                return Error("missing assignment");
            }
            if (!ExtractString(request, "value", value)) {
                uint64_t raw = 0;
                if (!ExtractUInt64(request, "value", raw)) {
                    return Error("missing value");
                }
                char temp[32];
                sprintf_s(temp, "0x%llX", (unsigned long long)raw);
                value = temp;
            }
            assignment = name + "=" + value;
        }
        std::wstring wide = Utf8ToWide(assignment);
        return (api->setRegisterValue != NULL &&
            api->setRegisterValue(api->context, wide.c_str())) ? Ok("\"value\":1") : Error("setRegisterValue failed");
    }
    if (cmd == "write_memory_patch") {
        uint64_t address = 0;
        std::string hex;
        if (!ExtractUInt64(request, "address", address) || !ExtractString(request, "data", hex)) {
            return Error("missing address or data");
        }
        std::vector<BYTE> bytes;
        if (!ParseHexBytes(hex, bytes)) {
            return Error("data must be even-length hex up to 4096 bytes");
        }
        return (api->writeMemoryPatch != NULL &&
            api->writeMemoryPatch(api->context, address, &bytes[0], (uint32_t)bytes.size())) ? Ok("\"value\":1") : Error("writeMemoryPatch failed");
    }
    if (cmd == "undo_memory_patch") {
        uint64_t count = 1;
        ExtractUInt64(request, "count", count);
        return (api->undoMemoryPatch != NULL &&
            api->undoMemoryPatch(api->context, (uint32_t)count)) ? Ok("\"value\":1") : Error("undoMemoryPatch failed");
    }
    if (cmd == "save_current_snapshot") {
        return (api->saveCurrentStopSnapshot != NULL &&
            api->saveCurrentStopSnapshot(api->context)) ? Ok("\"value\":1") : Error("saveCurrentStopSnapshot failed");
    }
    if (cmd == "save_snapshot") {
        std::string name;
        if (!ExtractString(request, "name", name)) {
            return Error("missing name");
        }
        std::wstring wide = Utf8ToWide(name);
        return (api->saveNamedSnapshot != NULL &&
            api->saveNamedSnapshot(api->context, wide.c_str())) ? Ok("\"value\":1") : Error("saveNamedSnapshot failed");
    }
    if (cmd == "restore_snapshot") {
        std::string name;
        bool rerun = false;
        if (!ExtractString(request, "name", name)) {
            return Error("missing name");
        }
        ExtractBool(request, "rerunAfterRestore", rerun);
        std::wstring wide = Utf8ToWide(name);
        return (api->restoreNamedSnapshot != NULL &&
            api->restoreNamedSnapshot(api->context, wide.c_str(), rerun ? 1 : 0)) ? Ok("\"value\":1") : Error("restoreNamedSnapshot failed");
    }
    if (cmd == "list_snapshots") {
        return (api->listNamedSnapshots != NULL &&
            api->listNamedSnapshots(api->context)) ? Ok("\"value\":1") : Error("listNamedSnapshots failed");
    }
    if (cmd == "step_back") {
        return (api->stepBackToPreviousSnapshot != NULL &&
            api->stepBackToPreviousSnapshot(api->context)) ? Ok("\"value\":1") : Error("stepBackToPreviousSnapshot failed");
    }
    if (cmd == "add_source_root" || cmd == "remove_source_root") {
        std::string path;
        if (!ExtractString(request, "path", path)) {
            return Error("missing path");
        }
        std::wstring wide = Utf8ToWide(path);
        int32_t ok = 0;
        if (cmd == "add_source_root" && api->addSourceRoot != NULL) {
            ok = api->addSourceRoot(api->context, wide.c_str());
        } else if (cmd == "remove_source_root" && api->removeSourceRoot != NULL) {
            ok = api->removeSourceRoot(api->context, wide.c_str());
        }
        return ok ? Ok("\"value\":1") : Error("source root operation failed");
    }
    if (cmd == "clear_source_roots") {
        return (api->clearSourceRoots != NULL &&
            api->clearSourceRoots(api->context)) ? Ok("\"value\":1") : Error("clearSourceRoots failed");
    }
    if (cmd == "list_source_roots") {
        return (api->listSourceRoots != NULL &&
            api->listSourceRoots(api->context)) ? Ok("\"value\":1") : Error("listSourceRoots failed");
    }
    if (cmd == "load_script") {
        std::string path;
        if (!ExtractString(request, "path", path)) {
            return Error("missing path");
        }
        std::wstring wide = Utf8ToWide(path);
        return (api->loadScriptFile != NULL &&
            api->loadScriptFile(api->context, wide.c_str())) ? Ok("\"value\":1") : Error("loadScriptFile failed");
    }
    if (cmd == "set_script_breakpoint" || cmd == "remove_script_breakpoint") {
        uint64_t line = 0;
        if (!ExtractUInt64(request, "line", line)) {
            return Error("missing line");
        }
        int32_t ok = 0;
        if (cmd == "set_script_breakpoint" && api->setScriptBreakpoint != NULL) {
            ok = api->setScriptBreakpoint(api->context, (uint32_t)line);
        } else if (cmd == "remove_script_breakpoint" && api->removeScriptBreakpoint != NULL) {
            ok = api->removeScriptBreakpoint(api->context, (uint32_t)line);
        }
        return ok ? Ok("\"value\":1") : Error("script breakpoint operation failed");
    }
    if (cmd == "list_script_breakpoints") {
        return (api->listScriptBreakpoints != NULL &&
            api->listScriptBreakpoints(api->context)) ? Ok("\"value\":1") : Error("listScriptBreakpoints failed");
    }
    if (cmd == "set_exception_ignore_all") {
        std::string scopeText;
        bool enabled = false;
        ExtractString(request, "scope", scopeText);
        ExtractBool(request, "enabled", enabled);
        return (api->configureExceptionIgnoreAll != NULL &&
            api->configureExceptionIgnoreAll(api->context, ParseExceptionScope(scopeText), enabled ? 1 : 0)) ? Ok("\"value\":1") : Error("configureExceptionIgnoreAll failed");
    }
    if (cmd == "add_ignored_exception" || cmd == "remove_ignored_exception") {
        std::string scopeText;
        uint64_t code = 0;
        if (!ExtractUInt64(request, "code", code)) {
            return Error("missing code");
        }
        ExtractString(request, "scope", scopeText);
        int32_t ok = 0;
        if (cmd == "add_ignored_exception" && api->addIgnoredExceptionCode != NULL) {
            ok = api->addIgnoredExceptionCode(api->context, ParseExceptionScope(scopeText), (uint32_t)code);
        } else if (cmd == "remove_ignored_exception" && api->removeIgnoredExceptionCode != NULL) {
            ok = api->removeIgnoredExceptionCode(api->context, ParseExceptionScope(scopeText), (uint32_t)code);
        }
        return ok ? Ok("\"value\":1") : Error("ignored exception operation failed");
    }
    if (cmd == "clear_ignored_exceptions") {
        std::string scopeText;
        ExtractString(request, "scope", scopeText);
        return (api->clearIgnoredExceptionCodes != NULL &&
            api->clearIgnoredExceptionCodes(api->context, ParseExceptionScope(scopeText))) ? Ok("\"value\":1") : Error("clearIgnoredExceptionCodes failed");
    }
    if (cmd == "list_exception_settings") {
        return (api->listExceptionSettings != NULL &&
            api->listExceptionSettings(api->context)) ? Ok("\"value\":1") : Error("listExceptionSettings failed");
    }
    if (cmd == "add_run_stop_expression") {
        std::string expression;
        if (!ExtractString(request, "expression", expression)) {
            return Error("missing expression");
        }
        std::wstring wide = Utf8ToWide(expression);
        return (api->addRunStopExpression != NULL &&
            api->addRunStopExpression(api->context, wide.c_str())) ? Ok("\"value\":1") : Error("addRunStopExpression failed");
    }
    if (cmd == "remove_run_stop_expression") {
        uint64_t index = 0;
        if (!ExtractUInt64(request, "index", index)) {
            return Error("missing index");
        }
        return (api->removeRunStopExpression != NULL &&
            api->removeRunStopExpression(api->context, (uint32_t)index)) ? Ok("\"value\":1") : Error("removeRunStopExpression failed");
    }
    if (cmd == "clear_run_stop_expressions") {
        return (api->clearRunStopExpressions != NULL &&
            api->clearRunStopExpressions(api->context)) ? Ok("\"value\":1") : Error("clearRunStopExpressions failed");
    }
    if (cmd == "list_run_stop_expressions") {
        return (api->listRunStopExpressions != NULL &&
            api->listRunStopExpressions(api->context)) ? Ok("\"value\":1") : Error("listRunStopExpressions failed");
    }
    if (cmd == "step_until_condition" || cmd == "run_until_condition") {
        std::string condition;
        uint64_t limit = 1;
        if (!ExtractString(request, "condition", condition)) {
            return Error("missing condition");
        }
        ExtractUInt64(request, cmd == "step_until_condition" ? "maxSteps" : "maxPauses", limit);
        std::wstring wide = Utf8ToWide(condition);
        int32_t ok = 0;
        if (cmd == "step_until_condition" && api->stepUntilCondition != NULL) {
            ok = api->stepUntilCondition(api->context, wide.c_str(), limit);
        } else if (cmd == "run_until_condition" && api->runUntilCondition != NULL) {
            ok = api->runUntilCondition(api->context, wide.c_str(), limit);
        }
        return ok ? Ok("\"value\":1") : Error("condition execution failed");
    }
    if (cmd == "auto_step" || cmd == "auto_run") {
        uint64_t count = 1;
        uint64_t delayMs = 0;
        ExtractUInt64(request, cmd == "auto_step" ? "steps" : "pauses", count);
        ExtractUInt64(request, "delayMs", delayMs);
        int32_t ok = 0;
        if (cmd == "auto_step" && api->autoStep != NULL) {
            ok = api->autoStep(api->context, count, (uint32_t)delayMs);
        } else if (cmd == "auto_run" && api->autoRun != NULL) {
            ok = api->autoRun(api->context, count, (uint32_t)delayMs);
        }
        return ok ? Ok("\"value\":1") : Error("auto execution failed");
    }
    return Error("unknown cmd");
}

bool ReadLine(HANDLE pipe, std::string& line) {
    line.clear();
    char ch = 0;
    DWORD read = 0;
    while (true) {
        if (!ReadFile(pipe, &ch, 1, &read, NULL) || read != 1) {
            return !line.empty();
        }
        if (ch == '\n') {
            return true;
        }
        if (ch != '\r') {
            line.push_back(ch);
        }
        if (line.size() > 65536) {
            return false;
        }
    }
}

bool ParseRequestedMode(const std::string& text, SecurityMode& mode) {
    const std::string lower = ToLowerAscii(text);
    if (lower == "plain" || lower == "diagnostic") {
        mode = SecurityPlain;
        return true;
    }
    if (lower == "optional" || lower == "auto") {
        mode = SecurityOptional;
        return true;
    }
    if (lower == "strict" || lower == "encrypted") {
        mode = SecurityStrict;
        return true;
    }
    return false;
}

void WriteLine(HANDLE pipe, const std::string& line) {
    std::string text = line + "\n";
    DWORD written = 0;
    WriteFile(pipe, text.c_str(), (DWORD)text.size(), &written, NULL);
    FlushFileBuffers(pipe);
}

bool NegotiateSession(
    HANDLE pipe,
    SecureSession& session,
    std::string& error) {
    error.clear();
    session = SecureSession();
    session.mode = ReadSecurityMode();
    session.secret = GetEnvironmentValue("Z0BDBG_MCP_SHARED_KEY");
    session.serverNonce = RandomNonce();
    if (session.serverNonce.empty()) {
        error = "cannot generate handshake nonce";
        return false;
    }

    char challenge[512] = {};
    sprintf_s(
        challenge,
        "{\"hello\":true,\"protocol\":\"%s\",\"mode\":\"%s\",\"nonce\":\"%s\"}",
        kProtocolName,
        SecurityModeName(session.mode).c_str(),
        session.serverNonce.c_str());
    WriteLine(pipe, challenge);

    std::string request;
    if (!ReadLine(pipe, request)) {
        error = "missing client handshake";
        return false;
    }
    std::string protocol;
    std::string clientModeText;
    std::string clientNonce;
    if (!ExtractString(request, "protocol", protocol) ||
        protocol != kProtocolName ||
        !ExtractString(request, "mode", clientModeText) ||
        !ExtractString(request, "nonce", clientNonce) ||
        clientNonce.empty()) {
        error = "invalid protocol handshake";
        return false;
    }
    SecurityMode clientMode = SecurityPlain;
    if (!ParseRequestedMode(clientModeText, clientMode)) {
        error = "unsupported client security mode";
        return false;
    }

    if ((session.mode == SecurityStrict && clientMode == SecurityPlain) ||
        (clientMode == SecurityStrict && session.mode == SecurityPlain)) {
        error = "security mode mismatch";
        return false;
    }
    const bool encrypted =
        session.mode == SecurityStrict ||
        clientMode == SecurityStrict ||
        (session.mode == SecurityOptional && clientMode == SecurityOptional);
    if (encrypted && session.secret.empty()) {
        error = "encrypted mode requires Z0BDBG_MCP_SHARED_KEY";
        return false;
    }

    session.encrypted = encrypted;
    session.clientNonce = clientNonce;
    if (encrypted) {
        std::string proof;
        std::string expected;
        if (!ExtractString(request, "proof", proof) ||
            !HmacHex(
                session.secret,
                std::string("hello|") + kProtocolName + "|" +
                    session.serverNonce + "|" + session.clientNonce + "|encrypted",
                expected) ||
            proof != expected) {
            error = "client handshake authentication failed";
            return false;
        }
    }

    std::string ackProof;
    if (encrypted &&
        !HmacHex(
            session.secret,
            std::string("ack|") + kProtocolName + "|" +
                session.serverNonce + "|" + session.clientNonce + "|encrypted",
            ackProof)) {
        error = "cannot create handshake authentication";
        return false;
    }
    std::string response = std::string("{\"ok\":true,\"hello\":true,\"protocol\":\"") +
        kProtocolName + "\",\"mode\":\"" +
        (encrypted ? "encrypted" : "plain") + "\"";
    if (encrypted) {
        response += ",\"proof\":\"" + ackProof + "\"";
    }
    response += "}";
    WriteLine(pipe, response);
    return true;
}

DWORD WINAPI PipeThreadProc(void* param) {
    BridgeContext* ctx = static_cast<BridgeContext*>(param);
    while (InterlockedCompareExchange(&ctx->stopping, 0, 0) == 0) {
        HANDLE pipe = CreateNamedPipeW(
            kPipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            65536,
            65536,
            0,
            NULL);
        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(200);
            continue;
        }
        BOOL connected = ConnectNamedPipe(pipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (connected) {
            SecureSession session;
            std::string handshakeError;
            if (!NegotiateSession(pipe, session, handshakeError)) {
                WriteLine(pipe, Error(handshakeError.c_str()));
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
                continue;
            }
            std::string line;
            while (InterlockedCompareExchange(&ctx->stopping, 0, 0) == 0 && ReadLine(pipe, line)) {
                std::string request = line;
                if (session.encrypted && !DecryptPayload(session, line, request)) {
                    WriteLine(pipe, Error("encrypted request authentication failed"));
                    break;
                }
                std::string response = HandleRequest(ctx, request);
                if (session.encrypted) {
                    std::string encryptedResponse;
                    if (!EncryptPayload(session, response, encryptedResponse)) {
                        WriteLine(pipe, Error("encrypted response failed"));
                        break;
                    }
                    WriteLine(pipe, encryptedResponse);
                } else {
                    WriteLine(pipe, response);
                }
            }
        }
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
    return 0;
}

void WakePipeThread() {
    HANDLE pipe = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(pipe);
    }
}

} // namespace

extern "C" __declspec(dllexport) int32_t WDBL_CALL WdblPluginGetInfo(WdblPluginInfo* outInfo) {
    if (outInfo == NULL || outInfo->size < sizeof(WdblPluginInfo)) {
        return 0;
    }
    WdblPluginInfo info = WdblPluginInfo();
    CopyText(info.name, _countof(info.name), L"Z0BDbgMcpBridge");
    CopyText(info.version, _countof(info.version), L"0.1");
    CopyText(info.description, _countof(info.description), L"Named pipe bridge for the Python MCP server.");
    *outInfo = info;
    return 1;
}

extern "C" __declspec(dllexport) int32_t WDBL_CALL WdblPluginInitialize(const WdblHostApi* hostApi, void** pluginContext) {
    if (hostApi == NULL || pluginContext == NULL || hostApi->debuggerApi == NULL) {
        return 0;
    }
    BridgeContext* ctx = new BridgeContext();
    ctx->host = *hostApi;
    ctx->stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    InitializeCriticalSection(&ctx->apiLock);
    InitializeCriticalSection(&ctx->eventLock);
    ctx->thread = CreateThread(NULL, 0, PipeThreadProc, ctx, 0, NULL);
    if (ctx->thread == NULL) {
        if (ctx->stopEvent != NULL) {
            CloseHandle(ctx->stopEvent);
        }
        DeleteCriticalSection(&ctx->eventLock);
        DeleteCriticalSection(&ctx->apiLock);
        delete ctx;
        return 0;
    }
    g_context = ctx;
    *pluginContext = ctx;
    if (ctx->host.log != NULL) {
        ctx->host.log(ctx->host.context, L"Z0BDbg MCP bridge listening on \\\\.\\pipe\\Z0BDbgMcpBridge");
    }
    return 1;
}

extern "C" __declspec(dllexport) int32_t WDBL_CALL WdblPluginExecute(void* pluginContext, const wchar_t* args) {
    BridgeContext* ctx = static_cast<BridgeContext*>(pluginContext);
    if (ctx == NULL) {
        return 0;
    }
    if (ctx->host.log != NULL) {
        ctx->host.log(ctx->host.context, L"Usage: start mcp_server\\z0bdbg_mcp_server.py; bridge is already listening.");
    }
    return 1;
}

extern "C" __declspec(dllexport) void WDBL_CALL WdblPluginShutdown(void* pluginContext) {
    BridgeContext* ctx = static_cast<BridgeContext*>(pluginContext);
    if (ctx == NULL) {
        return;
    }
    InterlockedExchange(&ctx->stopping, 1);
    WakePipeThread();
    if (ctx->thread != NULL) {
        WaitForSingleObject(ctx->thread, 3000);
        CloseHandle(ctx->thread);
    }
    if (ctx->stopEvent != NULL) {
        CloseHandle(ctx->stopEvent);
    }
    DeleteCriticalSection(&ctx->eventLock);
    DeleteCriticalSection(&ctx->apiLock);
    if (g_context == ctx) {
        g_context = NULL;
    }
    delete ctx;
}

extern "C" __declspec(dllexport) void WDBL_CALL WdblPluginOnEvent(void* pluginContext, const WdblPluginEvent* eventData) {
    BridgeContext* ctx = static_cast<BridgeContext*>(pluginContext);
    if (ctx == NULL || eventData == NULL) {
        return;
    }
    QueueEvent(ctx, *eventData);
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) {
    return TRUE;
}
