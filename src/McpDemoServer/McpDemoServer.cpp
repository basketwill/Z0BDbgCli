#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

namespace {

std::string EscapeJson(const std::string& value) {
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
                char tmp[8] = {};
                std::snprintf(tmp, sizeof(tmp), "\\u%04x", static_cast<unsigned int>(ch));
                out += tmp;
            } else {
                out.push_back(static_cast<char>(ch));
            }
            break;
        }
    }
    return out;
}

bool ReadMessage(std::string& outPayload) {
    outPayload.clear();
    std::string line;
    size_t contentLength = 0;
    bool haveLength = false;

    while (true) {
        if (!std::getline(std::cin, line)) {
            return false;
        }
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) {
            break;
        }
        std::string lower = line;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        static const char kPrefix[] = "content-length:";
        if (lower.rfind(kPrefix, 0) == 0) {
            const std::string value = line.substr(sizeof(kPrefix) - 1);
            try {
                contentLength = static_cast<size_t>(std::stoull(value));
                haveLength = true;
            } catch (...) {
                return false;
            }
        }
    }

    if (!haveLength) {
        return false;
    }

    outPayload.resize(contentLength);
    std::cin.read(outPayload.data(), static_cast<std::streamsize>(contentLength));
    return static_cast<size_t>(std::cin.gcount()) == contentLength;
}

void WriteMessage(const std::string& json) {
    std::cout << "Content-Length: " << json.size() << "\r\n\r\n";
    std::cout.write(json.data(), static_cast<std::streamsize>(json.size()));
    std::cout.flush();
}

std::string BuildResult(uint64_t id, const std::string& resultJson) {
    std::ostringstream ss;
    ss << "{\"jsonrpc\":\"2.0\",\"id\":" << id << ",\"result\":" << resultJson << "}";
    return ss.str();
}

std::string BuildError(uint64_t id, int code, const std::string& message) {
    std::ostringstream ss;
    ss << "{\"jsonrpc\":\"2.0\",\"id\":" << id << ",\"error\":{\"code\":" << code
       << ",\"message\":\"" << EscapeJson(message) << "\"}}";
    return ss.str();
}

bool ExtractStringField(const std::string& json, const char* field, std::string& out) {
    out.clear();
    if (field == nullptr || *field == '\0') {
        return false;
    }
    const std::string pattern = std::string("\"") + field + "\"\\s*:\\s*\"([^\"]*)\"";
    const std::regex re(pattern);
    std::smatch m;
    if (!std::regex_search(json, m, re) || m.size() < 2) {
        return false;
    }
    out = m[1].str();
    return true;
}

bool ExtractUInt64Field(const std::string& json, const char* field, uint64_t& out) {
    out = 0;
    if (field == nullptr || *field == '\0') {
        return false;
    }
    const std::string pattern = std::string("\"") + field + "\"\\s*:\\s*([0-9]+)";
    const std::regex re(pattern);
    std::smatch m;
    if (!std::regex_search(json, m, re) || m.size() < 2) {
        return false;
    }
    try {
        out = std::stoull(m[1].str());
        return true;
    } catch (...) {
        return false;
    }
}

bool ExtractLooseStringField(const std::string& json, const char* field, std::string& out) {
    out.clear();
    if (field == nullptr || *field == '\0') {
        return false;
    }
    const std::string pattern = std::string("\"?") + field + "\"?\\s*:\\s*(?:\"([^\"]*)\"|([^,}\\s]+))";
    const std::regex re(pattern);
    std::smatch m;
    if (!std::regex_search(json, m, re) || m.size() < 3) {
        return false;
    }
    if (!m[1].str().empty()) {
        out = m[1].str();
        return true;
    }
    out = m[2].str();
    return !out.empty();
}

bool ExtractLooseNumberField(const std::string& json, const char* field, double& out) {
    out = 0.0;
    if (field == nullptr || *field == '\0') {
        return false;
    }
    const std::string pattern = std::string("\"?") + field + "\"?\\s*:\\s*(-?[0-9]+(?:\\.[0-9]+)?)";
    const std::regex re(pattern);
    std::smatch m;
    if (!std::regex_search(json, m, re) || m.size() < 2) {
        return false;
    }
    try {
        out = std::stod(m[1].str());
        return true;
    } catch (...) {
        return false;
    }
}

std::string NormalizeForParsing(const std::string& json) {
    std::string out;
    out.reserve(json.size());
    for (size_t i = 0; i < json.size(); ++i) {
        if (json[i] == '\\' && i + 1 < json.size() && json[i + 1] == '\"') {
            continue;
        }
        out.push_back(json[i]);
    }
    return out;
}

std::string HandleRequest(const std::string& json) {
    const std::string normalized = NormalizeForParsing(json);
    uint64_t id = 0;
    if (!ExtractUInt64Field(normalized, "id", id)) {
        return {};
    }

    std::string method;
    if (!ExtractStringField(normalized, "method", method)) {
        return BuildError(id, -32600, "Missing method");
    }

    if (method == "initialize") {
        return BuildResult(
            id,
            "{\"protocolVersion\":\"2024-11-05\","
            "\"serverInfo\":{\"name\":\"WinDbgLiteMcpDemoServer\",\"version\":\"1.0\"},"
            "\"capabilities\":{\"tools\":{},\"prompts\":{},\"resources\":{}}}");
    }
    if (method == "tools/list") {
        return BuildResult(
            id,
            "{\"tools\":["
            "{\"name\":\"echo\",\"description\":\"Echo input text.\","
            "\"inputSchema\":{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\"}},\"required\":[\"text\"]}},"
            "{\"name\":\"add\",\"description\":\"Add two numbers.\","
            "\"inputSchema\":{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"number\"},\"b\":{\"type\":\"number\"}},\"required\":[\"a\",\"b\"]}}"
            "]}");
    }
    if (method == "tools/call") {
        std::string name;
        if (!ExtractLooseStringField(normalized, "name", name)) {
            return BuildError(id, -32602, "tools/call missing name");
        }
        if (name == "echo") {
            std::string text;
            ExtractLooseStringField(normalized, "text", text);
            return BuildResult(
                id,
                std::string("{\"content\":[{\"type\":\"text\",\"text\":\"") + EscapeJson(text) + "\"}]}");
        }
        if (name == "add") {
            double a = 0.0;
            double b = 0.0;
            if (!ExtractLooseNumberField(normalized, "a", a) ||
                !ExtractLooseNumberField(normalized, "b", b)) {
                return BuildError(id, -32602, "add expects numeric a and b");
            }
            std::ostringstream sum;
            sum << (a + b);
            return BuildResult(
                id,
                std::string("{\"content\":[{\"type\":\"text\",\"text\":\"") + EscapeJson(sum.str()) + "\"}]}");
        }
        return BuildError(id, -32601, std::string("Unknown tool: ") + name);
    }
    if (method == "prompts/list") {
        return BuildResult(
            id,
            "{\"prompts\":[{\"name\":\"greeting\",\"description\":\"Return a greeting prompt template.\","
            "\"arguments\":[{\"name\":\"name\",\"required\":false}]}]}");
    }
    if (method == "prompts/get") {
        std::string name;
        if (!ExtractStringField(normalized, "name", name) || name != "greeting") {
            return BuildError(id, -32601, "Unknown prompt");
        }
        std::string who = "friend";
        ExtractStringField(normalized, "name", who);
        // The first "name" is prompt name. Look for arguments.name explicitly:
        std::regex argName("\"arguments\"\\s*:\\s*\\{[^\\}]*\"name\"\\s*:\\s*\"([^\"]*)\"");
        std::smatch m;
        if (std::regex_search(normalized, m, argName) && m.size() >= 2 && !m[1].str().empty()) {
            who = m[1].str();
        }
        return BuildResult(
            id,
            std::string("{\"description\":\"Greeting prompt\",\"messages\":[{\"role\":\"user\",\"content\":{\"type\":\"text\",\"text\":\"Hello, ")
                + EscapeJson(who) + "!\"}}]}");
    }
    if (method == "resources/list") {
        return BuildResult(
            id,
            "{\"resources\":[{\"uri\":\"wdbl://demo/status\",\"name\":\"Demo Status\","
            "\"description\":\"Simple server status resource\",\"mimeType\":\"text/plain\"}]}");
    }
    if (method == "resources/read") {
        std::string uri;
        if (!ExtractStringField(normalized, "uri", uri)) {
            return BuildError(id, -32602, "resources/read missing uri");
        }
        if (uri != "wdbl://demo/status") {
            return BuildError(id, -32602, "Unknown resource uri");
        }
        return BuildResult(
            id,
            "{\"contents\":[{\"uri\":\"wdbl://demo/status\",\"mimeType\":\"text/plain\","
            "\"text\":\"WinDbgLite MCP demo server is running.\"}]}");
    }

    return BuildError(id, -32601, std::string("Method not found: ") + method);
}

} // namespace

int main() {
#if defined(_WIN32)
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif

    while (true) {
        std::string payload;
        if (!ReadMessage(payload)) {
            break;
        }
        const std::string response = HandleRequest(payload);
        if (!response.empty()) {
            WriteMessage(response);
        }
    }
    return 0;
}
