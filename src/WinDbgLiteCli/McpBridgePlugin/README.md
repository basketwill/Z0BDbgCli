# Z0BDbg MCP Bridge Plugin

This DLL is a thin WinDbgLite plugin. It listens on:

```text
\\.\pipe\Z0BDbgMcpBridge
```

The Python MCP server in `..\mcp_server\z0bdbg_mcp_server.py` connects to this pipe and exposes MCP tools.

Build:

```bat
msbuild McpBridgePlugin.vcxproj /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v100
```

Load in WinDbgLite:

```text
plugin load C:\Users\Administrator\source\repos\WinDbgLite\BuildVS2010\Build\Bin\Release\x64\Z0BDbgMcpBridge.dll
```

Bridge security is configured with the same environment variables used by the
Python server:

```bat
set Z0BDBG_MCP_SECURITY_MODE=plain
set Z0BDBG_MCP_SHARED_KEY=replace-with-a-long-random-secret
```

Use `plain` for readable diagnostic traffic. Use `strict` on both the
debugger/plugin side and the Python server side for deployment; strict mode
requires a matching shared key and rejects plain peers. `optional` enables
encrypted packets when both peers negotiate it and falls back to plain only
when the peer explicitly allows it. The encrypted mode is designed for the
local named-pipe bridge and uses a matching HMAC-SHA256-derived stream and
packet tag; it is not intended as a general TLS replacement.
