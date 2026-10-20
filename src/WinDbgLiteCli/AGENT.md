# WinDbgLite Agent Terminal

In the WinDbgLite CLI, enter `agent` to load the MCP bridge and open the Agent
Terminal. It connects to the current debugger through the local named pipe; it
does not launch a second debugger or replace the current debuggee. Enter
`agent config` to open the model and permission settings, or `agent help` for
command help.

The CLI executable needs `Z0BDbgMcpBridge.dll` in the same directory. The
launcher lives at `src/WinDbgLiteCli/mcp_server/agent_launcher.py`; its adjacent
MCP server and an installed Python 3 are required. The launcher prefers
`src/WinDbgLiteCli/agent/McpServerCompact.exe`, then `McpServer.exe`.
On first use, configure a model URL,
model name, and API key with `agent config`.

Optional environment overrides:

* `Z0BDBG_PYTHON_EXE`: full path to Python 3.
* `Z0BDBG_AGENT_LAUNCHER`: full path to `agent_launcher.py`.
* `Z0BDBG_AGENT_EXE`: full path to the Agent frontend executable.
* `Z0BDBG_MCP_PLUGIN`: full path to the bridge DLL.

The adapter listens only on `127.0.0.1:3001` while the Agent is open. Close the
Agent Terminal to stop its local HTTP endpoint. A second Agent instance using
the same port reports a port conflict. Read-only tool annotations cover an
explicit list of inspection commands; other tools retain the Agent's default
approval behavior.
The launcher creates a new Bearer token for each session; the HTTP adapter
rejects requests without it.
The Agent stores MCP history under `%LOCALAPPDATA%\WinDbgLite\mcp` by default;
`Z0BDBG_MCP_STORE` overrides that location.

The Agent frontend source is in `agent/source`. Building
`BuildVS2010/WinDbgLiteCli.vcxproj` also builds its Agent and bridge project
references. The Agent executable is written directly to
`src/WinDbgLiteCli/agent/McpServerCompact.exe`, beside `McpServer.ini`; the
bridge DLL is written beside the CLI executable under
`BuildVS2010/Build/Bin/<configuration>/<x86|x64>/`.
