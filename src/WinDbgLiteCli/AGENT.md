# WinDbgLite Agent Terminal

In the WinDbgLite CLI, enter `agent` to use the C++ Agent model core inside the
CLI process. Its embedded tool adapter calls the current debugger API directly.
The Agent prints the current model and task description when it starts and when
a request is submitted. Enter `/status` to show them again; model routing updates
the displayed model after a request finishes.
Enter `/help` for the embedded command list. `/models`, `/model`, `/tools`,
`/history`, `/task`, and `/tasks` expose the current model, debugger tools,
saved chat, managed task state, and saved checkpoints. Use `/continue` for an
interrupted chat or `/resume <task-id>` for a paused managed task. A reviewed
operation can be retried with `/continue retry` or `/resume retry` after
confirmation. Plain text is sent as an Agent request.
Enter `/exit` to return to CLI mode. Enter `/detach` or use `agent --detach` from
CLI mode to open the separate Agent terminal through the MCP bridge. Enter
`agent --config` to open the model and permission settings UI from the same CLI
executable in a separate process.

The embedded adapter currently exposes target context, status, threads,
registers, stack frames, modules, breakpoints, memory reads, symbol resolution,
address expression resolution, symbol paths and symbol loading, thread selection,
breakpoint enable/disable, conditions, hardware and guard-page breakpoints,
target launch/attach/detach, run/step,
register changes, reversible and raw memory writes, snapshot management,
source roots, script breakpoints, exception rules, run-stop expressions,
conditional and automatic execution, symbol downloads, and native debugger
commands. Tool observations are returned to the model as structured data:
management lists, full stop and register state, stack frame source locations,
and native command output (up to 8191 wide characters, with a truncation flag).
Changes requested by
the model require confirmation in the CLI window. Other Agent tools
remain available in the detached terminal while their direct adapters are
migrated. Agent model, history, task, policy, and audit code is compiled into
the CLI executable from `agent/source/McpServerApp.cpp`.

External MCP clients are independent of the built-in Agent. Enter `mcp server`
in CLI mode to load the debugger bridge and start a server-only HTTP endpoint
on `http://127.0.0.1:3002/mcp`. Its terminal prints a fresh Bearer token for
the external client. Configure that client with streamable HTTP transport, the
printed endpoint, and an `Authorization: Bearer <token>` header. The external
client supplies its own model and instructions; it does not use the built-in
Agent's model settings. Closing that terminal stops the endpoint; the CLI and
embedded Agent remain available. Set `Z0BDBG_MCP_BIND` before launching CLI to
bind another interface, and put TLS in front of the endpoint when accessed
across a network. External clients may also run `z0bdbg_mcp_server.py` through
MCP stdio while the bridge is loaded.

The detached terminal needs `Z0BDbgMcpBridge.dll` beside the CLI executable,
the Python launcher at `mcp_server/agent_launcher.py`, its adjacent MCP server,
and Python 3. The launcher starts `Z0BDbgCli.exe --chat-cli` in a separate
console. The embedded mode and settings UI do not need Python or the bridge
DLL. Configure a model URL, model name, and API key with `agent --config`
before first use.

Optional environment overrides:

* `Z0BDBG_PYTHON_EXE`: full path to Python 3.
* `Z0BDBG_AGENT_LAUNCHER`: full path to `agent_launcher.py`.
* `Z0BDBG_AGENT_EXE`: full path to `Z0BDbgCli.exe` for detached mode.
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

Building `BuildVS2010/WinDbgLiteCli.vcxproj` compiles the Agent core into the
CLI executable and builds the bridge project reference. The post-build target stages all runtime files under the
repository's `Z0BDbg/` directory.
