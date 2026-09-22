# Z0BDbg MCP Server

Start this script as an MCP stdio server after loading `Z0BDbgMcpBridge.dll` in WinDbgLite.

Pipe used:

```text
\\.\pipe\Z0BDbgMcpBridge
```

Example MCP server command:

```bat
python C:\Users\Administrator\source\repos\WinDbgLite\src\WinDbgLiteCli\mcp_server\z0bdbg_mcp_server.py
```

Local store:

```text
mcp_server\data\z0bdbg_mcp.sqlite
```

Override with:

```text
Z0BDBG_MCP_STORE=C:\path\z0bdbg_mcp.sqlite
Z0BDBG_MCP_ROUTER_CONFIG=C:\path\case_router.json
Z0BDBG_MCP_AUTOMATION_CONFIG=C:\path\automation.json
Z0BDBG_MCP_AUDIT=1
Z0BDBG_MCP_AUTO_TRIAGE_ON_EVENT=0
Z0BDBG_MCP_AUTO_LLM_ON_EVENT=0
Z0BDBG_MCP_DEDUP_SECONDS=5.0
Z0BDBG_MCP_SECURITY_MODE=plain
Z0BDBG_MCP_SHARED_KEY=replace-with-a-long-random-secret
```

Bridge security modes:

- `plain` is the diagnostic mode. JSON remains readable for troubleshooting.
- `optional` uses encrypted packets when both ends support and configure it; otherwise it may use plain packets.
- `strict` requires encrypted, authenticated packets and rejects a plain peer.

The Python server and `Z0BDbgMcpBridge.dll` must use the same
`Z0BDBG_MCP_SHARED_KEY` in `optional`/`strict` encrypted sessions. The bridge
performs a protocol-version handshake, mode negotiation, nonce exchange, and
HMAC authentication before accepting debugger commands. Business packets are
then encrypted and authenticated with a dependency-free HMAC-SHA256-derived
stream and packet tag. For the current local named-pipe threat model, use
`strict` on both sides for deployment and `plain` only for local diagnosis.
This is a private bridge protocol, not a replacement for TLS or a general
internet-facing transport.

Case matching weights live in:

```text
mcp_server\config\case_router.json
mcp_server\config\automation.json
```

Local LLM:

```text
llama-server.exe -m models\SmolLM2-135M-Instruct-Q4_K_M.gguf --host 127.0.0.1 --port 8080
```

The MCP server talks to an OpenAI-compatible local endpoint:

```text
http://127.0.0.1:8080/v1/chat/completions
```

Override with:

```text
Z0BDBG_LLM_BASE_URL=http://127.0.0.1:8080
Z0BDBG_LLM_MODEL=local-model
```

Skills live under:

```text
mcp_server\skills\<skill_name>\
```

Demo skill:

```text
mcp_server\skills\demo_stop_triage\SKILL.md
mcp_server\skills\demo_stop_triage\workflow.json
```

Call `wdbl_demo_skill` with `execute=false` to preview the workflow, or `execute=true` to run the read-only stop triage steps.

Generic skill tools are `wdbl_list_skills` and `wdbl_run_skill`. `wdbl_run_skill` loads `workflow.json` by skill name. Skills default to dry-run; set `execute=true` to run. Non-read-only skills must also pass `allowStateChange=true`.

Risk levels:

```text
read-only
debugger-state-change
target-state-change
destructive
```

`destructive` skills require both `allowStateChange=true` and `allowDestructive=true`.

Included skills:

```text
demo_stop_triage
exception_triage
breakpoint_hit_triage
createfilew_args
access_violation_triage
veh_disconnect_triage
```

Minimal workflow shape:

```json
{
  "name": "demo_stop_triage",
  "risk": "read-only",
  "readOnly": true,
  "parameterDefaults": {
    "threadIndex": 0,
    "maxFrames": 8
  },
  "steps": [
    {
      "tool": "wdbl_stop_info",
      "request": {
        "cmd": "stop_info"
      }
    }
  ]
}
```

Current tools:

```text
wdbl_ping
wdbl_execute
wdbl_launch
wdbl_attach
wdbl_detach
wdbl_set_breakpoint
wdbl_set_hardware_breakpoint
wdbl_set_memory_breakpoint
wdbl_set_breakpoint_condition
wdbl_clear_breakpoint_condition
wdbl_enable_breakpoint
wdbl_disable_breakpoint
wdbl_remove_breakpoint
wdbl_resolve
wdbl_symbol
wdbl_load_symbols
wdbl_download_symbols
wdbl_set_symbol_path
wdbl_get_symbol_path
wdbl_continue
wdbl_step
wdbl_step_over
wdbl_stop_info
wdbl_threads
wdbl_select_thread
wdbl_modules
wdbl_breakpoints
wdbl_registers
wdbl_stack
wdbl_read_memory
wdbl_write_memory
wdbl_set_register
wdbl_write_memory_patch
wdbl_undo_memory_patch
wdbl_save_current_snapshot
wdbl_save_snapshot
wdbl_restore_snapshot
wdbl_list_snapshots
wdbl_step_back
wdbl_add_source_root
wdbl_remove_source_root
wdbl_clear_source_roots
wdbl_list_source_roots
wdbl_load_script
wdbl_set_script_breakpoint
wdbl_remove_script_breakpoint
wdbl_list_script_breakpoints
wdbl_set_exception_ignore_all
wdbl_add_ignored_exception
wdbl_remove_ignored_exception
wdbl_clear_ignored_exceptions
wdbl_list_exception_settings
wdbl_add_run_stop_expression
wdbl_remove_run_stop_expression
wdbl_clear_run_stop_expressions
wdbl_list_run_stop_expressions
wdbl_step_until_condition
wdbl_run_until_condition
wdbl_auto_step
wdbl_auto_run
wdbl_veh_launch
wdbl_veh_on
wdbl_veh_off
wdbl_veh_detach
wdbl_veh_kill
wdbl_veh_status
wdbl_veh_break
wdbl_veh_refresh
wdbl_veh_modules
wdbl_veh_threads
wdbl_veh_read_memory
wdbl_veh_write_memory
wdbl_veh_context
wdbl_veh_set_register
wdbl_veh_suspend_thread
wdbl_veh_resume_thread
wdbl_veh_exception_policy
wdbl_driver_on
wdbl_driver_off
wdbl_driver_status
wdbl_process_info
wdbl_processes
wdbl_current_thread_info
wdbl_vm_info
wdbl_memory_map
wdbl_disasm
wdbl_flow_graph
wdbl_pseudo_c
wdbl_examine_symbols
wdbl_source_where
wdbl_source_at
wdbl_source_breakpoint
wdbl_source_resolve
wdbl_script_show
wdbl_script_run
wdbl_script_step
wdbl_script_until
wdbl_script_set_var
wdbl_script_unset_var
wdbl_script_vars
wdbl_script_reset
wdbl_script_clear
wdbl_env_save
wdbl_env_load
wdbl_patch_text
wdbl_patch_file
wdbl_patch_file_preview
wdbl_patch_nop
wdbl_patch_list
wdbl_stack_contents
wdbl_peb
wdbl_teb
wdbl_seh
wdbl_handles
wdbl_memory_strings
wdbl_dump_memory_to_file
wdbl_go_up
wdbl_watch_trace
wdbl_run_to_entry
wdbl_snapshot_clear
wdbl_asm_color
wdbl_memory_dump
wdbl_memory_ascii
wdbl_memory_binary
wdbl_memory_search_ascii
wdbl_memory_search_unicode
wdbl_memory_search_bytes
wdbl_memory_search_dword
wdbl_memory_search_qword
wdbl_display_type
wdbl_dump_image_or_range
wdbl_virtual_alloc
wdbl_context_views
wdbl_comment_add
wdbl_comment_set
wdbl_comment_delete
wdbl_comment_show
wdbl_comment_list
wdbl_plugin_list
wdbl_plugin_autoload
wdbl_plugin_load
wdbl_plugin_enable
wdbl_plugin_disable
wdbl_plugin_unload
wdbl_plugin_run
wdbl_thread_command
wdbl_python_help
wdbl_python_run
wdbl_python_exec
wdbl_quit
wdbl_list_skills
wdbl_run_skill
wdbl_store_status
wdbl_session_status
wdbl_session_list
wdbl_events_poll
wdbl_event_history
wdbl_autocapture_status
wdbl_automation_status
wdbl_automation_config
wdbl_case_add
wdbl_case_capture_current
wdbl_case_get
wdbl_case_search
wdbl_case_update_resolution
wdbl_case_list
wdbl_case_match
wdbl_skill_recommend
wdbl_skill_history
wdbl_tool_history
wdbl_feature_add
wdbl_feature_list
wdbl_feature_get
wdbl_feature_match
wdbl_feature_match_current
wdbl_feature_learn_from_pc
wdbl_feature_export
wdbl_feature_reload
wdbl_feature_update
wdbl_feature_delete
wdbl_feature_import
wdbl_auto_triage
wdbl_store_export
wdbl_store_import_cases
wdbl_model_context
wdbl_llm_status
wdbl_llm_summarize_text
wdbl_llm_analyze_stop
wdbl_llm_analyze_case
wdbl_llm_notes
wdbl_demo_skill
```

The debugger-side plugin handles pipe requests on its own worker thread. Requests are serialized before entering `WdblDebuggerApi`.

Raw command execution uses the bridge `execute_capture` request when available. The response includes `value`, `output`, and `truncated`, so MCP clients can inspect command output without scraping the debugger UI.

The debugger CLI also exposes the following analysis commands:

- `vad dump <index|0xaddress> <file>` dumps one committed memory region.
- `iatcheck [module|all]` checks imported function pointers.
- `modifycheck [module|all]` checks selected module/API bytes.
- `syscallcheck [module]` checks syscall stubs against a disk baseline.
- `threadcheck` checks thread start/current addresses and private executable candidates.
- `analysis report` prints a combined analysis summary.
- `timeline [max]` and `timeline follow [interval_ms]` show driver events and debugger stops.
- `exceptioncheck` checks SEH and exception-dispatcher integrity.
- `modulecheck` checks loaded module headers and mapping candidates.
- `report export <file> [txt|json]` exports a session analysis summary.
- `apitrace [max] [filter]` displays driver-backed behavior events.

The integrity and threat indicators above are heuristic. In particular, `apitrace` currently reports driver behavior events rather than exact API calls with decoded arguments.

Debugger events are queued by the plugin through `WdblPluginOnEvent` and can be drained with `wdbl_events_poll`. The Python server starts a background auto-capture thread by default and stores pause events as SQLite cases. Set `Z0BDBG_MCP_AUTOCAPTURE=0` to disable it, or `Z0BDBG_MCP_AUTOCAPTURE_INTERVAL=<seconds>` to tune the polling interval.

`wdbl_auto_triage` captures the current debugger context, matches it against local cases, selects a read-only skill, and can optionally call the local LLM. Use `wdbl_case_update_resolution` after solving a case so future matching has a concrete resolution to reuse.

Automation defaults are conservative. Event auto-capture is enabled, but event-triggered skill execution and LLM calls are disabled unless `Z0BDBG_MCP_AUTO_TRIAGE_ON_EVENT=1` or `Z0BDBG_MCP_AUTO_LLM_ON_EVENT=1` is set. Use `wdbl_automation_config` to change these flags at runtime. Tool-call auditing is enabled by default and can be reviewed with `wdbl_tool_history`.

`wdbl_automation_config` persists changes to `mcp_server\config\automation.json` by default. Pass `persist=false` to change only the current server process.

LLM tools degrade cleanly when the local model server is offline: responses include `llmError` while still returning captured context, matches, and case data where available.

Before a debugger state is sent to the local LLM, the server builds a compact `modelContext` package containing `summary`, `evidence`, `similarCases`, `availableSkills`, recent activity, references, and safety constraints. Use `wdbl_model_context` to inspect this package without calling the model. LLM analysis tools return the same `modelContext` beside the model response.

Use `wdbl_store_export` to write a JSON knowledge bundle containing sessions, cases, skill runs, LLM notes, events, and debug feature signatures. Use `wdbl_store_import_cases` to import the case portion of that bundle into another local store.

Reusable debug features are stored in SQLite as `debug_features`. They are intended for signatures such as MSVC STL asm patterns, runtime helper calls, and previously solved debugger situations. Use `wdbl_feature_add` to record a feature, `wdbl_feature_learn_from_pc` to save the current `pc` output as a feature, `wdbl_feature_match` to match text or the current `pc` output, and `wdbl_feature_export` / `wdbl_feature_import` to move feature-only bundles between machines.

Seed feature files live under `mcp_server\features` by default. The server imports `*.json` files from that directory on startup with `INSERT OR IGNORE`, so new rules can be dropped in without changing Python code. Set `Z0BDBG_MCP_FEATURES_DIR=<path>` to load a different seed directory. Use `wdbl_feature_reload` after editing JSON files to upsert seed rules without restarting the server.

Current seed categories include `cpp_std`, `cpp_runtime`, `anti_debug`, `winapi_file`, `winapi_process_thread`, `packer`, and `veh_seh`.

Example feature workflow:

```text
wdbl_feature_match(expression="rip", count=128)
wdbl_feature_match_current(count=128)
wdbl_feature_learn_from_pc(name="my_vector_case", semantic="std::vector reallocate in target case", category="cpp_std", expression="rip", count=160, keywords=["std::vector", "+8", "+10h"])
wdbl_feature_export(path="features.json")
wdbl_feature_import(path="features.json")
wdbl_feature_reload()
wdbl_feature_update(name="my_vector_case", confidence=0.75, notes="confirmed in target")
wdbl_feature_delete(name="my_vector_case")
```

Sessions group related MCP activity, debug launches/attaches, events, cases, skill runs, LLM notes, and tool calls. `wdbl_session_status` shows the active session, and `wdbl_session_list` lists recent sessions.

Auto-capture deduplicates repeated pause stops for `Z0BDBG_MCP_DEDUP_SECONDS` seconds using process, thread, exception code, instruction pointer, and stop reason.

MCP resources are also exposed:

```text
z0bdbg://status
z0bdbg://automation
z0bdbg://sessions/recent
z0bdbg://cases/recent
z0bdbg://events/recent
z0bdbg://features
z0bdbg://skills
z0bdbg://context/current
z0bdbg://model/context/current
z0bdbg://readme
```
