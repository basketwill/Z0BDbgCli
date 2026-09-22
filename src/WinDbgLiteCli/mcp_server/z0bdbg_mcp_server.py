#!/usr/bin/env python
from __future__ import annotations

import json
import hashlib
import hmac
import os
import secrets
import sys
import threading
import time
from typing import Any, Dict, Optional

from context_builder import build_model_context, build_model_prompt
from local_llm import LocalLlmClient
from local_store import LocalStore

PIPE_NAME = r"\\.\pipe\Z0BDbgMcpBridge"
PROTOCOL_NAME = "Z0BDbgMcpBridge-v1"
SECURITY_MODE = os.environ.get("Z0BDBG_MCP_SECURITY_MODE", "plain").strip().lower()
SHARED_KEY = os.environ.get("Z0BDBG_MCP_SHARED_KEY", "")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SKILLS_DIR = os.path.join(SCRIPT_DIR, "skills")
DATA_DIR = os.path.join(SCRIPT_DIR, "data")
CONFIG_DIR = os.path.join(SCRIPT_DIR, "config")
FEATURES_DIR = os.environ.get("Z0BDBG_MCP_FEATURES_DIR", os.path.join(SCRIPT_DIR, "features"))
STORE_PATH = os.environ.get("Z0BDBG_MCP_STORE", os.path.join(DATA_DIR, "z0bdbg_mcp.sqlite"))
ROUTER_CONFIG_PATH = os.environ.get("Z0BDBG_MCP_ROUTER_CONFIG", os.path.join(CONFIG_DIR, "case_router.json"))
AUTOMATION_CONFIG_PATH = os.environ.get("Z0BDBG_MCP_AUTOMATION_CONFIG", os.path.join(CONFIG_DIR, "automation.json"))
AUTOCAPTURE_ENABLED = os.environ.get("Z0BDBG_MCP_AUTOCAPTURE", "1").lower() not in ("0", "false", "no", "off")
AUTOCAPTURE_INTERVAL = float(os.environ.get("Z0BDBG_MCP_AUTOCAPTURE_INTERVAL", "1.0"))
AUTO_TRIAGE_ON_EVENT = os.environ.get("Z0BDBG_MCP_AUTO_TRIAGE_ON_EVENT", "0").lower() in ("1", "true", "yes", "on")
AUTO_LLM_ON_EVENT = os.environ.get("Z0BDBG_MCP_AUTO_LLM_ON_EVENT", "0").lower() in ("1", "true", "yes", "on")
AUDIT_TOOL_CALLS = os.environ.get("Z0BDBG_MCP_AUDIT", "1").lower() not in ("0", "false", "no", "off")


def normalize_security_mode(value: str) -> str:
    value = str(value or "").strip().lower()
    if value in ("strict", "encrypted"):
        return "strict"
    if value in ("optional", "auto"):
        return "optional"
    return "plain"


def hmac_hex(key: str, value: str) -> str:
    return hmac.new(
        key.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def xor_crypt(key: str, nonce: str, value: bytes) -> bytes:
    output = bytearray()
    offset = 0
    counter = 0
    key_bytes = key.encode("utf-8")
    while offset < len(value):
        block = hmac.new(
            key_bytes,
            ("stream|%s|%d" % (nonce, counter)).encode("ascii"),
            hashlib.sha256,
        ).digest()
        count = min(len(block), len(value) - offset)
        output.extend(value[offset:offset + count][i] ^ block[i] for i in range(count))
        offset += count
        counter += 1
    return bytes(output)


def load_json_file(path: str, default: Dict[str, Any]) -> Dict[str, Any]:
    if not path or not os.path.isfile(path):
        return dict(default)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        if isinstance(loaded, dict):
            merged = dict(default)
            merged.update(loaded)
            return merged
    except Exception:
        pass
    return dict(default)


def save_json_file(path: str, value: Dict[str, Any]) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)


def bool_config(name: str, default: bool = False) -> bool:
    value = automation_config.get(name, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).lower() in ("1", "true", "yes", "on")


AUTOMATION_DEFAULTS: Dict[str, Any] = {
    "autocaptureEnabled": AUTOCAPTURE_ENABLED,
    "autoTriageOnEvent": AUTO_TRIAGE_ON_EVENT,
    "autoLlmOnEvent": AUTO_LLM_ON_EVENT,
    "auditToolCalls": AUDIT_TOOL_CALLS,
}
automation_config: Dict[str, Any] = load_json_file(AUTOMATION_CONFIG_PATH, AUTOMATION_DEFAULTS)

RISK_POLICIES = {
    "read-only": {"requiresStateChange": False, "requiresDestructive": False},
    "debugger-state-change": {"requiresStateChange": True, "requiresDestructive": False},
    "target-state-change": {"requiresStateChange": True, "requiresDestructive": False},
    "destructive": {"requiresStateChange": True, "requiresDestructive": True},
}


def read_mcp_message() -> Optional[Dict[str, Any]]:
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        line = line.rstrip(b"\r\n")
        if not line:
            break
        name, _, value = line.decode("ascii", "replace").partition(":")
        headers[name.lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    payload = sys.stdin.buffer.read(length)
    return json.loads(payload.decode("utf-8"))


def write_mcp_message(message: Dict[str, Any]) -> None:
    payload = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(b"Content-Length: " + str(len(payload)).encode("ascii") + b"\r\n\r\n")
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


class BridgeClient:
    def __init__(self, pipe_name: str = PIPE_NAME, connect_timeout: float = 5.0, keep_open: bool = False) -> None:
        self.pipe_name = pipe_name
        self.connect_timeout = connect_timeout
        self.keep_open = keep_open
        self._pipe = None
        self._lock = threading.Lock()
        self._encrypted = False
        self._server_nonce = ""
        self._client_nonce = ""

    def close(self) -> None:
        if self._pipe is not None:
            try:
                self._pipe.close()
            finally:
                self._pipe = None
        self._encrypted = False
        self._server_nonce = ""
        self._client_nonce = ""

    def _connect(self):
        deadline = time.time() + max(0.05, self.connect_timeout)
        last_error = None
        while time.time() < deadline:
            try:
                return open(self.pipe_name, "r+b", buffering=0)
            except OSError as exc:
                last_error = exc
                time.sleep(0.05)
        raise RuntimeError("connect to %s failed: %s" % (self.pipe_name, last_error))

    def _read_line(self) -> bytes:
        line = self._pipe.readline()
        if not line:
            raise RuntimeError("empty bridge response")
        return line

    def _handshake(self) -> None:
        challenge = json.loads(self._read_line().decode("utf-8"))
        if not challenge.get("hello") or challenge.get("protocol") != PROTOCOL_NAME:
            raise RuntimeError("invalid bridge handshake challenge")
        remote_mode = normalize_security_mode(challenge.get("mode", "plain"))
        client_mode = normalize_security_mode(SECURITY_MODE)
        if (remote_mode == "strict" and client_mode == "plain") or (
            client_mode == "strict" and remote_mode == "plain"
        ):
            raise RuntimeError("bridge security mode mismatch")
        encrypted = (
            remote_mode == "strict"
            or client_mode == "strict"
            or (remote_mode == "optional" and client_mode == "optional")
        )
        if encrypted and not SHARED_KEY:
            raise RuntimeError("encrypted mode requires Z0BDBG_MCP_SHARED_KEY")
        server_nonce = str(challenge.get("nonce", ""))
        client_nonce = secrets.token_hex(16)
        hello = {
            "hello": True,
            "protocol": PROTOCOL_NAME,
            "mode": client_mode,
            "nonce": client_nonce,
        }
        if encrypted:
            hello["proof"] = hmac_hex(
                SHARED_KEY,
                "hello|%s|%s|%s|encrypted"
                % (PROTOCOL_NAME, server_nonce, client_nonce),
            )
        self._pipe.write((json.dumps(hello, separators=(",", ":")) + "\n").encode("utf-8"))
        self._pipe.flush()
        ack = json.loads(self._read_line().decode("utf-8"))
        if not ack.get("ok") or not ack.get("hello") or ack.get("protocol") != PROTOCOL_NAME:
            raise RuntimeError(ack.get("error", "bridge handshake failed"))
        negotiated = ack.get("mode")
        if negotiated != ("encrypted" if encrypted else "plain"):
            raise RuntimeError("bridge negotiated unexpected security mode")
        if encrypted:
            expected = hmac_hex(
                SHARED_KEY,
                "ack|%s|%s|%s|encrypted"
                % (PROTOCOL_NAME, server_nonce, client_nonce),
            )
            if not hmac.compare_digest(str(ack.get("proof", "")), expected):
                raise RuntimeError("bridge handshake authentication failed")
        self._encrypted = encrypted
        self._server_nonce = server_nonce
        self._client_nonce = client_nonce

    def _encode_request(self, payload: Dict[str, Any]) -> bytes:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if not self._encrypted:
            return raw + b"\n"
        nonce = secrets.token_hex(16)
        cipher = xor_crypt(SHARED_KEY, nonce, raw)
        data = cipher.hex()
        envelope = {
            "secure": 1,
            "nonce": nonce,
            "data": data,
            "tag": hmac_hex(SHARED_KEY, "packet|%s|%s" % (nonce, data)),
        }
        return (json.dumps(envelope, separators=(",", ":")) + "\n").encode("utf-8")

    def _decode_response(self, line: bytes) -> Dict[str, Any]:
        response = json.loads(line.decode("utf-8"))
        if not self._encrypted:
            return response
        if response.get("secure") != 1:
            raise RuntimeError("missing encrypted bridge response")
        nonce = str(response.get("nonce", ""))
        data = str(response.get("data", ""))
        tag = str(response.get("tag", ""))
        expected = hmac_hex(SHARED_KEY, "packet|%s|%s" % (nonce, data))
        if not hmac.compare_digest(tag, expected):
            raise RuntimeError("encrypted bridge response authentication failed")
        try:
            cipher = bytes.fromhex(data)
        except ValueError:
            raise RuntimeError("invalid encrypted bridge response")
        raw = xor_crypt(SHARED_KEY, nonce, cipher)
        return json.loads(raw.decode("utf-8"))

    def request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            for attempt in range(2):
                if self._pipe is None:
                    self._pipe = self._connect()
                try:
                    self._handshake()
                    self._pipe.write(self._encode_request(payload))
                    self._pipe.flush()
                    response = self._decode_response(self._read_line())
                    if not response.get("ok", False):
                        raise RuntimeError(response.get("error", "bridge request failed"))
                    if not self.keep_open:
                        self.close()
                    return response
                except Exception:
                    self.close()
                    if attempt == 0:
                        continue
                    raise
        raise RuntimeError("bridge request failed")


bridge = BridgeClient()
store = LocalStore(STORE_PATH, ROUTER_CONFIG_PATH, FEATURES_DIR)
llm = LocalLlmClient()
current_session_id = store.start_session("mcp_server", "Z0BDbgMcpServer", {"pid": os.getpid()})
current_session_lock = threading.Lock()
recent_stop_fingerprints: Dict[str, float] = {}
DEDUP_WINDOW_SECONDS = float(os.environ.get("Z0BDBG_MCP_DEDUP_SECONDS", "5.0"))


TOOLS = [
    {
        "name": "wdbl_ping",
        "description": "Check the WinDbgLite bridge pipe.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "wdbl_execute",
        "description": "Execute a raw WinDbgLite command.",
        "inputSchema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
    {
        "name": "wdbl_launch",
        "description": "Launch a debuggee command line.",
        "inputSchema": {
            "type": "object",
            "properties": {"commandLine": {"type": "string"}},
            "required": ["commandLine"],
        },
    },
    {
        "name": "wdbl_attach",
        "description": "Attach to an existing process id.",
        "inputSchema": {
            "type": "object",
            "properties": {"pid": {"type": "integer"}},
            "required": ["pid"],
        },
    },
    {"name": "wdbl_detach", "description": "Detach from the current debuggee.", "inputSchema": {"type": "object", "properties": {}}},
    {
        "name": "wdbl_set_breakpoint",
        "description": "Set a software breakpoint by symbol or address expression.",
        "inputSchema": {
            "type": "object",
            "properties": {"expression": {"type": "string"}},
            "required": ["expression"],
        },
    },
    {
        "name": "wdbl_set_hardware_breakpoint",
        "description": "Set a hardware breakpoint. access: x, w, or rw.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "expression": {"type": "string"},
                "access": {"type": "string", "default": "x"},
                "length": {"type": "integer", "default": 1},
                "slot": {"type": "integer", "default": 0},
                "threadId": {"type": "integer", "default": 0},
            },
            "required": ["expression"],
        },
    },
    {
        "name": "wdbl_set_memory_breakpoint",
        "description": "Set a guard-page memory breakpoint. access can combine r, w, x.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "expression": {"type": "string"},
                "size": {"type": "integer"},
                "access": {"type": "string", "default": "rw"},
            },
            "required": ["expression", "size"],
        },
    },
    {
        "name": "wdbl_set_breakpoint_condition",
        "description": "Set a breakpoint condition expression.",
        "inputSchema": {"type": "object", "properties": {"breakpointId": {"type": "integer"}, "condition": {"type": "string"}}, "required": ["breakpointId", "condition"]},
    },
    {
        "name": "wdbl_clear_breakpoint_condition",
        "description": "Clear a breakpoint condition.",
        "inputSchema": {"type": "object", "properties": {"breakpointId": {"type": "integer"}}, "required": ["breakpointId"]},
    },
    {
        "name": "wdbl_enable_breakpoint",
        "description": "Enable a breakpoint by id.",
        "inputSchema": {"type": "object", "properties": {"breakpointId": {"type": "integer"}}, "required": ["breakpointId"]},
    },
    {
        "name": "wdbl_disable_breakpoint",
        "description": "Disable a breakpoint by id.",
        "inputSchema": {"type": "object", "properties": {"breakpointId": {"type": "integer"}}, "required": ["breakpointId"]},
    },
    {
        "name": "wdbl_remove_breakpoint",
        "description": "Remove a breakpoint by id.",
        "inputSchema": {"type": "object", "properties": {"breakpointId": {"type": "integer"}}, "required": ["breakpointId"]},
    },
    {
        "name": "wdbl_resolve",
        "description": "Resolve a symbol or address expression to an address.",
        "inputSchema": {"type": "object", "properties": {"expression": {"type": "string"}}, "required": ["expression"]},
    },
    {
        "name": "wdbl_symbol",
        "description": "Resolve an address to symbol text.",
        "inputSchema": {"type": "object", "properties": {"address": {"oneOf": [{"type": "integer"}, {"type": "string"}]}}, "required": ["address"]},
    },
    {
        "name": "wdbl_load_symbols",
        "description": "Load symbols for all modules or one module target.",
        "inputSchema": {"type": "object", "properties": {"target": {"type": "string", "default": "*"}}},
    },
    {
        "name": "wdbl_download_symbols",
        "description": "Download and load symbols. cacheDir and serverUrl are optional but must be supplied together.",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string", "default": "*"}, "cacheDir": {"type": "string"}, "serverUrl": {"type": "string"}},
        },
    },
    {
        "name": "wdbl_set_symbol_path",
        "description": "Set symbol search path.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
    },
    {"name": "wdbl_get_symbol_path", "description": "Get symbol search path.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_continue", "description": "Continue debuggee execution.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_step", "description": "Single-step the current thread.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_step_over", "description": "Step over the current instruction.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_stop_info", "description": "Return current stop information.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_threads", "description": "List debuggee threads.", "inputSchema": {"type": "object", "properties": {}}},
    {
        "name": "wdbl_select_thread",
        "description": "Select the current thread by thread list index.",
        "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}}, "required": ["index"]},
    },
    {"name": "wdbl_modules", "description": "List loaded modules.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_breakpoints", "description": "List breakpoints.", "inputSchema": {"type": "object", "properties": {}}},
    {
        "name": "wdbl_registers",
        "description": "Get registers for a thread index.",
        "inputSchema": {
            "type": "object",
            "properties": {"index": {"type": "integer", "default": 0}},
        },
    },
    {
        "name": "wdbl_stack",
        "description": "Get stack frames for a thread index.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "threadIndex": {"type": "integer", "default": 0},
                "maxFrames": {"type": "integer", "default": 16},
            },
        },
    },
    {
        "name": "wdbl_read_memory",
        "description": "Read process memory and return hex bytes. Size is capped at 4096.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                "size": {"type": "integer"},
            },
            "required": ["address", "size"],
        },
    },
    {
        "name": "wdbl_write_memory",
        "description": "Write process memory from hex bytes. Data is capped at 4096 bytes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                "data": {"type": "string"},
            },
            "required": ["address", "data"],
        },
    },
    {
        "name": "wdbl_set_register",
        "description": "Set a register using assignment or name/value.",
        "inputSchema": {"type": "object", "properties": {"assignment": {"type": "string"}, "name": {"type": "string"}, "value": {"oneOf": [{"type": "integer"}, {"type": "string"}]}}},
    },
    {
        "name": "wdbl_write_memory_patch",
        "description": "Patch memory bytes and keep undo history. Data is hex and capped at 4096 bytes.",
        "inputSchema": {"type": "object", "properties": {"address": {"oneOf": [{"type": "integer"}, {"type": "string"}]}, "data": {"type": "string"}}, "required": ["address", "data"]},
    },
    {"name": "wdbl_undo_memory_patch", "description": "Undo recent memory patch operations.", "inputSchema": {"type": "object", "properties": {"count": {"type": "integer", "default": 1}}}},
    {"name": "wdbl_save_current_snapshot", "description": "Save the current stop snapshot to history.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_save_snapshot", "description": "Save a named stop snapshot.", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {
        "name": "wdbl_restore_snapshot",
        "description": "Restore a named stop snapshot.",
        "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "rerunAfterRestore": {"type": "boolean", "default": False}}, "required": ["name"]},
    },
    {"name": "wdbl_list_snapshots", "description": "List named snapshots in the debugger console.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_step_back", "description": "Restore the previous stop snapshot.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_add_source_root", "description": "Add a source root.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "wdbl_remove_source_root", "description": "Remove a source root.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "wdbl_clear_source_roots", "description": "Clear source roots.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_list_source_roots", "description": "List source roots in the debugger console.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_load_script", "description": "Load a debugger script file.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "wdbl_set_script_breakpoint", "description": "Set a script breakpoint by source line.", "inputSchema": {"type": "object", "properties": {"line": {"type": "integer"}}, "required": ["line"]}},
    {"name": "wdbl_remove_script_breakpoint", "description": "Remove a script breakpoint by source line.", "inputSchema": {"type": "object", "properties": {"line": {"type": "integer"}}, "required": ["line"]}},
    {"name": "wdbl_list_script_breakpoints", "description": "List script breakpoints in the debugger console.", "inputSchema": {"type": "object", "properties": {}}},
    {
        "name": "wdbl_set_exception_ignore_all",
        "description": "Enable or disable ignore-all for an exception scope: debugging, runtime, or stepping.",
        "inputSchema": {"type": "object", "properties": {"scope": {"type": "string", "default": "debugging"}, "enabled": {"type": "boolean"}}, "required": ["enabled"]},
    },
    {
        "name": "wdbl_add_ignored_exception",
        "description": "Add an ignored exception code for a scope.",
        "inputSchema": {"type": "object", "properties": {"scope": {"type": "string", "default": "debugging"}, "code": {"oneOf": [{"type": "integer"}, {"type": "string"}]}}, "required": ["code"]},
    },
    {
        "name": "wdbl_remove_ignored_exception",
        "description": "Remove an ignored exception code for a scope.",
        "inputSchema": {"type": "object", "properties": {"scope": {"type": "string", "default": "debugging"}, "code": {"oneOf": [{"type": "integer"}, {"type": "string"}]}}, "required": ["code"]},
    },
    {"name": "wdbl_clear_ignored_exceptions", "description": "Clear ignored exception codes for a scope.", "inputSchema": {"type": "object", "properties": {"scope": {"type": "string", "default": "debugging"}}}},
    {"name": "wdbl_list_exception_settings", "description": "List exception ignore settings in the debugger console.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_add_run_stop_expression", "description": "Add a run-stop expression.", "inputSchema": {"type": "object", "properties": {"expression": {"type": "string"}}, "required": ["expression"]}},
    {"name": "wdbl_remove_run_stop_expression", "description": "Remove a run-stop expression by index.", "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}}, "required": ["index"]}},
    {"name": "wdbl_clear_run_stop_expressions", "description": "Clear run-stop expressions.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_list_run_stop_expressions", "description": "List run-stop expressions in the debugger console.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_step_until_condition", "description": "Single-step until an expression is true.", "inputSchema": {"type": "object", "properties": {"condition": {"type": "string"}, "maxSteps": {"type": "integer", "default": 1}}, "required": ["condition"]}},
    {"name": "wdbl_run_until_condition", "description": "Continue until an expression is true.", "inputSchema": {"type": "object", "properties": {"condition": {"type": "string"}, "maxPauses": {"type": "integer", "default": 1}}, "required": ["condition"]}},
    {"name": "wdbl_auto_step", "description": "Repeated single-step.", "inputSchema": {"type": "object", "properties": {"steps": {"type": "integer", "default": 1}, "delayMs": {"type": "integer", "default": 0}}}},
    {"name": "wdbl_auto_run", "description": "Repeated continue-to-pause.", "inputSchema": {"type": "object", "properties": {"pauses": {"type": "integer", "default": 1}, "delayMs": {"type": "integer", "default": 0}}}},
]


RESOURCES = [
    {"uri": "z0bdbg://status", "name": "Z0BDbg Store Status", "description": "Local store and bridge status.", "mimeType": "application/json"},
    {"uri": "z0bdbg://automation", "name": "Z0BDbg Automation", "description": "Current MCP automation settings.", "mimeType": "application/json"},
    {"uri": "z0bdbg://sessions/recent", "name": "Recent Sessions", "description": "Recent MCP/debug sessions.", "mimeType": "application/json"},
    {"uri": "z0bdbg://cases/recent", "name": "Recent Cases", "description": "Recent local debugging cases.", "mimeType": "application/json"},
    {"uri": "z0bdbg://events/recent", "name": "Recent Events", "description": "Recent debugger events stored by auto-capture.", "mimeType": "application/json"},
    {"uri": "z0bdbg://features", "name": "Debug Features", "description": "Reusable asm/context feature signatures.", "mimeType": "application/json"},
    {"uri": "z0bdbg://skills", "name": "Skills", "description": "Discovered MCP-side skills.", "mimeType": "application/json"},
    {"uri": "z0bdbg://context/current", "name": "Current Debug Context", "description": "Current read-only debugger context.", "mimeType": "application/json"},
    {"uri": "z0bdbg://model/context/current", "name": "Current Model Context", "description": "Compact context package sent to the local LLM.", "mimeType": "application/json"},
    {"uri": "z0bdbg://readme", "name": "MCP Server README", "description": "Local MCP server documentation.", "mimeType": "text/markdown"},
]

TOOLS.extend([
    {"name": "wdbl_veh_launch", "description": "Launch a process under VEH agent mode.", "inputSchema": {"type": "object", "properties": {"commandLine": {"type": "string"}}, "required": ["commandLine"]}},
    {"name": "wdbl_veh_on", "description": "Enable or inject VEH mode for an optional pid.", "inputSchema": {"type": "object", "properties": {"pid": {"type": "integer"}, "dllPath": {"type": "string"}}}},
    {"name": "wdbl_veh_off", "description": "Disable VEH mode and unload the agent when possible.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_veh_detach", "description": "Detach from the VEH target.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_veh_kill", "description": "Terminate the VEH target process.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_veh_status", "description": "Show VEH mode status in the debugger console.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_veh_break", "description": "Interrupt the VEH target process.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_veh_refresh", "description": "Refresh VEH module/thread snapshot.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_veh_modules", "description": "Show VEH module cache in the debugger console.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_veh_threads", "description": "Show VEH thread cache in the debugger console.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_veh_read_memory", "description": "Read memory through the VEH agent.", "inputSchema": {"type": "object", "properties": {"address": {"oneOf": [{"type": "integer"}, {"type": "string"}]}, "size": {"type": "integer", "default": 16}}, "required": ["address"]}},
    {"name": "wdbl_veh_write_memory", "description": "Write memory bytes through the VEH agent.", "inputSchema": {"type": "object", "properties": {"address": {"oneOf": [{"type": "integer"}, {"type": "string"}]}, "bytes": {"type": "array", "items": {"type": "integer"}}}, "required": ["address", "bytes"]}},
    {"name": "wdbl_veh_context", "description": "Get VEH thread context.", "inputSchema": {"type": "object", "properties": {"threadId": {"type": "integer"}}, "required": ["threadId"]}},
    {"name": "wdbl_veh_set_register", "description": "Set VEH thread context register.", "inputSchema": {"type": "object", "properties": {"threadId": {"type": "integer"}, "name": {"type": "string"}, "value": {"oneOf": [{"type": "integer"}, {"type": "string"}]}}, "required": ["threadId", "name", "value"]}},
    {"name": "wdbl_veh_suspend_thread", "description": "Suspend a VEH target thread.", "inputSchema": {"type": "object", "properties": {"threadId": {"type": "integer"}}, "required": ["threadId"]}},
    {"name": "wdbl_veh_resume_thread", "description": "Resume a VEH target thread.", "inputSchema": {"type": "object", "properties": {"threadId": {"type": "integer"}}, "required": ["threadId"]}},
    {"name": "wdbl_veh_exception_policy", "description": "Set VEH exception forwarding policy: bp, search, or continue.", "inputSchema": {"type": "object", "properties": {"policy": {"type": "string"}, "code": {"oneOf": [{"type": "integer"}, {"type": "string"}]}}, "required": ["policy"]}},
    {"name": "wdbl_driver_on", "description": "Enable driver mode.", "inputSchema": {"type": "object", "properties": {"devicePath": {"type": "string"}}}},
    {"name": "wdbl_driver_off", "description": "Disable driver mode.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_driver_status", "description": "Show driver status in the debugger console.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_process_info", "description": "Show current process information.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_processes", "description": "List processes in the debugger console.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_current_thread_info", "description": "Show current thread information.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_vm_info", "description": "Show virtual memory status.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_memory_map", "description": "Show process memory map.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_disasm", "description": "Disassemble at an optional address/expression.", "inputSchema": {"type": "object", "properties": {"expression": {"type": "string"}, "count": {"type": "integer"}}}},
    {"name": "wdbl_flow_graph", "description": "Show textual control-flow graph.", "inputSchema": {"type": "object", "properties": {"expression": {"type": "string"}, "maxBlocks": {"type": "integer"}}}},
    {"name": "wdbl_pseudo_c", "description": "Generate minimal C-like pseudocode for the current function slice.", "inputSchema": {"type": "object", "properties": {"expression": {"type": "string"}, "count": {"type": "integer", "default": 128}, "ui": {"type": "boolean", "default": False}}}},
    {"name": "wdbl_examine_symbols", "description": "Examine symbols by mask, for example kernelbase!*CreateFile*.", "inputSchema": {"type": "object", "properties": {"mask": {"type": "string"}}, "required": ["mask"]}},
    {"name": "wdbl_source_where", "description": "Show source at the current instruction pointer.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_source_at", "description": "Show source around an address.", "inputSchema": {"type": "object", "properties": {"address": {"oneOf": [{"type": "integer"}, {"type": "string"}]}, "contextLines": {"type": "integer", "default": 2}}, "required": ["address"]}},
    {"name": "wdbl_source_breakpoint", "description": "Set a source-level breakpoint.", "inputSchema": {"type": "object", "properties": {"file": {"type": "string"}, "line": {"type": "integer"}}, "required": ["file", "line"]}},
    {"name": "wdbl_source_resolve", "description": "Resolve a source location to an address.", "inputSchema": {"type": "object", "properties": {"file": {"type": "string"}, "line": {"type": "integer"}}, "required": ["file", "line"]}},
    {"name": "wdbl_script_show", "description": "Show loaded debugger script.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_script_run", "description": "Run loaded debugger script.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_script_step", "description": "Execute one debugger script line.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_script_until", "description": "Run script until a label.", "inputSchema": {"type": "object", "properties": {"label": {"type": "string"}}, "required": ["label"]}},
    {"name": "wdbl_script_set_var", "description": "Set a debugger script variable.", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "value": {"type": "string"}}, "required": ["name", "value"]}},
    {"name": "wdbl_script_unset_var", "description": "Remove a debugger script variable.", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "wdbl_script_vars", "description": "Show debugger script variables.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_script_reset", "description": "Reset debugger script cursor.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_script_clear", "description": "Clear debugger script state.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_env_save", "description": "Save runtime environment snapshot.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    {"name": "wdbl_env_load", "description": "Load runtime environment snapshot.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    {"name": "wdbl_patch_text", "description": "Patch ASCII or UTF-16 text into target memory.", "inputSchema": {"type": "object", "properties": {"address": {"oneOf": [{"type": "integer"}, {"type": "string"}]}, "encoding": {"type": "string", "default": "ascii"}, "text": {"type": "string"}}, "required": ["address", "text"]}},
    {"name": "wdbl_patch_file", "description": "Patch bytes loaded from a local file slice.", "inputSchema": {"type": "object", "properties": {"address": {"oneOf": [{"type": "integer"}, {"type": "string"}]}, "path": {"type": "string"}, "offset": {"type": "integer"}, "size": {"type": "integer"}}, "required": ["address", "path"]}},
    {"name": "wdbl_patch_file_preview", "description": "Preview bytes from a local file slice.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "offset": {"type": "integer"}, "size": {"type": "integer"}}, "required": ["path"]}},
    {"name": "wdbl_patch_nop", "description": "Patch NOP bytes at an address.", "inputSchema": {"type": "object", "properties": {"address": {"oneOf": [{"type": "integer"}, {"type": "string"}]}, "count": {"type": "integer"}}, "required": ["address", "count"]}},
    {"name": "wdbl_patch_list", "description": "Show recent patch history.", "inputSchema": {"type": "object", "properties": {"maxItems": {"type": "integer"}}}},
    {"name": "wdbl_stack_contents", "description": "Show stack memory contents.", "inputSchema": {"type": "object", "properties": {"maxFrames": {"type": "integer"}}}},
    {"name": "wdbl_peb", "description": "Show PEB details.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_teb", "description": "Show TEB details.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_seh", "description": "Show SEH chain details.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_handles", "description": "Show process handles.", "inputSchema": {"type": "object", "properties": {"limit": {"oneOf": [{"type": "integer"}, {"type": "string"}]}}}},
    {"name": "wdbl_memory_strings", "description": "Scan memory strings.", "inputSchema": {"type": "object", "properties": {"minLength": {"type": "integer"}, "maxItems": {"type": "integer"}}}},
    {"name": "wdbl_dump_memory_to_file", "description": "Dump a memory range to a local file.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]}, "size": {"type": "integer"}}, "required": ["path", "address", "size"]}},
    {"name": "wdbl_go_up", "description": "Continue until the current function returns.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_watch_trace", "description": "Trace/watch execution timing.", "inputSchema": {"type": "object", "properties": {"maxSteps": {"type": "integer"}}}},
    {"name": "wdbl_run_to_entry", "description": "Run and break at the main-module entry point.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_snapshot_clear", "description": "Clear named snapshots.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_asm_color", "description": "Set or query disassembly color output.", "inputSchema": {"type": "object", "properties": {"mode": {"type": "string", "default": "status"}}}},
    {"name": "wdbl_memory_dump", "description": "Dump memory in byte/word/dword/qword format.", "inputSchema": {"type": "object", "properties": {"format": {"type": "string", "default": "db"}, "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]}, "bytes": {"type": "integer"}, "perLine": {"type": "integer"}, "ui": {"type": "boolean", "default": False}}, "required": ["address"]}},
    {"name": "wdbl_memory_ascii", "description": "Display ASCII memory.", "inputSchema": {"type": "object", "properties": {"address": {"oneOf": [{"type": "integer"}, {"type": "string"}]}, "bytes": {"type": "integer"}, "ui": {"type": "boolean", "default": False}}, "required": ["address"]}},
    {"name": "wdbl_memory_binary", "description": "Show memory as binary bytes.", "inputSchema": {"type": "object", "properties": {"address": {"oneOf": [{"type": "integer"}, {"type": "string"}]}, "size": {"type": "integer"}}, "required": ["address", "size"]}},
    {"name": "wdbl_memory_search_ascii", "description": "Search memory for ASCII text.", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}},
    {"name": "wdbl_memory_search_unicode", "description": "Search memory for UTF-16 text.", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}},
    {"name": "wdbl_memory_search_bytes", "description": "Search memory for byte values.", "inputSchema": {"type": "object", "properties": {"bytes": {"type": "array", "items": {"type": "integer"}}}, "required": ["bytes"]}},
    {"name": "wdbl_memory_search_dword", "description": "Search memory for a dword value.", "inputSchema": {"type": "object", "properties": {"value": {"oneOf": [{"type": "integer"}, {"type": "string"}]}}, "required": ["value"]}},
    {"name": "wdbl_memory_search_qword", "description": "Search memory for a qword value.", "inputSchema": {"type": "object", "properties": {"value": {"oneOf": [{"type": "integer"}, {"type": "string"}]}}, "required": ["value"]}},
    {"name": "wdbl_display_type", "description": "Display structure fields and values.", "inputSchema": {"type": "object", "properties": {"type": {"type": "string"}, "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]}, "depth": {"type": "integer"}}, "required": ["type", "address"]}},
    {"name": "wdbl_dump_image_or_range", "description": "Dump current exe or a memory range to a file.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]}, "size": {"type": "integer"}}, "required": ["path"]}},
    {"name": "wdbl_virtual_alloc", "description": "Allocate virtual memory in target process.", "inputSchema": {"type": "object", "properties": {"size": {"type": "integer"}}, "required": ["size"]}},
    {"name": "wdbl_context_views", "description": "Show key debug context views.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_comment_add", "description": "Add an instruction comment.", "inputSchema": {"type": "object", "properties": {"address": {"oneOf": [{"type": "integer"}, {"type": "string"}]}, "text": {"type": "string"}}, "required": ["address", "text"]}},
    {"name": "wdbl_comment_set", "description": "Set an instruction comment.", "inputSchema": {"type": "object", "properties": {"address": {"oneOf": [{"type": "integer"}, {"type": "string"}]}, "text": {"type": "string"}}, "required": ["address", "text"]}},
    {"name": "wdbl_comment_delete", "description": "Delete an instruction comment.", "inputSchema": {"type": "object", "properties": {"address": {"oneOf": [{"type": "integer"}, {"type": "string"}]}}, "required": ["address"]}},
    {"name": "wdbl_comment_show", "description": "Show an instruction comment.", "inputSchema": {"type": "object", "properties": {"address": {"oneOf": [{"type": "integer"}, {"type": "string"}]}}, "required": ["address"]}},
    {"name": "wdbl_comment_list", "description": "List instruction comments.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_plugin_list", "description": "List loaded plugin modules.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_plugin_autoload", "description": "Load all plugins from default plugin folders.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_plugin_load", "description": "Load a plugin DLL.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "wdbl_plugin_enable", "description": "Enable a plugin by id or name.", "inputSchema": {"type": "object", "properties": {"idOrName": {"oneOf": [{"type": "integer"}, {"type": "string"}]}}, "required": ["idOrName"]}},
    {"name": "wdbl_plugin_disable", "description": "Disable a plugin by id or name.", "inputSchema": {"type": "object", "properties": {"idOrName": {"oneOf": [{"type": "integer"}, {"type": "string"}]}}, "required": ["idOrName"]}},
    {"name": "wdbl_plugin_unload", "description": "Unload a plugin by id, name, or *.", "inputSchema": {"type": "object", "properties": {"idOrName": {"oneOf": [{"type": "integer"}, {"type": "string"}]}}, "required": ["idOrName"]}},
    {"name": "wdbl_plugin_run", "description": "Run a plugin command.", "inputSchema": {"type": "object", "properties": {"idOrName": {"oneOf": [{"type": "integer"}, {"type": "string"}]}, "args": {"type": "string"}}, "required": ["idOrName"]}},
    {"name": "wdbl_thread_command", "description": "Execute a raw thread command such as ~, ~*, ~0s, or ~*k.", "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}},
    {"name": "wdbl_python_help", "description": "Show Python bridge help.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_python_run", "description": "Run a Python script file in the debugger bridge.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "wdbl_python_exec", "description": "Execute inline Python code in the debugger bridge.", "inputSchema": {"type": "object", "properties": {"code": {"type": "string"}}, "required": ["code"]}},
    {"name": "wdbl_quit", "description": "Exit the debugger.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_list_skills", "description": "List MCP-side skills discovered under mcp_server/skills.", "inputSchema": {"type": "object", "properties": {}}},
    {
        "name": "wdbl_run_skill",
        "description": "Run or preview an MCP-side skill. Skills default to dry-run unless execute=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "skill": {"type": "string"},
                "execute": {"type": "boolean", "default": False},
                "allowStateChange": {"type": "boolean", "default": False},
                "allowDestructive": {"type": "boolean", "default": False},
                "parameters": {"type": "object"},
            },
            "required": ["skill"],
        },
    },
    {"name": "wdbl_store_status", "description": "Show local SQLite store status.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_session_status", "description": "Show the current MCP/debug session.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_session_list", "description": "List recent MCP/debug sessions.", "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 20}}}},
    {"name": "wdbl_events_poll", "description": "Drain pending debugger events from the MCP bridge.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_event_history", "description": "List recent debugger events stored by auto-capture.", "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 50}}}},
    {"name": "wdbl_autocapture_status", "description": "Show automatic event case capture status.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_automation_status", "description": "Show MCP automation policy flags.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_automation_config", "description": "Update MCP automation policy flags and persist them by default.", "inputSchema": {"type": "object", "properties": {"autocaptureEnabled": {"type": "boolean"}, "autoTriageOnEvent": {"type": "boolean"}, "autoLlmOnEvent": {"type": "boolean"}, "auditToolCalls": {"type": "boolean"}, "persist": {"type": "boolean", "default": True}}}},
    {
        "name": "wdbl_case_add",
        "description": "Add a local debugging case to SQLite memory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "skill": {"type": "string"},
                "resolution": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "context": {"type": "object"},
            },
            "required": ["title"],
        },
    },
    {
        "name": "wdbl_case_capture_current",
        "description": "Capture current read-only debug state into the local case store.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "skill": {"type": "string"},
                "resolution": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "threadIndex": {"type": "integer", "default": 0},
                "maxFrames": {"type": "integer", "default": 8},
            },
            "required": ["title"],
        },
    },
    {"name": "wdbl_case_get", "description": "Get one local debugging case by id.", "inputSchema": {"type": "object", "properties": {"caseId": {"type": "integer"}, "includeContext": {"type": "boolean", "default": True}}, "required": ["caseId"]}},
    {"name": "wdbl_case_search", "description": "Search local debugging cases by text.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "limit": {"type": "integer", "default": 20}}, "required": ["query"]}},
    {"name": "wdbl_case_update_resolution", "description": "Update the resolution/lesson for a local debugging case.", "inputSchema": {"type": "object", "properties": {"caseId": {"type": "integer"}, "resolution": {"type": "string"}, "skill": {"type": "string"}}, "required": ["caseId", "resolution"]}},
    {"name": "wdbl_case_list", "description": "List recent local debugging cases.", "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 20}}}},
    {
        "name": "wdbl_case_match",
        "description": "Match a supplied debug context against local cases.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context": {"type": "object"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "limit": {"type": "integer", "default": 5},
            },
            "required": ["context"],
        },
    },
    {
        "name": "wdbl_skill_recommend",
        "description": "Recommend skills by matching current or supplied debug context against local cases.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context": {"type": "object"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "threadIndex": {"type": "integer", "default": 0},
                "maxFrames": {"type": "integer", "default": 8},
                "limit": {"type": "integer", "default": 5},
            },
        },
    },
    {"name": "wdbl_skill_history", "description": "List recent skill run history from SQLite.", "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 20}}}},
    {"name": "wdbl_tool_history", "description": "List recent MCP tool calls recorded in SQLite.", "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 50}}}},
    {
        "name": "wdbl_feature_add",
        "description": "Add or update a reusable debug feature signature, such as an asm pattern for a C++ STL operation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "category": {"type": "string", "default": "generic"},
                "semantic": {"type": "string"},
                "pattern": {"type": "object"},
                "evidence": {"type": "object"},
                "action": {"type": "object"},
                "compiler": {"type": "string"},
                "arch": {"type": "string"},
                "confidence": {"type": "number", "default": 0.5},
                "sourceCaseId": {"type": "integer"},
                "notes": {"type": "string"},
            },
            "required": ["name", "semantic", "pattern"],
        },
    },
    {"name": "wdbl_feature_list", "description": "List stored debug feature signatures.", "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 50}, "category": {"type": "string"}}}},
    {"name": "wdbl_feature_get", "description": "Get one debug feature signature.", "inputSchema": {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"]}},
    {"name": "wdbl_feature_match", "description": "Match text or current pseudo C/disassembly against stored debug feature signatures.", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}, "expression": {"type": "string"}, "count": {"type": "integer", "default": 128}, "limit": {"type": "integer", "default": 10}, "category": {"type": "string"}}}},
    {"name": "wdbl_feature_match_current", "description": "Shortcut for matching current pc output against stored debug feature signatures.", "inputSchema": {"type": "object", "properties": {"count": {"type": "integer", "default": 128}, "limit": {"type": "integer", "default": 10}, "category": {"type": "string"}}}},
    {"name": "wdbl_feature_learn_from_pc", "description": "Capture pc output and save it as a reusable debug feature signature.", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "semantic": {"type": "string"}, "category": {"type": "string", "default": "generic"}, "expression": {"type": "string"}, "count": {"type": "integer", "default": 128}, "keywords": {"type": "array", "items": {"type": "string"}}, "required": {"type": "array", "items": {"type": "string"}}, "mnemonics": {"type": "array", "items": {"type": "string"}}, "compiler": {"type": "string"}, "arch": {"type": "string"}, "confidence": {"type": "number", "default": 0.5}, "notes": {"type": "string"}}, "required": ["name", "semantic"]}},
    {"name": "wdbl_feature_export", "description": "Export only debug feature signatures as a JSON bundle.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "limit": {"type": "integer", "default": 500}, "category": {"type": "string"}}}},
    {"name": "wdbl_feature_reload", "description": "Reload built-in and JSON seed debug feature signatures into SQLite.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wdbl_feature_update", "description": "Update an existing debug feature signature by id or name.", "inputSchema": {"type": "object", "properties": {"id": {"type": "integer"}, "name": {"type": "string"}, "category": {"type": "string"}, "semantic": {"type": "string"}, "pattern": {"type": "object"}, "evidence": {"type": "object"}, "action": {"type": "object"}, "compiler": {"type": "string"}, "arch": {"type": "string"}, "confidence": {"type": "number"}, "notes": {"type": "string"}}}},
    {"name": "wdbl_feature_delete", "description": "Delete a debug feature signature by id or name.", "inputSchema": {"type": "object", "properties": {"id": {"type": "integer"}, "name": {"type": "string"}}}},
    {"name": "wdbl_feature_import", "description": "Import debug feature signatures from a JSON bundle.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "wdbl_auto_triage", "description": "Capture current context, recommend a read-only skill, optionally run it, and optionally ask the local LLM.", "inputSchema": {"type": "object", "properties": {"executeSkill": {"type": "boolean", "default": True}, "useLlm": {"type": "boolean", "default": False}, "store": {"type": "boolean", "default": True}, "threadIndex": {"type": "integer", "default": 0}, "maxFrames": {"type": "integer", "default": 8}, "limit": {"type": "integer", "default": 5}}}},
    {"name": "wdbl_store_export", "description": "Export local cases, skill runs, LLM notes, events, and debug feature signatures as a JSON bundle.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "includeContext": {"type": "boolean", "default": True}, "limit": {"type": "integer", "default": 500}}}},
    {"name": "wdbl_store_import_cases", "description": "Import cases from a JSON bundle produced by wdbl_store_export.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {
        "name": "wdbl_model_context",
        "description": "Build the compact context package used for local LLM analysis without calling the model.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context": {"type": "object"},
                "threadIndex": {"type": "integer", "default": 0},
                "maxFrames": {"type": "integer", "default": 8},
                "limit": {"type": "integer", "default": 5},
                "includeRecent": {"type": "boolean", "default": True},
            },
        },
    },
    {"name": "wdbl_llm_status", "description": "Check local llama.cpp/OpenAI-compatible LLM server status.", "inputSchema": {"type": "object", "properties": {}}},
    {
        "name": "wdbl_llm_summarize_text",
        "description": "Summarize text with the local LLM server.",
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}, "store": {"type": "boolean", "default": False}}, "required": ["text"]},
    },
    {
        "name": "wdbl_llm_analyze_stop",
        "description": "Collect current read-only debug state, match local cases, and ask local LLM for concise analysis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "threadIndex": {"type": "integer", "default": 0},
                "maxFrames": {"type": "integer", "default": 8},
                "store": {"type": "boolean", "default": False},
            },
        },
    },
    {"name": "wdbl_llm_analyze_case", "description": "Analyze a stored case with the local LLM and store the note.", "inputSchema": {"type": "object", "properties": {"caseId": {"type": "integer"}, "store": {"type": "boolean", "default": True}}, "required": ["caseId"]}},
    {"name": "wdbl_llm_notes", "description": "List recent local LLM notes.", "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 20}}}},
    {
        "name": "wdbl_demo_skill",
        "description": "Compatibility wrapper for wdbl_run_skill(skill=demo_stop_triage).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scenario": {"type": "string", "default": "stop_triage"},
                "execute": {"type": "boolean", "default": False},
                "allowStateChange": {"type": "boolean", "default": False},
                "allowDestructive": {"type": "boolean", "default": False},
                "threadIndex": {"type": "integer", "default": 0},
                "maxFrames": {"type": "integer", "default": 8},
            },
        },
    },
])


def text_result(value: Any) -> Dict[str, Any]:
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, ensure_ascii=False, indent=2)
    return {"content": [{"type": "text", "text": text}]}


def resource_text(uri: str, value: Any, mime_type: str = "application/json") -> Dict[str, Any]:
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, ensure_ascii=False, indent=2)
    return {"contents": [{"uri": uri, "mimeType": mime_type, "text": text}]}


def read_resource(uri: str) -> Dict[str, Any]:
    if uri == "z0bdbg://status":
        return resource_text(uri, {"store": store.status(), "session": session_status()})
    if uri == "z0bdbg://automation":
        return resource_text(uri, automation_status())
    if uri == "z0bdbg://sessions/recent":
        return resource_text(uri, {"sessions": store.list_sessions(20)})
    if uri == "z0bdbg://cases/recent":
        return resource_text(uri, {"cases": store.list_cases(20)})
    if uri == "z0bdbg://events/recent":
        return resource_text(uri, {"events": store.list_events(50)})
    if uri == "z0bdbg://features":
        return resource_text(uri, {"features": store.list_debug_features(200)})
    if uri == "z0bdbg://skills":
        skills = []
        for skill in discover_skills():
            skills.append({
                "name": skill.get("name", skill.get("_skillName", "")),
                "description": skill.get("description", ""),
                "risk": skill.get("risk", "unknown"),
                "readOnly": bool(skill.get("readOnly", False)),
                "autoTriggers": skill.get("autoTriggers", []),
                "directory": skill.get("_skillDirectory", ""),
            })
        return resource_text(uri, {"skills": skills})
    if uri == "z0bdbg://context/current":
        try:
            context = capture_debug_context(0, 8)
        except Exception as exc:
            context = {"ok": False, "error": str(exc)}
        return resource_text(uri, context)
    if uri == "z0bdbg://model/context/current":
        try:
            context = normalize_context_for_store(capture_debug_context(0, 8))
            matches = store.match_cases(context, [], 5)
            model_context = make_model_context_package(context, matches, None, True, 5)
        except Exception as exc:
            model_context = {"ok": False, "error": str(exc)}
        return resource_text(uri, model_context)
    if uri == "z0bdbg://readme":
        path = os.path.join(SCRIPT_DIR, "README.md")
        with open(path, "r", encoding="utf-8") as handle:
            return resource_text(uri, handle.read(), "text/markdown")
    raise RuntimeError("unknown resource: %s" % uri)


def get_current_session_id() -> Optional[int]:
    with current_session_lock:
        return current_session_id


def set_current_session(session_id: Optional[int]) -> None:
    global current_session_id
    with current_session_lock:
        current_session_id = session_id


def begin_debug_session(kind: str, target: str, metadata: Optional[Dict[str, Any]] = None) -> int:
    old_session = get_current_session_id()
    if old_session is not None:
        store.end_session(old_session, "superseded")
    session_id = store.start_session(kind, target, metadata or {})
    set_current_session(session_id)
    return session_id


def close_current_session(status: str = "closed") -> bool:
    session_id = get_current_session_id()
    closed = store.end_session(session_id, status)
    if closed:
        set_current_session(None)
    return closed


def session_status() -> Dict[str, Any]:
    session_id = get_current_session_id()
    session = store.get_session(session_id) if session_id is not None else None
    return {"currentSessionId": session_id, "session": session}


def arg_text(value: Any) -> str:
    if isinstance(value, int):
        return "0x%X" % value
    return str(value)


def quote_arg(value: Any) -> str:
    text = arg_text(value)
    if not text:
        return '""'
    if not any(ch.isspace() or ch == '"' for ch in text):
        return text
    if '"' not in text:
        return '"' + text + '"'
    if "'" not in text:
        return "'" + text + "'"
    return '"' + text.replace('"', "") + '"'


def execute_command(command: str) -> Dict[str, Any]:
    try:
        return text_result(bridge.request({"cmd": "execute_capture", "command": command}))
    except Exception:
        return text_result(bridge.request({"cmd": "execute", "command": command}))


def execute_capture_text(command: str) -> str:
    try:
        response = bridge.request({"cmd": "execute_capture", "command": command})
    except Exception:
        response = bridge.request({"cmd": "execute", "command": command})
    if isinstance(response, dict):
        for key in ("output", "value", "text"):
            value = response.get(key)
            if isinstance(value, str) and value:
                return value
        return json.dumps(response, ensure_ascii=False)
    return str(response or "")


def _as_string_list(value: Any) -> Any:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item or "")]
    return []


def feature_terms(feature: Dict[str, Any]) -> Any:
    pattern = feature.get("pattern", {}) if isinstance(feature, dict) else {}
    terms = []
    if isinstance(pattern, dict):
        for key in ("required", "keywords", "mnemonics"):
            terms.extend(_as_string_list(pattern.get(key)))
    semantic = str(feature.get("semantic") or "") if isinstance(feature, dict) else ""
    for token in semantic.replace("::", "_").replace("/", " ").replace("-", " ").replace(",", " ").split():
        if len(token) >= 4:
            terms.append(token)
    seen = set()
    out = []
    for term in terms:
        lowered = str(term or "").lower()
        if lowered and lowered not in seen:
            seen.add(lowered)
            out.append(lowered)
    return out


def find_feature_hit_lines(text: str, terms: Any, max_lines: int = 8) -> Any:
    lines = str(text or "").splitlines()
    hits = []
    for index, line in enumerate(lines):
        lowered = line.lower()
        matched = [term for term in terms if term in lowered]
        if matched:
            hits.append({"line": index + 1, "text": line[:500], "terms": matched[:8]})
            if len(hits) >= max_lines:
                break
    return hits


def feature_analysis(feature: Dict[str, Any]) -> Dict[str, Any]:
    semantic = str(feature.get("semantic") or "").lower()
    category = str(feature.get("category") or "").lower()
    inspect = []
    risk = "heuristic"
    if "vector" in semantic:
        inspect.extend(["Identify begin/end/capacity pointers.", "Check element size from pointer delta.", "Look for slow path allocation and old-buffer release."])
    if "string" in semantic or "basic_string" in semantic:
        inspect.extend(["Check SSO capacity/size fields.", "Decide whether data pointer is inline or heap.", "Confirm source length and copy size."])
    if "shared_ptr" in semantic:
        inspect.extend(["Inspect control block pointer.", "Watch atomic strong/weak reference counters.", "Check release path for final deleter call."])
    if "mutex" in semantic or "lock_guard" in semantic:
        inspect.extend(["Confirm lock object address.", "Pair lock and unlock paths.", "Check error/early-return cleanup."])
    if "rtti" in semantic or "dynamic_cast" in semantic or "type_info" in semantic:
        inspect.extend(["Resolve RTTI type descriptors.", "Inspect vtable and complete object locator.", "Compare expected and actual class names."])
    if "anti-debug" in category or "anti-debug" in semantic:
        inspect.extend(["Check return value branch.", "Patch or force benign return only after confirming side effects.", "Look for repeated checks nearby."])
        risk = "anti-debug"
    if "security cookie" in semantic:
        inspect.extend(["Verify stack frame integrity.", "Check overwritten locals before the cookie failure.", "Walk back to the write that corrupts the frame."])
        risk = "memory-corruption"
    if "exception" in semantic or "unwind" in semantic:
        inspect.extend(["Capture stack and exception record.", "Inspect cleanup funclets.", "Check thrown type or failing validation path."])
    if not inspect:
        inspect.append("Review the hit lines and confirm data-flow manually before naming the construct.")
    deduped = []
    for item in inspect:
        if item not in deduped:
            deduped.append(item)
    return {"summary": feature.get("semantic", ""), "risk": risk, "inspect": deduped[:6]}


def enrich_feature_matches(text: str, matches: Any) -> Any:
    enriched = []
    for item in matches:
        if not isinstance(item, dict):
            continue
        copy = dict(item)
        terms = feature_terms(copy)
        copy["hitLines"] = find_feature_hit_lines(text, terms)
        copy["analysis"] = feature_analysis(copy)
        action = copy.get("action", {})
        if isinstance(action, dict):
            copy["suggestedCommands"] = _as_string_list(action.get("commands"))
            if action.get("skill"):
                copy["suggestedSkill"] = str(action.get("skill"))
        enriched.append(copy)
    return enriched


def derive_feature_keywords(text: str, semantic: str, supplied: Any) -> Any:
    keywords = _as_string_list(supplied)
    lower_text = str(text or "").lower()
    for term in (
        "std::basic_string",
        "std::string",
        "std::vector",
        "std::shared_ptr",
        "std::mutex",
        "operator new",
        "operator delete",
        "memcpy",
        "memmove",
        "strlen",
        "wcslen",
        "interlockedincrement",
        "interlockeddecrement",
        "entercriticalsection",
        "leavecriticalsection",
        "length_error",
        "invalid_parameter",
        "+8",
        "+10h",
        "+18h",
        "0fh",
    ):
        if term in lower_text:
            keywords.append(term)
    for raw in str(semantic or "").replace("::", "_").replace("/", " ").replace("-", " ").replace(",", " ").split():
        token = raw.strip().lower()
        if len(token) >= 4:
            keywords.append(token)
    seen = set()
    out = []
    for keyword in keywords:
        key = str(keyword or "").lower()
        if key and key not in seen:
            seen.add(key)
            out.append(key)
    return out[:24]


def llm_chat_safe(prompt: Any) -> Dict[str, Any]:
    try:
        response = llm.chat(prompt)
        return {"ok": True, "response": response, "error": ""}
    except Exception as exc:
        return {"ok": False, "response": "", "error": str(exc)}


def capture_debug_context(thread_index: int = 0, max_frames: int = 8, client: Optional[BridgeClient] = None) -> Dict[str, Any]:
    context: Dict[str, Any] = {}
    active = client or bridge
    requests = [
        ("stopInfo", {"cmd": "stop_info"}),
        ("threads", {"cmd": "threads"}),
        ("modules", {"cmd": "modules"}),
        ("breakpoints", {"cmd": "breakpoints"}),
        ("registers", {"cmd": "registers", "index": thread_index}),
        ("stack", {"cmd": "stack", "threadIndex": thread_index, "maxFrames": max_frames}),
    ]
    for key, request in requests:
        try:
            context[key] = active.request(request)
        except Exception as exc:
            context[key] = {"ok": False, "error": str(exc)}
    return context


def normalize_context_for_store(context: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(context)
    for key in ("modules", "breakpoints", "stack", "threads"):
        value = out.get(key)
        if isinstance(value, dict):
            if key == "stack":
                out[key] = value.get("frames", [])
            else:
                out[key] = value.get(key, [])
    if isinstance(out.get("stopInfo"), dict):
        out["stopInfo"] = dict(out["stopInfo"])
    return out


def make_model_context_package(
    context: Dict[str, Any],
    matches: Optional[list] = None,
    recommendations: Optional[list] = None,
    include_recent: bool = True,
    limit: int = 5,
) -> Dict[str, Any]:
    recent_events = store.list_events(8) if include_recent else []
    recent_tool_calls = store.list_tool_calls(12) if include_recent else []
    if recommendations is None:
        recommendations = recommend_skills_from_triggers(context, [], limit)
    return build_model_context(
        context,
        matches=matches or [],
        skills=recommendations or [],
        recent_events=recent_events,
        recent_tool_calls=recent_tool_calls,
    )


autocapture_lock = threading.Lock()
autocapture_thread = None
autocapture_stop = threading.Event()
autocapture_stats: Dict[str, Any] = {
    "enabled": AUTOCAPTURE_ENABLED,
    "running": False,
    "captured": 0,
    "autoTriaged": 0,
    "autoLlmNotes": 0,
    "lastError": "",
    "lastEvent": None,
    "lastCaseId": None,
    "lastAutoTriage": None,
    "intervalSeconds": AUTOCAPTURE_INTERVAL,
}


def poll_bridge_events(client: Optional[BridgeClient] = None) -> Dict[str, Any]:
    active = client or bridge
    return active.request({"cmd": "poll_events"})


def stop_fingerprint(event: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> str:
    stop_info: Dict[str, Any] = {}
    if context and isinstance(context.get("stopInfo"), dict):
        stop_info = context.get("stopInfo", {})
    elif isinstance(event.get("stopInfo"), dict):
        stop_info = event.get("stopInfo", {})
    values = [
        str(event.get("typeName", "")),
        str(stop_info.get("processId") or event.get("processId") or ""),
        str(stop_info.get("threadId") or event.get("threadId") or ""),
        str(stop_info.get("exceptionCode") or ""),
        str(stop_info.get("instructionPointer") or event.get("address") or ""),
        str(stop_info.get("reason") or event.get("message") or ""),
    ]
    return "|".join(values)


def should_skip_duplicate_stop(fingerprint: str) -> bool:
    now = time.time()
    expired = [key for key, seen_at in recent_stop_fingerprints.items() if now - seen_at > DEDUP_WINDOW_SECONDS]
    for key in expired:
        recent_stop_fingerprints.pop(key, None)
    seen_at = recent_stop_fingerprints.get(fingerprint)
    if seen_at is not None and now - seen_at <= DEDUP_WINDOW_SECONDS:
        return True
    recent_stop_fingerprints[fingerprint] = now
    return False


def capture_event_case(event: Dict[str, Any], client: BridgeClient) -> Optional[int]:
    type_name = str(event.get("typeName", "unknown"))
    case_id = None
    if type_name != "paused":
        store.add_event(event, None, get_current_session_id())
        return None
    context = capture_debug_context(0, 8, client)
    context["event"] = event
    fingerprint = stop_fingerprint(event, context)
    if should_skip_duplicate_stop(fingerprint):
        event["deduplicated"] = True
        store.add_event(event, None, get_current_session_id())
        return None
    stop_info = context.get("stopInfo", {})
    reason = ""
    if isinstance(stop_info, dict):
        reason = str(stop_info.get("reason", ""))
    title = "auto pause"
    if reason:
        title += ": " + reason[:80]
    tags = ["auto", "event", type_name]
    if isinstance(stop_info, dict) and stop_info.get("exceptionCode") is not None:
        tags.append("ex_%08X" % int(stop_info.get("exceptionCode", 0)))
    case_id = store.add_case(title, normalize_context_for_store(context), "", "", tags, session_id=get_current_session_id())
    store.add_event(event, case_id, get_current_session_id())
    return case_id


def automation_status() -> Dict[str, Any]:
    with autocapture_lock:
        stats = dict(autocapture_stats)
    status = {
        "autocapture": stats,
        "configPath": AUTOMATION_CONFIG_PATH,
        "autoTriageOnEvent": bool_config("autoTriageOnEvent", False),
        "autoLlmOnEvent": bool_config("autoLlmOnEvent", False),
        "auditToolCalls": bool_config("auditToolCalls", True),
    }
    return status


def update_automation_config(args: Dict[str, Any]) -> Dict[str, Any]:
    for key in ("autocaptureEnabled", "autoTriageOnEvent", "autoLlmOnEvent", "auditToolCalls"):
        if key in args:
            automation_config[key] = bool(args.get(key))
    with autocapture_lock:
        autocapture_stats["enabled"] = bool_config("autocaptureEnabled", True)
    if bool(args.get("persist", True)):
        save_json_file(AUTOMATION_CONFIG_PATH, automation_config)
    return automation_status()


def auto_triage_event(event: Dict[str, Any], case_id: Optional[int], client: BridgeClient) -> Dict[str, Any]:
    if str(event.get("typeName", "")) != "paused":
        return {"skipped": "event is not paused"}
    context = capture_debug_context(0, 8, client)
    context["event"] = event
    normalized = normalize_context_for_store(context)
    tags = ["auto_event_triage"]
    matches = store.match_cases(normalized, tags, 5)
    recommendations = recommend_skills_from_triggers(normalized, tags, 5)
    selected = choose_auto_skill(recommendations)
    result: Dict[str, Any] = {
        "caseId": case_id,
        "selectedSkill": selected,
        "recommendations": recommendations,
        "matches": matches,
    }
    result["skillResult"] = run_skill(selected, {
        "execute": True,
        "allowStateChange": False,
        "allowDestructive": False,
        "parameters": {
            "threadIndex": 0,
            "maxFrames": 8,
        },
    })
    if bool_config("autoLlmOnEvent", False):
        model_context = make_model_context_package(normalized, matches, recommendations, True, 5)
        prompt = build_model_prompt(model_context)
        result["modelContext"] = model_context
        llm_result = llm_chat_safe(prompt)
        if llm_result.get("ok"):
            note_id = store.add_llm_note("auto_event_triage", prompt[-1]["content"], str(llm_result.get("response", "")), normalized, get_current_session_id())
            result["llmResponse"] = llm_result.get("response", "")
            result["llmNoteId"] = note_id
        else:
            result["llmError"] = llm_result.get("error", "")
    return result


def autocapture_loop() -> None:
    client = BridgeClient(connect_timeout=0.15)
    with autocapture_lock:
        autocapture_stats["running"] = True
    try:
        while not autocapture_stop.wait(max(0.2, AUTOCAPTURE_INTERVAL)):
            if not bool_config("autocaptureEnabled", True):
                continue
            try:
                response = poll_bridge_events(client)
                events = response.get("events", [])
                if not isinstance(events, list):
                    events = []
                for event in events:
                    if not isinstance(event, dict):
                        continue
                    case_id = capture_event_case(event, client)
                    auto_result = None
                    if case_id is not None and bool_config("autoTriageOnEvent", False):
                        auto_result = auto_triage_event(event, case_id, client)
                    with autocapture_lock:
                        autocapture_stats["lastEvent"] = event
                        autocapture_stats["lastCaseId"] = case_id
                        autocapture_stats["lastError"] = ""
                        if case_id is not None:
                            autocapture_stats["captured"] = int(autocapture_stats.get("captured", 0)) + 1
                        if auto_result is not None:
                            autocapture_stats["lastAutoTriage"] = auto_result
                            autocapture_stats["autoTriaged"] = int(autocapture_stats.get("autoTriaged", 0)) + 1
                            if auto_result.get("llmNoteId") is not None:
                                autocapture_stats["autoLlmNotes"] = int(autocapture_stats.get("autoLlmNotes", 0)) + 1
            except Exception as exc:
                with autocapture_lock:
                    autocapture_stats["lastError"] = str(exc)
                time.sleep(1.0)
    finally:
        client.close()
        with autocapture_lock:
            autocapture_stats["running"] = False


def start_autocapture() -> None:
    global autocapture_thread
    if not AUTOCAPTURE_ENABLED:
        return
    if autocapture_thread is not None:
        return
    autocapture_thread = threading.Thread(target=autocapture_loop)
    autocapture_thread.daemon = True
    autocapture_thread.start()


def stop_autocapture() -> None:
    autocapture_stop.set()
    thread = autocapture_thread
    if thread is not None:
        thread.join(2.0)


def safe_skill_name(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise RuntimeError("missing skill name")
    for ch in text:
        if not (ch.isalnum() or ch in ("_", "-")):
            raise RuntimeError("invalid skill name")
    return text


def load_skill_file(skill_name: str, file_name: str) -> Optional[Any]:
    safe_name = safe_skill_name(skill_name)
    base = os.path.abspath(os.path.join(SKILLS_DIR, safe_name))
    root = os.path.abspath(SKILLS_DIR)
    if not base.startswith(root + os.sep):
        return None
    path = os.path.join(base, file_name)
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    if file_name.endswith(".json"):
        return json.loads(text)
    return text


def load_skill(skill_name: str) -> Dict[str, Any]:
    safe_name = safe_skill_name(skill_name)
    workflow = load_skill_file(safe_name, "workflow.json")
    if not isinstance(workflow, dict):
        raise RuntimeError("skill not found: %s" % safe_name)
    instructions = load_skill_file(safe_name, "SKILL.md") or ""
    workflow["_skillName"] = safe_name
    workflow["_skillDirectory"] = os.path.join(SKILLS_DIR, safe_name)
    workflow["_instructions"] = instructions
    return workflow


def list_skills() -> Dict[str, Any]:
    skills = []
    if os.path.isdir(SKILLS_DIR):
        for name in sorted(os.listdir(SKILLS_DIR)):
            try:
                skill = load_skill(name)
            except Exception:
                continue
            skills.append({
                "name": skill.get("name", name),
                "directory": skill.get("_skillDirectory"),
                "description": skill.get("description", ""),
                "risk": skill.get("risk", "unknown"),
                "readOnly": bool(skill.get("readOnly", False)),
                "autoTriggers": skill.get("autoTriggers", []),
                "parameters": skill.get("parameters", {}),
            })
    return text_result({"skills": skills})


def discover_skills() -> Any:
    skills = []
    if not os.path.isdir(SKILLS_DIR):
        return skills
    for name in sorted(os.listdir(SKILLS_DIR)):
        try:
            skills.append(load_skill(name))
        except Exception:
            continue
    return skills


def context_search_text(context: Dict[str, Any], tags: Any) -> str:
    compact = json.dumps(context, ensure_ascii=False).lower()
    tag_text = " ".join(str(tag).lower() for tag in (tags or []))
    return compact + " " + tag_text


def recommend_skills_from_triggers(context: Dict[str, Any], tags: Any, limit: int) -> Any:
    text = context_search_text(context, tags)
    out = []
    def add_rule(skill_name: str, score: int, reason: str) -> None:
        out.append({
            "skill": skill_name,
            "score": score,
            "reason": reason,
            "matchedTriggers": [],
            "risk": "read-only",
            "readOnly": True,
        })

    stop = context.get("stopInfo", {}) if isinstance(context.get("stopInfo"), dict) else {}
    exception_code = str(stop.get("exceptionCode") or "").lower()
    reason_text = str(stop.get("reason") or "").lower()
    if exception_code in ("3221225477", "0xc0000005", "c0000005") or "access violation" in text:
        add_rule("access_violation_triage", 260, "exceptionCode/access violation rule")
    if "createfilew" in text:
        add_rule("createfilew_args", 240, "CreateFileW rule")
    if "breakpoint" in text or "int 3" in text or exception_code in ("2147483651", "0x80000003", "80000003"):
        add_rule("breakpoint_hit_triage", 220, "breakpoint rule")
    if "veh disconnect" in text or "agent disconnected" in text or "veh_agent_disconnected" in reason_text:
        add_rule("veh_disconnect_triage", 230, "VEH disconnect rule")
    if "exception" in text and not out:
        add_rule("exception_triage", 160, "generic exception rule")

    for skill in discover_skills():
        triggers = skill.get("autoTriggers", [])
        matched = []
        for trigger in triggers:
            needle = str(trigger).lower()
            if needle and needle in text:
                matched.append(str(trigger))
        if matched:
            out.append({
                "skill": skill.get("name", skill.get("_skillName")),
                "score": 100 + len(matched) * 10,
                "reason": "autoTrigger matched",
                "matchedTriggers": matched,
                "risk": skill.get("risk", "unknown"),
                "readOnly": bool(skill.get("readOnly", False)),
            })
    merged = []
    best_by_skill: Dict[str, Dict[str, Any]] = {}
    for item in out:
        skill_name = str(item.get("skill") or "")
        existing = best_by_skill.get(skill_name)
        if existing is None or int(item.get("score", 0)) > int(existing.get("score", 0)):
            best_by_skill[skill_name] = item
    for item in best_by_skill.values():
        merged.append(item)
    merged.sort(key=lambda item: item.get("score", 0), reverse=True)
    return merged[: max(1, min(int(limit), 50))]


def apply_skill_parameters(value: Any, params: Dict[str, Any]) -> Any:
    if isinstance(value, str):
        if value.startswith("$") and value[1:] in params:
            return params.get(value[1:], value)
        text = value
        for key, param_value in params.items():
            text = text.replace("$" + str(key), arg_text(param_value))
        return text
    if isinstance(value, list):
        return [apply_skill_parameters(item, params) for item in value]
    if isinstance(value, dict):
        return {key: apply_skill_parameters(item, params) for key, item in value.items()}
    return value


def bridge_step_request(request: Dict[str, Any]) -> Dict[str, Any]:
    prepared = dict(request or {})
    if prepared.get("cmd") == "execute":
        prepared["cmd"] = "execute_capture"
    return prepared


def structured_step_result(tool: Any, request: Dict[str, Any]) -> Dict[str, Any]:
    prepared = bridge_step_request(request)
    item: Dict[str, Any] = {
        "tool": str(tool or ""),
        "request": prepared,
        "ok": False,
        "data": {},
        "output": "",
        "error": "",
    }
    try:
        response = bridge.request(prepared)
        item["ok"] = True
        item["data"] = response
        if response.get("output") is not None:
            item["output"] = str(response.get("output") or "")
    except Exception as exc:
        item["error"] = str(exc)
    return item


def run_skill(skill_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    skill = load_skill(skill_name)
    parameters = dict(skill.get("parameterDefaults", {}))
    supplied = args.get("parameters", {})
    if isinstance(supplied, dict):
        parameters.update(supplied)
    for key in ("threadIndex", "maxFrames", "scenario"):
        if key in args:
            parameters[key] = args[key]

    execute = bool(args.get("execute", False))
    allow_state_change = bool(args.get("allowStateChange", False))
    allow_destructive = bool(args.get("allowDestructive", False))
    read_only = bool(skill.get("readOnly", False))
    risk = str(skill.get("risk", "unknown"))
    policy = RISK_POLICIES.get(risk, {"requiresStateChange": not read_only, "requiresDestructive": False})
    raw_steps = list(skill.get("steps", []))
    steps = []
    for raw in raw_steps:
        step = dict(raw)
        step["request"] = apply_skill_parameters(step.get("request", {}), parameters)
        steps.append(step)

    result: Dict[str, Any] = {
        "skill": skill.get("name", skill_name),
        "skillDirectory": skill.get("_skillDirectory"),
        "risk": risk,
        "readOnly": read_only,
        "execute": execute,
        "policy": policy,
        "parameters": parameters,
        "description": skill.get("description", ""),
        "instructions": skill.get("_instructions", ""),
        "steps": [{"tool": step.get("tool"), "request": step.get("request")} for step in steps],
    }
    if not execute:
        result["next"] = "Set execute=true to run this skill."
        return text_result(result)
    if policy.get("requiresStateChange") and not allow_state_change:
        result["blocked"] = "Skill risk is %s. Set allowStateChange=true to execute it." % risk
        return text_result(result)
    if policy.get("requiresDestructive") and not allow_destructive:
        result["blocked"] = "Skill risk is destructive. Set allowDestructive=true to execute it."
        return text_result(result)

    outputs = []
    for step in steps:
        item = structured_step_result(step.get("tool"), step.get("request", {}))
        outputs.append(item)
        if not item.get("ok", False) and bool(skill.get("stopOnError", True)):
            break
    result["outputs"] = outputs
    try:
        result["runId"] = store.add_skill_run(str(skill.get("name", skill_name)), execute, parameters, result, get_current_session_id())
    except Exception as exc:
        result["historyError"] = str(exc)
    return text_result(result)


def run_demo_skill(args: Dict[str, Any]) -> Dict[str, Any]:
    run_args = {
        "execute": bool(args.get("execute", False)),
        "allowStateChange": bool(args.get("allowStateChange", False)),
        "allowDestructive": bool(args.get("allowDestructive", False)),
        "parameters": {
            "scenario": str(args.get("scenario", "stop_triage") or "stop_triage"),
            "threadIndex": int(args.get("threadIndex", 0)),
            "maxFrames": int(args.get("maxFrames", 8)),
        },
    }
    return run_skill("demo_stop_triage", run_args)


def choose_auto_skill(recommendations: Any) -> str:
    if isinstance(recommendations, list):
        for item in recommendations:
            if not isinstance(item, dict):
                continue
            skill_name = str(item.get("skill") or "")
            if not skill_name:
                continue
            try:
                skill = load_skill(skill_name)
            except Exception:
                continue
            if bool(skill.get("readOnly", False)):
                return skill_name
    return "demo_stop_triage"


def auto_triage(args: Dict[str, Any]) -> Dict[str, Any]:
    thread_index = int(args.get("threadIndex", 0))
    max_frames = int(args.get("maxFrames", 8))
    limit = int(args.get("limit", 5))
    context = capture_debug_context(thread_index, max_frames)
    normalized = normalize_context_for_store(context)
    tags = ["auto_triage"]
    matches = store.match_cases(normalized, tags, limit)
    recommendations = recommend_skills_from_triggers(normalized, tags, limit)
    seen = set(str(item.get("skill", "")) for item in recommendations if isinstance(item, dict))
    for match in matches:
        skill = str(match.get("skill") or "")
        if skill and skill not in seen:
            seen.add(skill)
            recommendations.append({"skill": skill, "score": match.get("score"), "caseId": match.get("id"), "title": match.get("title")})
    if not recommendations:
        recommendations.append({"skill": "demo_stop_triage", "score": 0, "reason": "default read-only triage"})

    selected = choose_auto_skill(recommendations)
    result: Dict[str, Any] = {
        "context": context,
        "matches": matches,
        "recommendations": recommendations,
        "selectedSkill": selected,
    }

    if bool(args.get("executeSkill", True)):
        skill_result = run_skill(selected, {
            "execute": True,
            "allowStateChange": False,
            "allowDestructive": False,
            "parameters": {
                "threadIndex": thread_index,
                "maxFrames": max_frames,
            },
        })
        result["skillResult"] = skill_result

    if bool(args.get("useLlm", False)):
        model_context = make_model_context_package(normalized, matches, recommendations, True, limit)
        prompt = build_model_prompt(model_context)
        result["modelContext"] = model_context
        llm_result = llm_chat_safe(prompt)
        if llm_result.get("ok"):
            response = str(llm_result.get("response", ""))
            result["llmResponse"] = response
            if bool(args.get("store", True)):
                result["llmNoteId"] = store.add_llm_note("auto_triage", prompt[-1]["content"], response, normalized, get_current_session_id())
        else:
            result["llmError"] = llm_result.get("error", "")

    if bool(args.get("store", True)):
        result["caseId"] = store.add_case(
            "auto triage",
            normalized,
            selected,
            str(result.get("llmResponse", "")),
            tags,
            session_id=get_current_session_id(),
        )
    return text_result(result)


def build_execute_command(name: str, args: Dict[str, Any]) -> Optional[str]:
    simple = {
        "wdbl_veh_off": "veh off",
        "wdbl_veh_detach": "veh detach",
        "wdbl_veh_kill": "veh kill",
        "wdbl_veh_status": "veh status",
        "wdbl_veh_break": "veh break",
        "wdbl_veh_refresh": "veh refresh",
        "wdbl_veh_modules": "veh modules",
        "wdbl_veh_threads": "veh threads",
        "wdbl_driver_off": "drv off",
        "wdbl_driver_status": "drv status",
        "wdbl_process_info": "process",
        "wdbl_processes": "processes",
        "wdbl_current_thread_info": "!thread",
        "wdbl_vm_info": "vm",
        "wdbl_memory_map": "vmmap",
        "wdbl_source_where": "srcwhere",
        "wdbl_script_show": "scriptshow",
        "wdbl_script_run": "scriptrun",
        "wdbl_script_step": "scriptstep",
        "wdbl_script_vars": "scriptvars",
        "wdbl_script_reset": "scriptreset",
        "wdbl_script_clear": "scriptclear",
        "wdbl_peb": "peb",
        "wdbl_teb": "teb",
        "wdbl_seh": "seh",
        "wdbl_go_up": "gu",
        "wdbl_run_to_entry": "runtoentry",
        "wdbl_context_views": "context",
        "wdbl_comment_list": "comment list",
        "wdbl_plugin_list": "plugin list",
        "wdbl_plugin_autoload": "plugin autoload",
        "wdbl_python_help": "py help",
        "wdbl_quit": "quit",
    }
    if name in simple:
        return simple[name]
    if name == "wdbl_veh_launch":
        return "veh launch " + str(args.get("commandLine", ""))
    if name == "wdbl_veh_on":
        parts = ["veh", "on"]
        if args.get("pid") is not None:
            parts.append(str(int(args.get("pid", 0))))
        if args.get("dllPath"):
            parts.append(quote_arg(args.get("dllPath")))
        return " ".join(parts)
    if name == "wdbl_veh_read_memory":
        return "veh read %s %d" % (arg_text(args.get("address")), int(args.get("size", 16)))
    if name == "wdbl_veh_write_memory":
        data = args.get("bytes") or []
        return "veh write %s %s" % (arg_text(args.get("address")), " ".join("0x%02X" % int(b) for b in data))
    if name == "wdbl_veh_context":
        return "veh ctx %d" % int(args.get("threadId", 0))
    if name == "wdbl_veh_set_register":
        return "veh setreg %d %s %s" % (int(args.get("threadId", 0)), quote_arg(args.get("name", "")), arg_text(args.get("value")))
    if name == "wdbl_veh_suspend_thread":
        return "veh suspend %d" % int(args.get("threadId", 0))
    if name == "wdbl_veh_resume_thread":
        return "veh resume %d" % int(args.get("threadId", 0))
    if name == "wdbl_veh_exception_policy":
        command = "veh ex " + quote_arg(args.get("policy", "bp"))
        if args.get("code") is not None:
            command += " " + arg_text(args.get("code"))
        return command
    if name == "wdbl_driver_on":
        return "drv on" + ((" " + quote_arg(args.get("devicePath"))) if args.get("devicePath") else "")
    if name == "wdbl_disasm":
        parts = ["u"]
        if args.get("expression"):
            parts.append(quote_arg(args.get("expression")))
        if args.get("count") is not None:
            parts.append(str(int(args.get("count", 0))))
        return " ".join(parts)
    if name == "wdbl_flow_graph":
        parts = ["flow"]
        if args.get("expression"):
            parts.append(quote_arg(args.get("expression")))
        if args.get("maxBlocks") is not None:
            parts.append(str(int(args.get("maxBlocks", 0))))
        return " ".join(parts)
    if name == "wdbl_pseudo_c":
        parts = ["pc"]
        if args.get("expression"):
            parts.append(quote_arg(args.get("expression")))
        if args.get("count") is not None:
            parts.append(str(int(args.get("count", 0))))
        if bool(args.get("ui", False)):
            parts.append("--ui")
        return " ".join(parts)
    if name == "wdbl_examine_symbols":
        return "x " + quote_arg(args.get("mask", ""))
    if name == "wdbl_source_at":
        return "srcat %s %d" % (arg_text(args.get("address")), int(args.get("contextLines", 2)))
    if name == "wdbl_source_breakpoint":
        return "srcbp %s %d" % (quote_arg(args.get("file", "")), int(args.get("line", 0)))
    if name == "wdbl_source_resolve":
        return "srcresolve %s %d" % (quote_arg(args.get("file", "")), int(args.get("line", 0)))
    if name == "wdbl_script_until":
        return "scriptuntil " + quote_arg(args.get("label", ""))
    if name == "wdbl_script_set_var":
        return "scriptset %s %s" % (quote_arg(args.get("name", "")), quote_arg(args.get("value", "")))
    if name == "wdbl_script_unset_var":
        return "scriptunset " + quote_arg(args.get("name", ""))
    if name == "wdbl_env_save":
        return "envsave" + ((" " + quote_arg(args.get("path"))) if args.get("path") else "")
    if name == "wdbl_env_load":
        return "envload" + ((" " + quote_arg(args.get("path"))) if args.get("path") else "")
    if name == "wdbl_patch_text":
        return "patchstr %s %s %s" % (arg_text(args.get("address")), quote_arg(args.get("encoding", "ascii")), quote_arg(args.get("text", "")))
    if name == "wdbl_patch_file":
        parts = ["patchfile", arg_text(args.get("address")), quote_arg(args.get("path", ""))]
        if args.get("offset") is not None:
            parts.append(str(int(args.get("offset", 0))))
        if args.get("size") is not None:
            parts.append(str(int(args.get("size", 0))))
        return " ".join(parts)
    if name == "wdbl_patch_file_preview":
        parts = ["patchfile", "preview", quote_arg(args.get("path", ""))]
        if args.get("offset") is not None:
            parts.append(str(int(args.get("offset", 0))))
        if args.get("size") is not None:
            parts.append(str(int(args.get("size", 0))))
        return " ".join(parts)
    if name == "wdbl_patch_nop":
        return "nop %s %d" % (arg_text(args.get("address")), int(args.get("count", 0)))
    if name == "wdbl_patch_list":
        return "patch list" + ((" " + str(int(args.get("maxItems", 0)))) if args.get("maxItems") is not None else "")
    if name == "wdbl_stack_contents":
        return "stack" + ((" " + str(int(args.get("maxFrames", 0)))) if args.get("maxFrames") is not None else "")
    if name == "wdbl_handles":
        return "handles" + ((" " + arg_text(args.get("limit"))) if args.get("limit") is not None else "")
    if name == "wdbl_memory_strings":
        parts = ["memstr"]
        if args.get("minLength") is not None:
            parts.append(str(int(args.get("minLength", 0))))
        if args.get("maxItems") is not None:
            parts.append(str(int(args.get("maxItems", 0))))
        return " ".join(parts)
    if name == "wdbl_dump_memory_to_file":
        return ".writemem %s %s L%d" % (quote_arg(args.get("path", "")), arg_text(args.get("address")), int(args.get("size", 0)))
    if name == "wdbl_watch_trace":
        return "wt" + ((" " + str(int(args.get("maxSteps", 0)))) if args.get("maxSteps") is not None else "")
    if name == "wdbl_snapshot_clear":
        return "snapshot clear"
    if name == "wdbl_asm_color":
        return "asm color " + quote_arg(args.get("mode", "status"))
    if name == "wdbl_memory_dump":
        fmt = str(args.get("format", "db")).lower()
        if fmt not in ("db", "dw", "dd", "dq"):
            fmt = "db"
        parts = [fmt, arg_text(args.get("address"))]
        if args.get("bytes") is not None:
            parts.append(str(int(args.get("bytes", 0))))
        if args.get("perLine") is not None:
            parts.append(str(int(args.get("perLine", 0))))
        if bool(args.get("ui", False)):
            parts.append("--ui")
        return " ".join(parts)
    if name == "wdbl_memory_ascii":
        parts = ["da", arg_text(args.get("address"))]
        if args.get("bytes") is not None:
            parts.append(str(int(args.get("bytes", 0))))
        if bool(args.get("ui", False)):
            parts.append("--ui")
        return " ".join(parts)
    if name == "wdbl_memory_binary":
        return "membin %s %d" % (arg_text(args.get("address")), int(args.get("size", 0)))
    if name == "wdbl_memory_search_ascii":
        return "s -a " + quote_arg(args.get("text", ""))
    if name == "wdbl_memory_search_unicode":
        return "s -u " + quote_arg(args.get("text", ""))
    if name == "wdbl_memory_search_bytes":
        data = args.get("bytes") or []
        return "s -b " + " ".join("0x%02X" % int(b) for b in data)
    if name == "wdbl_memory_search_dword":
        return "s -d " + arg_text(args.get("value"))
    if name == "wdbl_memory_search_qword":
        return "s -q " + arg_text(args.get("value"))
    if name == "wdbl_display_type":
        command = "dt %s %s" % (quote_arg(args.get("type", "")), arg_text(args.get("address")))
        if args.get("depth") is not None:
            command += " " + str(int(args.get("depth", 0)))
        return command
    if name == "wdbl_dump_image_or_range":
        command = "dump " + quote_arg(args.get("path", ""))
        if args.get("address") is not None and args.get("size") is not None:
            command += " %s %d" % (arg_text(args.get("address")), int(args.get("size", 0)))
        return command
    if name == "wdbl_virtual_alloc":
        return ".dvalloc %d" % int(args.get("size", 0))
    if name in ("wdbl_comment_add", "wdbl_comment_set"):
        action = "add" if name == "wdbl_comment_add" else "set"
        return "comment %s %s %s" % (action, arg_text(args.get("address")), quote_arg(args.get("text", "")))
    if name == "wdbl_comment_delete":
        return "comment del " + arg_text(args.get("address"))
    if name == "wdbl_comment_show":
        return "comment show " + arg_text(args.get("address"))
    if name == "wdbl_plugin_load":
        return "plugin load " + quote_arg(args.get("path", ""))
    if name == "wdbl_plugin_enable":
        return "plugin enable " + quote_arg(args.get("idOrName"))
    if name == "wdbl_plugin_disable":
        return "plugin disable " + quote_arg(args.get("idOrName"))
    if name == "wdbl_plugin_unload":
        return "plugin unload " + quote_arg(args.get("idOrName"))
    if name == "wdbl_plugin_run":
        command = "plugin run " + quote_arg(args.get("idOrName"))
        if args.get("args"):
            command += " " + str(args.get("args"))
        return command
    if name == "wdbl_thread_command":
        return str(args.get("command", ""))
    if name == "wdbl_python_run":
        return "py run " + quote_arg(args.get("path", ""))
    if name == "wdbl_python_exec":
        return "py exec " + str(args.get("code", ""))
    return None


def call_tool_impl(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    if name == "wdbl_list_skills":
        return list_skills()
    if name == "wdbl_run_skill":
        return run_skill(str(args.get("skill", "")), args)
    if name == "wdbl_store_status":
        return text_result(store.status())
    if name == "wdbl_session_status":
        return text_result(session_status())
    if name == "wdbl_session_list":
        return text_result({"sessions": store.list_sessions(int(args.get("limit", 20)))})
    if name == "wdbl_events_poll":
        return text_result(poll_bridge_events())
    if name == "wdbl_event_history":
        return text_result({"events": store.list_events(int(args.get("limit", 50)))})
    if name == "wdbl_autocapture_status":
        with autocapture_lock:
            return text_result(dict(autocapture_stats))
    if name == "wdbl_automation_status":
        return text_result(automation_status())
    if name == "wdbl_automation_config":
        return text_result(update_automation_config(args))
    if name == "wdbl_execute":
        return execute_command(str(args.get("command", "")))
    if name == "wdbl_case_add":
        context = args.get("context")
        if not isinstance(context, dict):
            context = {}
        case_id = store.add_case(
            str(args.get("title", "debug case")),
            normalize_context_for_store(context),
            str(args.get("skill", "")),
            str(args.get("resolution", "")),
            [str(tag) for tag in (args.get("tags") or [])],
            session_id=get_current_session_id(),
        )
        return text_result({"caseId": case_id})
    if name == "wdbl_case_capture_current":
        context = capture_debug_context(int(args.get("threadIndex", 0)), int(args.get("maxFrames", 8)))
        case_id = store.add_case(
            str(args.get("title", "captured debug case")),
            normalize_context_for_store(context),
            str(args.get("skill", "")),
            str(args.get("resolution", "")),
            [str(tag) for tag in (args.get("tags") or [])],
            session_id=get_current_session_id(),
        )
        return text_result({"caseId": case_id, "context": context})
    if name == "wdbl_case_get":
        case = store.get_case(int(args.get("caseId", 0)), bool(args.get("includeContext", True)))
        if case is None:
            raise RuntimeError("case not found")
        return text_result({"case": case})
    if name == "wdbl_case_search":
        return text_result({"cases": store.search_cases(str(args.get("query", "")), int(args.get("limit", 20)))})
    if name == "wdbl_case_update_resolution":
        ok = store.update_case_resolution(
            int(args.get("caseId", 0)),
            str(args.get("resolution", "")),
            str(args.get("skill", "")),
        )
        return text_result({"updated": ok})
    if name == "wdbl_case_list":
        return text_result({"cases": store.list_cases(int(args.get("limit", 20)))})
    if name == "wdbl_case_match":
        context = args.get("context")
        if not isinstance(context, dict):
            raise RuntimeError("context must be an object")
        matches = store.match_cases(
            normalize_context_for_store(context),
            [str(tag) for tag in (args.get("tags") or [])],
            int(args.get("limit", 5)),
        )
        return text_result({"matches": matches})
    if name == "wdbl_skill_recommend":
        context = args.get("context")
        if not isinstance(context, dict):
            context = capture_debug_context(int(args.get("threadIndex", 0)), int(args.get("maxFrames", 8)))
        tags = [str(tag) for tag in (args.get("tags") or [])]
        matches = store.match_cases(
            normalize_context_for_store(context),
            tags,
            int(args.get("limit", 5)),
        )
        recommended = recommend_skills_from_triggers(normalize_context_for_store(context), tags, int(args.get("limit", 5)))
        seen = set()
        for item in recommended:
            seen.add(str(item.get("skill", "")))
        for match in matches:
            skill = str(match.get("skill") or "")
            if skill and skill not in seen:
                seen.add(skill)
                recommended.append({"skill": skill, "score": match.get("score"), "caseId": match.get("id"), "title": match.get("title")})
        if not recommended:
            recommended.append({"skill": "demo_stop_triage", "score": 0, "reason": "default read-only triage"})
        return text_result({"recommendations": recommended, "matches": matches, "context": context})
    if name == "wdbl_skill_history":
        return text_result({"runs": store.list_skill_runs(int(args.get("limit", 20)))})
    if name == "wdbl_tool_history":
        return text_result({"calls": store.list_tool_calls(int(args.get("limit", 50)))})
    if name == "wdbl_feature_add":
        feature_id = store.add_debug_feature(
            str(args.get("name") or ""),
            str(args.get("category") or "generic"),
            str(args.get("semantic") or ""),
            args.get("pattern") if isinstance(args.get("pattern"), dict) else {},
            args.get("evidence") if isinstance(args.get("evidence"), dict) else {},
            args.get("action") if isinstance(args.get("action"), dict) else {},
            str(args.get("compiler") or ""),
            str(args.get("arch") or ""),
            float(args.get("confidence") or 0.5),
            int(args.get("sourceCaseId")) if args.get("sourceCaseId") is not None else None,
            get_current_session_id(),
            str(args.get("notes") or ""),
        )
        return text_result({"id": feature_id, "feature": store.get_debug_feature(feature_id)})
    if name == "wdbl_feature_list":
        return text_result({"features": store.list_debug_features(int(args.get("limit", 50)), str(args.get("category") or ""))})
    if name == "wdbl_feature_get":
        feature = store.get_debug_feature(int(args.get("id", 0)))
        if feature is None:
            raise RuntimeError("feature not found")
        return text_result({"feature": feature})
    if name == "wdbl_feature_match" or name == "wdbl_feature_match_current":
        text = str(args.get("text") or "")
        command = ""
        if not text:
            parts = ["pc"]
            if name == "wdbl_feature_match" and args.get("expression"):
                parts.append(quote_arg(args.get("expression")))
            if args.get("count") is not None:
                parts.append(str(int(args.get("count", 128))))
            command = " ".join(parts)
            text = execute_capture_text(command)
        matches = store.match_debug_features(text, int(args.get("limit", 10)), str(args.get("category") or ""))
        enriched = enrich_feature_matches(text, matches)
        next_commands = []
        for item in enriched:
            for command_item in item.get("suggestedCommands", []):
                if command_item not in next_commands:
                    next_commands.append(command_item)
        return text_result({"matches": enriched, "command": command, "textSample": text[:2000], "suggestedCommands": next_commands[:12]})
    if name == "wdbl_feature_reload":
        imported = store.reload_debug_feature_seeds()
        return text_result({"imported": imported, "featuresDir": FEATURES_DIR, "debugFeatures": store.status().get("debugFeatures")})
    if name == "wdbl_feature_update":
        current = None
        if args.get("id") is not None:
            current = store.get_debug_feature(int(args.get("id")))
        elif args.get("name"):
            current = store.get_debug_feature_by_name(str(args.get("name") or ""))
        if current is None:
            raise RuntimeError("feature not found")
        update_name = str(current.get("name") or "")
        if args.get("id") is None and args.get("name"):
            update_name = str(args.get("name") or update_name)
        feature_id = store.add_debug_feature(
            update_name,
            str(args.get("category") or current.get("category") or "generic"),
            str(args.get("semantic") or current.get("semantic") or ""),
            args.get("pattern") if isinstance(args.get("pattern"), dict) else current.get("pattern", {}),
            args.get("evidence") if isinstance(args.get("evidence"), dict) else current.get("evidence", {}),
            args.get("action") if isinstance(args.get("action"), dict) else current.get("action", {}),
            str(args.get("compiler") if args.get("compiler") is not None else current.get("compiler", "")),
            str(args.get("arch") if args.get("arch") is not None else current.get("arch", "")),
            float(args.get("confidence") if args.get("confidence") is not None else current.get("confidence", 0.5)),
            current.get("sourceCaseId"),
            get_current_session_id(),
            str(args.get("notes") if args.get("notes") is not None else current.get("notes", "")),
        )
        return text_result({"id": feature_id, "feature": store.get_debug_feature(feature_id)})
    if name == "wdbl_feature_delete":
        deleted = store.delete_debug_feature(
            int(args.get("id")) if args.get("id") is not None else None,
            str(args.get("name") or ""),
        )
        return text_result({"deleted": deleted})
    if name == "wdbl_feature_learn_from_pc":
        feature_name = str(args.get("name") or "")
        semantic = str(args.get("semantic") or "")
        if not feature_name:
            raise RuntimeError("missing feature name")
        if not semantic:
            raise RuntimeError("missing feature semantic")
        parts = ["pc"]
        if args.get("expression"):
            parts.append(quote_arg(args.get("expression")))
        if args.get("count") is not None:
            parts.append(str(int(args.get("count", 128))))
        command = " ".join(parts)
        text = execute_capture_text(command)
        pattern = {
            "keywords": derive_feature_keywords(text, semantic, args.get("keywords")),
            "required": _as_string_list(args.get("required")),
            "mnemonics": _as_string_list(args.get("mnemonics")),
        }
        evidence = {
            "command": command,
            "expression": str(args.get("expression") or ""),
            "count": int(args.get("count", 128)),
            "sample": text[:4000],
        }
        action = {"commands": [command, "u rip 64"], "skill": ""}
        feature_id = store.add_debug_feature(
            feature_name,
            str(args.get("category") or "generic"),
            semantic,
            pattern,
            evidence,
            action,
            str(args.get("compiler") or ""),
            str(args.get("arch") or ""),
            float(args.get("confidence") or 0.5),
            None,
            get_current_session_id(),
            str(args.get("notes") or "learned from pc"),
        )
        feature = store.get_debug_feature(feature_id)
        matches = enrich_feature_matches(text, store.match_debug_features(text, 5, str(args.get("category") or "")))
        return text_result({"id": feature_id, "feature": feature, "command": command, "textSample": text[:2000], "selfMatches": matches})
    if name == "wdbl_feature_export":
        bundle = {
            "version": 1,
            "exportedAt": int(time.time()),
            "debugFeatures": store.list_debug_features(int(args.get("limit", 500)), str(args.get("category") or "")),
        }
        path = str(args.get("path", "") or "")
        if path:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(bundle, handle, ensure_ascii=False, indent=2)
            return text_result({"path": path, "counts": {"debugFeatures": len(bundle.get("debugFeatures", []))}})
        return text_result(bundle)
    if name == "wdbl_feature_import":
        path = str(args.get("path", "") or "")
        if not path:
            raise RuntimeError("missing path")
        with open(path, "r", encoding="utf-8") as handle:
            bundle = json.load(handle)
        return text_result({"imported": store.import_debug_features(bundle)})
    if name == "wdbl_auto_triage":
        return auto_triage(args)
    if name == "wdbl_store_export":
        bundle = store.export_bundle(bool(args.get("includeContext", True)), int(args.get("limit", 500)))
        path = str(args.get("path", "") or "")
        if path:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(bundle, handle, ensure_ascii=False, indent=2)
            return text_result({"path": path, "counts": {key: len(bundle.get(key, [])) for key in ("sessions", "cases", "skillRuns", "llmNotes", "events", "debugFeatures")}})
        return text_result(bundle)
    if name == "wdbl_store_import_cases":
        path = str(args.get("path", "") or "")
        if not path:
            raise RuntimeError("missing path")
        with open(path, "r", encoding="utf-8") as handle:
            bundle = json.load(handle)
        return text_result({"imported": store.import_cases(bundle)})
    if name == "wdbl_model_context":
        if isinstance(args.get("context"), dict):
            context = normalize_context_for_store(args.get("context", {}))
        else:
            context = normalize_context_for_store(capture_debug_context(int(args.get("threadIndex", 0)), int(args.get("maxFrames", 8))))
        limit = int(args.get("limit", 5))
        matches = store.match_cases(context, [], limit)
        recommendations = recommend_skills_from_triggers(context, [], limit)
        model_context = make_model_context_package(context, matches, recommendations, bool(args.get("includeRecent", True)), limit)
        return text_result({"modelContext": model_context, "matches": matches, "recommendations": recommendations})
    if name == "wdbl_llm_status":
        return text_result(llm.status())
    if name == "wdbl_llm_summarize_text":
        prompt = [
            {"role": "system", "content": "You are a concise local assistant for debugger notes."},
            {"role": "user", "content": "Summarize this text and extract actionable debugger next steps:\n\n" + str(args.get("text", ""))},
        ]
        llm_result = llm_chat_safe(prompt)
        note_id = None
        response = str(llm_result.get("response", ""))
        if llm_result.get("ok") and bool(args.get("store", False)):
            note_id = store.add_llm_note("summarize_text", prompt[-1]["content"], response, {"text": args.get("text", "")}, get_current_session_id())
        return text_result({"response": response, "llmError": "" if llm_result.get("ok") else llm_result.get("error", ""), "noteId": note_id})
    if name == "wdbl_llm_analyze_stop":
        context = capture_debug_context(int(args.get("threadIndex", 0)), int(args.get("maxFrames", 8)))
        normalized = normalize_context_for_store(context)
        matches = store.match_cases(normalized, [], 5)
        recommendations = recommend_skills_from_triggers(normalized, [], 5)
        model_context = make_model_context_package(normalized, matches, recommendations, True, 5)
        prompt = build_model_prompt(model_context)
        llm_result = llm_chat_safe(prompt)
        note_id = None
        response = str(llm_result.get("response", ""))
        if llm_result.get("ok") and bool(args.get("store", False)):
            note_id = store.add_llm_note("analyze_stop", prompt[-1]["content"], response, normalized, get_current_session_id())
        return text_result({"response": response, "llmError": "" if llm_result.get("ok") else llm_result.get("error", ""), "matches": matches, "recommendations": recommendations, "modelContext": model_context, "context": context, "noteId": note_id})
    if name == "wdbl_llm_analyze_case":
        case = store.get_case(int(args.get("caseId", 0)), True)
        if case is None:
            raise RuntimeError("case not found")
        context = case.get("context", {})
        if not isinstance(context, dict):
            context = {}
        normalized = normalize_context_for_store(context)
        matches = store.match_cases(normalized, [], 5)
        recommendations = recommend_skills_from_triggers(normalized, [], 5)
        model_context = make_model_context_package(normalized, matches, recommendations, True, 5)
        prompt = build_model_prompt(model_context)
        llm_result = llm_chat_safe(prompt)
        note_id = None
        response = str(llm_result.get("response", ""))
        if llm_result.get("ok") and bool(args.get("store", True)):
            note_id = store.add_llm_note("analyze_case", prompt[-1]["content"], response, {"case": case}, get_current_session_id())
        return text_result({"response": response, "llmError": "" if llm_result.get("ok") else llm_result.get("error", ""), "matches": matches, "recommendations": recommendations, "modelContext": model_context, "case": case, "noteId": note_id})
    if name == "wdbl_llm_notes":
        return text_result({"notes": store.list_llm_notes(int(args.get("limit", 20)))})
    if name == "wdbl_demo_skill":
        return run_demo_skill(args)

    command = build_execute_command(name, args)
    if command is not None:
        if name == "wdbl_quit":
            close_current_session("quit")
        return execute_command(command)

    mapping = {
        "wdbl_ping": {"cmd": "ping"},
        "wdbl_launch": {"cmd": "launch", "commandLine": args.get("commandLine", "")},
        "wdbl_attach": {"cmd": "attach", "pid": int(args.get("pid", 0))},
        "wdbl_detach": {"cmd": "detach"},
        "wdbl_set_breakpoint": {"cmd": "set_breakpoint", "expression": args.get("expression", "")},
        "wdbl_set_hardware_breakpoint": {
            "cmd": "set_hardware_breakpoint",
            "expression": args.get("expression", ""),
            "access": args.get("access", "x"),
            "length": int(args.get("length", 1)),
            "slot": int(args.get("slot", 0)),
            "threadId": int(args.get("threadId", 0)),
        },
        "wdbl_set_memory_breakpoint": {
            "cmd": "set_memory_breakpoint",
            "expression": args.get("expression", ""),
            "size": int(args.get("size", 0)),
            "access": args.get("access", "rw"),
        },
        "wdbl_set_breakpoint_condition": {"cmd": "set_breakpoint_condition", "breakpointId": int(args.get("breakpointId", 0)), "condition": args.get("condition", "")},
        "wdbl_clear_breakpoint_condition": {"cmd": "clear_breakpoint_condition", "breakpointId": int(args.get("breakpointId", 0))},
        "wdbl_enable_breakpoint": {"cmd": "enable_breakpoint", "breakpointId": int(args.get("breakpointId", 0))},
        "wdbl_disable_breakpoint": {"cmd": "disable_breakpoint", "breakpointId": int(args.get("breakpointId", 0))},
        "wdbl_remove_breakpoint": {"cmd": "remove_breakpoint", "breakpointId": int(args.get("breakpointId", 0))},
        "wdbl_resolve": {"cmd": "resolve", "expression": args.get("expression", "")},
        "wdbl_symbol": {"cmd": "symbol", "address": args.get("address")},
        "wdbl_load_symbols": {"cmd": "load_symbols", "target": args.get("target", "*")},
        "wdbl_download_symbols": {"cmd": "download_symbols", "target": args.get("target", "*"), "cacheDir": args.get("cacheDir", ""), "serverUrl": args.get("serverUrl", "")},
        "wdbl_set_symbol_path": {"cmd": "set_symbol_path", "path": args.get("path", "")},
        "wdbl_get_symbol_path": {"cmd": "get_symbol_path"},
        "wdbl_continue": {"cmd": "continue"},
        "wdbl_step": {"cmd": "step"},
        "wdbl_step_over": {"cmd": "step_over"},
        "wdbl_stop_info": {"cmd": "stop_info"},
        "wdbl_threads": {"cmd": "threads"},
        "wdbl_select_thread": {"cmd": "select_thread", "index": int(args.get("index", 0))},
        "wdbl_modules": {"cmd": "modules"},
        "wdbl_breakpoints": {"cmd": "breakpoints"},
        "wdbl_registers": {"cmd": "registers", "index": int(args.get("index", 0))},
        "wdbl_stack": {
            "cmd": "stack",
            "threadIndex": int(args.get("threadIndex", 0)),
            "maxFrames": int(args.get("maxFrames", 16)),
        },
        "wdbl_read_memory": {"cmd": "read_memory", "address": args.get("address"), "size": int(args.get("size", 0))},
        "wdbl_write_memory": {"cmd": "write_memory", "address": args.get("address"), "data": args.get("data", "")},
        "wdbl_set_register": {"cmd": "set_register", "assignment": args.get("assignment", ""), "name": args.get("name", ""), "value": args.get("value", "")},
        "wdbl_write_memory_patch": {"cmd": "write_memory_patch", "address": args.get("address"), "data": args.get("data", "")},
        "wdbl_undo_memory_patch": {"cmd": "undo_memory_patch", "count": int(args.get("count", 1))},
        "wdbl_save_current_snapshot": {"cmd": "save_current_snapshot"},
        "wdbl_save_snapshot": {"cmd": "save_snapshot", "name": args.get("name", "")},
        "wdbl_restore_snapshot": {"cmd": "restore_snapshot", "name": args.get("name", ""), "rerunAfterRestore": bool(args.get("rerunAfterRestore", False))},
        "wdbl_list_snapshots": {"cmd": "list_snapshots"},
        "wdbl_step_back": {"cmd": "step_back"},
        "wdbl_add_source_root": {"cmd": "add_source_root", "path": args.get("path", "")},
        "wdbl_remove_source_root": {"cmd": "remove_source_root", "path": args.get("path", "")},
        "wdbl_clear_source_roots": {"cmd": "clear_source_roots"},
        "wdbl_list_source_roots": {"cmd": "list_source_roots"},
        "wdbl_load_script": {"cmd": "load_script", "path": args.get("path", "")},
        "wdbl_set_script_breakpoint": {"cmd": "set_script_breakpoint", "line": int(args.get("line", 0))},
        "wdbl_remove_script_breakpoint": {"cmd": "remove_script_breakpoint", "line": int(args.get("line", 0))},
        "wdbl_list_script_breakpoints": {"cmd": "list_script_breakpoints"},
        "wdbl_set_exception_ignore_all": {"cmd": "set_exception_ignore_all", "scope": args.get("scope", "debugging"), "enabled": bool(args.get("enabled", False))},
        "wdbl_add_ignored_exception": {"cmd": "add_ignored_exception", "scope": args.get("scope", "debugging"), "code": args.get("code")},
        "wdbl_remove_ignored_exception": {"cmd": "remove_ignored_exception", "scope": args.get("scope", "debugging"), "code": args.get("code")},
        "wdbl_clear_ignored_exceptions": {"cmd": "clear_ignored_exceptions", "scope": args.get("scope", "debugging")},
        "wdbl_list_exception_settings": {"cmd": "list_exception_settings"},
        "wdbl_add_run_stop_expression": {"cmd": "add_run_stop_expression", "expression": args.get("expression", "")},
        "wdbl_remove_run_stop_expression": {"cmd": "remove_run_stop_expression", "index": int(args.get("index", 0))},
        "wdbl_clear_run_stop_expressions": {"cmd": "clear_run_stop_expressions"},
        "wdbl_list_run_stop_expressions": {"cmd": "list_run_stop_expressions"},
        "wdbl_step_until_condition": {"cmd": "step_until_condition", "condition": args.get("condition", ""), "maxSteps": int(args.get("maxSteps", 1))},
        "wdbl_run_until_condition": {"cmd": "run_until_condition", "condition": args.get("condition", ""), "maxPauses": int(args.get("maxPauses", 1))},
        "wdbl_auto_step": {"cmd": "auto_step", "steps": int(args.get("steps", 1)), "delayMs": int(args.get("delayMs", 0))},
        "wdbl_auto_run": {"cmd": "auto_run", "pauses": int(args.get("pauses", 1)), "delayMs": int(args.get("delayMs", 0))},
    }
    if name not in mapping:
        raise RuntimeError("unknown tool: %s" % name)
    response = bridge.request(mapping[name])
    if name == "wdbl_launch":
        response["sessionId"] = begin_debug_session("launch", str(args.get("commandLine", "")), {"tool": name})
    elif name == "wdbl_attach":
        response["sessionId"] = begin_debug_session("attach", str(args.get("pid", "")), {"tool": name})
    elif name == "wdbl_detach":
        response["sessionClosed"] = close_current_session("detached")
    return text_result(response)


def compact_tool_result(result: Dict[str, Any]) -> Any:
    try:
        content = result.get("content", [])
        if isinstance(content, list) and content:
            text = str(content[0].get("text", "")) if isinstance(content[0], dict) else str(content[0])
            return {"text": text[:4000], "truncated": len(text) > 4000}
    except Exception:
        pass
    return result


def call_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    safe_args = args if isinstance(args, dict) else {}
    try:
        result = call_tool_impl(name, safe_args)
        if bool_config("auditToolCalls", True) and name not in ("wdbl_tool_history",):
            try:
                store.add_tool_call(name, safe_args, True, compact_tool_result(result), "", get_current_session_id())
            except Exception:
                pass
        return result
    except Exception as exc:
        if bool_config("auditToolCalls", True):
            try:
                store.add_tool_call(name, safe_args, False, {}, str(exc), get_current_session_id())
            except Exception:
                pass
        raise


def handle(message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    method = message.get("method")
    msg_id = message.get("id")
    if method == "notifications/initialized":
        return None
    try:
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "Z0BDbgMcpServer", "version": "0.1"},
                "capabilities": {"tools": {}, "resources": {}},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = message.get("params") or {}
            result = call_tool(params.get("name", ""), params.get("arguments") or {})
        elif method == "resources/list":
            result = {"resources": RESOURCES}
        elif method == "resources/read":
            params = message.get("params") or {}
            result = read_resource(str(params.get("uri", "")))
        else:
            return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "method not found: %s" % method}}
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}
    except Exception as exc:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32000, "message": str(exc)}}


def main() -> int:
    if os.name != "nt":
        raise SystemExit("Z0BDbg MCP bridge requires Windows named pipes")
    start_autocapture()
    try:
        while True:
            message = read_mcp_message()
            if message is None:
                break
            response = handle(message)
            if response is not None and "id" in message:
                write_mcp_message(response)
    finally:
        stop_autocapture()
        close_current_session("server_exit")
        bridge.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
