#!/usr/bin/env python3
"""Minimal MCP stdio demo server for WinDbgLite McpPlugin testing.

Implements:
- initialize
- tools/list
- tools/call (echo, add)
- prompts/list
- prompts/get
- resources/list
- resources/read
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional


PROTOCOL_VERSION = "2024-11-05"


TOOLS: List[Dict[str, Any]] = [
    {
        "name": "echo",
        "description": "Echo input text.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "add",
        "description": "Add two numbers.",
        "inputSchema": {
            "type": "object",
            "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
            "required": ["a", "b"],
        },
    },
]

PROMPTS: List[Dict[str, Any]] = [
    {
        "name": "greeting",
        "description": "Return a greeting prompt template.",
        "arguments": [{"name": "name", "required": False}],
    }
]

RESOURCES: List[Dict[str, Any]] = [
    {
        "uri": "wdbl://demo/status",
        "name": "Demo Status",
        "description": "Simple server status resource",
        "mimeType": "text/plain",
    }
]


def read_message() -> Optional[Dict[str, Any]]:
    headers: Dict[str, str] = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        if line in (b"\r\n", b"\n"):
            break
        decoded = line.decode("utf-8", errors="replace").strip()
        if ":" in decoded:
            key, value = decoded.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    if "content-length" not in headers:
        return None
    try:
        length = int(headers["content-length"])
    except ValueError:
        return None
    payload = sys.stdin.buffer.read(length)
    if not payload:
        return None
    try:
        return json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError:
        return None


def write_message(msg: Dict[str, Any]) -> None:
    payload = json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    header = f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii")
    sys.stdout.buffer.write(header)
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def make_result(msg_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def make_error(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def handle_initialize(msg_id: Any) -> Dict[str, Any]:
    return make_result(
        msg_id,
        {
            "protocolVersion": PROTOCOL_VERSION,
            "serverInfo": {"name": "WinDbgLiteMcpDemoServer", "version": "1.0"},
            "capabilities": {
                "tools": {},
                "prompts": {},
                "resources": {},
            },
        },
    )


def handle_tools_list(msg_id: Any) -> Dict[str, Any]:
    return make_result(msg_id, {"tools": TOOLS})


def handle_tools_call(msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    name = str(params.get("name", ""))
    arguments = params.get("arguments", {})
    if not isinstance(arguments, dict):
        arguments = {}

    if name == "echo":
        text = str(arguments.get("text", ""))
        return make_result(
            msg_id,
            {"content": [{"type": "text", "text": text}]},
        )
    if name == "add":
        try:
            a = float(arguments.get("a", 0))
            b = float(arguments.get("b", 0))
        except (TypeError, ValueError):
            return make_error(msg_id, -32602, "Invalid numeric arguments for add")
        return make_result(
            msg_id,
            {"content": [{"type": "text", "text": str(a + b)}]},
        )
    return make_error(msg_id, -32601, f"Unknown tool: {name}")


def handle_prompts_list(msg_id: Any) -> Dict[str, Any]:
    return make_result(msg_id, {"prompts": PROMPTS})


def handle_prompts_get(msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    name = str(params.get("name", ""))
    args = params.get("arguments", {})
    if not isinstance(args, dict):
        args = {}
    if name != "greeting":
        return make_error(msg_id, -32601, f"Unknown prompt: {name}")
    who = str(args.get("name", "friend"))
    return make_result(
        msg_id,
        {
            "description": "Greeting prompt",
            "messages": [
                {"role": "user", "content": {"type": "text", "text": f"Hello, {who}!"}}
            ],
        },
    )


def handle_resources_list(msg_id: Any) -> Dict[str, Any]:
    return make_result(msg_id, {"resources": RESOURCES})


def handle_resources_read(msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    uri = str(params.get("uri", ""))
    if uri != "wdbl://demo/status":
        return make_error(msg_id, -32602, f"Unknown resource uri: {uri}")
    return make_result(
        msg_id,
        {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "text/plain",
                    "text": "WinDbgLite MCP demo server is running.",
                }
            ]
        },
    )


def main() -> int:
    while True:
        msg = read_message()
        if msg is None:
            return 0

        method = msg.get("method")
        msg_id = msg.get("id")
        params = msg.get("params", {})
        if not isinstance(params, dict):
            params = {}

        # notifications have no "id"
        if msg_id is None:
            continue

        if method == "initialize":
            write_message(handle_initialize(msg_id))
        elif method == "tools/list":
            write_message(handle_tools_list(msg_id))
        elif method == "tools/call":
            write_message(handle_tools_call(msg_id, params))
        elif method == "prompts/list":
            write_message(handle_prompts_list(msg_id))
        elif method == "prompts/get":
            write_message(handle_prompts_get(msg_id, params))
        elif method == "resources/list":
            write_message(handle_resources_list(msg_id))
        elif method == "resources/read":
            write_message(handle_resources_read(msg_id, params))
        else:
            write_message(make_error(msg_id, -32601, f"Method not found: {method}"))


if __name__ == "__main__":
    raise SystemExit(main())

