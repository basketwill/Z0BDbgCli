from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional


DEFAULT_BUDGET: Dict[str, int] = {
    "maxRegisters": 24,
    "maxStackFrames": 8,
    "maxModules": 24,
    "maxBreakpoints": 32,
    "maxSimilarCases": 5,
    "maxSkills": 12,
    "maxRecentEvents": 8,
    "maxRecentToolCalls": 12,
    "maxFieldChars": 600,
    "maxPromptChars": 12000,
}

SENSITIVE_KEYS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "authorization",
    "cookie",
)


def _budget(overrides: Optional[Dict[str, Any]]) -> Dict[str, int]:
    out = dict(DEFAULT_BUDGET)
    if isinstance(overrides, dict):
        for key, value in overrides.items():
            if key in out:
                try:
                    out[key] = max(1, int(value))
                except Exception:
                    pass
    return out


def _text(value: Any, limit: int = 600) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = _redact_paths(value)
    if len(value) > limit:
        return value[:limit] + "...<truncated>"
    return value


def _redact_paths(value: str) -> str:
    user_profile = os.environ.get("USERPROFILE", "")
    if user_profile:
        value = value.replace(user_profile, "%USERPROFILE%")
    value = re.sub(r"[A-Za-z]:\\Users\\[^\\\s]+", r"%USERPROFILE%", value)
    return value


def _redact_value(key: str, value: Any, limit: int) -> Any:
    lowered = key.lower()
    if any(sensitive in lowered for sensitive in SENSITIVE_KEYS):
        return "<redacted>"
    if isinstance(value, str):
        return _text(value, limit)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _text(value, limit)


def _pick_dict(value: Any, keys: List[str], limit: int) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    out: Dict[str, Any] = {}
    for key in keys:
        if key in value:
            out[key] = _redact_value(key, value.get(key), limit)
    return out


def _as_list(value: Any, nested_key: str = "") -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict) and nested_key and isinstance(value.get(nested_key), list):
        return value.get(nested_key, [])
    return []


def _hex_code(value: Any) -> str:
    if isinstance(value, int):
        return "0x%08X" % value
    text = str(value or "")
    if not text:
        return ""
    try:
        return "0x%08X" % int(text, 0)
    except Exception:
        return text


def classify_scenario(context: Dict[str, Any]) -> str:
    stop = context.get("stopInfo", {})
    event = context.get("event", {})
    if not isinstance(stop, dict):
        stop = {}
    if not isinstance(event, dict):
        event = {}
    blob = json.dumps({"stop": stop, "event": event}, ensure_ascii=False).lower()
    code = _hex_code(stop.get("exceptionCode")).lower()
    reason = str(stop.get("reason", "")).lower()
    symbol = str(stop.get("symbol") or stop.get("function") or stop.get("nearestSymbol") or "").lower()

    if code == "0xc0000005" or "access violation" in blob:
        return "access_violation"
    if "createfilew" in symbol or "createfilew" in blob:
        return "createfilew"
    if code == "0x80000003" or "breakpoint" in reason or "int3" in blob:
        return "breakpoint"
    if "veh" in blob and ("disconnect" in blob or "agent disconnected" in blob):
        return "veh_disconnect"
    if code:
        return "exception"
    return "unknown"


def _summarize_stop(context: Dict[str, Any], limit: int) -> Dict[str, Any]:
    stop = context.get("stopInfo", {})
    if not isinstance(stop, dict):
        return {"raw": _text(stop, limit)}
    keys = [
        "reason",
        "exceptionCode",
        "exceptionAddress",
        "instructionPointer",
        "symbol",
        "function",
        "nearestSymbol",
        "module",
        "processId",
        "threadId",
        "processName",
    ]
    out = _pick_dict(stop, keys, limit)
    if "exceptionCode" in out:
        out["exceptionCode"] = _hex_code(out.get("exceptionCode"))
    return out


def _summarize_registers(context: Dict[str, Any], budget: Dict[str, int]) -> Dict[str, Any]:
    regs = context.get("registers", {})
    if isinstance(regs, dict) and isinstance(regs.get("registers"), dict):
        regs = regs.get("registers", {})
    if not isinstance(regs, dict):
        return {}
    priority = [
        "rip",
        "eip",
        "rsp",
        "esp",
        "rbp",
        "ebp",
        "rax",
        "eax",
        "rcx",
        "ecx",
        "rdx",
        "edx",
        "rbx",
        "ebx",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "eflags",
    ]
    out: Dict[str, Any] = {}
    lowered = {str(k).lower(): k for k in regs.keys()}
    for key in priority:
        if key in lowered and len(out) < budget["maxRegisters"]:
            real_key = lowered[key]
            out[str(real_key)] = _redact_value(str(real_key), regs.get(real_key), budget["maxFieldChars"])
    if len(out) < budget["maxRegisters"]:
        for key in sorted(regs.keys(), key=lambda item: str(item)):
            if str(key) not in out and len(out) < budget["maxRegisters"]:
                out[str(key)] = _redact_value(str(key), regs.get(key), budget["maxFieldChars"])
    return out


def _summarize_stack(context: Dict[str, Any], budget: Dict[str, int]) -> List[Dict[str, Any]]:
    frames = _as_list(context.get("stack"), "frames")
    out: List[Dict[str, Any]] = []
    for frame in frames[: budget["maxStackFrames"]]:
        if isinstance(frame, dict):
            out.append(_pick_dict(frame, ["index", "address", "instructionPointer", "module", "symbol", "function", "source", "line"], budget["maxFieldChars"]))
        else:
            out.append({"text": _text(frame, budget["maxFieldChars"])})
    return out


def _summarize_modules(context: Dict[str, Any], budget: Dict[str, int]) -> List[Dict[str, Any]]:
    modules = _as_list(context.get("modules"), "modules")
    interesting = []
    for module in modules:
        if not isinstance(module, dict):
            continue
        item = _pick_dict(module, ["name", "path", "base", "size", "version", "symbols"], budget["maxFieldChars"])
        name = str(item.get("name", "")).lower()
        if len(interesting) < budget["maxModules"] or any(mark in name for mark in ("kernel", "ntdll", "user32", "dbg", "veh")):
            interesting.append(item)
    return interesting[: budget["maxModules"]]


def _summarize_breakpoints(context: Dict[str, Any], budget: Dict[str, int]) -> List[Dict[str, Any]]:
    breakpoints = _as_list(context.get("breakpoints"), "breakpoints")
    out: List[Dict[str, Any]] = []
    for bp in breakpoints[: budget["maxBreakpoints"]]:
        if isinstance(bp, dict):
            out.append(_pick_dict(bp, ["id", "address", "expression", "symbol", "enabled", "type", "hitCount", "condition"], budget["maxFieldChars"]))
        else:
            out.append({"text": _text(bp, budget["maxFieldChars"])})
    return out


def _summarize_cases(matches: Optional[List[Dict[str, Any]]], budget: Dict[str, int]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in (matches or [])[: budget["maxSimilarCases"]]:
        if not isinstance(item, dict):
            continue
        out.append(_pick_dict(item, ["id", "title", "score", "skill", "resolution", "tags", "createdAt"], budget["maxFieldChars"]))
    return out


def _summarize_skills(skills: Optional[List[Dict[str, Any]]], budget: Dict[str, int]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for skill in (skills or [])[: budget["maxSkills"]]:
        if not isinstance(skill, dict):
            continue
        out.append(_pick_dict(skill, ["name", "skill", "description", "risk", "readOnly", "score", "reason"], budget["maxFieldChars"]))
    return out


def _summarize_recent(items: Optional[List[Dict[str, Any]]], max_items: int, limit: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in (items or [])[:max_items]:
        if isinstance(item, dict):
            compact: Dict[str, Any] = {}
            for key in sorted(item.keys()):
                if key in ("context", "result", "arguments"):
                    continue
                compact[str(key)] = _redact_value(str(key), item.get(key), limit)
            out.append(compact)
        else:
            out.append({"text": _text(item, limit)})
    return out


def build_model_context(
    context: Dict[str, Any],
    matches: Optional[List[Dict[str, Any]]] = None,
    skills: Optional[List[Dict[str, Any]]] = None,
    recent_events: Optional[List[Dict[str, Any]]] = None,
    recent_tool_calls: Optional[List[Dict[str, Any]]] = None,
    budget: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    budget_values = _budget(budget)
    normalized = context if isinstance(context, dict) else {}
    scenario = classify_scenario(normalized)
    references: Dict[str, Any] = {
        "resources": ["z0bdbg://context/current", "z0bdbg://model/context/current"],
        "caseIds": [item.get("id") for item in (matches or []) if isinstance(item, dict) and item.get("id") is not None],
    }
    return {
        "task": "Analyze the debugger stop and recommend concrete next debugger actions.",
        "scenario": scenario,
        "summary": _summarize_stop(normalized, budget_values["maxFieldChars"]),
        "evidence": {
            "registers": _summarize_registers(normalized, budget_values),
            "topStackFrames": _summarize_stack(normalized, budget_values),
            "breakpoints": _summarize_breakpoints(normalized, budget_values),
            "modules": _summarize_modules(normalized, budget_values),
            "event": _pick_dict(normalized.get("event", {}), ["typeName", "processId", "threadId", "address", "message", "timestamp"], budget_values["maxFieldChars"]),
        },
        "similarCases": _summarize_cases(matches, budget_values),
        "availableSkills": _summarize_skills(skills, budget_values),
        "recentEvents": _summarize_recent(recent_events, budget_values["maxRecentEvents"], budget_values["maxFieldChars"]),
        "recentToolCalls": _summarize_recent(recent_tool_calls, budget_values["maxRecentToolCalls"], budget_values["maxFieldChars"]),
        "references": references,
        "constraints": {
            "doNotContinueTarget": True,
            "doNotPatchMemory": True,
            "preferReadOnlyCommands": True,
            "doNotInventMissingFacts": True,
        },
    }


def build_model_prompt(model_context: Dict[str, Any], budget: Optional[Dict[str, Any]] = None) -> List[Dict[str, str]]:
    budget_values = _budget(budget)
    compact = json.dumps(model_context, ensure_ascii=False, indent=2)
    if len(compact) > budget_values["maxPromptChars"]:
        compact = compact[: budget_values["maxPromptChars"]] + "\n...<truncated>"
    return [
        {
            "role": "system",
            "content": (
                "You are a local debugging assistant for Z0BDbg. "
                "Use only the provided model context. Prefer read-only debugger commands. "
                "Return concise structured JSON and do not continue or modify the target."
            ),
        },
        {
            "role": "user",
            "content": (
                "Analyze this compact debugger context. Return JSON with this shape:\n"
                "{\n"
                "  \"diagnosis\": \"\",\n"
                "  \"confidence\": \"low|medium|high\",\n"
                "  \"nextActions\": [\n"
                "    {\"command\": \"\", \"risk\": \"read-only|debugger-state-change|target-state-change|destructive\", \"why\": \"\"}\n"
                "  ],\n"
                "  \"recommendedSkill\": \"\",\n"
                "  \"needsMoreContext\": []\n"
                "}\n\n"
                "Model context:\n%s"
            )
            % compact,
        },
    ]
