from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional


DEFAULT_WEIGHTS = {
    "exceptionCode": 40,
    "reason": 10,
    "module": 20,
    "symbol": 30,
    "breakpoint": 20,
    "stackSymbol": 8,
    "tag": 12,
}


def load_router_config(config_path: str) -> Dict[str, Any]:
    config = {"weights": dict(DEFAULT_WEIGHTS), "maxScanCases": 500}
    if not config_path or not os.path.isfile(config_path):
        return config
    with open(config_path, "r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if isinstance(loaded, dict):
        weights = loaded.get("weights")
        if isinstance(weights, dict):
            merged = dict(DEFAULT_WEIGHTS)
            for key, value in weights.items():
                try:
                    merged[str(key)] = int(value)
                except Exception:
                    pass
            config["weights"] = merged
        if loaded.get("maxScanCases") is not None:
            config["maxScanCases"] = max(1, min(int(loaded.get("maxScanCases")), 5000))
    return config


class LocalStore:
    def __init__(self, db_path: str, router_config_path: str = "", features_dir: str = "") -> None:
        self.db_path = db_path
        self.router_config_path = router_config_path
        self.features_dir = features_dir
        self.router_config = load_router_config(router_config_path)
        self.weights = dict(self.router_config.get("weights", DEFAULT_WEIGHTS))
        self.max_scan_cases = int(self.router_config.get("maxScanCases", 500))
        parent = os.path.dirname(os.path.abspath(db_path))
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    ended_at INTEGER,
                    kind TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    skill TEXT,
                    resolution TEXT,
                    tags_json TEXT NOT NULL,
                    features_json TEXT NOT NULL,
                    context_json TEXT NOT NULL
                )
                """
            )
            self._ensure_column(conn, "cases", "session_id", "INTEGER")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS skill_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    skill TEXT NOT NULL,
                    execute INTEGER NOT NULL,
                    parameters_json TEXT NOT NULL,
                    result_json TEXT NOT NULL
                )
                """
            )
            self._ensure_column(conn, "skill_runs", "session_id", "INTEGER")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS llm_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    prompt TEXT NOT NULL,
                    response TEXT NOT NULL,
                    context_json TEXT NOT NULL
                )
                """
            )
            self._ensure_column(conn, "llm_notes", "session_id", "INTEGER")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS event_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    type_name TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    case_id INTEGER
                )
                """
            )
            self._ensure_column(conn, "event_log", "session_id", "INTEGER")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tool_calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    args_json TEXT NOT NULL,
                    ok INTEGER NOT NULL,
                    result_json TEXT NOT NULL,
                    error TEXT NOT NULL
                )
                """
            )
            self._ensure_column(conn, "tool_calls", "session_id", "INTEGER")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS debug_features (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    name TEXT NOT NULL UNIQUE,
                    category TEXT NOT NULL,
                    compiler TEXT,
                    arch TEXT,
                    semantic TEXT NOT NULL,
                    pattern_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    action_json TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 0,
                    last_hit_at INTEGER,
                    source_case_id INTEGER,
                    source_session_id INTEGER,
                    notes TEXT NOT NULL
                )
                """
            )
            self._seed_builtin_debug_features(conn)

    def _ensure_column(self, conn: sqlite3.Connection, table: str, column: str, declaration: str) -> None:
        rows = conn.execute("PRAGMA table_info(%s)" % table).fetchall()
        for row in rows:
            if str(row["name"]).lower() == column.lower():
                return
        conn.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, column, declaration))

    def status(self) -> Dict[str, Any]:
        with self._connect() as conn:
            sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            cases = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
            runs = conn.execute("SELECT COUNT(*) FROM skill_runs").fetchone()[0]
            notes = conn.execute("SELECT COUNT(*) FROM llm_notes").fetchone()[0]
            events = conn.execute("SELECT COUNT(*) FROM event_log").fetchone()[0]
            calls = conn.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
            features = conn.execute("SELECT COUNT(*) FROM debug_features").fetchone()[0]
        return {
            "dbPath": self.db_path,
            "routerConfigPath": self.router_config_path,
            "featuresDir": self.features_dir,
            "weights": self.weights,
            "maxScanCases": self.max_scan_cases,
            "sessions": sessions,
            "cases": cases,
            "skillRuns": runs,
            "llmNotes": notes,
            "events": events,
            "toolCalls": calls,
            "debugFeatures": features,
        }

    def _builtin_debug_features(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "msvc_std_string_sso_init",
                "category": "cpp_std",
                "compiler": "msvc",
                "arch": "x64",
                "semantic": "MSVC std::basic_string SSO init/default constructor",
                "pattern": {"keywords": ["+10h", "0fh", "+18h"], "mnemonics": ["mov"]},
                "evidence": {"notes": "MSVC string stores SSO capacity/size fields near +10h/+18h in common layouts."},
                "action": {"commands": ["pc rip 128", "u rip 32"], "skill": ""},
                "confidence": 0.62,
                "notes": "builtin",
            },
            {
                "name": "msvc_std_string_sso_heap_branch",
                "category": "cpp_std",
                "compiler": "msvc",
                "arch": "x64",
                "semantic": "MSVC std::basic_string short-string versus heap-buffer branch",
                "pattern": {"keywords": ["+10h", "+18h", "0fh"], "mnemonics": ["cmp", "jbe", "ja"]},
                "evidence": {"notes": "MSVC string paths commonly compare capacity against the inline SSO limit 0Fh."},
                "action": {"commands": ["pc rip 160", "u rip 64"], "skill": ""},
                "confidence": 0.6,
                "notes": "builtin",
            },
            {
                "name": "msvc_std_string_assign_cstr",
                "category": "cpp_std",
                "compiler": "msvc",
                "arch": "any",
                "semantic": "std::basic_string assign/construct from C string",
                "pattern": {"keywords": ["strlen", "wcslen", "memcpy", "+10h", "+18h"]},
                "evidence": {"notes": "C-string assignment usually measures source length then copies into SSO or heap storage."},
                "action": {"commands": ["pc rip 160", "u rip 64"], "skill": ""},
                "confidence": 0.64,
                "notes": "builtin",
            },
            {
                "name": "msvc_vector_push_fast_path",
                "category": "cpp_std",
                "compiler": "msvc",
                "arch": "x64",
                "semantic": "MSVC std::vector push_back/emplace_back fast path or capacity check",
                "pattern": {"keywords": ["+8", "+10h"], "mnemonics": ["mov", "cmp", "jz"]},
                "evidence": {"notes": "MSVC vector commonly stores begin/end/capacity as three pointers."},
                "action": {"commands": ["pc rip 128", "u rip 48"], "skill": ""},
                "confidence": 0.58,
                "notes": "builtin",
            },
            {
                "name": "msvc_vector_reallocate_reserve",
                "category": "cpp_std",
                "compiler": "msvc",
                "arch": "x64",
                "semantic": "MSVC std::vector reserve/reallocate slow path",
                "pattern": {"keywords": ["+8", "+10h", "operator new", "memmove", "operator delete"], "mnemonics": ["sub", "call"]},
                "evidence": {"notes": "Vector growth allocates a new buffer, moves/copies elements, then releases the old buffer."},
                "action": {"commands": ["pc rip 192", "u rip 96"], "skill": ""},
                "confidence": 0.66,
                "notes": "builtin",
            },
            {
                "name": "msvc_vector_size_capacity_calc",
                "category": "cpp_std",
                "compiler": "msvc",
                "arch": "x64",
                "semantic": "MSVC std::vector size/capacity pointer arithmetic",
                "pattern": {"keywords": ["+8", "+10h"], "mnemonics": ["sub", "sar", "shr"]},
                "evidence": {"notes": "Vector size and capacity are commonly computed from end-begin and cap-begin pointer differences."},
                "action": {"commands": ["pc rip 128", "u rip 64"], "skill": ""},
                "confidence": 0.55,
                "notes": "builtin",
            },
            {
                "name": "msvc_shared_ptr_refcount",
                "category": "cpp_std",
                "compiler": "msvc",
                "arch": "x64",
                "semantic": "std::shared_ptr/control block atomic addref/release",
                "pattern": {"keywords": ["interlockedincrement", "interlockeddecrement", "lock inc", "lock xadd", "_mt_incref", "_mt_decref"]},
                "evidence": {"notes": "shared_ptr control blocks use atomic reference count operations."},
                "action": {"commands": ["pc rip 128", "u rip 48"], "skill": ""},
                "confidence": 0.72,
                "notes": "builtin",
            },
            {
                "name": "msvc_mutex_lock_guard",
                "category": "cpp_std",
                "compiler": "msvc",
                "arch": "x64",
                "semantic": "std::mutex/std::lock_guard lock or unlock",
                "pattern": {"keywords": ["entercriticalsection", "leavecriticalsection", "mtx_lock", "mtx_unlock"]},
                "evidence": {"notes": "MSVC mutex wrappers often call CRT lock helpers or Win32 critical section APIs."},
                "action": {"commands": ["pc rip 96", "u rip 32"], "skill": ""},
                "confidence": 0.7,
                "notes": "builtin",
            },
            {
                "name": "msvc_cpp_exception_unwind",
                "category": "cpp_runtime",
                "compiler": "msvc",
                "arch": "any",
                "semantic": "MSVC C++ exception/unwind region",
                "pattern": {"keywords": ["__cxxframehandler3", "__cxxframehandler4", "funclet", "unwind"]},
                "evidence": {"notes": "MSVC C++ EH metadata and funclets mark cleanup/unwind paths."},
                "action": {"commands": ["k 16", "seh", "pc rip 128"], "skill": "exception_triage"},
                "confidence": 0.75,
                "notes": "builtin",
            },
            {
                "name": "msvc_stl_validation_failure",
                "category": "cpp_runtime",
                "compiler": "msvc",
                "arch": "any",
                "semantic": "MSVC STL invalid parameter/range/length failure path",
                "pattern": {"keywords": ["invalid_parameter", "length_error", "out_of_range", "_xlength", "_xran"]},
                "evidence": {"notes": "MSVC STL helper names and CRT invalid-parameter paths often identify failed range or size checks."},
                "action": {"commands": ["k 16", "pc rip 128"], "skill": "exception_triage"},
                "confidence": 0.72,
                "notes": "builtin",
            },
        ]

    def _seed_builtin_debug_features(self, conn: sqlite3.Connection) -> None:
        now = int(time.time())
        for item in self._builtin_debug_features():
            self._seed_debug_feature_item(conn, item, now)
        for item in self._load_feature_seed_files():
            self._seed_debug_feature_item(conn, item, now)

    def reload_debug_feature_seeds(self) -> int:
        imported = 0
        for item in self._builtin_debug_features() + self._load_feature_seed_files():
            if not isinstance(item, dict) or not item.get("name"):
                continue
            self.add_debug_feature(
                str(item.get("name") or ""),
                str(item.get("category") or "generic"),
                str(item.get("semantic") or ""),
                item.get("pattern") if isinstance(item.get("pattern"), dict) else {},
                item.get("evidence") if isinstance(item.get("evidence"), dict) else {},
                item.get("action") if isinstance(item.get("action"), dict) else {},
                str(item.get("compiler") or ""),
                str(item.get("arch") or ""),
                float(item.get("confidence", 0.5)),
                item.get("sourceCaseId"),
                item.get("sourceSessionId"),
                str(item.get("notes") or "seed json"),
            )
            imported += 1
        return imported

    def _seed_debug_feature_item(self, conn: sqlite3.Connection, item: Dict[str, Any], now: int) -> None:
        if not isinstance(item, dict) or not item.get("name"):
            return
        conn.execute(
            """
            INSERT OR IGNORE INTO debug_features(
                created_at, updated_at, name, category, compiler, arch, semantic,
                pattern_json, evidence_json, action_json, confidence, notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                now,
                str(item.get("name") or ""),
                str(item.get("category") or "generic"),
                str(item.get("compiler") or ""),
                str(item.get("arch") or ""),
                str(item.get("semantic") or ""),
                json.dumps(item.get("pattern", {}), ensure_ascii=False),
                json.dumps(item.get("evidence", {}), ensure_ascii=False),
                json.dumps(item.get("action", {}), ensure_ascii=False),
                float(item.get("confidence", 0.5)),
                str(item.get("notes") or "builtin"),
            ),
        )

    def _load_feature_seed_files(self) -> List[Dict[str, Any]]:
        out = []
        if not self.features_dir or not os.path.isdir(self.features_dir):
            return out
        for name in sorted(os.listdir(self.features_dir)):
            if not name.lower().endswith(".json"):
                continue
            path = os.path.join(self.features_dir, name)
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    loaded = json.load(handle)
            except Exception:
                continue
            if isinstance(loaded, dict):
                features = loaded.get("debugFeatures") or loaded.get("features")
            else:
                features = loaded
            if not isinstance(features, list):
                continue
            for item in features:
                if isinstance(item, dict):
                    out.append(item)
        return out

    def add_case(
        self,
        title: str,
        context: Dict[str, Any],
        skill: str = "",
        resolution: str = "",
        tags: Optional[List[str]] = None,
        features: Optional[Dict[str, Any]] = None,
        session_id: Optional[int] = None,
    ) -> int:
        tags = tags or []
        features = features or extract_features(context, tags)
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO cases(created_at, title, skill, resolution, tags_json, features_json, context_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(time.time()),
                    title or "debug case",
                    skill,
                    resolution,
                    json.dumps(tags, ensure_ascii=False),
                    json.dumps(features, ensure_ascii=False),
                    json.dumps(context, ensure_ascii=False),
                ),
            )
            if session_id is not None:
                conn.execute("UPDATE cases SET session_id = ? WHERE id = ?", (int(session_id), int(cur.lastrowid)))
            return int(cur.lastrowid)

    def start_session(self, kind: str, target: str = "", metadata: Optional[Dict[str, Any]] = None) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO sessions(created_at, ended_at, kind, target, status, metadata_json)
                VALUES (?, NULL, ?, ?, ?, ?)
                """,
                (
                    int(time.time()),
                    str(kind or "debug"),
                    str(target or ""),
                    "active",
                    json.dumps(metadata or {}, ensure_ascii=False),
                ),
            )
            return int(cur.lastrowid)

    def end_session(self, session_id: Optional[int], status: str = "closed") -> bool:
        if session_id is None:
            return False
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE sessions SET ended_at = ?, status = ? WHERE id = ? AND ended_at IS NULL",
                (int(time.time()), str(status or "closed"), int(session_id)),
            )
            return cur.rowcount > 0

    def list_sessions(self, limit: int = 20) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 200))
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM sessions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [self._row_to_session(row) for row in rows]

    def get_session(self, session_id: int) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE id = ?", (int(session_id),)).fetchone()
        if row is None:
            return None
        return self._row_to_session(row)

    def list_cases(self, limit: int = 20) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 200))
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, created_at, title, skill, resolution, tags_json, features_json, session_id FROM cases ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_case(row, include_context=False) for row in rows]

    def get_case(self, case_id: int, include_context: bool = True) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM cases WHERE id = ?", (int(case_id),)).fetchone()
        if row is None:
            return None
        return self._row_to_case(row, include_context=include_context)

    def search_cases(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        text = "%%%s%%" % str(query or "")
        limit = max(1, min(int(limit), 200))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, title, skill, resolution, tags_json, features_json, session_id
                FROM cases
                WHERE title LIKE ? OR skill LIKE ? OR resolution LIKE ? OR tags_json LIKE ? OR features_json LIKE ?
                ORDER BY id DESC LIMIT ?
                """,
                (text, text, text, text, text, limit),
            ).fetchall()
        return [self._row_to_case(row, include_context=False) for row in rows]

    def update_case_resolution(self, case_id: int, resolution: str, skill: str = "") -> bool:
        with self._connect() as conn:
            if skill:
                cur = conn.execute(
                    "UPDATE cases SET resolution = ?, skill = ? WHERE id = ?",
                    (resolution, skill, int(case_id)),
                )
            else:
                cur = conn.execute(
                    "UPDATE cases SET resolution = ? WHERE id = ?",
                    (resolution, int(case_id)),
                )
            return cur.rowcount > 0

    def match_cases(self, context: Dict[str, Any], tags: Optional[List[str]] = None, limit: int = 5) -> List[Dict[str, Any]]:
        query_features = extract_features(context, tags or [])
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM cases ORDER BY id DESC LIMIT ?", (self.max_scan_cases,)).fetchall()
        matches = []
        for row in rows:
            item = self._row_to_case(row, include_context=False)
            score, reasons = score_features(query_features, item.get("features", {}), self.weights)
            if score > 0:
                item["score"] = score
                item["matchReasons"] = reasons
                matches.append(item)
        matches.sort(key=lambda item: item.get("score", 0), reverse=True)
        return matches[: max(1, min(int(limit), 50))]

    def add_skill_run(self, skill: str, execute: bool, parameters: Dict[str, Any], result: Dict[str, Any], session_id: Optional[int] = None) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO skill_runs(created_at, skill, execute, parameters_json, result_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    int(time.time()),
                    skill,
                    1 if execute else 0,
                    json.dumps(parameters, ensure_ascii=False),
                    json.dumps(result, ensure_ascii=False),
                ),
            )
            if session_id is not None:
                conn.execute("UPDATE skill_runs SET session_id = ? WHERE id = ?", (int(session_id), int(cur.lastrowid)))
            return int(cur.lastrowid)

    def list_skill_runs(self, limit: int = 20) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 200))
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM skill_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [
            {
                "id": int(row["id"]),
                "createdAt": int(row["created_at"]),
                "sessionId": row["session_id"],
                "skill": row["skill"],
                "execute": bool(row["execute"]),
                "parameters": json.loads(row["parameters_json"] or "{}"),
                "result": json.loads(row["result_json"] or "{}"),
            }
            for row in rows
        ]

    def add_llm_note(self, kind: str, prompt: str, response: str, context: Dict[str, Any], session_id: Optional[int] = None) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO llm_notes(created_at, kind, prompt, response, context_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (int(time.time()), kind, prompt, response, json.dumps(context, ensure_ascii=False)),
            )
            if session_id is not None:
                conn.execute("UPDATE llm_notes SET session_id = ? WHERE id = ?", (int(session_id), int(cur.lastrowid)))
            return int(cur.lastrowid)

    def list_llm_notes(self, limit: int = 20) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 200))
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM llm_notes ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [
            {
                "id": int(row["id"]),
                "createdAt": int(row["created_at"]),
                "sessionId": row["session_id"],
                "kind": row["kind"],
                "prompt": row["prompt"],
                "response": row["response"],
                "context": json.loads(row["context_json"] or "{}"),
            }
            for row in rows
        ]

    def add_event(self, event: Dict[str, Any], case_id: Optional[int] = None, session_id: Optional[int] = None) -> int:
        type_name = str(event.get("typeName") or event.get("type") or "unknown")
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO event_log(created_at, type_name, event_json, case_id) VALUES (?, ?, ?, ?)",
                (int(time.time()), type_name, json.dumps(event, ensure_ascii=False), case_id),
            )
            if session_id is not None:
                conn.execute("UPDATE event_log SET session_id = ? WHERE id = ?", (int(session_id), int(cur.lastrowid)))
            return int(cur.lastrowid)

    def list_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM event_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [
            {
                "id": int(row["id"]),
                "createdAt": int(row["created_at"]),
                "sessionId": row["session_id"],
                "typeName": row["type_name"],
                "caseId": row["case_id"],
                "event": json.loads(row["event_json"] or "{}"),
            }
            for row in rows
        ]

    def add_tool_call(self, name: str, args: Dict[str, Any], ok: bool, result: Any = None, error: str = "", session_id: Optional[int] = None) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO tool_calls(created_at, name, args_json, ok, result_json, error)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    int(time.time()),
                    str(name or ""),
                    json.dumps(args or {}, ensure_ascii=False),
                    1 if ok else 0,
                    json.dumps(result if result is not None else {}, ensure_ascii=False),
                    str(error or ""),
                ),
            )
            if session_id is not None:
                conn.execute("UPDATE tool_calls SET session_id = ? WHERE id = ?", (int(session_id), int(cur.lastrowid)))
            return int(cur.lastrowid)

    def list_tool_calls(self, limit: int = 50) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM tool_calls ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [
            {
                "id": int(row["id"]),
                "createdAt": int(row["created_at"]),
                "sessionId": row["session_id"],
                "name": row["name"],
                "args": json.loads(row["args_json"] or "{}"),
                "ok": bool(row["ok"]),
                "result": json.loads(row["result_json"] or "{}"),
                "error": row["error"],
            }
            for row in rows
        ]

    def add_debug_feature(
        self,
        name: str,
        category: str,
        semantic: str,
        pattern: Dict[str, Any],
        evidence: Optional[Dict[str, Any]] = None,
        action: Optional[Dict[str, Any]] = None,
        compiler: str = "",
        arch: str = "",
        confidence: float = 0.5,
        source_case_id: Optional[int] = None,
        source_session_id: Optional[int] = None,
        notes: str = "",
    ) -> int:
        now = int(time.time())
        with self._connect() as conn:
            feature_name = str(name or "debug_feature")
            existing = conn.execute("SELECT id FROM debug_features WHERE name = ?", (feature_name,)).fetchone()
            values = (
                now,
                str(category or "generic"),
                str(compiler or ""),
                str(arch or ""),
                str(semantic or ""),
                json.dumps(pattern or {}, ensure_ascii=False),
                json.dumps(evidence or {}, ensure_ascii=False),
                json.dumps(action or {}, ensure_ascii=False),
                float(confidence),
                source_case_id,
                source_session_id,
                str(notes or ""),
            )
            if existing is not None:
                conn.execute(
                    """
                    UPDATE debug_features
                    SET updated_at = ?, category = ?, compiler = ?, arch = ?, semantic = ?,
                        pattern_json = ?, evidence_json = ?, action_json = ?, confidence = ?,
                        source_case_id = ?, source_session_id = ?, notes = ?
                    WHERE id = ?
                    """,
                    values + (int(existing["id"]),),
                )
                return int(existing["id"])
            cur = conn.execute(
                """
                INSERT INTO debug_features(
                    created_at, updated_at, name, category, compiler, arch, semantic,
                    pattern_json, evidence_json, action_json, confidence,
                    source_case_id, source_session_id, notes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (now, values[0], feature_name) + values[1:],
            )
            return int(cur.lastrowid)

    def get_debug_feature(self, feature_id: int) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM debug_features WHERE id = ?", (int(feature_id),)).fetchone()
        return self._row_to_debug_feature(row) if row is not None else None

    def get_debug_feature_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM debug_features WHERE name = ?", (str(name or ""),)).fetchone()
        return self._row_to_debug_feature(row) if row is not None else None

    def delete_debug_feature(self, feature_id: Optional[int] = None, name: str = "") -> int:
        with self._connect() as conn:
            if feature_id is not None:
                cur = conn.execute("DELETE FROM debug_features WHERE id = ?", (int(feature_id),))
            elif name:
                cur = conn.execute("DELETE FROM debug_features WHERE name = ?", (str(name),))
            else:
                return 0
            return int(cur.rowcount)

    def list_debug_features(self, limit: int = 50, category: str = "") -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._connect() as conn:
            if category:
                rows = conn.execute(
                    "SELECT * FROM debug_features WHERE category = ? ORDER BY updated_at DESC, id DESC LIMIT ?",
                    (str(category), limit),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM debug_features ORDER BY updated_at DESC, id DESC LIMIT ?", (limit,)).fetchall()
        return [self._row_to_debug_feature(row) for row in rows]

    def match_debug_features(self, text: str, limit: int = 10, category: str = "") -> List[Dict[str, Any]]:
        text_lower = str(text or "").lower()
        if not text_lower:
            return []
        candidates = self.list_debug_features(500, category)
        matches = []
        for item in candidates:
            pattern = item.get("pattern", {})
            score, reasons = score_debug_feature_text(text_lower, pattern)
            if score > 0:
                confidence = float(item.get("confidence", 0.5))
                final_score = score * (0.5 + max(0.0, min(confidence, 1.0)))
                item["score"] = final_score
                item["rawScore"] = score
                item["scoreDetails"] = {
                    "rawScore": score,
                    "confidence": confidence,
                    "confidenceMultiplier": 0.5 + max(0.0, min(confidence, 1.0)),
                    "finalScore": final_score,
                }
                item["matchReasons"] = reasons
                matches.append(item)
        matches.sort(key=lambda item: item.get("score", 0), reverse=True)
        matches = matches[: max(1, min(int(limit), 50))]
        if matches:
            now = int(time.time())
            with self._connect() as conn:
                for item in matches:
                    conn.execute(
                        "UPDATE debug_features SET hit_count = hit_count + 1, last_hit_at = ? WHERE id = ?",
                        (now, int(item["id"])),
                    )
        return matches

    def export_bundle(self, include_context: bool = True, limit: int = 500) -> Dict[str, Any]:
        limit = max(1, min(int(limit), 5000))
        with self._connect() as conn:
            sessions = conn.execute("SELECT * FROM sessions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            cases = conn.execute("SELECT * FROM cases ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            runs = conn.execute("SELECT * FROM skill_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            notes = conn.execute("SELECT * FROM llm_notes ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            events = conn.execute("SELECT * FROM event_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            features = conn.execute("SELECT * FROM debug_features ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return {
            "version": 1,
            "exportedAt": int(time.time()),
            "sessions": [self._row_to_session(row) for row in sessions],
            "cases": [self._row_to_case(row, include_context=include_context) for row in cases],
            "skillRuns": [
                {
                    "id": int(row["id"]),
                    "createdAt": int(row["created_at"]),
                    "sessionId": row["session_id"],
                    "skill": row["skill"],
                    "execute": bool(row["execute"]),
                    "parameters": json.loads(row["parameters_json"] or "{}"),
                    "result": json.loads(row["result_json"] or "{}"),
                }
                for row in runs
            ],
            "llmNotes": [
                {
                    "id": int(row["id"]),
                    "createdAt": int(row["created_at"]),
                    "sessionId": row["session_id"],
                    "kind": row["kind"],
                    "prompt": row["prompt"],
                    "response": row["response"],
                    "context": json.loads(row["context_json"] or "{}"),
                }
                for row in notes
            ],
            "events": [
                {
                    "id": int(row["id"]),
                    "createdAt": int(row["created_at"]),
                    "sessionId": row["session_id"],
                    "typeName": row["type_name"],
                    "caseId": row["case_id"],
                    "event": json.loads(row["event_json"] or "{}"),
                }
                for row in events
            ],
            "debugFeatures": [self._row_to_debug_feature(row) for row in features],
        }

    def import_cases(self, bundle: Dict[str, Any]) -> int:
        cases = bundle.get("cases", []) if isinstance(bundle, dict) else []
        imported = 0
        if not isinstance(cases, list):
            return 0
        for item in cases:
            if not isinstance(item, dict):
                continue
            context = item.get("context", {})
            if not isinstance(context, dict):
                context = {}
            self.add_case(
                str(item.get("title") or "imported debug case"),
                context,
                str(item.get("skill") or ""),
                str(item.get("resolution") or ""),
                [str(tag) for tag in (item.get("tags") or [])],
                item.get("features") if isinstance(item.get("features"), dict) else None,
            )
            imported += 1
        return imported

    def import_debug_features(self, bundle: Dict[str, Any]) -> int:
        features = bundle.get("debugFeatures", []) if isinstance(bundle, dict) else []
        imported = 0
        if not isinstance(features, list):
            return 0
        for item in features:
            if not isinstance(item, dict):
                continue
            self.add_debug_feature(
                str(item.get("name") or "imported_feature"),
                str(item.get("category") or "generic"),
                str(item.get("semantic") or ""),
                item.get("pattern") if isinstance(item.get("pattern"), dict) else {},
                item.get("evidence") if isinstance(item.get("evidence"), dict) else {},
                item.get("action") if isinstance(item.get("action"), dict) else {},
                str(item.get("compiler") or ""),
                str(item.get("arch") or ""),
                float(item.get("confidence") or 0.5),
                item.get("sourceCaseId"),
                item.get("sourceSessionId"),
                str(item.get("notes") or ""),
            )
            imported += 1
        return imported

    def _row_to_session(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": int(row["id"]),
            "createdAt": int(row["created_at"]),
            "endedAt": row["ended_at"],
            "kind": row["kind"],
            "target": row["target"],
            "status": row["status"],
            "metadata": json.loads(row["metadata_json"] or "{}"),
        }

    def _row_to_case(self, row: sqlite3.Row, include_context: bool) -> Dict[str, Any]:
        item = {
            "id": int(row["id"]),
            "createdAt": int(row["created_at"]),
            "sessionId": row["session_id"] if "session_id" in row.keys() else None,
            "title": row["title"],
            "skill": row["skill"] or "",
            "resolution": row["resolution"] or "",
            "tags": json.loads(row["tags_json"] or "[]"),
            "features": json.loads(row["features_json"] or "{}"),
        }
        if include_context:
            item["context"] = json.loads(row["context_json"] or "{}")
        return item

    def _row_to_debug_feature(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": int(row["id"]),
            "createdAt": int(row["created_at"]),
            "updatedAt": int(row["updated_at"]),
            "name": row["name"],
            "category": row["category"],
            "compiler": row["compiler"] or "",
            "arch": row["arch"] or "",
            "semantic": row["semantic"] or "",
            "pattern": json.loads(row["pattern_json"] or "{}"),
            "evidence": json.loads(row["evidence_json"] or "{}"),
            "action": json.loads(row["action_json"] or "{}"),
            "confidence": float(row["confidence"]),
            "hitCount": int(row["hit_count"]),
            "lastHitAt": row["last_hit_at"],
            "sourceCaseId": row["source_case_id"],
            "sourceSessionId": row["source_session_id"],
            "notes": row["notes"] or "",
        }


def extract_features(context: Dict[str, Any], tags: List[str]) -> Dict[str, Any]:
    stop = context.get("stopInfo") or context.get("stop_info") or {}
    modules = context.get("modules") or []
    breakpoints = context.get("breakpoints") or []
    stack = context.get("stack") or context.get("frames") or []
    symbol = str(stop.get("symbol") or stop.get("reason") or "")
    return {
        "exceptionCode": normalize_hex(stop.get("exceptionCode")),
        "reason": str(stop.get("reason") or ""),
        "instructionPointer": normalize_hex(stop.get("instructionPointer")),
        "symbol": symbol,
        "modules": collect_names(modules, ("name", "moduleName", "path")),
        "breakpoints": collect_names(breakpoints, ("symbol", "address", "id")),
        "stackSymbols": collect_names(stack, ("symbol", "returnAddress", "ip")),
        "tags": [str(tag).lower() for tag in tags],
    }


def normalize_hex(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, int):
        return "0x%X" % value
    text = str(value).strip()
    if not text:
        return ""
    try:
        return "0x%X" % int(text, 0)
    except Exception:
        return text.lower()


def collect_names(items: Any, keys: Any) -> List[str]:
    out = []
    if not isinstance(items, list):
        return out
    for item in items:
        if not isinstance(item, dict):
            continue
        for key in keys:
            value = item.get(key)
            if value is not None and str(value):
                out.append(str(value).lower())
                break
    return out


def score_features(query: Dict[str, Any], case: Dict[str, Any], weights: Optional[Dict[str, int]] = None) -> Any:
    weights = weights or DEFAULT_WEIGHTS
    score = 0
    reasons = []
    for key in ("exceptionCode", "reason", "symbol"):
        if query.get(key) and case.get(key) and str(query.get(key)).lower() == str(case.get(key)).lower():
            weight = weights.get(key, 1)
            score += weight
            reasons.append("%s matched" % key)
    for query_key, case_key, weight_key in (
        ("modules", "modules", "module"),
        ("breakpoints", "breakpoints", "breakpoint"),
        ("stackSymbols", "stackSymbols", "stackSymbol"),
        ("tags", "tags", "tag"),
    ):
        overlap = sorted(set(query.get(query_key, [])) & set(case.get(case_key, [])))
        if overlap:
            weight = weights.get(weight_key, 1) * min(len(overlap), 5)
            score += weight
            reasons.append("%s overlap: %s" % (query_key, ", ".join(overlap[:5])))
    return score, reasons


def score_debug_feature_text(text_lower: str, pattern: Dict[str, Any]) -> Any:
    score = 0
    reasons = []
    if not isinstance(pattern, dict):
        return 0, reasons

    normalized = []
    for ch in text_lower:
        normalized.append(ch if (ch.isalnum() or ch == "_") else " ")
    token_text = " " + "".join(normalized) + " "

    keywords = pattern.get("keywords", [])
    if isinstance(keywords, str):
        keywords = [keywords]
    keyword_hits = []
    if isinstance(keywords, list):
        for keyword in keywords:
            key = str(keyword or "").lower()
            if key and key in text_lower:
                keyword_hits.append(key)
    if keyword_hits:
        score += 20 * len(keyword_hits)
        reasons.append("keywords: %s" % ", ".join(keyword_hits[:8]))

    mnemonics = pattern.get("mnemonics", [])
    if isinstance(mnemonics, str):
        mnemonics = [mnemonics]
    mnemonic_hits = []
    if isinstance(mnemonics, list):
        for mnemonic in mnemonics:
            key = str(mnemonic or "").lower().strip()
            if key and (" " + key + " ") in token_text:
                mnemonic_hits.append(key)
    if mnemonic_hits:
        score += 5 * len(mnemonic_hits)
        reasons.append("mnemonics: %s" % ", ".join(mnemonic_hits[:8]))

    required = pattern.get("required", [])
    if isinstance(required, str):
        required = [required]
    if isinstance(required, list) and required:
        missing = [str(item).lower() for item in required if str(item or "").lower() not in text_lower]
        if missing:
            return 0, []
        score += 30
        reasons.append("required matched")

    return score, reasons
