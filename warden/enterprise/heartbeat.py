"""Per-tool-call volume heartbeat — makes "tool calls inspected" a real number.

Findings-only telemetry tells the org what was *flagged*; it says nothing about
how much the agent actually did. This module counts every hook-dispatched tool
call locally and, at most once per ``FLUSH_INTERVAL`` seconds, uploads a single
``agent_activity`` record carrying the accumulated count. The control plane
sums the ``count`` column for the "tool calls inspected" KPI.

Privacy: the heartbeat carries *only* a number plus the same metadata enums as
any redacted record (agent name, session id). No commands, paths, or content —
it is volume, not activity detail.

Cost: one fcntl-locked JSON read/write per tool call (sub-millisecond) and one
HTTP POST per minute at most, with the same short-timeout + offline-spool
semantics as finding telemetry (warden/sinks.upload_telemetry). Failures never
raise into the hook path.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from warden.enterprise import identity as _identity

FLUSH_INTERVAL = 60.0


def _counter_path() -> Path:
    return _identity.prismor_home() / "heartbeat.json"


def _load(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def record_call(agent: Optional[str] = None, session_id: Optional[str] = None) -> None:
    """Count one inspected tool call. Never raises; no-op when not enrolled."""
    if not _identity.is_enrolled():
        return
    path = _counter_path()
    try:
        import fcntl
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path.with_suffix(".lock"), "w") as lock_f:
            fcntl.flock(lock_f, fcntl.LOCK_EX)
            try:
                data = _load(path)
                data["count"] = int(data.get("count", 0)) + 1
                if agent:
                    data["agent"] = agent
                if session_id:
                    data["session_id"] = session_id
                data.setdefault("last_flush", time.time())
                path.write_text(json.dumps(data), encoding="utf-8")
            finally:
                fcntl.flock(lock_f, fcntl.LOCK_UN)
    except OSError:
        pass


def maybe_flush(now: Optional[float] = None) -> bool:
    """Upload the accumulated count as one agent_activity record, at most once
    per FLUSH_INTERVAL. Returns True if a flush was attempted. Never raises.

    The counter is reset *before* the upload; on failure the record lands in
    the offline spool (see sinks.upload_telemetry), so the count is never lost
    and never double-sent.
    """
    ident = _identity.load_identity()
    if not ident or _identity.revoked_backoff_active():
        return False

    path = _counter_path()
    record: Optional[Dict[str, Any]] = None
    try:
        import fcntl
        if not path.exists():
            return False
        with open(path.with_suffix(".lock"), "w") as lock_f:
            fcntl.flock(lock_f, fcntl.LOCK_EX)
            try:
                data = _load(path)
                count = int(data.get("count", 0))
                last = float(data.get("last_flush", 0))
                t = time.time() if now is None else now
                if count <= 0 or (t - last) < FLUSH_INTERVAL:
                    return False
                import uuid
                record = {
                    "schema": "warden.telemetry.v1",
                    "event_id": "evt_" + uuid.uuid4().hex,
                    "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "type": "agent_activity",
                    "verdict": "observed",
                    "title": "Agent activity heartbeat",
                    "agent": data.get("agent"),
                    "session_id": data.get("session_id"),
                    "count": count,
                    "redacted": True,
                }
                path.write_text(
                    json.dumps({**data, "count": 0, "last_flush": t}), encoding="utf-8"
                )
            finally:
                fcntl.flock(lock_f, fcntl.LOCK_UN)
    except (OSError, ValueError):
        return False

    if record is None:
        return False
    try:
        from warden.sinks import upload_telemetry
        upload_telemetry([record])
    except Exception as exc:  # spooled by upload_telemetry; just note it
        sys.stderr.write(f"[warden] heartbeat upload deferred: {exc}\n")
    return True
