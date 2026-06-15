"""Telemetry redaction — what is allowed to leave the developer's machine.

When a Warden install is enrolled against an org (see :mod:`warden.identity`),
findings are forwarded to the Prismor control plane for org-wide observability.
This module is the privacy boundary: it converts an internal finding + the
event that produced it into a cloud telemetry record.

Two modes:

* **redacted** (default): only enum/metadata fields leave — severity, category,
  rule id, event type, agent, verdict, a static rule title, and a *hash* of the
  matched evidence. No raw commands, file paths, URLs, prompts, file contents,
  or secrets are emitted. This is the default posture and the only mode an org
  gets unless an admin explicitly opts in.

* **full**: additionally includes the raw evidence/content, but still scrubbed
  through the cloaking secret patterns as defense-in-depth so registered or
  secret-shaped values never leave even in full-capture mode.

The contract: :func:`build_record` in redacted mode must *never* place
user-controlled free text in the output. Everything carrying user data is
dropped and replaced by a hash. The test-suite asserts this invariant.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SCHEMA = "warden.telemetry.v1"

# Finding/event fields that may contain user-controlled free text. In redacted
# mode every one of these is dropped (hashed, not forwarded). Kept centralized
# so the privacy boundary is auditable in one place.
_SENSITIVE_FINDING_FIELDS = ("evidence", "matched", "snippet", "context")
_SENSITIVE_EVENT_FIELDS = (
    "command", "stdout", "stderr", "path", "url", "content",
    "prompt", "response", "outbound_payload",
)

_REDACTED = "[REDACTED]"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _event_id() -> str:
    import uuid
    return "evt_" + uuid.uuid4().hex


def _hash(value: Any) -> Optional[str]:
    """Stable short hash of a value — lets the cloud dedup/count distinct
    evidence without ever seeing it. None for empty input."""
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    if not text:
        return None
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def _verdict(finding: Dict[str, Any]) -> str:
    # Enforcement is per-rule via `mode`: an enforced finding blocks (on a
    # pre-action event), everything else is observed (detected + logged). This is
    # the authoritative signal — the legacy `action` field is decorative, so a
    # rule with action:block in observe mode must report "observed", not "blocked".
    mode = str(finding.get("mode", "")).lower()
    if mode == "enforce":
        return "blocked"
    if mode == "observe":
        return "observed"
    # Legacy findings without `mode`: fall back to the old action-based verdict.
    action = str(finding.get("action", "")).lower()
    if action in ("block", "deny", "blocked"):
        return "blocked"
    if action in ("warn", "warned"):
        return "warned"
    return "observed"


def _compile_scrubbers(patterns: Optional[List[str]]) -> List[re.Pattern[str]]:
    compiled: List[re.Pattern[str]] = []
    for pat in patterns or []:
        try:
            compiled.append(re.compile(pat))
        except re.error:
            continue
    return compiled


def scrub(text: str, scrubbers: List[re.Pattern[str]]) -> str:
    """Replace any secret-shaped substrings with a redaction marker.

    Used in full-capture mode as defense-in-depth so that even when raw
    evidence is forwarded, registered/secret-shaped values are stripped.
    """
    if not text:
        return text
    out = text
    for rx in scrubbers:
        out = rx.sub(_REDACTED, out)
    return out


def build_record(
    finding: Dict[str, Any],
    event: Dict[str, Any],
    extra: Optional[Dict[str, Any]] = None,
    *,
    full_capture: bool = False,
    scrub_patterns: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build a single cloud telemetry record from a finding + its event.

    In the default (``full_capture=False``) mode the result contains only
    metadata and hashes — no user free text. In full mode, scrubbed raw
    evidence/content is added under ``detail``.
    """
    extra = extra or {}
    event_type = str(event.get("type", "")).lower() or None

    record: Dict[str, Any] = {
        "schema": SCHEMA,
        # Stable client-generated id → the control plane uses it as the row PK
        # with skip-duplicates, so a retried upload (network blip, pooler
        # connection reset mid-insert) can never create a duplicate event.
        "event_id": _event_id(),
        "ts": _now_iso(),
        "session_id": extra.get("session_id"),
        "device_id": extra.get("device_id"),
        "agent": extra.get("agent"),
        "mode": extra.get("mode"),
        "type": event_type,
        "verdict": _verdict(finding),
        "severity": finding.get("severity"),
        "category": finding.get("category"),
        "rule_id": finding.get("ruleId"),
        "tool_name": _tool_name(event, extra),
        # Repo + policy scope so the org dashboard can show which repo an event
        # came from and whether it ran under an admin-granted exemption (vs full
        # org policy). Only managed/company repos report, so the repo identifier
        # is org-owned context, not the developer's private data.
        "repo": extra.get("repo"),
        "policy_scope": extra.get("policy_scope") or "org",
        # Title is the *rule's* static description (from policy YAML), not user
        # text. Forwarded so the dashboard is human-readable without raw evidence.
        "title": finding.get("title"),
        # Hash of the matched evidence: lets the cloud count distinct hits and
        # build "top patterns" without ever seeing the underlying text.
        "evidence_hash": _hash(finding.get("evidence")),
        "redacted": not full_capture,
    }

    if full_capture:
        scrubbers = _compile_scrubbers(scrub_patterns)
        detail: Dict[str, Any] = {}
        ev = finding.get("evidence")
        if isinstance(ev, str) and ev:
            detail["evidence"] = scrub(ev, scrubbers)
        for fld in _SENSITIVE_EVENT_FIELDS:
            val = event.get(fld)
            if isinstance(val, str) and val:
                detail[fld] = scrub(val, scrubbers)
        if detail:
            record["detail"] = detail

    return record


def _tool_name(event: Dict[str, Any], extra: Dict[str, Any]) -> Optional[str]:
    meta = event.get("metadata")
    if isinstance(meta, dict) and meta.get("tool_name"):
        return str(meta["tool_name"])
    # Fall back to the normalized event type as a coarse tool name.
    return str(event.get("type")) if event.get("type") else None


def assert_redacted(record: Dict[str, Any]) -> None:
    """Raise AssertionError if a 'redacted' record carries any free-text detail.

    Defensive guard the sink can call before upload to fail closed if a future
    change ever leaks raw content through the redacted path.
    """
    if not record.get("redacted"):
        return
    if "detail" in record:
        raise AssertionError("redacted telemetry record must not contain 'detail'")
