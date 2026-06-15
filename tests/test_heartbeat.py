"""Tests for the per-tool-call volume heartbeat (warden/enterprise/heartbeat.py).

Invariants:
  * Not enrolled → record_call is a no-op (zero files, zero cost).
  * Calls accumulate; maybe_flush respects the debounce window.
  * A due flush emits exactly one agent_activity record carrying the count,
    resets the counter, and never double-sends.
  * Upload failure → the record lands in the offline spool (count preserved).
"""
from __future__ import annotations

import json
import time

import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    yield


def _enroll(api_base="http://127.0.0.1:1"):
    from warden.enterprise import identity
    identity.save_identity({
        "device_id": "d1", "org_id": "o1", "user_id": "u1",
        "device_key": "prism_dev_x", "api_base": api_base,
    })


def test_record_call_noop_when_not_enrolled():
    from warden.enterprise import heartbeat
    heartbeat.record_call(agent="claude", session_id="s1")
    assert not heartbeat._counter_path().exists()


def test_calls_accumulate_and_flush_debounces(monkeypatch):
    from warden.enterprise import heartbeat
    _enroll()

    sent = []
    monkeypatch.setattr("warden.sinks.upload_telemetry", lambda recs, **kw: sent.extend(recs))

    for _ in range(5):
        heartbeat.record_call(agent="claude", session_id="s1")
    data = json.loads(heartbeat._counter_path().read_text())
    assert data["count"] == 5

    # Within the debounce window (last_flush was set on first record) → no flush.
    assert heartbeat.maybe_flush() is False
    assert sent == []

    # Past the window → exactly one record with the accumulated count.
    assert heartbeat.maybe_flush(now=time.time() + heartbeat.FLUSH_INTERVAL + 1) is True
    assert len(sent) == 1
    rec = sent[0]
    assert rec["type"] == "agent_activity"
    assert rec["count"] == 5
    assert rec["agent"] == "claude"
    assert rec["redacted"] is True

    # Counter reset — an immediate second flush has nothing to send.
    assert heartbeat.maybe_flush(now=time.time() + 2 * heartbeat.FLUSH_INTERVAL + 2) is False
    assert len(sent) == 1


def test_failed_flush_lands_in_spool():
    from warden.enterprise import heartbeat, telemetry_spool
    _enroll(api_base="http://127.0.0.1:1")  # dead endpoint

    for _ in range(3):
        heartbeat.record_call(agent="codex", session_id="s2")
    assert heartbeat.maybe_flush(now=time.time() + heartbeat.FLUSH_INTERVAL + 1) is True

    spooled = telemetry_spool.drain(limit=10)
    assert len(spooled) == 1
    assert spooled[0]["type"] == "agent_activity"
    assert spooled[0]["count"] == 3
    # Counter was reset — the count lives in the spool, not both places.
    assert json.loads(heartbeat._counter_path().read_text())["count"] == 0
