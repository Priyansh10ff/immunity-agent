#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

__version__ = "0.1.0"

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from warden.feed import load_feed, match_advisories
from warden.hooks import install_hooks, normalize_payload, should_block, uninstall_hooks
from warden.policies import evaluate_event
from warden.store import (
    append_session_event,
    get_db_path,
    get_sessions_dir,
    get_session,
    infer_default_workspace,
    initialize_database,
    list_sessions,
    read_session_events,
    save_session_snapshot,
)

SEVERITY_WEIGHT = {
    "CRITICAL": 30,
    "HIGH": 18,
    "MEDIUM": 8,
    "LOW": 3,
    "UNKNOWN": 1,
}


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    repo_root = Path(__file__).resolve().parent.parent
    workspace = Path(args.workspace).resolve() if getattr(args, "workspace", None) else infer_default_workspace(Path.cwd())

    if args.command == "analyze":
        events = parse_jsonl(read_text(args.input))
        result = analyze_events(events, repo_root=repo_root)
        emit(result, as_json=args.json, formatter=format_analysis)
        return

    if args.command == "ingest":
        events = parse_jsonl(read_text(args.input))
        result = analyze_events(events, repo_root=repo_root)
        session_id = args.session_id or derive_session_id(events)
        db_path = save_session_snapshot(
            workspace=workspace,
            session_id=session_id,
            agent=args.agent or infer_agent(events),
            source="ingest",
            repo_url=None,
            events=events,
            analysis=result,
        )
        print(f"Stored session {session_id} in {db_path} with {result['summary']['totalFindings']} findings.")
        return

    if args.command == "sessions":
        sessions = list_sessions(workspace, args.limit)
        emit({"sessions": sessions}, as_json=args.json, formatter=format_sessions)
        return

    if args.command == "session":
        session = get_session(workspace, args.session_id)
        if session is None:
            raise SystemExit(f"Session not found: {args.session_id}")
        emit(session, as_json=args.json, formatter=format_session)
        return

    if args.command == "install-hooks":
        results = install_hooks(
            repo_root=repo_root,
            workspace=workspace,
            agent=args.agent,
            scope=args.scope,
            mode=args.mode,
        )
        for item in results:
            print(f"Installed {item['agent']} hooks at {item['configPath']}")
        return

    if args.command == "uninstall-hooks":
        results = uninstall_hooks(
            repo_root=repo_root,
            workspace=workspace,
            agent=args.agent,
            scope=args.scope,
        )
        for item in results:
            if item["removed"]:
                print(f"Removed {item['agent']} hooks from {item['configPath']}")
            else:
                print(f"No Prismor hooks found for {item['agent']} at {item['configPath']}")
        return

    if args.command == "hook-dispatch":
        payload = json.loads(sys.stdin.read() or "{}")
        normalized = normalize_payload(agent=args.agent, payload=payload, workspace=workspace)
        event = normalized["event"]
        append_session_event(workspace, normalized["sessionId"], event)
        events = read_session_events(workspace, normalized["sessionId"])
        result = analyze_events(events, repo_root=repo_root, session_id=normalized["sessionId"])
        save_session_snapshot(
            workspace=workspace,
            session_id=normalized["sessionId"],
            agent=args.agent,
            source="hook",
            repo_url=None,
            events=events,
            analysis=result,
        )
        blocking = should_block(result["findings"], event)
        if args.mode == "enforce" and blocking is not None:
            sys.stderr.write(f"Prismor Warden blocked this action: [{blocking['severity']}] {blocking['title']}\n")
            if blocking.get("evidence"):
                sys.stderr.write(f"{blocking['evidence']}\n")
            raise SystemExit(2)
        return

    raise SystemExit(f"Unsupported command: {args.command}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prismor Warden — local session-security utility for AI coding agents.")
    parser.add_argument("--version", action="version", version=f"prismor-warden {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    analyze = subparsers.add_parser("analyze")
    analyze.add_argument("--input", required=True)
    analyze.add_argument("--workspace")
    analyze.add_argument("--json", action="store_true")

    ingest = subparsers.add_parser("ingest")
    ingest.add_argument("--input", required=True)
    ingest.add_argument("--workspace")
    ingest.add_argument("--session-id")
    ingest.add_argument("--agent")

    sessions_parser = subparsers.add_parser("sessions")
    sessions_parser.add_argument("--workspace")
    sessions_parser.add_argument("--limit", type=int, default=20)
    sessions_parser.add_argument("--json", action="store_true")

    session_parser = subparsers.add_parser("session")
    session_parser.add_argument("--workspace")
    session_parser.add_argument("--session-id", required=True)
    session_parser.add_argument("--json", action="store_true")

    install_parser = subparsers.add_parser("install-hooks")
    install_parser.add_argument("--workspace")
    install_parser.add_argument("--agent", choices=["claude", "cursor", "windsurf", "all"], required=True)
    install_parser.add_argument("--scope", choices=["project", "user"], default="project")
    install_parser.add_argument("--mode", choices=["observe", "enforce"], default="observe")

    uninstall_parser = subparsers.add_parser("uninstall-hooks")
    uninstall_parser.add_argument("--workspace")
    uninstall_parser.add_argument("--agent", choices=["claude", "cursor", "windsurf", "all"], required=True)
    uninstall_parser.add_argument("--scope", choices=["project", "user"], default="project")

    hook_dispatch = subparsers.add_parser("hook-dispatch")
    hook_dispatch.add_argument("--workspace")
    hook_dispatch.add_argument("--agent", choices=["claude", "cursor", "windsurf"], required=True)
    hook_dispatch.add_argument("--mode", choices=["observe", "enforce"], default="observe")

    return parser


def analyze_events(events: List[Dict[str, Any]], *, repo_root: Path, session_id: str = "") -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    for index, event in enumerate(events):
        findings.extend(evaluate_event(event, index, session_id=session_id))

    feed_matches = match_advisories(findings, load_feed(repo_root))
    summary = {
        "totalEvents": len(events),
        "totalFindings": len(findings),
        "riskScore": min(100, sum(SEVERITY_WEIGHT.get(finding.get("severity", "UNKNOWN"), 1) for finding in findings)),
        "severityBreakdown": severity_breakdown(findings),
    }
    return {
        "summary": summary,
        "findings": sorted(findings, key=lambda item: SEVERITY_WEIGHT.get(item.get("severity", "UNKNOWN"), 0), reverse=True),
        "feedMatches": feed_matches,
    }


def severity_breakdown(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for finding in findings:
        summary[finding.get("severity", "UNKNOWN")] += 1
    return summary


def parse_jsonl(text: str) -> List[Dict[str, Any]]:
    events = []
    for index, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            events.append(json.loads(stripped))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Invalid JSON on line {index}: {exc}") from exc
    return events


def read_text(input_path: str) -> str:
    if input_path == "-":
        return sys.stdin.read()
    return Path(input_path).read_text(encoding="utf-8")


def derive_session_id(events: List[Dict[str, Any]]) -> str:
    if events and events[0].get("session_id"):
        return str(events[0]["session_id"])
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"session-{Path.cwd().name}-{timestamp}"


def infer_agent(events: List[Dict[str, Any]]) -> str:
    if events and events[0].get("agent"):
        return str(events[0]["agent"])
    return "unknown"


def emit(payload: Any, *, as_json: bool, formatter=None) -> None:
    if as_json:
        print(json.dumps(payload, indent=2))
        return
    if formatter is None:
        print(json.dumps(payload, indent=2))
        return
    print(formatter(payload))


def format_sessions(payload: Dict[str, Any]) -> str:
    sessions = payload["sessions"]
    lines = ["Prismor Warden Sessions", "======================="]
    if not sessions:
        lines.append("No sessions stored.")
        return "\n".join(lines)
    for index, session in enumerate(sessions, start=1):
        lines.append(
            f"{index}. {session['sessionId']} | agent={session['agent']} | risk={session['riskScore']} | findings={session['findingsCount']} | updated={session['updatedAt']}"
        )
        lines.append(f"   workspace={session['workspacePath']}")
    return "\n".join(lines)


def format_analysis(result: Dict[str, Any]) -> str:
    lines = [
        "Prismor Warden Report",
        "=====================",
        f"Events: {result['summary']['totalEvents']}",
        f"Findings: {result['summary']['totalFindings']}",
        f"Risk score: {result['summary']['riskScore']}/100",
        (
            "Severity: "
            f"CRITICAL={result['summary']['severityBreakdown']['CRITICAL']}, "
            f"HIGH={result['summary']['severityBreakdown']['HIGH']}, "
            f"MEDIUM={result['summary']['severityBreakdown']['MEDIUM']}, "
            f"LOW={result['summary']['severityBreakdown']['LOW']}"
        ),
        "",
        "Findings",
        "--------",
    ]

    if not result["findings"]:
        lines.append("No findings.")
    else:
        for finding in result["findings"]:
            lines.append(f"- [{finding['severity']}] {finding['title']} ({finding['category']})")
            if finding.get("evidence"):
                lines.append(f"  {finding['evidence']}")

    if result["feedMatches"]:
        lines.extend(["", "Relevant advisories", "------------------"])
        for advisory in result["feedMatches"]:
            lines.append(f"- [{advisory['severity']}] {advisory['id']} {advisory['title']}")

    return "\n".join(lines)


def format_session(session: Dict[str, Any]) -> str:
    lines = [
        f"Session {session['sessionId']}",
        "=" * (8 + len(session["sessionId"])),
        f"Agent: {session['agent']}",
        f"Source: {session['source']}",
        f"Workspace: {session['workspacePath']}",
        f"Started: {session['startedAt']}",
        f"Updated: {session['updatedAt']}",
        f"Risk score: {session['riskScore']}",
        f"Findings: {session['findingsCount']}",
        "",
        "Findings",
        "--------",
    ]
    for finding in session["findings"]:
        lines.append(f"- [{finding['severity']}] {finding['title']} ({finding['category']})")
        if finding.get("evidence"):
            lines.append(f"  {finding['evidence']}")
    lines.extend(["", "Recent events", "-------------"])
    for event in session["events"][-10:]:
        parts = [event.get("ts"), event.get("type"), event.get("path"), event.get("command"), event.get("url")]
        lines.append(f"- {' | '.join(part for part in parts if part)}")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
