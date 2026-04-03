#!/usr/bin/env python3
"""Prismor Warden CLI — local session-security utility for AI coding agents.

Commands:
  check         Quick pre-check a command or file path against policy rules
  status        Show findings from the most recent session
  analyze       Analyze a JSONL session file
  ingest        Analyze and store a session
  sessions      List stored sessions
  session       Show a specific session
  install-hooks Install IDE hooks for real-time monitoring
  uninstall-hooks Remove IDE hooks
  hook-dispatch Internal: called by IDE hooks (not for direct use)
  policy init   Generate a starter policy.yaml for your project
  policy validate  Validate a policy.yaml file
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

__version__ = "0.2.0"

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from warden.feed import load_feed, match_advisories
from warden.hooks import install_hooks, normalize_payload, should_block, uninstall_hooks
from warden.policy_engine import PolicyEngine, validate_policy
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

# ANSI colors for terminal output
_RED = "\033[0;31m"
_YELLOW = "\033[1;33m"
_GREEN = "\033[0;32m"
_CYAN = "\033[0;36m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_NC = "\033[0m"


def _color(text: str, color: str) -> str:
    """Apply ANSI color if stdout is a terminal."""
    if not sys.stderr.isatty():
        return text
    return f"{color}{text}{_NC}"


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    repo_root = Path(__file__).resolve().parent.parent
    workspace = Path(args.workspace).resolve() if getattr(args, "workspace", None) else infer_default_workspace(Path.cwd())

    # ── check: quick pre-check a command or path ───────────────────────
    if args.command == "check":
        engine = PolicyEngine(workspace=workspace)
        if args.type == "command":
            findings = engine.check_command(args.value)
        elif args.type in ("read", "write"):
            event_type = "file_read" if args.type == "read" else "file_write"
            findings = engine.check_path(args.value, event_type=event_type)
        else:
            findings = engine.check_command(args.value)

        if not findings:
            print(_color("PASS", _GREEN) + f"  {args.value}")
            return

        for f in findings:
            sev = f["severity"]
            color = _RED if sev == "CRITICAL" else _YELLOW if sev == "HIGH" else _DIM
            action_label = f.get("action", "warn").upper()
            print(_color(f"[{sev}]", color) + f" {f['title']}  " + _color(f"({action_label})", color))
            print(f"  rule: {f.get('ruleId', '?')}  evidence: {f['evidence']}")

        # Exit 2 if any finding has action=block, 1 for warn-only, 0 for log-only.
        if any(f.get("action") == "block" for f in findings):
            raise SystemExit(2)
        if any(f.get("action") == "warn" for f in findings):
            raise SystemExit(1)
        return

    # ── status: show most recent session findings ──────────────────────
    if args.command == "status":
        sessions = list_sessions(workspace, 1)
        if not sessions:
            print("No sessions found.")
            return
        latest = sessions[0]
        session = get_session(workspace, latest["sessionId"])
        if session is None:
            print("No session data available.")
            return
        _print_status(session)
        return

    # ── analyze ────────────────────────────────────────────────────────
    if args.command == "analyze":
        events = parse_jsonl(read_text(args.input))
        result = analyze_events(events, repo_root=repo_root, workspace=workspace)
        if getattr(args, "sarif", False):
            print(json.dumps(format_sarif(result), indent=2))
        else:
            emit(result, as_json=args.json, formatter=format_analysis)
        return

    # ── ingest ─────────────────────────────────────────────────────────
    if args.command == "ingest":
        events = parse_jsonl(read_text(args.input))
        result = analyze_events(events, repo_root=repo_root, workspace=workspace)
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

    # ── sessions ───────────────────────────────────────────────────────
    if args.command == "sessions":
        sessions = list_sessions(workspace, args.limit)
        if getattr(args, "findings_only", False):
            sessions = [s for s in sessions if s.get("findingsCount", 0) > 0]
            # Sort by risk score (highest first)
            sessions.sort(key=lambda s: s.get("riskScore", 0), reverse=True)
            # Enrich with actual findings for display
            for s in sessions:
                full = get_session(workspace, s["sessionId"])
                if full:
                    s["findings"] = full.get("findings", [])
        emit({"sessions": sessions}, as_json=args.json, formatter=format_sessions)
        return

    if args.command == "session":
        session = get_session(workspace, args.session_id)
        if session is None:
            raise SystemExit(f"Session not found: {args.session_id}")
        emit(session, as_json=args.json, formatter=format_session)
        return

    # ── install-hooks ──────────────────────────────────────────────────
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

    # ── uninstall-hooks ────────────────────────────────────────────────
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

    # ── hook-dispatch (called by IDE hooks) ────────────────────────────
    if args.command == "hook-dispatch":
        payload = json.loads(sys.stdin.read() or "{}")
        normalized = normalize_payload(agent=args.agent, payload=payload, workspace=workspace)
        event = normalized["event"]
        append_session_event(workspace, normalized["sessionId"], event)
        events = read_session_events(workspace, normalized["sessionId"])
        result = analyze_events(events, repo_root=repo_root, workspace=workspace, session_id=normalized["sessionId"])
        save_session_snapshot(
            workspace=workspace,
            session_id=normalized["sessionId"],
            agent=args.agent,
            source="hook",
            repo_url=None,
            events=events,
            analysis=result,
        )
        blocking = should_block(result["findings"], event, block_categories=set(result.get("blockCategories", [])))
        if args.mode == "enforce" and blocking is not None:
            sys.stderr.write(f"Prismor Warden blocked this action: [{blocking['severity']}] {blocking['title']}\n")
            if blocking.get("evidence"):
                sys.stderr.write(f"{blocking['evidence']}\n")
            raise SystemExit(2)
        elif args.mode == "observe" and blocking is not None:
            # Show warnings in observe mode so humans/agents see feedback.
            sys.stderr.write(_color(f"[warden] ", _YELLOW) + f"[{blocking['severity']}] {blocking['title']}\n")
        return

    # ── policy subcommands ─────────────────────────────────────────────
    if args.command == "policy":
        if args.policy_command == "init":
            _policy_init(workspace)
            return
        if args.policy_command == "validate":
            _policy_validate(Path(args.file))
            return
        if args.policy_command == "show":
            _policy_show(workspace)
            return

    raise SystemExit(f"Unsupported command: {args.command}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prismor Warden — local session-security utility for AI coding agents.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--workspace", help="Workspace path (applies to all commands)")
    parser.add_argument("--version", action="version", version=f"prismor-warden {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    # ── check ──────────────────────────────────────────────────────────
    check_parser = subparsers.add_parser("check", help="Quick pre-check a command or file path")
    check_parser.add_argument("value", help="The command string or file path to check")
    check_parser.add_argument(
        "--type", "-t",
        choices=["command", "read", "write"],
        default="command",
        help="What to check: command (default), read (file read), write (file write)",
    )
    check_parser.add_argument("--workspace", help="Workspace path for project-level policy")

    # ── status ─────────────────────────────────────────────────────────
    status_parser = subparsers.add_parser("status", help="Show findings from the most recent session")
    status_parser.add_argument("--workspace", help="Workspace path")

    # ── analyze ────────────────────────────────────────────────────────
    analyze = subparsers.add_parser("analyze", help="Analyze a JSONL session file")
    analyze.add_argument("--input", required=True, help="Path to JSONL session file (or - for stdin)")
    analyze.add_argument("--workspace", help="Workspace path")
    analyze.add_argument("--json", action="store_true", help="Output raw JSON")
    analyze.add_argument("--sarif", action="store_true", help="Output SARIF 2.1.0 format")

    # ── ingest ─────────────────────────────────────────────────────────
    ingest = subparsers.add_parser("ingest", help="Analyze and store a session")
    ingest.add_argument("--input", required=True, help="Path to JSONL session file")
    ingest.add_argument("--workspace", help="Workspace path")
    ingest.add_argument("--session-id", help="Override session ID")
    ingest.add_argument("--agent", help="Agent name")

    # ── sessions ───────────────────────────────────────────────────────
    sessions_parser = subparsers.add_parser("sessions", help="List stored sessions")
    sessions_parser.add_argument("--workspace", help="Workspace path")
    sessions_parser.add_argument("--limit", type=int, default=20, help="Max sessions to show (default: 20)")
    sessions_parser.add_argument("--json", action="store_true", help="Output raw JSON")
    sessions_parser.add_argument("--findings-only", action="store_true", help="Only show sessions with findings")

    # ── session ────────────────────────────────────────────────────────
    session_parser = subparsers.add_parser("session", help="Show a specific session")
    session_parser.add_argument("--workspace", help="Workspace path")
    session_parser.add_argument("--session-id", required=True, help="Session ID to view")
    session_parser.add_argument("--json", action="store_true", help="Output raw JSON")

    # ── install-hooks ──────────────────────────────────────────────────
    install_parser = subparsers.add_parser("install-hooks", help="Install IDE hooks for real-time monitoring")
    install_parser.add_argument("--workspace", help="Workspace path")
    install_parser.add_argument("--agent", choices=["claude", "cursor", "windsurf", "all"], required=True, help="Which agent/IDE")
    install_parser.add_argument("--scope", choices=["project", "user"], default="project", help="Hook scope (default: project)")
    install_parser.add_argument("--mode", choices=["observe", "enforce"], default="observe", help="observe=log only, enforce=block dangerous actions")

    # ── uninstall-hooks ────────────────────────────────────────────────
    uninstall_parser = subparsers.add_parser("uninstall-hooks", help="Remove IDE hooks")
    uninstall_parser.add_argument("--workspace", help="Workspace path")
    uninstall_parser.add_argument("--agent", choices=["claude", "cursor", "windsurf", "all"], required=True, help="Which agent/IDE")
    uninstall_parser.add_argument("--scope", choices=["project", "user"], default="project", help="Hook scope")

    # ── hook-dispatch (internal) ───────────────────────────────────────
    hook_dispatch = subparsers.add_parser("hook-dispatch", help="(internal) Called by IDE hooks")
    hook_dispatch.add_argument("--workspace", help="Workspace path")
    hook_dispatch.add_argument("--agent", choices=["claude", "cursor", "windsurf"], required=True)
    hook_dispatch.add_argument("--mode", choices=["observe", "enforce"], default="observe")

    # ── policy ─────────────────────────────────────────────────────────
    policy_parser = subparsers.add_parser("policy", help="Manage Warden policies")
    policy_sub = policy_parser.add_subparsers(dest="policy_command")

    policy_init = policy_sub.add_parser("init", help="Create a starter policy.yaml in your workspace")
    policy_init.add_argument("--workspace", help="Workspace path")

    policy_validate = policy_sub.add_parser("validate", help="Validate a policy YAML file")
    policy_validate.add_argument("file", help="Path to policy.yaml")
    policy_validate.add_argument("--workspace", help="Workspace path")

    policy_show = policy_sub.add_parser("show", help="Show active policy rules (default + project overrides)")
    policy_show.add_argument("--workspace", help="Workspace path")

    return parser


# ── New command implementations ─────────────────────────────────────────

def _print_status(session: Dict[str, Any]) -> None:
    """Pretty-print the latest session status."""
    risk = session.get("riskScore", 0)
    findings_count = session.get("findingsCount", 0)
    sid = session.get("sessionId", "?")

    if findings_count == 0:
        print(_color("CLEAN", _GREEN) + f"  session={sid}  risk={risk}/100")
        return

    risk_color = _RED if risk >= 50 else _YELLOW if risk >= 20 else _GREEN
    print(_color(f"RISK {risk}/100", risk_color) + f"  session={sid}  findings={findings_count}")
    print()
    for finding in session.get("findings", []):
        sev = finding.get("severity", "?")
        color = _RED if sev == "CRITICAL" else _YELLOW if sev == "HIGH" else _DIM
        print(f"  {_color(f'[{sev}]', color)} {finding['title']} ({finding['category']})")
        if finding.get("evidence"):
            print(f"         {finding['evidence']}")


def _policy_init(workspace: Path) -> None:
    """Generate a starter policy.yaml with comments explaining each section."""
    target_dir = workspace / ".prismor-warden"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / "policy.yaml"
    if target.exists():
        print(f"Policy already exists at {target}")
        raise SystemExit(1)

    starter = '''version: "1.0"

# Project-level Warden policy overrides.
# Rules here merge with the defaults — override a rule by matching its id,
# or add new rules with unique ids.
#
# Docs: https://github.com/PrismorSec/prismor

rules: []
  # Example: add a custom rule
  # - id: block-prod-db
  #   severity: CRITICAL
  #   category: db_access
  #   title: Direct production database access blocked
  #   event_types: [shell]
  #   fields: [command]
  #   patterns: ["psql.*prod", "mysql.*production"]
  #   action: block

  # Example: disable a default rule
  # - id: risky-write
  #   enabled: false

allowlists:
  # Example: allow reading .env in this project (it has no real secrets)
  # - id: allow-dotenv
  #   rule_ids: ["secret-access"]
  #   patterns: ["\\.env$"]
  #   reason: ".env in this project only has non-sensitive defaults"
'''
    target.write_text(starter, encoding="utf-8")
    print(f"Created {target}")
    print(f"Edit this file to customize detection rules and allowlists for your project.")


def _policy_validate(path: Path) -> None:
    """Validate a policy YAML and print errors."""
    errors = validate_policy(path)
    if not errors:
        print(_color("VALID", _GREEN) + f"  {path}")
        return
    print(_color("INVALID", _RED) + f"  {path}")
    for error in errors:
        print(f"  - {error}")
    raise SystemExit(1)


def _policy_show(workspace: Path) -> None:
    """Show all active rules after merging defaults + project overrides."""
    engine = PolicyEngine(workspace=workspace)
    print(f"Active rules: {len(engine.rules)}")
    print(f"Allowlists:   {len(engine.allowlists)}")
    print()

    override_path = workspace / ".prismor-warden" / "policy.yaml"
    if override_path.exists():
        print(f"Project policy: {override_path}")
    else:
        print(f"Project policy: (none — using defaults only)")
    print()

    for rule in sorted(engine.rules, key=lambda r: SEVERITY_WEIGHT.get(r.severity, 0), reverse=True):
        sev = rule.severity
        color = _RED if sev == "CRITICAL" else _YELLOW if sev == "HIGH" else _DIM
        print(f"  {_color(f'[{sev}]', color)} {rule.id}: {rule.title}  ({rule.action})")

    if engine.allowlists:
        print()
        print("Allowlists:")
        for al in engine.allowlists:
            targets = ", ".join(al.rule_ids) if "*" not in al.rule_ids else "all rules"
            print(f"  {al.id}: {targets}" + (f"  — {al.reason}" if al.reason else ""))


# ── SARIF output ────────────────────────────────────────────────────────

def format_sarif(result: Dict[str, Any]) -> Dict[str, Any]:
    """Format analysis results as SARIF 2.1.0 for GitHub Code Scanning."""
    rules_seen: Dict[str, int] = {}
    sarif_rules: List[Dict[str, Any]] = []
    sarif_results: List[Dict[str, Any]] = []

    for finding in result.get("findings", []):
        category = finding.get("category", "unknown")
        if category not in rules_seen:
            rules_seen[category] = len(sarif_rules)
            sarif_rules.append({
                "id": category,
                "name": category.replace("_", " ").title(),
                "shortDescription": {"text": finding.get("title", category)},
                "defaultConfiguration": {
                    "level": _sarif_level(finding.get("severity", "MEDIUM")),
                },
            })

        sarif_results.append({
            "ruleId": category,
            "ruleIndex": rules_seen[category],
            "level": _sarif_level(finding.get("severity", "MEDIUM")),
            "message": {
                "text": f"{finding.get('title', '')}. Evidence: {finding.get('evidence', 'N/A')}",
            },
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Prismor Warden",
                    "version": __version__,
                    "informationUri": "https://github.com/PrismorSec/prismor",
                    "rules": sarif_rules,
                },
            },
            "results": sarif_results,
        }],
    }


def _sarif_level(severity: str) -> str:
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(severity, "warning")


# ── Existing functionality (unchanged) ──────────────────────────────────

def analyze_events(
    events: List[Dict[str, Any]],
    *,
    repo_root: Path,
    workspace: Optional[Path] = None,
    session_id: str = "",
) -> Dict[str, Any]:
    engine = PolicyEngine(workspace=workspace)
    findings: List[Dict[str, Any]] = []
    for index, event in enumerate(events):
        findings.extend(engine.evaluate(event, index, session_id=session_id))

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
        "blockCategories": sorted(engine.block_categories),
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


_SECRET_PATTERNS = re.compile(
    r"((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{10,})"    # GitHub tokens
    r"|((?:sk|pk)[-_][A-Za-z0-9-]{16,})"                            # Stripe/OpenAI keys
    r"|((?:AKIA)[A-Z0-9]{12,})"                                    # AWS access keys
    r"|(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,})"           # JWTs
    r"|((?:token|secret|password|bearer|apikey)[\s=:\"']+\S{8,})", # key=value secrets
    re.IGNORECASE,
)


def _redact_evidence(evidence: str) -> str:
    """Redact secrets in evidence strings with ****."""
    if not evidence:
        return evidence
    def _mask(m):
        full = m.group(0)
        if len(full) <= 8:
            return full
        return full[:6] + "****" + full[-2:]
    return _SECRET_PATTERNS.sub(_mask, evidence)


def format_sessions(payload: Dict[str, Any]) -> str:
    sessions = payload["sessions"]
    lines = ["Prismor Warden Sessions", "======================="]
    if not sessions:
        lines.append("No sessions stored.")
        return "\n".join(lines)
    for index, session in enumerate(sessions, start=1):
        risk = session['riskScore']
        risk_color = _RED if risk >= 50 else _YELLOW if risk >= 20 else _GREEN
        lines.append(
            f"\n{_color(f'{index}.', _BOLD)} {session['sessionId']}"
            f"  {_color(f'risk={risk}/100', risk_color)}"
            f"  findings={session['findingsCount']}"
            f"  agent={session['agent']}"
        )
        # Show inline findings if they were enriched (--findings-only)
        findings = session.get("findings", [])
        if findings:
            for f in findings:
                sev = f.get("severity", "?")
                sev_color = _RED if sev == "CRITICAL" else _YELLOW if sev == "HIGH" else _DIM
                evidence = _redact_evidence(f.get("evidence", ""))
                lines.append(f"   {_color(f'[{sev}]', sev_color)} {f.get('title', f.get('category', ''))}")
                if evidence:
                    lines.append(f"          {_color(evidence, _DIM)}")
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
