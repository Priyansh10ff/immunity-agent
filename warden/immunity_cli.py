#!/usr/bin/env python3
"""immunity — unified CLI for the Prismor security toolkit.

Every command in the toolkit is reachable as ``immunity <command> [args...]``.
Run ``immunity --help`` for the full map. The umbrella dispatches to the
existing engines:

  - warden.cli:main         runtime / session security, hooks, policy, sweep,
                            cloak, iam, canary, scope, learn, setup, audit ...
  - supplychain.cli:run_supply  package-install interception + project hardening
"""
from __future__ import annotations

import sys
from typing import List, Optional

from warden import __version__

# ANSI helpers (mirrors warden/cli.py palette so output is visually consistent)
_BOLD = "\033[1m"
_DIM = "\033[37m"
_RESET = "\033[0m"


def _c(text: str, code: str) -> str:
    if sys.stdout.isatty():
        return f"{code}{text}{_RESET}"
    return text


# ── Routing tables ──────────────────────────────────────────────────────────
#
# Commands that map 1:1 to a warden.cli subcommand. Listing them here both
# (a) lets the umbrella accept them as top-level shortcuts (e.g. `immunity
# status` -> warden.cli ['status']), and (b) drives the curated --help.
#
# These names match argparse subparsers declared in warden.cli:build_parser().
_TOP_LEVEL_SHORTCUTS = {
    # Common, frequently-typed:
    "setup", "status", "audit", "info", "dashboard", "serve",
    "check", "scan", "deps",
    "analyze", "ingest", "sessions", "session",
    "install-hooks", "uninstall-hooks", "hook-dispatch",
}

# Domains that map to a warden.cli subparser of the same name.
# `immunity <domain> <action>` forwards as `warden.cli [<domain>, <action>]`.
_WARDEN_DOMAINS = {
    "cloak", "policy", "sweep", "iam", "canary", "scope", "learn",
}

_SUPPLY_DOMAIN = "supplychain"


def main(argv: Optional[List[str]] = None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    if not argv or argv[0] in ("-h", "--help", "help"):
        _print_usage()
        return

    if argv[0] in ("-V", "--version"):
        print(f"immunity {__version__}")
        return

    cmd, rest = argv[0], argv[1:]

    # `immunity warden ...` — pass through to warden.cli untouched.
    if cmd == "warden":
        from warden.cli import main as warden_main
        warden_main(rest)
        return

    # `immunity <domain> ...` where <domain> matches a warden.cli subparser.
    if cmd in _WARDEN_DOMAINS:
        from warden.cli import main as warden_main
        warden_main([cmd, *rest])
        return

    # `immunity <shortcut> ...` — same dispatch, just exposed at the top level.
    if cmd in _TOP_LEVEL_SHORTCUTS:
        from warden.cli import main as warden_main
        warden_main([cmd, *rest])
        return

    # `immunity supplychain ...` — supply-chain enforcement engine.
    if cmd == _SUPPLY_DOMAIN:
        from supplychain.cli import run_supply
        run_supply(rest)
        return

    sys.stderr.write(
        f"immunity: unknown command '{cmd}'.\n"
        f"  Run 'immunity --help' to see all commands.\n"
    )
    sys.exit(2)


def _print_usage() -> None:
    def b(t: str) -> str: return _c(t, _BOLD)
    def d(t: str) -> str: return _c(t, _DIM)

    print()
    print(f"  {b('immunity')} — runtime security for AI coding agents")
    print()
    print(f"  Usage: {b('immunity')} <command> [options...]")
    print()
    print(f"  {b('Quick start')}")
    print(f"    immunity setup              {d('Interactive onboarding wizard')}")
    print(f"    immunity status             {d('One-shot health check: hooks, mode, cloak, latest session')}")
    print(f"    immunity audit              {d('Full security posture audit')}")
    print(f"    immunity info               {d('Workspace summary (deprecated alias of status)')}")
    print()
    print(f"  {b('Domains')}  {d('(each takes an action; see `immunity <domain> --help`)')}")
    print(f"    immunity warden      <action>   {d('Runtime / session security (all warden subcommands)')}")
    print(f"    immunity cloak       <action>   {d('Secret cloaking at the tool boundary')}")
    print(f"    immunity policy      <action>   {d('Manage policy rules (init/validate/show/edit/test)')}")
    print(f"    immunity sweep       [options]  {d('Scan AI tool configs for leaked secrets')}")
    print(f"    immunity iam         <action>   {d('Agent identities and permission profiles')}")
    print(f"    immunity canary      <action>   {d('Plant and manage canarytokens')}")
    print(f"    immunity scope       <action>   {d('Session-scoped policy rules')}")
    print(f"    immunity learn       [options]  {d('Mine session history for new rules')}")
    print(f"    immunity supplychain <action>   {d('Supply chain (npm/pip/pnpm/uv/cargo/go + harden)')}")
    print()
    print(f"  {b('Runtime shortcuts')}")
    print(f"    immunity check <cmd>        {d('Pre-check a command against policy')}")
    print(f"    immunity scan               {d('Scan MCP servers and skills for security risks')}")
    print(f"    immunity deps               {d('Check workspace dependencies vs. threat feed')}")
    print(f"    immunity sessions           {d('List stored sessions')}")
    print(f"    immunity session <id>       {d('Show a specific session')}")
    print(f"    immunity analyze <file>     {d('Analyze a JSONL session file')}")
    print(f"    immunity install-hooks      {d('Install IDE hooks for real-time monitoring')}")
    print(f"    immunity uninstall-hooks    {d('Remove IDE hooks')}")
    print(f"    immunity dashboard          {d('Global overview of all registered workspaces')}")
    print(f"    immunity serve              {d('Start the local HTTP API server (web dashboard)')}")
    print()
    print(f"  {b('Supply-chain interception')}  {d('(also: pip3, pnpm, yarn, uv, cargo, go)')}")
    print(f"    immunity supplychain npm install <pkg>")
    print(f"    immunity supplychain pip install <pkg>")
    print(f"    immunity supplychain harden [--dry-run] [PATH]")
    print()
    print(f"  {b('Help & version')}")
    print(f"    immunity --help             {d('This message')}")
    print(f"    immunity <command> --help   {d('Help for a specific command')}")
    print(f"    immunity --version          {d('Show version')}")
    print()


def _warden_shim() -> None:
    """Deprecation shim installed as the 'warden' entry point.

    Replaces the old standalone binary on upgrade so users who still have
    'warden' in aliases or scripts get a clear migration message instead of
    silently running stale code.  All arguments are forwarded to immunity
    unchanged, so existing invocations keep working.
    """
    import sys
    sys.stderr.write(
        "Warning: 'warden' is deprecated and will be removed in a future release.\n"
        "Use 'immunity' instead — it is a drop-in replacement.\n\n"
    )
    main()


if __name__ == "__main__":
    main()
