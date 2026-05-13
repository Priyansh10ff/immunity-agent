"""immunity — supply chain enforcement CLI.

Usage:
  immunity npm install express
  immunity pip install requests numpy
  immunity pnpm add lodash
  immunity uv add fastapi
  immunity cargo add serde
  immunity go get github.com/some/pkg

Any command that isn't a recognised package install is passed through
transparently — so you can alias npm/pip to immunity without breakage.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List

_REPO_ROOT = Path(__file__).resolve().parent.parent

# ── ANSI colours (same palette as warden/cli.py) ─────────────────────────────
_RED    = "\033[0;31m"
_YELLOW = "\033[1;33m"
_GREEN  = "\033[0;32m"
_DIM    = "\033[37m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"


def _c(text: str, colour: str) -> str:
    if sys.stdout.isatty():
        return f"{colour}{text}{_RESET}"
    return text


def _ce(text: str, colour: str) -> str:
    if sys.stderr.isatty():
        return f"{colour}{text}{_RESET}"
    return text


# ── Feed helpers (reuse existing warden modules, don't re-implement) ──────────

def _load_feed() -> dict:
    try:
        from warden.feed import load_feed
        return load_feed(_REPO_ROOT)
    except Exception:
        return {"advisories": []}


def _check_feed(packages, feed: dict) -> list:
    try:
        from warden.deps import check_against_feed
        deps = [{"name": p.name, "version": "", "ecosystem": ""} for p in packages]
        return check_against_feed(deps, feed)
    except Exception:
        return []


# ── Output ────────────────────────────────────────────────────────────────────

def _print_report(event, verdicts, feed_hits: list) -> None:
    from supplychain.scoring.engine import PackageVerdict

    print()
    print(f"  {_c('IMMUNITY', _BOLD)}  supply chain  {_c(f'[{event.ecosystem}]', _DIM)}")
    print(f"  {_c('─' * 52, _DIM)}")
    print()

    for v in verdicts:
        if v.verdict == "block":
            badge = _c("BLOCK", _RED)
            score_str = _c(f"score {v.score:>3}", _RED)
        elif v.verdict == "warn":
            badge = _c("WARN ", _YELLOW)
            score_str = _c(f"score {v.score:>3}", _YELLOW)
        else:
            badge = _c("ALLOW", _GREEN)
            score_str = _c(f"score {v.score:>3}", _DIM)

        meta_parts: List[str] = []
        if v.meta.age_days is not None:
            meta_parts.append(f"age {v.meta.age_days}d")
        if v.meta.maintainer_count is not None:
            n = v.meta.maintainer_count
            meta_parts.append(f"{n} maintainer{'s' if n != 1 else ''}")
        if v.meta.fetch_error:
            meta_parts.append(_c(f"[{v.meta.fetch_error}]", _DIM))

        meta_str = "  " + ", ".join(meta_parts) if meta_parts else ""
        print(f"  {badge}  {score_str}  {v.spec.raw}{meta_str}")

        for sig in v.signals:
            print(f"             {_c(f'+{sig.points}', _DIM)} {sig.description}")
        if v.signals:
            print()

    if not any(v.signals for v in verdicts):
        print()  # trailing blank line when all are clean

    if feed_hits:
        print(f"  {_c('Advisory matches:', _YELLOW)}")
        for hit in feed_hits:
            sev = hit.get("severity", "").upper()
            print(f"    {_ce(sev, _RED)}  {hit.get('title', '')}")
        print()


# ── Process replacement ───────────────────────────────────────────────────────

def _exec(argv: List[str]) -> None:
    """Replace the current process with the real command — transparent passthrough."""
    import shutil
    binary = shutil.which(argv[0])
    if binary is None:
        sys.stderr.write(f"immunity: command not found: {argv[0]}\n")
        sys.exit(127)
    os.execv(binary, argv)


# ── Store integration ─────────────────────────────────────────────────────────

def _record_to_store(event, verdicts) -> None:
    """Write scoring results to the warden store. Fail-open."""
    try:
        import uuid
        from datetime import datetime, timezone
        from warden.store import infer_default_workspace, write_supply_chain_event
        workspace = infer_default_workspace(Path.cwd())
        write_supply_chain_event(
            workspace=workspace,
            session_id=f"immunity-{uuid.uuid4().hex[:16]}",
            ts=datetime.now(timezone.utc).isoformat(),
            ecosystem=event.ecosystem,
            install_cmd=" ".join(sys.argv[1:]),
            verdicts=verdicts,
        )
    except Exception:
        pass


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    argv = sys.argv[1:]

    if not argv or argv[0] in ("-h", "--help"):
        _usage()
        return

    # Add repo root to path so warden imports work when called as a script
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))

    from supplychain.ecosystems.detector import detect_install
    event = detect_install(argv)

    # Not a recognised install command — hand off transparently
    if event is None:
        _exec(argv)
        return  # unreachable; satisfies type checkers

    # Bare manifest install (e.g. `npm install` with no packages) — pass through
    if not event.packages:
        _exec(argv)
        return

    # ── Evaluate ──────────────────────────────────────────────────────────────
    from supplychain.ecosystems.metadata import fetch_metadata
    from supplychain.scoring.engine import RiskScorer

    scorer = RiskScorer()
    verdicts = []
    for spec in event.packages:
        meta = fetch_metadata(spec, event.ecosystem)
        verdicts.append(scorer.score(spec, meta, event))

    # Cross-check against the existing Warden advisory feed
    feed = _load_feed()
    feed_hits = _check_feed(event.packages, feed)

    _print_report(event, verdicts, feed_hits)
    _record_to_store(event, verdicts)

    # ── Decision ──────────────────────────────────────────────────────────────
    blocked = [v for v in verdicts if v.verdict == "block"]
    warned  = [v for v in verdicts if v.verdict == "warn"]

    if blocked:
        names = ", ".join(v.spec.raw for v in blocked)
        print(
            f"  {_c('Blocked:', _RED)} {names}\n"
            f"  To override: add to supply_chain.allowlist in "
            f".prismor-warden/policy.yaml\n"
        )
        sys.exit(1)

    if warned:
        print(f"  {_c('Warning:', _YELLOW)} flagged packages above — proceeding.\n")

    _exec(argv)


def _usage() -> None:
    print(f"  {_c('immunity', _BOLD)} — AI-native supply chain enforcement")
    print()
    print("  Usage: immunity <command> [args...]")
    print()
    print("  Examples:")
    print("    immunity npm install express")
    print("    immunity pip install requests numpy")
    print("    immunity pnpm add lodash")
    print("    immunity uv add fastapi")
    print("    immunity cargo add serde")
    print("    immunity go get github.com/some/pkg")
    print()
    print("  Non-install commands pass through transparently.")
    print()


if __name__ == "__main__":
    main()
