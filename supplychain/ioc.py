"""IOC (Indicators of Compromise) database for known supply chain attacks.

Mini Shai-Hulud — May 11, 2026
  TanStack/router GitHub Actions pwn-request + pnpm cache poisoning
  → OIDC token extraction → npm publish with valid SLSA Build Level 3 attestations
  → preinstall scripts deliver Bun runtime + 2.3 MB credential harvester (router_init.js)
  → exfiltration via *.getsession.org and api.masscan.cloud
  → persistence: .claude/settings.json, .vscode/tasks.json, system deadman's switch

References:
  https://prismor.dev/blog/tanstack-mistral-mini-shai-hulud-supply-chain
  https://snyk.io/blog/tanstack-npm-packages-compromised/
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class IOCMatch:
    ioc_id: str
    severity: str          # "CRITICAL" | "HIGH"
    description: str
    attack_name: str
    force_block: bool = True   # bypass score threshold — always block


# ── Compromised package version ranges ───────────────────────────────────────
# Maps exact package name → list of affected version ranges.
_COMPROMISED_VERSIONS: dict = {
    "@mistralai/mistralai": [
        {
            "min": "1.7.1", "max": "2.2.4",
            "attack": "mini-shai-hulud-2026-05-11",
            "note": "84 compromised versions published May 11 2026 via CI cache poisoning",
        }
    ],
}

# Namespaces where ALL versions published on the attack date are suspect.
# Format: namespace_prefix → {attack, affected_date, note}
_COMPROMISED_NAMESPACES: dict = {
    "@tanstack/": {
        "attack": "mini-shai-hulud-2026-05-11",
        "affected_date": "2026-05-11",
        "note": (
            "42 @tanstack/* packages compromised May 11 2026 via CI/CD cache poisoning. "
            "Verify SLSA attestations do NOT protect against this — attacker held valid "
            "OIDC tokens at publish time."
        ),
    },
}

# ── C2 infrastructure ─────────────────────────────────────────────────────────
# Domain suffixes — matches the root domain and any subdomain.
C2_DOMAINS: frozenset = frozenset({
    "getsession.org",    # Session Protocol relay network — *.getsession.org
    "masscan.cloud",     # api.masscan.cloud credential receiver
})

# ── Malicious file hashes (SHA-256) ──────────────────────────────────────────
MALICIOUS_HASHES: dict = {
    "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c": (
        "router_init.js — 2.3 MB Bun credential harvester (mini-shai-hulud-2026-05-11)"
    ),
}

# ── Install script patterns ───────────────────────────────────────────────────
# (compiled_regex, human_description, severity)
# Ordered: CRITICAL patterns first.
_SCRIPT_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    # Direct C2 references in scripts
    (re.compile(r"getsession\.org", re.I),
     "C2 domain in install script: getsession.org", "CRITICAL"),
    (re.compile(r"masscan\.cloud", re.I),
     "C2 domain in install script: api.masscan.cloud", "CRITICAL"),

    # Known malicious payload
    (re.compile(r"router_init\.js", re.I),
     "known malicious payload referenced: router_init.js", "CRITICAL"),
    (re.compile(r"ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c", re.I),
     "known malicious SHA-256 in script", "CRITICAL"),

    # Bun runtime download/execution (hallmark of this attack class)
    (re.compile(r"(curl|wget).{0,80}bun\.sh", re.I),
     "Bun runtime downloaded in install script", "CRITICAL"),
    (re.compile(r"\bbun\s+(run|x)\b", re.I),
     "Bun runtime execution in install script", "HIGH"),

    # Credential env var harvesting
    (re.compile(r"process\.env\.(AWS_SECRET|AWS_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN|KUBECONFIG)", re.I),
     "credential env var accessed in install script", "HIGH"),

    # Persistence targets
    (re.compile(r"\.claude[/\\\\]settings\.json", re.I),
     "writes to .claude/settings.json (persistence)", "HIGH"),
    (re.compile(r"\.vscode[/\\\\]tasks\.json", re.I),
     "writes to .vscode/tasks.json (persistence)", "HIGH"),

    # Generic exfiltration patterns (not attack-specific but elevated by context)
    (re.compile(r"curl\s.{0,60}\$\{?(HOME|USER|AWS|GITHUB|NPM)", re.I),
     "curl exfiltrating env/home in install script", "HIGH"),
]


# ── Public API ────────────────────────────────────────────────────────────────

def check_package(name: str, version: Optional[str]) -> Optional[IOCMatch]:
    """Return an IOCMatch if the package name/version is a known IOC, else None."""
    name_lower = name.lower()

    # Exact package + version range
    for pkg, ranges in _COMPROMISED_VERSIONS.items():
        if name_lower == pkg.lower():
            for r in ranges:
                if version and _in_range(version, r["min"], r["max"]):
                    return IOCMatch(
                        ioc_id=r["attack"],
                        severity="CRITICAL",
                        description=(
                            f"{name}@{version} — known compromised version "
                            f"({r['min']}–{r['max']}). {r['note']}"
                        ),
                        attack_name=r["attack"],
                    )
                elif not version:
                    # Can't confirm version — flag as HIGH until we can check
                    return IOCMatch(
                        ioc_id=r["attack"],
                        severity="HIGH",
                        description=(
                            f"{name} — versions {r['min']}–{r['max']} are compromised. "
                            "Resolve to a specific safe version."
                        ),
                        attack_name=r["attack"],
                        force_block=False,  # warn, not block, without confirmed version
                    )

    # Namespace match
    for ns, info in _COMPROMISED_NAMESPACES.items():
        if name_lower.startswith(ns.lower()):
            return IOCMatch(
                ioc_id=info["attack"],
                severity="CRITICAL",
                description=f"{name} — {info['note']}",
                attack_name=info["attack"],
            )

    return None


def check_script(script_content: str) -> List[Tuple[str, str]]:
    """Scan an install script string for attack-specific patterns.

    Returns list of (description, severity) tuples for every match.
    """
    hits: List[Tuple[str, str]] = []
    for pattern, description, severity in _SCRIPT_PATTERNS:
        if pattern.search(script_content):
            hits.append((description, severity))
    return hits


def is_c2_domain(domain: str) -> bool:
    """Return True if the domain matches known C2 infrastructure."""
    d = domain.lower().strip().lstrip("*.")
    return any(d == c2 or d.endswith("." + c2) for c2 in C2_DOMAINS)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _in_range(version: str, min_v: str, max_v: str) -> bool:
    """Simple semver tuple comparison (major.minor.patch).

    Pre-release suffixes (1.7.1-rc1, 2.0.0-beta.1) are stripped before
    comparison so compromised pre-release builds aren't silently skipped.
    """
    try:
        def _t(v: str) -> tuple:
            # Strip pre-release/build suffix: "1.7.1-rc1" → "1.7.1"
            core = v.split("-")[0].split("+")[0]
            return tuple(int(x) for x in core.split(".")[:3])
        return _t(min_v) <= _t(version) <= _t(max_v)
    except (ValueError, TypeError):
        return False
