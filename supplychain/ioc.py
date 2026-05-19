"""IOC (Indicators of Compromise) database for known supply chain attacks.

Mini Shai-Hulud - May 11, 2026
  TanStack/router GitHub Actions pwn-request + pnpm cache poisoning
  -> OIDC token extraction -> npm publish with valid SLSA Build Level 3 attestations
  -> preinstall scripts deliver Bun runtime + credential harvester (router_init.js,
     tanstack_runner.js) via setup.mjs + optionalDependencies pointing to malicious
     GitHub commits
  -> PyPI variant: mistralai==2.4.6 and guardrails-ai==0.10.1 inject into __init__.py,
     download transformers.pyz on import
  -> exfiltration via filev2.getsession.org, git-tanstack.com
  -> probes AWS metadata (169.254.169.254) and HashiCorp Vault (127.0.0.1:8200)
  -> GitHub GraphQL C2: encodes instructions in commit messages, exfiltrates via
     repo contents, worm-spreads via createCommitOnBranch to feature branches
  -> persistence: .claude/settings.json, .claude/setup.mjs, .claude/router_runtime.js,
     .vscode/tasks.json, .vscode/setup.mjs
  -> attribution: TeamPCP - same actor as March 2026 Trivy supply chain compromise

References:
  https://prismor.dev/blog/tanstack-mistral-mini-shai-hulud-supply-chain
  https://snyk.io/blog/tanstack-npm-packages-compromised/
  https://safedep.io/mass-npm-supply-chain-attack-tanstack-mistral/

AntV Hijacked Maintainer - May 19, 2026
  atool maintainer account hijacked -> coordinated malicious publish wave across @antv/*
  -> 300+ versions published May 19 2026; highest-impact packages listed in COMPROMISED_VERSIONS
  -> echarts-for-react, timeago.js, size-sensor, canvas-nest.js caught in same wave
     (shared maintainer identity, outside @antv namespace)
  -> preinstall hook fetches Bun from GitHub Releases, executes ~11.7 MB obfuscated JS payload
  -> exfiltration via git-tanstack.com; credential receiver at api.masscan.cloud
  -> persistence: gh-token-monitor service, new GitHub Actions workflows in repos with npm publish access
  -> any @antv/* version published on or after May 19 2026 is suspect; see COMPROMISED_NAMESPACES
  -> attribution: TeamPCP

References:
  https://prismor.dev/blog/antv-npm-packages-compromised-supply-chain
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
    force_block: bool = True   # bypass score threshold - always block


# ── Compromised package version ranges ───────────────────────────────────────
# Maps exact package name (npm or pypi) -> list of affected version ranges.
_COMPROMISED_VERSIONS: dict = {
    # ── AntV hijacked-maintainer attack (May 19, 2026) ───────────────────────
    # Highest-impact packages. Full wave touched 300+ versions across @antv/*;
    # any @antv/* published May 19 2026 is also caught by _COMPROMISED_NAMESPACES.
    "@antv/g2": [
        {"min": "5.5.8", "max": "5.5.8", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026 via hijacked atool account. Safe: ≤ 5.4.8"},
        {"min": "5.6.8", "max": "5.6.8", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026 via hijacked atool account. Safe: ≤ 5.4.8"},
    ],
    "@antv/g6": [
        {"min": "5.2.1", "max": "5.2.1", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 5.2.1"},
        {"min": "5.3.1", "max": "5.3.1", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 5.2.1"},
    ],
    "@antv/x6": [
        {"min": "3.2.7", "max": "3.2.7", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 3.2.7"},
        {"min": "3.3.7", "max": "3.3.7", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 3.2.7"},
    ],
    "@antv/g2plot": [
        {"min": "2.5.35", "max": "2.5.35", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 2.5.35"},
        {"min": "2.6.35", "max": "2.6.35", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 2.5.35"},
    ],
    "@antv/s2": [
        {"min": "2.8.1", "max": "2.8.1", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 2.8.1"},
        {"min": "2.9.1", "max": "2.9.1", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 2.8.1"},
    ],
    "@antv/f2": [
        {"min": "5.15.0", "max": "5.15.0", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 5.15.0"},
        {"min": "5.16.0", "max": "5.16.0", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 5.15.0"},
    ],
    "@antv/graphin": [
        {"min": "3.1.5", "max": "3.1.5", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 3.1.5"},
        {"min": "3.2.5", "max": "3.2.5", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 3.1.5"},
    ],
    "@antv/data-set": [
        {"min": "0.12.8", "max": "0.12.8", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 0.12.8"},
        {"min": "0.13.8", "max": "0.13.8", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 0.12.8"},
    ],
    "@antv/g": [
        {"min": "6.4.1", "max": "6.4.1", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 6.4.1"},
        {"min": "6.5.1", "max": "6.5.1", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 6.4.1"},
    ],
    "@antv/l7": [
        {"min": "2.26.10", "max": "2.26.10", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 2.26.10"},
        {"min": "2.27.10", "max": "2.27.10", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 2.26.10"},
    ],
    "@antv/graphlib": [
        {"min": "2.1.4", "max": "2.1.4", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 2.1.4"},
        {"min": "2.2.4", "max": "2.2.4", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 2.1.4"},
    ],
    # Outside @antv namespace — caught by shared maintainer identity (atool account)
    "echarts-for-react": [
        {"min": "3.0.7", "max": "3.0.7", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026 (3 bumps same day). Safe: ≤ 3.0.6"},
        {"min": "3.1.7", "max": "3.1.7", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: ≤ 3.0.6"},
        {"min": "3.2.7", "max": "3.2.7", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: ≤ 3.0.6"},
    ],
    "timeago.js": [
        {"min": "4.1.2", "max": "4.1.2", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 4.1.2"},
        {"min": "4.2.2", "max": "4.2.2", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 4.1.2"},
    ],
    "timeago-react": [
        {"min": "3.1.7", "max": "3.1.7", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 3.1.7"},
        {"min": "3.2.7", "max": "3.2.7", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 3.1.7"},
    ],
    "size-sensor": [
        {"min": "1.1.4", "max": "1.1.4", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 1.1.4"},
        {"min": "1.2.4", "max": "1.2.4", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 1.1.4"},
    ],
    "canvas-nest.js": [
        {"min": "2.1.4", "max": "2.1.4", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 2.1.4"},
        {"min": "2.2.4", "max": "2.2.4", "attack": "antv-hijacked-maintainer-2026-05-19",
         "note": "malicious publish May 19 2026. Safe: < 2.1.4"},
    ],
    # ── Mini Shai-Hulud (May 11, 2026) ───────────────────────────────────────
    # npm
    "@mistralai/mistralai": [
        {
            "min": "1.7.1", "max": "2.2.4",
            "attack": "mini-shai-hulud-2026-05-11",
            "note": "compromised versions published May 11 2026 via CI cache poisoning",
        }
    ],
    # PyPI - version-bumped fakes published alongside npm attack
    "mistralai": [
        {
            "min": "2.4.6", "max": "2.4.6",
            "attack": "mini-shai-hulud-2026-05-11",
            "note": (
                "PyPI mistralai==2.4.6 is malicious (legitimate latest is 2.4.5). "
                "Payload injected into __init__.py, downloads /tmp/transformers.pyz on import."
            ),
        }
    ],
    "guardrails-ai": [
        {
            "min": "0.10.1", "max": "0.10.1",
            "attack": "mini-shai-hulud-2026-05-11",
            "note": (
                "PyPI guardrails-ai==0.10.1 is malicious (legitimate latest is 0.10.0). "
                "Payload injected into __init__.py, downloads /tmp/transformers.pyz on import."
            ),
        }
    ],
}

# ── Compromised namespaces ────────────────────────────────────────────────────
# All versions published under these prefixes on or after the attack date are suspect.
_COMPROMISED_NAMESPACES: dict = {
    "@antv/": {
        "attack": "antv-hijacked-maintainer-2026-05-19",
        "affected_date": "2026-05-19",
        "note": (
            "Full @antv/* namespace compromised May 19 2026 via hijacked atool maintainer account. "
            "Over 300 versions published. Any @antv/* version published on or after May 19 2026 "
            "is suspect. Highest-impact packages are also listed individually in COMPROMISED_VERSIONS. "
            "Safe versions are those published before May 19 2026."
        ),
    },
    "@tanstack/": {
        "attack": "mini-shai-hulud-2026-05-11",
        "affected_date": "2026-05-11",
        "note": (
            "42 @tanstack/* packages compromised May 11 2026 via CI/CD cache poisoning "
            "via malicious commit tanstack/router@79ac49ee. "
            "SLSA attestations do NOT protect against this - attacker held valid OIDC tokens."
        ),
    },
    "@opensearch-project/": {
        "attack": "mini-shai-hulud-2026-05-11",
        "affected_date": "2026-05-11",
        "note": (
            "@opensearch-project/* packages affected (1.3M+ weekly downloads). "
            "Compromised May 11 2026 as part of the same campaign."
        ),
    },
    "@uipath/": {
        "attack": "mini-shai-hulud-2026-05-11",
        "affected_date": "2026-05-11",
        "note": (
            "@uipath/* - 65 packages compromised May 11 2026 as part of the same campaign."
        ),
    },
}

# ── C2 infrastructure ─────────────────────────────────────────────────────────
# Domain suffixes - matches the root domain and any subdomain.
C2_DOMAINS: frozenset = frozenset({
    "getsession.org",      # filev2.getsession.org - Session Protocol exfiltration endpoint
    "masscan.cloud",       # api.masscan.cloud - credential receiver (earlier reporting)
    "git-tanstack.com",    # phishing/C2 domain (Cloudflare-flagged) - mini-shai-hulud
})

# ── Internal infrastructure probes ───────────────────────────────────────────
# IPs/hosts the payload probes to harvest cloud credentials.
# Used in script pattern detection below.
_IMDS_PROBES = [
    "169.254.169.254",   # AWS instance metadata service
    "127.0.0.1:8200",    # HashiCorp Vault default local address
]

# ── Malicious file hashes (SHA-256) ──────────────────────────────────────────
MALICIOUS_HASHES: dict = {
    "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c": (
        "router_init.js - 2.3 MB Bun credential harvester (mini-shai-hulud-2026-05-11)"
    ),
    "ce7e4199506959fd7a71b64209b2c07b9c82e53a946aa7d78298dc9249230d01": (
        "tanstack_runner.js - Bun credential harvester variant (mini-shai-hulud-2026-05-11)"
    ),
}

# ── Malicious commit SHAs ─────────────────────────────────────────────────────
MALICIOUS_COMMITS: dict = {
    "79ac49eedf774dd4b0cfa308722bc463cfe5885c": (
        "tanstack/router - poisoned CI cache commit (mini-shai-hulud-2026-05-11)"
    ),
}

# ── Install script patterns ───────────────────────────────────────────────────
# (compiled_regex, human_description, severity)
# Ordered: CRITICAL patterns first.
_SCRIPT_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    # C2 domains
    (re.compile(r"getsession\.org", re.I),
     "C2 domain in install script: getsession.org", "CRITICAL"),
    (re.compile(r"masscan\.cloud", re.I),
     "C2 domain in install script: masscan.cloud", "CRITICAL"),
    (re.compile(r"git-tanstack\.com", re.I),
     "C2 domain in install script: git-tanstack.com (phishing domain)", "CRITICAL"),

    # Known malicious payloads
    (re.compile(r"router_init\.js", re.I),
     "known malicious payload: router_init.js", "CRITICAL"),
    (re.compile(r"tanstack_runner\.js", re.I),
     "known malicious payload: tanstack_runner.js", "CRITICAL"),
    (re.compile(r"transformers\.pyz", re.I),
     "known malicious payload: transformers.pyz (PyPI variant)", "CRITICAL"),
    (re.compile(r"setup\.mjs", re.I),
     "known malicious dropper: setup.mjs", "CRITICAL"),
    (re.compile(r"ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c", re.I),
     "known malicious SHA-256: router_init.js", "CRITICAL"),
    (re.compile(r"ce7e4199506959fd7a71b64209b2c07b9c82e53a946aa7d78298dc9249230d01", re.I),
     "known malicious SHA-256: tanstack_runner.js", "CRITICAL"),

    # Bun runtime (hallmark of this attack class)
    (re.compile(r"(curl|wget).{0,80}bun\.sh", re.I),
     "Bun runtime downloaded in install script", "CRITICAL"),
    (re.compile(r"\bbun\s+(run|x)\b", re.I),
     "Bun runtime execution in install script", "HIGH"),

    # AWS metadata service probe
    (re.compile(r"169\.254\.169\.254", re.I),
     "AWS instance metadata probe (credential harvesting)", "CRITICAL"),

    # HashiCorp Vault probe
    (re.compile(r"127\.0\.0\.1:8200", re.I),
     "HashiCorp Vault probe (credential harvesting)", "CRITICAL"),

    # GitHub GraphQL C2 (commit message encoding / repo contents exfil)
    (re.compile(r"api\.github\.com/graphql", re.I),
     "GitHub GraphQL API called from install script (possible C2 channel)", "HIGH"),
    (re.compile(r"createCommitOnBranch", re.I),
     "GitHub GraphQL createCommitOnBranch mutation (worm propagation)", "CRITICAL"),

    # Token pattern harvesting
    (re.compile(r"ghp_[A-Za-z0-9]{36}", re.I),
     "GitHub personal access token pattern in install script", "CRITICAL"),
    (re.compile(r"npm_[A-Za-z0-9]{36}", re.I),
     "npm publish token pattern in install script", "CRITICAL"),
    (re.compile(r"process\.env\.(AWS_SECRET|AWS_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN|KUBECONFIG|VAULT_TOKEN)", re.I),
     "credential env var accessed in install script", "HIGH"),

    # Persistence targets
    (re.compile(r"\.claude[/\\]settings\.json", re.I),
     "writes to .claude/settings.json (persistence)", "HIGH"),
    (re.compile(r"\.claude[/\\]setup\.mjs", re.I),
     "writes to .claude/setup.mjs (persistence dropper)", "CRITICAL"),
    (re.compile(r"\.claude[/\\]router_runtime\.js", re.I),
     "writes to .claude/router_runtime.js (persistence payload)", "CRITICAL"),
    (re.compile(r"\.vscode[/\\]tasks\.json", re.I),
     "writes to .vscode/tasks.json (persistence)", "HIGH"),
    (re.compile(r"\.vscode[/\\]setup\.mjs", re.I),
     "writes to .vscode/setup.mjs (persistence dropper)", "CRITICAL"),

    # Generic exfiltration
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
                            f"{name}@{version} - known compromised version "
                            f"({r['min']}-{r['max']}). {r['note']}"
                        ),
                        attack_name=r["attack"],
                    )
                elif not version:
                    return IOCMatch(
                        ioc_id=r["attack"],
                        severity="HIGH",
                        description=(
                            f"{name} - versions {r['min']}-{r['max']} are compromised. "
                            "Resolve to a specific safe version."
                        ),
                        attack_name=r["attack"],
                        force_block=False,
                    )

    # Namespace match
    for ns, info in _COMPROMISED_NAMESPACES.items():
        if name_lower.startswith(ns.lower()):
            return IOCMatch(
                ioc_id=info["attack"],
                severity="CRITICAL",
                description=f"{name} - {info['note']}",
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
