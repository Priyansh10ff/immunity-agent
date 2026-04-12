from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

CATEGORY_TO_FEED_TYPES = {
    "prompt_injection": {"prompt_injection", "jailbreak", "policy_bypass"},
    "destructive_command": {"unsafe_tool_execution", "policy_bypass"},
    "remote_execution": {"unsafe_tool_execution", "policy_bypass"},
    "secret_access": {"data_exfiltration", "policy_bypass"},
    "secret_exfiltration": {"data_exfiltration", "policy_bypass"},
    "risky_write": {"unsafe_tool_execution", "dependency_vulnerability"},
    "dependency_risk": {"dependency_vulnerability"},
    "dos_resource_exhaustion": {"model_denial_of_service"},
    "rce_canary": {"unsafe_tool_execution"},
    "db_modification": {"unsafe_tool_execution", "policy_bypass"},
    "db_access": {"data_exfiltration"},
    "privilege_escalation": {"policy_bypass"},
    "path_traversal": {"data_exfiltration"},
    "skill_risk": {"unsafe_tool_execution", "policy_bypass", "prompt_injection"},
    "network_isolation": {"data_exfiltration", "unsafe_tool_execution"},
}


def load_feed(repo_root: Path) -> Dict[str, Any]:
    feed_path = repo_root / "advisories" / "immunity-feed.json"
    with feed_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def match_advisories(findings: List[Dict[str, Any]], feed: Dict[str, Any], limit: int = 5) -> List[Dict[str, Any]]:
    desired_types = set()
    for finding in findings:
      desired_types.update(CATEGORY_TO_FEED_TYPES.get(finding.get("category", ""), set()))

    if not desired_types:
        return []

    advisories = feed.get("advisories", [])
    matches = [advisory for advisory in advisories if advisory.get("type") in desired_types]
    matches.sort(key=lambda advisory: _severity_rank(advisory.get("severity", "unknown")), reverse=True)
    return matches[:limit]


def _severity_rank(severity: str) -> int:
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "unknown": 1,
    }.get(str(severity).lower(), 0)
