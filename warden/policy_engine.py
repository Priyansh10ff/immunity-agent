"""YAML-based policy engine for Warden.

Loads detection rules from default_policy.yaml, merges with project-level
overrides from .prismor-warden/policy.yaml, compiles regex patterns, and
evaluates events. Replaces the hardcoded patterns in policies.py.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]


_DEFAULT_POLICY_PATH = Path(__file__).parent / "default_policy.yaml"

# Canonical field for each event type when 'fields' is not specified in the rule.
_DEFAULT_FIELDS: Dict[str, List[str]] = {
    "shell": ["command"],
    "file_read": ["path"],
    "file_write": ["path"],
    "network": ["url"],
    "prompt": ["combined_text"],
    "tool_result": ["combined_text"],
    "skill_manifest": ["combined_text"],
}


class CompiledRule:
    """A single policy rule with compiled regex patterns."""

    __slots__ = (
        "id", "severity", "category", "title", "event_types",
        "fields", "patterns", "action", "enabled",
        "severity_on_write", "severity_on_manifest",
    )

    def __init__(self, raw: Dict[str, Any]) -> None:
        self.id: str = raw["id"]
        self.severity: str = raw["severity"]
        self.category: str = raw["category"]
        self.title: str = raw["title"]
        self.event_types: set[str] = set(raw["event_types"])
        self.fields: List[str] = raw.get("fields") or []
        self.action: str = raw.get("action", "warn")
        self.enabled: bool = raw.get("enabled", True)
        self.severity_on_write: Optional[str] = raw.get("severity_on_write")
        self.severity_on_manifest: Optional[str] = raw.get("severity_on_manifest")

        # Compile all patterns into a single alternation for speed.
        joined = "|".join(f"(?:{p})" for p in raw["patterns"])
        self.patterns: re.Pattern[str] = re.compile(joined, re.IGNORECASE)


class AllowlistEntry:
    """A compiled allowlist entry that suppresses findings."""

    __slots__ = ("id", "rule_ids", "patterns", "reason")

    def __init__(self, raw: Dict[str, Any]) -> None:
        self.id: str = raw["id"]
        self.rule_ids: set[str] = set(raw["rule_ids"])
        self.reason: str = raw.get("reason", "")
        joined = "|".join(f"(?:{p})" for p in raw["patterns"])
        self.patterns: re.Pattern[str] = re.compile(joined, re.IGNORECASE)

    def applies_to(self, rule_id: str) -> bool:
        return "*" in self.rule_ids or rule_id in self.rule_ids


class PolicyEngine:
    """Loads, merges, and evaluates YAML-based security policies."""

    def __init__(
        self,
        workspace: Optional[Path] = None,
        policy_path: Optional[Path] = None,
    ) -> None:
        self.rules: List[CompiledRule] = []
        self.allowlists: List[AllowlistEntry] = []
        self.block_categories: set[str] = set()
        self._manifest_re: Optional[re.Pattern[str]] = None
        self._load(workspace, policy_path)

    def _load(self, workspace: Optional[Path], policy_path: Optional[Path]) -> None:
        default_raw = _load_yaml(_DEFAULT_POLICY_PATH)
        if default_raw is None:
            return

        # Start with default rules indexed by id.
        rules_by_id: Dict[str, Dict[str, Any]] = {}
        for rule in default_raw.get("rules", []):
            rules_by_id[rule["id"]] = rule

        allowlist_raw: List[Dict[str, Any]] = list(default_raw.get("allowlists", []) or [])

        # Settings start from defaults; project policy can extend or override.
        settings: Dict[str, Any] = dict(default_raw.get("settings", {}) or {})

        # Merge project-level override if present.
        override_path = policy_path
        if override_path is None and workspace is not None:
            candidate = workspace / ".prismor-warden" / "policy.yaml"
            if candidate.exists():
                override_path = candidate

        if override_path is not None and override_path.exists():
            override_raw = _load_yaml(override_path)
            if override_raw is not None:
                for rule in override_raw.get("rules", []):
                    rules_by_id[rule["id"]] = rule  # override by id
                allowlist_raw.extend(override_raw.get("allowlists", []) or [])
                # Project settings override defaults key-by-key.
                settings.update(override_raw.get("settings", {}) or {})

        # Compile settings.
        self.block_categories = set(settings.get("block_categories", []))

        manifest_pats: List[str] = settings.get("manifest_patterns", []) or []
        if manifest_pats:
            joined = "|".join(f"(?:{p})" for p in manifest_pats)
            self._manifest_re = re.compile(joined, re.IGNORECASE)

        # Compile rules.
        for rule_data in rules_by_id.values():
            if rule_data.get("enabled", True):
                self.rules.append(CompiledRule(rule_data))

        for al_data in allowlist_raw:
            self.allowlists.append(AllowlistEntry(al_data))

    def _is_manifest(self, path: str) -> bool:
        if not path or self._manifest_re is None:
            return False
        return bool(self._manifest_re.search(path))

    def evaluate(
        self,
        event: Dict[str, Any],
        index: int,
        session_id: str = "",
    ) -> List[Dict[str, Any]]:
        """Evaluate a single event against all loaded rules. Returns findings."""
        event_type = str(event.get("type", "")).lower()
        if not event_type:
            return []

        # Pre-extract fields that rules might match against.
        field_values = _extract_fields(event)
        findings: List[Dict[str, Any]] = []

        for rule in self.rules:
            if event_type not in rule.event_types:
                continue

            # Determine which fields to check.
            check_fields = rule.fields if rule.fields else _DEFAULT_FIELDS.get(event_type, [])
            matched_evidence = None

            for field_name in check_fields:
                value = field_values.get(field_name, "")
                if not value:
                    continue
                if rule.patterns.search(value):
                    matched_evidence = value
                    break

            if matched_evidence is None:
                continue

            # Check allowlist.
            if self._is_allowlisted(rule.id, matched_evidence):
                continue

            # Per-rule severity overrides (configured in YAML, not hardcoded).
            severity = rule.severity
            if rule.severity_on_write and event_type == "file_write":
                severity = rule.severity_on_write
            if rule.severity_on_manifest and self._is_manifest(field_values.get("path", "")):
                severity = rule.severity_on_manifest

            finding_id = f"{rule.id}-{index}"
            prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id

            findings.append({
                "id": prefixed_id,
                "severity": severity,
                "category": rule.category,
                "title": rule.title,
                "evidence": _truncate(matched_evidence),
                "eventIndex": index,
                "ruleId": rule.id,
                "action": rule.action,
            })

        return findings

    def check_command(self, command: str) -> List[Dict[str, Any]]:
        """Quick check: evaluate a shell command string. Returns findings."""
        event = {"type": "shell", "command": command}
        return self.evaluate(event, 0)

    def check_path(self, path: str, event_type: str = "file_read") -> List[Dict[str, Any]]:
        """Quick check: evaluate a file path. Returns findings."""
        event = {"type": event_type, "path": path}
        return self.evaluate(event, 0)

    def _is_allowlisted(self, rule_id: str, evidence: str) -> bool:
        for entry in self.allowlists:
            if entry.applies_to(rule_id) and entry.patterns.search(evidence):
                return True
        return False


# ── Shared helpers ──────────────────────────────────────────────────────────

def _extract_fields(event: Dict[str, Any]) -> Dict[str, str]:
    """Extract all matchable fields from an event."""
    combined_parts = []
    for key in ("prompt", "response", "content", "stdout", "stderr"):
        val = event.get(key)
        if val:
            combined_parts.append(str(val))

    return {
        "command": str(event.get("command", "")),
        "path": str(event.get("path", "")),
        "url": str(event.get("url", "")),
        "combined_text": "\n".join(combined_parts),
    }


def _truncate(value: str, max_length: int = 220) -> str:
    text = str(value).strip()
    return text if len(text) <= max_length else f"{text[:max_length - 3]}..."


def _load_yaml(path: Path) -> Optional[Dict[str, Any]]:
    """Load a YAML file. Falls back to basic parsing if PyYAML is missing."""
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    if yaml is not None:
        return yaml.safe_load(text)
    # Minimal fallback: try JSON (YAML is a superset of JSON).
    import json
    try:
        return json.loads(text)
    except Exception:
        print(f"Warning: PyYAML not installed, cannot load {path}", file=sys.stderr)
        return None


def validate_policy(path: Path) -> List[str]:
    """Validate a policy YAML file. Returns a list of error messages (empty = valid)."""
    errors: List[str] = []
    raw = _load_yaml(path)
    if raw is None:
        return [f"Cannot read {path}"]

    if "version" not in raw:
        errors.append("Missing required field: version")
    elif raw["version"] != "1.0":
        errors.append(f"Unsupported version: {raw['version']} (expected 1.0)")

    if "rules" not in raw:
        errors.append("Missing required field: rules")
        return errors

    seen_ids: set[str] = set()
    for i, rule in enumerate(raw.get("rules", [])):
        prefix = f"rules[{i}]"
        for field in ("id", "severity", "category", "title", "event_types", "patterns", "action"):
            if field not in rule:
                errors.append(f"{prefix}: missing required field '{field}'")

        rule_id = rule.get("id", "")
        if rule_id in seen_ids:
            errors.append(f"{prefix}: duplicate rule id '{rule_id}'")
        seen_ids.add(rule_id)

        for j, pattern in enumerate(rule.get("patterns", [])):
            try:
                re.compile(pattern)
            except re.error as e:
                errors.append(f"{prefix}.patterns[{j}]: invalid regex: {e}")

        action = rule.get("action", "")
        if action and action not in ("block", "warn", "log"):
            errors.append(f"{prefix}: invalid action '{action}' (must be block, warn, or log)")

    for i, entry in enumerate(raw.get("allowlists", []) or []):
        prefix = f"allowlists[{i}]"
        for field in ("id", "rule_ids", "patterns"):
            if field not in entry:
                errors.append(f"{prefix}: missing required field '{field}'")
        for j, pattern in enumerate(entry.get("patterns", [])):
            try:
                re.compile(pattern)
            except re.error as e:
                errors.append(f"{prefix}.patterns[{j}]: invalid regex: {e}")

    return errors
