"""Prismor Warden — tokenization subsystem.

Prevention layer that keeps real secret values out of AI coding agent
context, JSONL transcripts, and upstream API requests. Complements
``warden sweep`` (post-hoc remediation) by providing realtime protection
at the tool boundary via Claude Code hooks.

Public entry points (imported by ``warden/cli.py``):
  install    — merge tokenization hooks into .claude/settings.json
  uninstall  — remove them
  add_secret — register a real secret value under a placeholder name
  list_secrets   — list registered placeholder names (never values)
  remove_secret  — delete a registered secret
  secrets_dir    — path to the secrets directory (honors $PRISMOR_SECRETS_DIR)
"""
from __future__ import annotations

from warden.tokenization.installer import install, uninstall, status
from warden.tokenization.secrets_store import (
    add_secret,
    list_secrets,
    remove_secret,
    secrets_dir,
)

__all__ = [
    "install",
    "uninstall",
    "status",
    "add_secret",
    "list_secrets",
    "remove_secret",
    "secrets_dir",
]
