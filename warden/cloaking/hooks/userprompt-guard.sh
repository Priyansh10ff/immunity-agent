#!/usr/bin/env bash
# Prismor Warden — cloaking UserPromptSubmit hook (soft-block).
#
# Scans the user's submitted prompt for recognizable secret patterns. On a
# match, auto-cloaks the value (writes it to $PRISMOR_SECRETS_DIR with a
# hashed name) and BLOCKS the prompt with a reason that shows the sanitized
# version. The user copies the sanitized prompt and resubmits — from that
# point forward, the model only ever sees the `@@SECRET:auto_xxxxxx@@`
# placeholder, never the raw value.
#
# UserPromptSubmit hooks cannot rewrite the prompt (Claude Code exposes only
# block/add-context on this event). One re-paste is the smallest achievable
# UX cost for a leak-proof user-prompt boundary.
#
# Stdin:  Claude Code UserPromptSubmit JSON payload
# Stdout: JSON with decision=block and a reason (if a secret was detected),
#         or empty (no-op) otherwise.
set -uo pipefail

SECRETS_DIR="${PRISMOR_SECRETS_DIR:-$HOME/.prismor/secrets}"
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR" 2>/dev/null || true

command -v jq >/dev/null 2>&1 || exit 0

input="$(cat)"
prompt="$(printf '%s' "$input" | jq -r '.prompt // empty')"
[[ -n "$prompt" ]] || exit 0

# Optional user bypass: a prompt starting with `!!allow ` (ignoring leading
# whitespace) is passed through unchanged. Useful when the user is deliberately
# discussing a secret in prose and doesn't want auto-cloaking.
trimmed="$(printf '%s' "$prompt" | sed 's/^[[:space:]]*//')"
if [[ "$trimmed" == "!!allow "* ]]; then
  exit 0
fi

# ── Detection patterns ────────────────────────────────────────────────────
# Conservative, known-prefix only. Order matters — longest/most-specific
# first so partial matches don't fire for the wrong pattern.
PATTERNS=(
  'sk_live_[0-9a-zA-Z]{16,}'          # Stripe live
  'sk_test_[0-9a-zA-Z]{16,}'          # Stripe test
  'rk_live_[0-9a-zA-Z]{16,}'          # Stripe restricted
  'github_pat_[0-9a-zA-Z_]{20,}'      # GitHub fine-grained PAT
  'ghp_[0-9a-zA-Z]{36}'               # GitHub PAT
  'gho_[0-9a-zA-Z]{36}'               # GitHub OAuth
  'ghs_[0-9a-zA-Z]{36}'               # GitHub server
  'ghu_[0-9a-zA-Z]{36}'               # GitHub user-to-server
  'AKIA[0-9A-Z]{16}'                  # AWS access key ID
  'ASIA[0-9A-Z]{16}'                  # AWS temp access key
  'AIza[0-9A-Za-z_-]{35}'             # Google API key
  'xox[bpoar]-[0-9]+-[0-9]+-[0-9a-zA-Z]{24,}'  # Slack tokens
  'glpat-[0-9a-zA-Z_-]{20,}'          # GitLab PAT
  'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'  # JWT
)

# Collect unique matches across all patterns.
matches="$(
  for pat in "${PATTERNS[@]}"; do
    printf '%s' "$prompt" | grep -oE "$pat" || true
  done | awk 'NF && !seen[$0]++'
)"

[[ -n "$matches" ]] || exit 0

# ── Cloak each match ─────────────────────────────────────────────────────
sanitized="$prompt"
reported_placeholders=""
while IFS= read -r real_value; do
  [[ -z "$real_value" ]] && continue

  # Deterministic placeholder name from value hash (first 8 hex chars).
  # Same value → same placeholder across sessions (no duplicate registration).
  hash="$(printf '%s' "$real_value" | shasum -a 256 | awk '{print $1}' | cut -c1-8)"
  placeholder_name="auto_${hash}"
  placeholder="@@SECRET:${placeholder_name}@@"
  secret_file="$SECRETS_DIR/$placeholder_name"

  # Only write if new — avoid touching mtime on existing entries.
  if [[ ! -f "$secret_file" ]]; then
    printf '%s' "$real_value" > "$secret_file"
    chmod 600 "$secret_file" 2>/dev/null || true
  fi

  # Substitute every occurrence of this value in the sanitized prompt.
  sanitized="${sanitized//"$real_value"/$placeholder}"
  reported_placeholders+="  • $placeholder"$'\n'
done <<< "$matches"

# ── Emit soft-block decision ──────────────────────────────────────────────
reason="Prismor cloaking: detected secret(s) in your prompt.

Stored under ${SECRETS_DIR} as:
${reported_placeholders%$'\n'}

Your original prompt was NOT sent to the model. Resubmit with the sanitized
version below (the model will resolve each placeholder at tool-call time):

---
${sanitized}
---

Prefix your prompt with '!!allow ' to bypass detection for a single message."

jq -n --arg r "$reason" '{decision: "block", reason: $r}'
