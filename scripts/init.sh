#!/bin/bash
set -e

# Prismor Init — Add Prismor security to any project
# Usage: curl -fsSL https://raw.githubusercontent.com/PrismorSec/prismor/main/scripts/init.sh | bash
#    or: bash /path/to/prismor/scripts/init.sh [TARGET_DIR]
#
# Environment:
#   PRISMOR_MODE      observe | enforce   (default: observe)
#   PRISMOR_CLOAK     1 | true | yes      (default: off — opts into the secret
#                                          cloaking prevention layer)

PRISMOR_REPO="https://github.com/PrismorSec/prismor.git"
PRISMOR_DIR="${PRISMOR_HOME:-$HOME/.prismor}"
TARGET_DIR="${1:-.}"
MODE="${PRISMOR_MODE:-observe}"
CLOAK_RAW="$(printf '%s' "${PRISMOR_CLOAK:-}" | tr '[:upper:]' '[:lower:]')"
case "$CLOAK_RAW" in
    1|true|yes|on) CLOAK=1 ;;
    *)             CLOAK=0 ;;
esac

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[prismor]${NC} $1"; }
ok()    { echo -e "${GREEN}[prismor]${NC} $1"; }
warn()  { echo -e "${YELLOW}[prismor]${NC} $1"; }
err()   { echo -e "${RED}[prismor]${NC} $1" >&2; }

# ── Interactive TUI wizard (when stdin is a real TTY) ────────────────────
SETUP_PY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/setup.py"
if [ -t 0 ] && [ -f "$SETUP_PY" ] && command -v python3 &>/dev/null; then
    exec python3 "$SETUP_PY" "$TARGET_DIR"
fi

# ── Non-interactive / piped fallback ─────────────────────────────────────
SETUP_PY_FALLBACK="${PRISMOR_DIR}/scripts/setup.py"
if [ -f "$SETUP_PY_FALLBACK" ] && command -v python3 &>/dev/null; then
    exec python3 "$SETUP_PY_FALLBACK" "$TARGET_DIR" --non-interactive
fi

# ── Step 1: Ensure Prismor is cloned locally ────────────────────────────
if [ -d "$PRISMOR_DIR" ] && [ -f "$PRISMOR_DIR/warden/cli.py" ]; then
    info "Prismor found at $PRISMOR_DIR"
    info "Pulling latest..."
    git -C "$PRISMOR_DIR" pull --quiet 2>/dev/null || warn "Could not pull (offline?). Using existing version."
else
    info "Cloning Prismor to $PRISMOR_DIR..."
    git clone --quiet "$PRISMOR_REPO" "$PRISMOR_DIR"
    ok "Cloned."
fi

# ── Step 2: Detect IDE/agent ─────────────────────────────────────────────
TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"
AGENTS_FOUND=()

if command -v claude &>/dev/null || [ -d "$TARGET_DIR/.claude" ]; then
    AGENTS_FOUND+=("claude")
fi
if [ -d "$TARGET_DIR/.cursor" ] || [ -d "$HOME/.cursor" ]; then
    AGENTS_FOUND+=("cursor")
fi
if [ -d "$TARGET_DIR/.windsurf" ] || [ -d "$HOME/.codeium" ]; then
    AGENTS_FOUND+=("windsurf")
fi

if [ ${#AGENTS_FOUND[@]} -eq 0 ]; then
    AGENTS_FOUND=("claude")
    info "No IDE detected, defaulting to Claude Code."
fi

info "Detected agents: ${AGENTS_FOUND[*]}"

# ── Step 3: Generate CLAUDE.md (or append to existing) ──────────────────
CLAUDE_MD="$TARGET_DIR/CLAUDE.md"
PRISMOR_BLOCK="## Security (Prismor)

At the start of every session, read \`https://raw.githubusercontent.com/PrismorSec/security-playbook/main/security.md\` and follow its instructions.

This loads behavioral guardrails, secure coding rules (OWASP Top 10), and LLM security rules (OWASP LLM Top 10).

For more info: https://github.com/PrismorSec/prismor"

if [ -f "$CLAUDE_MD" ]; then
    if grep -q "Prismor" "$CLAUDE_MD" 2>/dev/null; then
        ok "CLAUDE.md already has Prismor section. Skipping."
    else
        info "Appending Prismor section to existing CLAUDE.md..."
        echo "" >> "$CLAUDE_MD"
        echo "$PRISMOR_BLOCK" >> "$CLAUDE_MD"
        ok "Appended to CLAUDE.md"
    fi
else
    info "Creating CLAUDE.md..."
    echo "$PRISMOR_BLOCK" > "$CLAUDE_MD"
    ok "Created CLAUDE.md"
fi

# ── Step 4: Install Warden hooks ────────────────────────────────────────
info "Installing Warden hooks (mode: $MODE)..."
for agent in "${AGENTS_FOUND[@]}"; do
    python3 "$PRISMOR_DIR/warden/cli.py" install-hooks \
        --agent "$agent" \
        --workspace "$TARGET_DIR" \
        --scope project \
        --mode "$MODE" 2>/dev/null && \
        ok "Installed $agent hooks" || \
        warn "Could not install $agent hooks"
done

# ── Step 4b: Cloaking hooks (opt-in) ────────────────────────────────────
if [ "$CLOAK" = "1" ]; then
    case " ${AGENTS_FOUND[*]} " in
        *" claude "*)
            if ! command -v jq >/dev/null 2>&1; then
                warn "PRISMOR_CLOAK=1 set but jq is missing — install with 'brew install jq' and re-run"
            else
                info "Installing cloaking hooks (secret prevention layer)..."
                python3 "$PRISMOR_DIR/warden/cli.py" cloak install \
                    --workspace "$TARGET_DIR" \
                    --scope project >/dev/null 2>&1 && \
                    ok "Cloaking hooks installed. Register secrets with: warden cloak add <name>" || \
                    warn "Could not install cloaking hooks"
            fi
            ;;
        *)
            warn "PRISMOR_CLOAK=1 set but no Claude Code agent detected — cloaking supports Claude Code only"
            ;;
    esac
fi

# ── Step 5: Verify feed ─────────────────────────────────────────────────
if [ -f "$PRISMOR_DIR/keys/public.pub" ]; then
    if bash "$PRISMOR_DIR/scripts/verify_feed.sh" "$PRISMOR_DIR/advisories/immunity-feed.json" "$PRISMOR_DIR/keys/public.pub" >/dev/null 2>&1; then
        ok "Feed signature verified"
    else
        warn "Feed signature verification failed"
    fi
fi

# ── Done ─────────────────────────────────────────────────────────────────
echo ""
ok "Prismor initialized for: $TARGET_DIR"
echo ""
echo -e "  ${GREEN}Warden:${NC}  hooks installed (mode: $MODE)"
echo -e "  ${GREEN}Config:${NC}  $CLAUDE_MD"
echo ""
echo -e "  To switch to enforce mode:  ${YELLOW}PRISMOR_MODE=enforce bash $PRISMOR_DIR/scripts/init.sh $TARGET_DIR${NC}"
if [ "$CLOAK" != "1" ]; then
    echo -e "  To enable secret cloaking: ${YELLOW}PRISMOR_CLOAK=1 bash $PRISMOR_DIR/scripts/init.sh $TARGET_DIR${NC}"
fi
echo -e "  To update the feed:         ${YELLOW}git -C $PRISMOR_DIR pull${NC}"

# ── Optional: Analyze current session state ────────────────────────────────
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
read -p "$(echo -e ${YELLOW}'Check current session for findings? (y/n):'${NC}) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    info "Analyzing your current session..."
    python3 "$PRISMOR_DIR/warden/cli.py" analyze 2>/dev/null || \
        warn "Session analysis failed"
fi
echo ""
