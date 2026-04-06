#!/bin/bash
# Prismor Sweep — convenience wrapper for `warden sweep`
#
# Usage:
#   bash sweep.sh                 # dry-run: scan and report only
#   bash sweep.sh --redact        # redact secrets, save to encrypted vault
#   bash sweep.sh --clean         # delete residue files (passphrase required)
#   bash sweep.sh --restore       # restore secrets from vault
#   bash sweep.sh --show-vault    # show vault contents
#   bash sweep.sh --dirs ~/.foo   # scan custom directories

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WARDEN_CLI="$(dirname "$SCRIPT_DIR")/warden/cli.py"

if [[ ! -f "$WARDEN_CLI" ]]; then
  echo "[sweep] Error: warden/cli.py not found at $WARDEN_CLI" >&2
  exit 1
fi

exec python3 "$WARDEN_CLI" sweep "$@"
