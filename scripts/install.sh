#!/usr/bin/env sh
set -e

# Prismor immunity-agent installer
# Usage: curl -sSL https://prismor.dev/install | sh

PACKAGE="immunity-agent"

echo "Installing Prismor immunity-agent..."

# Check if pipx is available
if command -v pipx >/dev/null 2>&1; then
    pipx install "$PACKAGE"
# Check if pip is available and not in an externally-managed environment
elif command -v pip >/dev/null 2>&1; then
    if pip install "$PACKAGE" 2>&1 | grep -q "externally-managed-environment"; then
        # Fall back to pipx if pip fails due to managed environment
        if command -v pipx >/dev/null 2>&1; then
            pipx install "$PACKAGE"
        else
            echo "pip install failed (externally-managed Python). Installing pipx first..."
            pip install --user pipx 2>/dev/null || python3 -m pip install --user pipx
            python3 -m pipx install "$PACKAGE"
        fi
    else
        pip install "$PACKAGE"
    fi
elif command -v pip3 >/dev/null 2>&1; then
    pip3 install "$PACKAGE"
else
    echo "Error: Python pip not found. Install Python from https://python.org and try again."
    exit 1
fi

echo ""
echo "Run 'immunity setup' to get started."
