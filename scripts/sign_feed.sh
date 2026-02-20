#!/bin/bash
set -e

FEED_FILE="advisories/immunity-feed.json"
SIG_FILE="advisories/immunity-feed.json.sig"

# The private key will be injected via environment variable in CI
if [ -z "$PRISMORSEC_SIGNING_PRIVATE_KEY" ]; then
    echo "Error: PRISMORSEC_SIGNING_PRIVATE_KEY environment variable is not set."
    exit 1
fi

echo "Signing $FEED_FILE..."

# Create a temporary file for the private key
PRIVATE_KEY_FILE=$(mktemp)
echo "$PRISMORSEC_SIGNING_PRIVATE_KEY" > "$PRIVATE_KEY_FILE"

# Ensure correct permissions
chmod 600 "$PRIVATE_KEY_FILE"

# Generates a raw detached Ed25519 signature and then base64 encodes it so it's ascii
openssl pkeyutl -sign -inkey "$PRIVATE_KEY_FILE" -rawin -in "$FEED_FILE" | base64 > "$SIG_FILE"

# Output summary
echo "Feed signed successfully."
echo "Signature saved to: $SIG_FILE"

# Clean up temporary keys
rm -f "$PRIVATE_KEY_FILE"
