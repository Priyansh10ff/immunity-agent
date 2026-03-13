#!/bin/bash
set -e

FEED_FILE="${1:-advisories/immunity-feed.json}"
SIG_FILE="${FEED_FILE}.sig"
PUBLIC_KEY="${2:-keys/public.pub}"

if [ ! -f "$FEED_FILE" ]; then
    echo "Error: Feed file not found at $FEED_FILE"
    exit 1
fi

if [ ! -f "$SIG_FILE" ]; then
    echo "Error: Signature file not found at $SIG_FILE"
    exit 1
fi

if [ ! -f "$PUBLIC_KEY" ]; then
    echo "Error: Public key not found at $PUBLIC_KEY"
    echo ""
    echo "To verify the Prismor feed signature you need the public key."
    echo "Get it from: https://github.com/PrismorSec/prismor/tree/main/keys/public.pub"
    exit 1
fi

echo "Verifying feed signature..."
echo "  Feed:      $FEED_FILE"
echo "  Signature: $SIG_FILE"
echo "  Key:       $PUBLIC_KEY"
echo ""

# Decode base64 signature to raw binary
SIG_RAW=$(mktemp)
base64 -d < "$SIG_FILE" > "$SIG_RAW"

if openssl pkeyutl -verify -pubin -inkey "$PUBLIC_KEY" -rawin -in "$FEED_FILE" -sigfile "$SIG_RAW" 2>/dev/null; then
    echo "VERIFIED: Feed signature is valid."
    rm -f "$SIG_RAW"
    exit 0
else
    echo "FAILED: Feed signature verification failed."
    echo "The feed may have been tampered with or the key does not match."
    rm -f "$SIG_RAW"
    exit 1
fi
