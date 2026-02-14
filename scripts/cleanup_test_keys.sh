#!/usr/bin/env bash
set -euo pipefail

# Clean up ephemeral test keys after testing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/../shared/tests/keys"

if [ -d "$KEYS_DIR" ]; then
    echo "🧹 Cleaning up test keys..."
    rm -f "$KEYS_DIR/test_private.pem"
    rm -f "$KEYS_DIR/test_public.pem"
    echo "✅ Test keys removed"
else
    echo "ℹ️  No test keys directory found"
fi
