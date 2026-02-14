#!/usr/bin/env bash
set -euo pipefail

# Generate test RSA keys for CI/CD and local testing
# These keys are ephemeral and should never be committed to git

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/../shared/tests/keys"

echo "🔑 Generating test RSA keys..."

# Create keys directory if it doesn't exist
mkdir -p "$KEYS_DIR"

# Generate 2048-bit RSA private key
openssl genrsa -out "$KEYS_DIR/test_private.pem" 2048 2>/dev/null

# Extract public key
openssl rsa -in "$KEYS_DIR/test_private.pem" -pubout -out "$KEYS_DIR/test_public.pem" 2>/dev/null

# Set restrictive permissions
chmod 600 "$KEYS_DIR/test_private.pem"
chmod 644 "$KEYS_DIR/test_public.pem"

echo "✅ Test keys generated at $KEYS_DIR"
echo "   - test_private.pem (2048-bit RSA)"
echo "   - test_public.pem"
