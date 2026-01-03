#!/bin/bash
# Setup Fly.io secrets for Construct Messenger
# This script reads values from .env and sets them as Fly.io secrets

set -e

# Check if .env exists
if [ ! -f .env ]; then
  echo "Error: .env file not found"
  exit 1
fi

# Load .env file
source .env

echo "=== Setting up Fly.io secrets from .env ==="
echo ""

# ============================================================================
# Core secrets (required for both apps)
# ============================================================================

echo "Setting up core secrets for construct-server..."
flyctl secrets set \
  DATABASE_URL="$DATABASE_URL" \
  REDIS_URL="$REDIS_URL" \
  JWT_SECRET="$JWT_SECRET" \
  JWT_ISSUER="$JWT_ISSUER" \
  LOG_HASH_SALT="$LOG_HASH_SALT" \
  ONLINE_CHANNEL="$ONLINE_CHANNEL" \
  --app construct-server

echo ""
echo "Setting up core secrets for construct-delivery-worker..."
flyctl secrets set \
  DATABASE_URL="$DATABASE_URL" \
  REDIS_URL="$REDIS_URL" \
  JWT_SECRET="$JWT_SECRET" \
  JWT_ISSUER="$JWT_ISSUER" \
  LOG_HASH_SALT="$LOG_HASH_SALT" \
  ONLINE_CHANNEL="$ONLINE_CHANNEL" \
  --app construct-delivery-worker

# ============================================================================
# Kafka secrets (if enabled)
# ============================================================================

if [ "$KAFKA_ENABLED" = "true" ]; then
  echo ""
  echo "Setting up Kafka secrets for construct-server..."
  flyctl secrets set \
    KAFKA_ENABLED="$KAFKA_ENABLED" \
    KAFKA_BROKERS="$KAFKA_BROKERS" \
    KAFKA_TOPIC="$KAFKA_TOPIC" \
    KAFKA_CONSUMER_GROUP="$KAFKA_CONSUMER_GROUP" \
    KAFKA_SSL_ENABLED="$KAFKA_SSL_ENABLED" \
    KAFKA_SASL_MECHANISM="$KAFKA_SASL_MECHANISM" \
    KAFKA_SASL_USERNAME="$KAFKA_SASL_USERNAME" \
    KAFKA_SASL_PASSWORD="$KAFKA_SASL_PASSWORD" \
    KAFKA_PRODUCER_COMPRESSION="$KAFKA_PRODUCER_COMPRESSION" \
    KAFKA_PRODUCER_LINGER_MS="$KAFKA_PRODUCER_LINGER_MS" \
    KAFKA_PRODUCER_ACKS="$KAFKA_PRODUCER_ACKS" \
    --app construct-server

  echo ""
  echo "Setting up Kafka secrets for construct-delivery-worker..."
  flyctl secrets set \
    KAFKA_ENABLED="$KAFKA_ENABLED" \
    KAFKA_BROKERS="$KAFKA_BROKERS" \
    KAFKA_TOPIC="$KAFKA_TOPIC" \
    KAFKA_CONSUMER_GROUP="$KAFKA_CONSUMER_GROUP" \
    KAFKA_SSL_ENABLED="$KAFKA_SSL_ENABLED" \
    KAFKA_SASL_MECHANISM="$KAFKA_SASL_MECHANISM" \
    KAFKA_SASL_USERNAME="$KAFKA_SASL_USERNAME" \
    KAFKA_SASL_PASSWORD="$KAFKA_SASL_PASSWORD" \
    --app construct-delivery-worker
fi

# ============================================================================
# APNs secrets (if encryption key is set)
# ============================================================================

if [ -n "$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" ] && [ "$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" != "CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32" ]; then
  echo ""
  echo "Setting up APNs device token encryption key for construct-server..."
  flyctl secrets set \
    APNS_DEVICE_TOKEN_ENCRYPTION_KEY="$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" \
    --app construct-server

  # Optional: Set other APNs configs if they exist
  if [ -n "$APNS_ENABLED" ]; then
    flyctl secrets set \
      APNS_ENABLED="$APNS_ENABLED" \
      --app construct-server
  fi

  if [ -n "$APNS_ENVIRONMENT" ]; then
    flyctl secrets set \
      APNS_ENVIRONMENT="$APNS_ENVIRONMENT" \
      --app construct-server
  fi

  if [ -n "$APNS_KEY_ID" ]; then
    flyctl secrets set \
      APNS_KEY_ID="$APNS_KEY_ID" \
      APNS_TEAM_ID="$APNS_TEAM_ID" \
      APNS_BUNDLE_ID="$APNS_BUNDLE_ID" \
      APNS_TOPIC="$APNS_TOPIC" \
      --app construct-server
  fi
fi

echo ""
echo "=== ✅ All secrets have been set! ==="
echo ""
echo "To verify:"
echo "  flyctl secrets list --app construct-server"
echo "  flyctl secrets list --app construct-delivery-worker"
echo ""
echo "To deploy:"
echo "  flyctl deploy --app construct-server"
echo "  flyctl deploy --config fly.worker.toml --app construct-delivery-worker"
