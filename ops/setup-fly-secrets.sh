#!/bin/bash
# Setup Fly.io secrets for Construct Messenger
# This script reads values from .env and sets them as Fly.io secrets

set -e

# Check if .env exists
if [ ! -f .env.deploy ]; then
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
  DELIVERY_QUEUE_PREFIX="$DELIVERY_QUEUE_PREFIX" \
  OFFLINE_QUEUE_PREFIX="$OFFLINE_QUEUE_PREFIX" \
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
  DELIVERY_QUEUE_PREFIX="$DELIVERY_QUEUE_PREFIX" \
  OFFLINE_QUEUE_PREFIX="$OFFLINE_QUEUE_PREFIX" \
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

# ============================================================================
# Federation and Domain Configuration
# ============================================================================

if [ -n "$INSTANCE_DOMAIN" ]; then
  echo ""
  echo "Setting up federation domain configuration for construct-server..."
  flyctl secrets set \
    INSTANCE_DOMAIN="$INSTANCE_DOMAIN" \
    --app construct-server
fi

if [ -n "$FEDERATION_BASE_DOMAIN" ]; then
  flyctl secrets set \
    FEDERATION_BASE_DOMAIN="$FEDERATION_BASE_DOMAIN" \
    --app construct-server
fi

if [ -n "$FEDERATION_ENABLED" ]; then
  flyctl secrets set \
    FEDERATION_ENABLED="$FEDERATION_ENABLED" \
    --app construct-server
fi

if [ -n "$DEEP_LINK_BASE_URL" ]; then
  flyctl secrets set \
    DEEP_LINK_BASE_URL="$DEEP_LINK_BASE_URL" \
    --app construct-server
fi

# ============================================================================
# Delivery ACK secrets (if enabled)
# ============================================================================

if [ -n "$DELIVERY_ACK_MODE" ] && [ "$DELIVERY_ACK_MODE" != "disabled" ]; then
  echo ""
  echo "Setting up Delivery ACK secrets for construct-server..."
  flyctl secrets set \
    DELIVERY_ACK_MODE="$DELIVERY_ACK_MODE" \
    DELIVERY_SECRET_KEY="$DELIVERY_SECRET_KEY" \
    DELIVERY_EXPIRY_DAYS="$DELIVERY_EXPIRY_DAYS" \
    DELIVERY_CLEANUP_INTERVAL_SECS="$DELIVERY_CLEANUP_INTERVAL_SECS" \
    DELIVERY_ACK_ENABLE_BATCHING="$DELIVERY_ACK_ENABLE_BATCHING" \
    DELIVERY_ACK_BATCH_BUFFER_SECS="$DELIVERY_ACK_BATCH_BUFFER_SECS" \
    --app construct-server

  echo ""
  echo "Setting up Delivery ACK secrets for construct-delivery-worker..."
  flyctl secrets set \
    DELIVERY_ACK_MODE="$DELIVERY_ACK_MODE" \
    DELIVERY_SECRET_KEY="$DELIVERY_SECRET_KEY" \
    DELIVERY_EXPIRY_DAYS="$DELIVERY_EXPIRY_DAYS" \
    --app construct-delivery-worker
fi

# ============================================================================
# Message Gateway secrets (if you want to use Message Gateway service)
# ============================================================================

if [ -n "$ENABLE_MESSAGE_GATEWAY" ] && [ "$ENABLE_MESSAGE_GATEWAY" = "true" ]; then
  echo ""
  echo "Setting up Message Gateway secrets..."
  flyctl secrets set \
    DATABASE_URL="$DATABASE_URL" \
    REDIS_URL="$REDIS_URL" \
    JWT_SECRET="$JWT_SECRET" \
    JWT_ISSUER="$JWT_ISSUER" \
    LOG_HASH_SALT="$LOG_HASH_SALT" \
    ONLINE_CHANNEL="$ONLINE_CHANNEL" \
    --app construct-message-gateway

  # Kafka secrets for Message Gateway
  if [ "$KAFKA_ENABLED" = "true" ]; then
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
      --app construct-message-gateway
  fi
fi

echo ""
echo "=== ✅ All secrets have been set! ==="
echo ""
echo "To verify:"
echo "  flyctl secrets list --app construct-server"
echo "  flyctl secrets list --app construct-delivery-worker"
if [ -n "$ENABLE_MESSAGE_GATEWAY" ] && [ "$ENABLE_MESSAGE_GATEWAY" = "true" ]; then
  echo "  flyctl secrets list --app construct-message-gateway"
fi
echo ""
echo "To deploy:"
echo "  flyctl deploy --app construct-server"
echo "  flyctl deploy --config fly.worker.toml --app construct-delivery-worker"
if [ -n "$ENABLE_MESSAGE_GATEWAY" ] && [ "$ENABLE_MESSAGE_GATEWAY" = "true" ]; then
  echo "  flyctl deploy --config fly.gateway.toml --app construct-message-gateway"
fi
