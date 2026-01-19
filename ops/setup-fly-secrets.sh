#!/bin/bash
# Setup Fly.io secrets for Construct Messenger
# This script reads values from .env and sets them as Fly.io secrets
#
# Usage:
#   ./ops/setup-fly-secrets.sh [service]
#
# Services:
#   server - construct-server
#   worker - construct-delivery-worker
#   gateway - construct-message-gateway
#   media - construct-media
#   api-gateway - construct-api-gateway
#   auth-service - construct-auth-service
#   user-service - construct-user-service
#   messaging-service - construct-messaging-service
#   notification-service - construct-notification-service
#   (no argument) - all services
#
# JWT Configuration:
#   - HS256 (legacy): Set JWT_SECRET (symmetric key)
#   - RS256 (recommended): Set JWT_PRIVATE_KEY and JWT_PUBLIC_KEY (RSA keypair)
#   - Key Management System: Requires RS256 + VAULT_ADDR
#
# Migration to RS256:
#   1. Generate RSA keypair:
#      openssl genrsa -out private.pem 4096
#      openssl rsa -in private.pem -pubout -out public.pem
#   2. Set in .env:
#      JWT_PRIVATE_KEY="$(cat private.pem)"
#      JWT_PUBLIC_KEY="$(cat public.pem)"
#   3. Keep JWT_SECRET for backward compatibility during migration

set -e

# Check if .env exists
if [ ! -f .env ]; then
  echo "Error: .env file not found"
  exit 1
fi

# Load .env file
source .env

# Initialize gateway setup flag
SHOULD_SETUP_GATEWAY=false

# Get service name from argument
SERVICE="${1:-all}"

echo "=== Setting up Fly.io secrets from .env ==="
echo "Service: $SERVICE"
echo ""

# ============================================================================
# Service-specific secret setup
# ============================================================================

if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "server" ]; then
  echo ""
  echo "Setting up secrets for construct-server..."
  # Create app if it doesn't exist
  if ! flyctl status --app construct-server >/dev/null 2>&1; then
    echo "Creating construct-server app..."
    flyctl apps create construct-server
  fi
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

  # Optional: JWT RSA keys for RS256 (if provided)
  # Required for Key Management System support
  if [ -n "$JWT_PRIVATE_KEY" ] && [ -n "$JWT_PUBLIC_KEY" ]; then
    echo "Setting JWT RSA keys for RS256 algorithm..."
    flyctl secrets set \
      JWT_PRIVATE_KEY="$JWT_PRIVATE_KEY" \
      JWT_PUBLIC_KEY="$JWT_PUBLIC_KEY" \
      --app construct-server
    echo "✅ RS256 keys configured - Key Management System ready"
  elif [ -n "$VAULT_ADDR" ]; then
    echo "⚠️  Warning: Key Management System enabled but JWT_PRIVATE_KEY/JWT_PUBLIC_KEY not set"
    echo "   RS256 keys are required for automatic key rotation"
    echo "   Key Management System will not work until RS256 keys are configured"
  fi
fi

if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "worker" ]; then
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

  # Optional: JWT public key for RS256 (only public key needed for verification)
  if [ -n "$JWT_PUBLIC_KEY" ]; then
    flyctl secrets set \
      JWT_PUBLIC_KEY="$JWT_PUBLIC_KEY" \
      --app construct-delivery-worker
  fi
fi

# ============================================================================
# Kafka secrets (if enabled)
# ============================================================================

if [ "$KAFKA_ENABLED" = "true" ]; then
  if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "server" ]; then
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
  fi

  if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "worker" ]; then
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
fi

# ============================================================================
# APNs secrets (if encryption key is set)
# ============================================================================

if [ -n "$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" ] && [ "$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" != "CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32" ]; then
  if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "server" ]; then
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
fi

# ============================================================================
# Federation and Domain Configuration
# ============================================================================

if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "server" ]; then
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

  # Server Signing Key for S2S federation authentication
  # Generate with: openssl rand -base64 32
  if [ -n "$SERVER_SIGNING_KEY" ]; then
    echo ""
    echo "Setting up server signing key for S2S federation..."
    flyctl secrets set \
      SERVER_SIGNING_KEY="$SERVER_SIGNING_KEY" \
      --app construct-server

    # Also set for message gateway if it uses federation
    if [ -n "$ENABLE_MESSAGE_GATEWAY" ] && [ "$ENABLE_MESSAGE_GATEWAY" = "true" ]; then
      flyctl secrets set \
        SERVER_SIGNING_KEY="$SERVER_SIGNING_KEY" \
        --app construct-message-gateway
    fi
  fi
fi

# ============================================================================
# Delivery ACK secrets (if enabled)
# ============================================================================

if [ -n "$DELIVERY_ACK_MODE" ] && [ "$DELIVERY_ACK_MODE" != "disabled" ]; then
  if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "server" ]; then
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
  fi

  if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "worker" ]; then
    echo ""
    echo "Setting up Delivery ACK secrets for construct-delivery-worker..."
    flyctl secrets set \
      DELIVERY_ACK_MODE="$DELIVERY_ACK_MODE" \
      DELIVERY_SECRET_KEY="$DELIVERY_SECRET_KEY" \
      DELIVERY_EXPIRY_DAYS="$DELIVERY_EXPIRY_DAYS" \
      --app construct-delivery-worker
  fi
fi

# ============================================================================
# Key Management System secrets (if enabled)
# ============================================================================
#
# IMPORTANT: Key Management System requires RS256 (RSA keys), not HS256 (JWT_SECRET)
# - JWT_PRIVATE_KEY and JWT_PUBLIC_KEY must be set for services using Key Management
# - Key Management System uses Vault Transit engine with RSA-4096 keys
# - JWT_SECRET (HS256) is not compatible with automatic key rotation
#
# Migration path:
# 1. Generate RSA keypair: openssl genrsa -out private.pem 4096
# 2. Extract public key: openssl rsa -in private.pem -pubout -out public.pem
# 3. Set JWT_PRIVATE_KEY and JWT_PUBLIC_KEY in .env
# 4. Set VAULT_ADDR and authentication (VAULT_TOKEN or VAULT_K8S_ROLE)
# 5. Initialize keys in Vault (see docs/KEY_MANAGEMENT_PRODUCTION.md)
# ============================================================================

if [ -n "$VAULT_ADDR" ]; then
  # Key Management System is enabled - set secrets for all services that use it
  echo ""
  echo "Setting up Key Management System secrets..."
  
  # Check if RS256 keys are set (required for Key Management System)
  if [ -z "$JWT_PRIVATE_KEY" ] || [ -z "$JWT_PUBLIC_KEY" ]; then
    echo ""
    echo "⚠️  WARNING: Key Management System requires RS256 (JWT_PRIVATE_KEY/JWT_PUBLIC_KEY)"
    echo "   JWT_SECRET (HS256) is not compatible with automatic key rotation"
    echo ""
    echo "   To enable Key Management System:"
    echo "   1. Generate RSA keypair:"
    echo "      openssl genrsa -out private.pem 4096"
    echo "      openssl rsa -in private.pem -pubout -out public.pem"
    echo "   2. Set in .env:"
    echo "      JWT_PRIVATE_KEY=\"\$(cat private.pem)\""
    echo "      JWT_PUBLIC_KEY=\"\$(cat public.pem)\""
    echo "   3. Re-run this script"
    echo ""
    echo "   Key Management System will be disabled until RS256 keys are configured."
  fi

  # Set secrets for construct-server
  if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "server" ]; then
    echo "Setting Key Management secrets for construct-server..."
    # Build secrets command dynamically based on what's set
    if [ -n "$VAULT_TOKEN" ] && [ -n "$VAULT_K8S_ROLE" ]; then
      # Both are set - use both
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_TOKEN="$VAULT_TOKEN" \
        VAULT_K8S_ROLE="$VAULT_K8S_ROLE" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-server
    elif [ -n "$VAULT_TOKEN" ]; then
      # Only VAULT_TOKEN is set
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_TOKEN="$VAULT_TOKEN" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-server
    elif [ -n "$VAULT_K8S_ROLE" ]; then
      # Only VAULT_K8S_ROLE is set
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_K8S_ROLE="$VAULT_K8S_ROLE" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-server
    else
      # Neither is set - just set VAULT_ADDR (will fail at runtime, but allow setup)
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-server
    fi
  fi

  # Set secrets for construct-auth-service
  if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "auth-service" ]; then
    echo "Setting Key Management secrets for construct-auth-service..."
    if [ -n "$VAULT_TOKEN" ] && [ -n "$VAULT_K8S_ROLE" ]; then
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_TOKEN="$VAULT_TOKEN" \
        VAULT_K8S_ROLE="$VAULT_K8S_ROLE" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-auth-service
    elif [ -n "$VAULT_TOKEN" ]; then
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_TOKEN="$VAULT_TOKEN" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-auth-service
    elif [ -n "$VAULT_K8S_ROLE" ]; then
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_K8S_ROLE="$VAULT_K8S_ROLE" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-auth-service
    else
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-auth-service
    fi
  fi

  # Set secrets for construct-messaging-service
  if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "messaging-service" ]; then
    echo "Setting Key Management secrets for construct-messaging-service..."
    if [ -n "$VAULT_TOKEN" ] && [ -n "$VAULT_K8S_ROLE" ]; then
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_TOKEN="$VAULT_TOKEN" \
        VAULT_K8S_ROLE="$VAULT_K8S_ROLE" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-messaging-service
    elif [ -n "$VAULT_TOKEN" ]; then
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_TOKEN="$VAULT_TOKEN" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-messaging-service
    elif [ -n "$VAULT_K8S_ROLE" ]; then
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_K8S_ROLE="$VAULT_K8S_ROLE" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-messaging-service
    else
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-messaging-service
    fi
  fi

  # Set secrets for construct-notification-service
  if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "notification-service" ]; then
    echo "Setting Key Management secrets for construct-notification-service..."
    if [ -n "$VAULT_TOKEN" ] && [ -n "$VAULT_K8S_ROLE" ]; then
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_TOKEN="$VAULT_TOKEN" \
        VAULT_K8S_ROLE="$VAULT_K8S_ROLE" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-notification-service
    elif [ -n "$VAULT_TOKEN" ]; then
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_TOKEN="$VAULT_TOKEN" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-notification-service
    elif [ -n "$VAULT_K8S_ROLE" ]; then
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_K8S_ROLE="$VAULT_K8S_ROLE" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-notification-service
    else
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-notification-service
    fi
  fi
else
  echo ""
  echo "ℹ️  Key Management System disabled (VAULT_ADDR not set)"
  echo "   To enable: Set VAULT_ADDR and either VAULT_TOKEN or VAULT_K8S_ROLE in .env"
fi

# ============================================================================
# Message Gateway secrets (if you want to use Message Gateway service)
# ============================================================================
#
# Required variables for message-gateway:
# - Core: DATABASE_URL, REDIS_URL, JWT_SECRET, JWT_ISSUER, LOG_HASH_SALT
# - Queues: ONLINE_CHANNEL, DELIVERY_QUEUE_PREFIX, OFFLINE_QUEUE_PREFIX
# - Routing: INSTANCE_DOMAIN, FEDERATION_ENABLED (for MessageRouter)
# - Kafka: All Kafka config if enabled
#
# Note: This section runs if ENABLE_MESSAGE_GATEWAY=true OR if running for
#       gateway-specific deployment (make secrets-gateway)
# ============================================================================

# Check if we should set up message-gateway secrets
# Either ENABLE_MESSAGE_GATEWAY is true, or we're running gateway-specific setup
if [ "$SERVICE" = "gateway" ]; then
  # Explicitly requested for gateway
  SHOULD_SETUP_GATEWAY=true
elif [ "$SERVICE" = "all" ] && [ -n "$ENABLE_MESSAGE_GATEWAY" ] && [ "$ENABLE_MESSAGE_GATEWAY" = "true" ]; then
  # Enabled via .env variable (only when setting up all services)
  SHOULD_SETUP_GATEWAY=true
elif [ "$SERVICE" = "all" ]; then
  # Check if app exists (might want to set up secrets even if not explicitly enabled)
  # Use flyctl status as it's faster and returns error if app doesn't exist
  if flyctl status --app construct-message-gateway >/dev/null 2>&1; then
    SHOULD_SETUP_GATEWAY=true
    echo ""
    echo "ℹ️  Message Gateway app exists but ENABLE_MESSAGE_GATEWAY not set to 'true'"
    echo "   Setting up secrets anyway (use ENABLE_MESSAGE_GATEWAY=true to suppress this message)"
  fi
fi

if [ "$SHOULD_SETUP_GATEWAY" = "true" ]; then
  echo ""
  echo "Setting up Message Gateway secrets..."
  flyctl secrets set \
    DATABASE_URL="$DATABASE_URL" \
    REDIS_URL="$REDIS_URL" \
    JWT_SECRET="$JWT_SECRET" \
    JWT_ISSUER="$JWT_ISSUER" \
    LOG_HASH_SALT="$LOG_HASH_SALT" \
    ONLINE_CHANNEL="$ONLINE_CHANNEL" \
    DELIVERY_QUEUE_PREFIX="$DELIVERY_QUEUE_PREFIX" \
    OFFLINE_QUEUE_PREFIX="$OFFLINE_QUEUE_PREFIX" \
    APNS_DEVICE_TOKEN_ENCRYPTION_KEY="$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" \
    --app construct-message-gateway

  # Optional: JWT RSA keys for RS256 (if provided)
  # Required for Key Management System support
  if [ -n "$JWT_PRIVATE_KEY" ] && [ -n "$JWT_PUBLIC_KEY" ]; then
    echo "Setting JWT RSA keys for RS256 algorithm..."
    flyctl secrets set \
      JWT_PRIVATE_KEY="$JWT_PRIVATE_KEY" \
      JWT_PUBLIC_KEY="$JWT_PUBLIC_KEY" \
      --app construct-message-gateway
    echo "✅ RS256 keys configured - Key Management System ready"
  elif [ -n "$VAULT_ADDR" ]; then
    echo "⚠️  Warning: Key Management System enabled but JWT_PRIVATE_KEY/JWT_PUBLIC_KEY not set"
    echo "   RS256 keys are required for automatic key rotation"
    echo "   Key Management System will not work until RS256 keys are configured"
  fi

  # Instance domain and federation (required for MessageRouter to route messages)
  if [ -n "$INSTANCE_DOMAIN" ]; then
    flyctl secrets set \
      INSTANCE_DOMAIN="$INSTANCE_DOMAIN" \
      --app construct-message-gateway
  fi

  if [ -n "$FEDERATION_ENABLED" ]; then
    flyctl secrets set \
      FEDERATION_ENABLED="$FEDERATION_ENABLED" \
      --app construct-message-gateway
  fi

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
else
  echo ""
  echo "ℹ️  Skipping Message Gateway secrets setup"
  echo "   (Set ENABLE_MESSAGE_GATEWAY=true in .env or use 'make secrets-gateway')"
fi

# ============================================================================
# Microservices secrets
# ============================================================================

if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "api-gateway" ]; then
  echo ""
  echo "Setting up secrets for construct-api-gateway..."
  # Create app if it doesn't exist
  if ! flyctl status --app construct-api-gateway >/dev/null 2>&1; then
    echo "Creating construct-api-gateway app..."
    flyctl apps create construct-api-gateway
  fi
  # Base secrets
  flyctl secrets set \
    DATABASE_URL="$DATABASE_URL" \
    REDIS_URL="$REDIS_URL" \
    JWT_SECRET="$JWT_SECRET" \
    JWT_ISSUER="$JWT_ISSUER" \
    LOG_HASH_SALT="$LOG_HASH_SALT" \
    ONLINE_CHANNEL="$ONLINE_CHANNEL" \
    DELIVERY_QUEUE_PREFIX="$DELIVERY_QUEUE_PREFIX" \
    OFFLINE_QUEUE_PREFIX="$OFFLINE_QUEUE_PREFIX" \
    CSRF_SECRET="${CSRF_SECRET:-$(openssl rand -hex 32)}" \
    --app construct-api-gateway

  # Optional: JWT RSA keys for RS256 (if provided)
  # Required for Key Management System support
  if [ -n "$JWT_PRIVATE_KEY" ] && [ -n "$JWT_PUBLIC_KEY" ]; then
    echo "Setting JWT RSA keys for RS256 algorithm..."
    flyctl secrets set \
      JWT_PRIVATE_KEY="$JWT_PRIVATE_KEY" \
      JWT_PUBLIC_KEY="$JWT_PUBLIC_KEY" \
      --app construct-api-gateway
    echo "✅ RS256 keys configured"
  fi
fi

if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "auth-service" ]; then
  echo ""
  echo "Setting up secrets for construct-auth-service..."
  # Create app if it doesn't exist
  if ! flyctl status --app construct-auth-service >/dev/null 2>&1; then
    echo "Creating construct-auth-service app..."
    flyctl apps create construct-auth-service
  fi
  flyctl secrets set \
    DATABASE_URL="$DATABASE_URL" \
    REDIS_URL="$REDIS_URL" \
    JWT_SECRET="$JWT_SECRET" \
    JWT_ISSUER="$JWT_ISSUER" \
    LOG_HASH_SALT="$LOG_HASH_SALT" \
    ONLINE_CHANNEL="$ONLINE_CHANNEL" \
    DELIVERY_QUEUE_PREFIX="$DELIVERY_QUEUE_PREFIX" \
    OFFLINE_QUEUE_PREFIX="$OFFLINE_QUEUE_PREFIX" \
    --app construct-auth-service

  # Optional: JWT RSA keys for RS256 (if provided)
  # Required for Key Management System support
  if [ -n "$JWT_PRIVATE_KEY" ] && [ -n "$JWT_PUBLIC_KEY" ]; then
    echo "Setting JWT RSA keys for RS256 algorithm..."
    flyctl secrets set \
      JWT_PRIVATE_KEY="$JWT_PRIVATE_KEY" \
      JWT_PUBLIC_KEY="$JWT_PUBLIC_KEY" \
      --app construct-auth-service
    echo "✅ RS256 keys configured - Key Management System ready"
  elif [ -n "$VAULT_ADDR" ]; then
    echo "⚠️  Warning: Key Management System enabled but JWT_PRIVATE_KEY/JWT_PUBLIC_KEY not set"
    echo "   RS256 keys are required for automatic key rotation"
  fi
fi

if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "user-service" ]; then
  echo ""
  echo "Setting up secrets for construct-user-service..."
  # Create app if it doesn't exist
  if ! flyctl status --app construct-user-service >/dev/null 2>&1; then
    echo "Creating construct-user-service app..."
    flyctl apps create construct-user-service
  fi
  flyctl secrets set \
    DATABASE_URL="$DATABASE_URL" \
    REDIS_URL="$REDIS_URL" \
    JWT_SECRET="$JWT_SECRET" \
    JWT_ISSUER="$JWT_ISSUER" \
    LOG_HASH_SALT="$LOG_HASH_SALT" \
    ONLINE_CHANNEL="$ONLINE_CHANNEL" \
    DELIVERY_QUEUE_PREFIX="$DELIVERY_QUEUE_PREFIX" \
    OFFLINE_QUEUE_PREFIX="$OFFLINE_QUEUE_PREFIX" \
    --app construct-user-service

  # Optional: JWT public key for RS256 (only public key needed for verification)
  if [ -n "$JWT_PUBLIC_KEY" ]; then
    flyctl secrets set \
      JWT_PUBLIC_KEY="$JWT_PUBLIC_KEY" \
      --app construct-user-service
  fi
fi

if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "messaging-service" ]; then
  echo ""
  echo "Setting up secrets for construct-messaging-service..."
  # Create app if it doesn't exist
  if ! flyctl status --app construct-messaging-service >/dev/null 2>&1; then
    echo "Creating construct-messaging-service app..."
    flyctl apps create construct-messaging-service
  fi
  flyctl secrets set \
    DATABASE_URL="$DATABASE_URL" \
    REDIS_URL="$REDIS_URL" \
    JWT_SECRET="$JWT_SECRET" \
    JWT_ISSUER="$JWT_ISSUER" \
    LOG_HASH_SALT="$LOG_HASH_SALT" \
    ONLINE_CHANNEL="$ONLINE_CHANNEL" \
    DELIVERY_QUEUE_PREFIX="$DELIVERY_QUEUE_PREFIX" \
    OFFLINE_QUEUE_PREFIX="$OFFLINE_QUEUE_PREFIX" \
    --app construct-messaging-service

  # Optional: JWT public key for RS256 (only public key needed for verification)
  if [ -n "$JWT_PUBLIC_KEY" ]; then
    flyctl secrets set \
      JWT_PUBLIC_KEY="$JWT_PUBLIC_KEY" \
      --app construct-messaging-service
  fi

  # Kafka secrets for Messaging Service
  if [ "$KAFKA_ENABLED" = "true" ]; then
    flyctl secrets set \
      KAFKA_ENABLED="$KAFKA_ENABLED" \
      KAFKA_BROKERS="$KAFKA_BROKERS" \
      KAFKA_TOPIC="$KAFKA_TOPIC" \
      KAFKA_SSL_ENABLED="$KAFKA_SSL_ENABLED" \
      KAFKA_SASL_MECHANISM="$KAFKA_SASL_MECHANISM" \
      KAFKA_SASL_USERNAME="$KAFKA_SASL_USERNAME" \
      KAFKA_SASL_PASSWORD="$KAFKA_SASL_PASSWORD" \
      KAFKA_PRODUCER_COMPRESSION="$KAFKA_PRODUCER_COMPRESSION" \
      KAFKA_PRODUCER_ACKS="$KAFKA_PRODUCER_ACKS" \
      --app construct-messaging-service
  fi
fi

if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "notification-service" ]; then
  echo ""
  echo "Setting up secrets for construct-notification-service..."
  # Create app if it doesn't exist
  if ! flyctl status --app construct-notification-service >/dev/null 2>&1; then
    echo "Creating construct-notification-service app..."
    flyctl apps create construct-notification-service
  fi
  flyctl secrets set \
    DATABASE_URL="$DATABASE_URL" \
    REDIS_URL="$REDIS_URL" \
    JWT_SECRET="$JWT_SECRET" \
    JWT_ISSUER="$JWT_ISSUER" \
    LOG_HASH_SALT="$LOG_HASH_SALT" \
    ONLINE_CHANNEL="$ONLINE_CHANNEL" \
    DELIVERY_QUEUE_PREFIX="$DELIVERY_QUEUE_PREFIX" \
    OFFLINE_QUEUE_PREFIX="$OFFLINE_QUEUE_PREFIX" \
    --app construct-notification-service

  # Optional: JWT public key for RS256 (only public key needed for verification)
  if [ -n "$JWT_PUBLIC_KEY" ]; then
    flyctl secrets set \
      JWT_PUBLIC_KEY="$JWT_PUBLIC_KEY" \
      --app construct-notification-service
  fi

  # APNs device token encryption key (REQUIRED for Notification Service, even if APNs is disabled)
  # This key is used to encrypt device tokens in the database
  if [ -n "$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" ] && [ "$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" != "CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32" ] && [ "$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" != "0000000000000000000000000000000000000000000000000000000000000000" ]; then
    flyctl secrets set \
      APNS_DEVICE_TOKEN_ENCRYPTION_KEY="$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" \
      --app construct-notification-service
  else
    echo "⚠️  Warning: APNS_DEVICE_TOKEN_ENCRYPTION_KEY not set or is default value"
    echo "   Notification Service requires this key to encrypt device tokens."
    echo "   Generate with: openssl rand -hex 32"
    echo "   Then set in .env and run: make secrets-notification-service"
  fi

  # Optional: APNs configuration (only if APNs is enabled)
  if [ -n "$APNS_ENABLED" ] && [ "$APNS_ENABLED" = "true" ]; then
    flyctl secrets set \
      APNS_ENABLED="$APNS_ENABLED" \
      APNS_ENVIRONMENT="${APNS_ENVIRONMENT:-production}" \
      --app construct-notification-service

    if [ -n "$APNS_KEY_ID" ]; then
      flyctl secrets set \
        APNS_KEY_ID="$APNS_KEY_ID" \
        APNS_TEAM_ID="$APNS_TEAM_ID" \
        APNS_BUNDLE_ID="$APNS_BUNDLE_ID" \
        APNS_TOPIC="$APNS_TOPIC" \
        --app construct-notification-service

      if [ -n "$APNS_KEY_PATH" ]; then
        flyctl secrets set \
          APNS_KEY_PATH="$APNS_KEY_PATH" \
          --app construct-notification-service
      fi
    fi
  fi
fi

echo ""
echo "=== ✅ All secrets have been set! ==="
echo ""
echo "To verify:"
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "server" ]; then
  echo "  flyctl secrets list --app construct-server"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "worker" ]; then
  echo "  flyctl secrets list --app construct-delivery-worker"
fi
if [ "$SHOULD_SETUP_GATEWAY" = "true" ] && ([ "$SERVICE" = "all" ] || [ "$SERVICE" = "gateway" ]); then
  echo "  flyctl secrets list --app construct-message-gateway"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "api-gateway" ]; then
  echo "  flyctl secrets list --app construct-api-gateway"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "auth-service" ]; then
  echo "  flyctl secrets list --app construct-auth-service"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "user-service" ]; then
  echo "  flyctl secrets list --app construct-user-service"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "messaging-service" ]; then
  echo "  flyctl secrets list --app construct-messaging-service"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "notification-service" ]; then
  echo "  flyctl secrets list --app construct-notification-service"
fi
echo ""
echo "To deploy:"
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "server" ]; then
  echo "  make deploy-server"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "worker" ]; then
  echo "  make deploy-worker"
fi
if [ "$SHOULD_SETUP_GATEWAY" = "true" ] && ([ "$SERVICE" = "all" ] || [ "$SERVICE" = "gateway" ]); then
  echo "  make deploy-gateway"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "api-gateway" ]; then
  echo "  make deploy-api-gateway"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "auth-service" ]; then
  echo "  make deploy-auth-service"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "user-service" ]; then
  echo "  make deploy-user-service"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "messaging-service" ]; then
  echo "  make deploy-messaging-service"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "notification-service" ]; then
  echo "  make deploy-notification-service"
fi
