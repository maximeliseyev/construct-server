#!/bin/bash

# Delivery Worker Test Script
# This script helps test the delivery worker functionality

set -e

echo "🧪 Delivery Worker Test Script"
echo "================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Load .env file
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
else
    echo -e "${RED}❌ .env file not found${NC}"
    exit 1
fi

# Check required environment variables
echo ""
echo "📋 Checking configuration..."

if [ -z "$ONLINE_CHANNEL" ]; then
    echo -e "${RED}❌ ONLINE_CHANNEL not set in .env${NC}"
    exit 1
else
    echo -e "${GREEN}✅ ONLINE_CHANNEL: $ONLINE_CHANNEL${NC}"
fi

if [ -z "$REDIS_URL" ]; then
    echo -e "${RED}❌ REDIS_URL not set in .env${NC}"
    exit 1
else
    # Mask password in Redis URL for display
    REDIS_URL_SAFE=$(echo $REDIS_URL | sed -E 's/:([^@]+)@/:****@/')
    echo -e "${GREEN}✅ REDIS_URL: $REDIS_URL_SAFE${NC}"
fi

# Test Redis connection
echo ""
echo "🔌 Testing Redis connection..."

# Extract Redis host and port
if [[ $REDIS_URL =~ rediss?://([^:]+:)?([^@]+@)?([^:]+):([0-9]+) ]]; then
    REDIS_HOST="${BASH_REMATCH[3]}"
    REDIS_PORT="${BASH_REMATCH[4]}"

    # Note: For TLS connections (rediss://), we can't easily test with redis-cli
    # without additional configuration
    if [[ $REDIS_URL == rediss://* ]]; then
        echo -e "${YELLOW}⚠️  TLS connection detected (rediss://). Skipping direct connection test.${NC}"
    else
        if command -v redis-cli &> /dev/null; then
            if redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" PING &> /dev/null; then
                echo -e "${GREEN}✅ Redis connection successful${NC}"
            else
                echo -e "${RED}❌ Cannot connect to Redis${NC}"
                exit 1
            fi
        else
            echo -e "${YELLOW}⚠️  redis-cli not installed, skipping connection test${NC}"
        fi
    fi
else
    echo -e "${YELLOW}⚠️  Could not parse Redis URL, skipping connection test${NC}"
fi

# Check if delivery-worker binary exists or can be built
echo ""
echo "🔨 Checking delivery-worker binary..."

if ! cargo build --bin delivery-worker --quiet 2>&1; then
    echo -e "${RED}❌ Failed to build delivery-worker${NC}"
    exit 1
else
    echo -e "${GREEN}✅ delivery-worker built successfully${NC}"
fi

# Instructions for manual testing
echo ""
echo "📖 Manual Testing Instructions:"
echo "================================"
echo ""
echo "1. Start the delivery worker in one terminal:"
echo -e "   ${YELLOW}cargo run --bin delivery-worker${NC}"
echo ""
echo "2. Start the main server in another terminal:"
echo -e "   ${YELLOW}cargo run --bin construct-server${NC}"
echo ""
echo "3. Send a message to an offline user"
echo ""
echo "4. Connect the user - the message should be delivered"
echo ""
echo "5. Check the logs for:"
echo "   - Main server: 'Published user online notification'"
echo "   - Delivery worker: 'User came online, processing offline messages'"
echo "   - Main server: 'Delivered offline message to online client'"
echo ""

# Offer to start monitoring
echo "Would you like to monitor Redis Pub/Sub activity? (y/n)"
read -r response

if [[ "$response" =~ ^[Yy]$ ]]; then
    if command -v redis-cli &> /dev/null && [[ $REDIS_URL != rediss://* ]]; then
        echo ""
        echo "📡 Monitoring Redis channel: $ONLINE_CHANNEL"
        echo "Press Ctrl+C to stop"
        echo ""
        redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SUBSCRIBE "$ONLINE_CHANNEL"
    else
        echo -e "${YELLOW}⚠️  Cannot monitor: redis-cli not available or TLS connection${NC}"
    fi
fi

echo ""
echo -e "${GREEN}✅ All checks passed!${NC}"
