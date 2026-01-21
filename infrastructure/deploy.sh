#!/bin/bash
# Construct Server - Production Deployment Script
# Run this on your VPS after Terraform creates the infrastructure

set -e

echo "=== Construct Server Production Deployment ==="
echo "Server: $(hostname -I | awk '{print $1}')"
echo "Date: $(date)"
echo ""

# Check if we're running as the construct user
if [[ "$USER" != "construct" ]]; then
    echo "❌ Please run this script as the 'construct' user"
    echo "   sudo su - construct"
    exit 1
fi

# Check if we're in the correct directory
if [[ ! -f "infrastructure/docker-compose.prod.yml" ]]; then
    echo "❌ Please run this script from the construct-server directory"
    exit 1
fi

echo "📦 Pulling latest code..."
git pull origin main || echo "⚠️  Git pull failed, continuing with local code"

echo "🔧 Setting up environment..."
if [[ ! -f "infrastructure/.env.prod" ]]; then
    echo "❌ .env.prod file not found!"
    echo "   Please copy infrastructure/.env.prod.example to infrastructure/.env.prod"
    echo "   and configure your production environment variables."
    exit 1
fi

echo "🐳 Stopping existing services..."
docker-compose -f infrastructure/docker-compose.prod.yml down || true

echo "🏗️  Building services..."
docker-compose -f infrastructure/docker-compose.prod.yml build --no-cache

echo "🚀 Starting services..."
docker-compose -f infrastructure/docker-compose.prod.yml up -d

echo "⏳ Waiting for services to be healthy..."
sleep 30

echo "🏥 Checking service health..."
SERVICES=("gateway" "auth-service" "messaging-service" "user-service" "notification-service" "media-service")

for service in "${SERVICES[@]}"; do
    echo -n "  $service: "
    if docker-compose -f infrastructure/docker-compose.prod.yml exec -T "$service" curl -f http://localhost:8000/health 2>/dev/null; then
        echo "✅ Healthy"
    else
        echo "❌ Unhealthy"
    fi
done

echo ""
echo "📊 Service Status:"
docker-compose -f infrastructure/docker-compose.prod.yml ps

echo ""
echo "🔗 Useful commands:"
echo "  View logs: docker-compose -f infrastructure/docker-compose.prod.yml logs -f"
echo "  Restart service: docker-compose -f infrastructure/docker-compose.prod.yml restart <service>"
echo "  Update: docker-compose -f infrastructure/docker-compose.prod.yml pull && docker-compose -f infrastructure/docker-compose.prod.yml up -d"

echo ""
echo "🎉 Deployment completed!"
echo "   API Gateway: http://$(hostname -I | awk '{print $1}')"
echo "   Health Check: http://$(hostname -I | awk '{print $1}')/health"