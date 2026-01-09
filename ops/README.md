# Construct Server - Deployment Guide

This directory contains deployment configurations for Construct Server components.

## 📁 Files Overview

```
ops/
├── fly.toml              # WebSocket server config (construct-server)
├── fly.gateway.toml      # Message Gateway config (construct-message-gateway)
├── fly.worker.toml       # Delivery Worker config (construct-delivery-worker)
├── Dockerfile            # Multi-stage Docker build (all binaries)
├── docker-compose.yml    # Local development stack
├── setup-fly-secrets.sh  # Automated secrets deployment from .env
└── README.md            # This file
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Fly.io Platform                          │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐   ┌───────────────────┐   ┌──────────────────┐
│ construct-    │   │ message-gateway   │   │ delivery-worker  │
│   server      │   │ (gRPC)            │   │ (Kafka consumer) │
│ (WebSocket)   │   │                   │   │                  │
│               │   │ Validates +       │   │ Reads Kafka →    │
│ Region: ams   │   │ Rate limits +     │   │ Delivers to      │
│ Instances:1-10│   │ Writes to Kafka   │   │ online users     │
│               │   │                   │   │                  │
│ fly.toml      │   │ Region: ams       │   │ Region: ams      │
│               │   │ Instances: 1-10   │   │ Instances: 2-10  │
└───────┬───────┘   └───────┬───────────┘   └──────┬───────────┘
        │                   │                      │
        │                   │                      │
        └───────────────────┼──────────────────────┘
                            │
        ┌───────────────────┼───────────────────────┐
        │                   │                       │
        ▼                   ▼                       ▼
┌───────────────┐   ┌──────────────────┐   ┌──────────────────┐
│ PostgreSQL    │   │ Redis (Upstash)   │   │ Kafka (Confluent)│
│ (Supabase)    │   │                   │   │                  │
│               │   │ • Rate limiting   │   │ • Messages       │
│ Region: EU    │   │ • Sessions        │   │ • Delivery ACKs  │
│               │   │ • Server registry │   │                  │
└───────────────┘   └──────────────────┘   └──────────────────┘
```

## 🚀 Quick Start

### Prerequisites

1. **Install Fly CLI**:
   ```bash
   curl -L https://fly.io/install.sh | sh
   ```

2. **Login to Fly.io**:
   ```bash
   fly auth login
   ```

3. **Configure .env file**:
   ```bash
   cp .env.example .env
   # Edit .env with your credentials
   ```

### First Deployment

```bash
# 1. Set secrets for all services (from .env)
make secrets-all

# 2. Deploy all services
make deploy-all

# 3. Check status
make status-all
```

## 📋 Deployment Commands

### Individual Service Deployment

```bash
# Deploy WebSocket server only
make deploy-server

# Deploy delivery worker only
make deploy-worker

# Deploy message gateway only
make deploy-gateway
```

### Secrets Management

```bash
# Set secrets for all services (recommended)
make secrets-all

# Or set individually
make secrets-server   # WebSocket server
make secrets-worker   # Delivery worker
make secrets-gateway  # Message Gateway
```

### Monitoring

```bash
# View logs
make logs-server
make logs-worker
make logs-gateway

# Check status
make status-all
```

## 🔧 Configuration

### Required Secrets

All secrets are set from `.env` file via `make secrets-all`. Required secrets:

#### Core Secrets (all services)
- `DATABASE_URL` - Supabase PostgreSQL connection string
- `REDIS_URL` - Upstash Redis connection string
- `JWT_SECRET` - JWT signing secret (64+ characters)
- `JWT_ISSUER` - JWT issuer (e.g., "construct-server")
- `LOG_HASH_SALT` - Salt for hashing user IDs in logs

#### Kafka Secrets (all services)
- `KAFKA_ENABLED=true`
- `KAFKA_BROKERS` - Confluent Cloud bootstrap servers
- `KAFKA_TOPIC` - Topic name (e.g., "cnstrct-msg")
- `KAFKA_CONSUMER_GROUP` - Consumer group (e.g., "cnstrct-dlvr-wrkrs")
- `KAFKA_SSL_ENABLED=true`
- `KAFKA_SASL_MECHANISM=PLAIN`
- `KAFKA_SASL_USERNAME` - Confluent API key
- `KAFKA_SASL_PASSWORD` - Confluent API secret

#### Delivery ACK Secrets (server + worker)
- `DELIVERY_ACK_MODE=kafka`
- `DELIVERY_SECRET_KEY` - HMAC secret key (64 hex chars)
- `DELIVERY_EXPIRY_DAYS=7`
- `DELIVERY_ACK_ENABLE_BATCHING=true`
- `DELIVERY_ACK_BATCH_BUFFER_SECS=5`

#### Federation Secrets (server only)
- `INSTANCE_DOMAIN` - Your server domain (e.g., "api.konstruct.cc")
- `FEDERATION_BASE_DOMAIN` - Base domain for federation
- `FEDERATION_ENABLED=false` (set to true when ready)

### Environment Variables (fly.toml)

Non-secret configuration is in fly.toml files:

```toml
[env]
  PORT = "8080"
  RUST_LOG = "info,construct_server=debug"
  MESSAGE_TTL_DAYS = "7"
  MAX_MESSAGES_PER_HOUR = "1000"
```

## 🐳 Local Development

### Docker Compose

Start full stack locally (PostgreSQL + Redis + Server + Worker):

```bash
make docker-up
make docker-logs
```

Stop services:

```bash
make docker-down
```

### Run Binaries Locally

```bash
# Run server
make run-server

# Run worker
make run-worker

# Run gateway
make run-gateway
```

## 📊 Monitoring & Debugging

### View Logs

```bash
# Real-time logs (all services)
make logs-server    # WebSocket server
make logs-worker    # Delivery worker
make logs-gateway   # Message gateway
```

### Check Service Status

```bash
# All services status
make status-all

# Individual services
make status-server
make status-worker
make status-gateway
```

### SSH into Running Machine

```bash
fly ssh console -a construct-server
fly ssh console -a construct-delivery-worker
fly ssh console -a construct-message-gateway
```

### Scale Instances

```bash
# Scale WebSocket server to 3 instances
fly scale count 3 -a construct-server

# Scale delivery worker to 5 instances
fly scale count 5 -a construct-delivery-worker
```

## 🔐 Security Best Practices

1. **Never commit .env file**:
   - .env is in .gitignore
   - Use `make secrets-all` to deploy secrets

2. **Rotate secrets regularly**:
   ```bash
   # Generate new JWT_SECRET
   openssl rand -base64 64

   # Generate new DELIVERY_SECRET_KEY
   openssl rand -hex 32

   # Update .env and redeploy secrets
   make secrets-all
   ```

3. **Use strong passwords**:
   - Database passwords: 32+ characters
   - JWT secrets: 64+ characters
   - HMAC keys: 64 hex characters (32 bytes)

4. **Enable HTTPS only**:
   - Fly.io enforces HTTPS by default
   - `force_https = true` in fly.toml

## 🚨 Troubleshooting

### Deployment Fails

```bash
# Check build logs
fly logs -a construct-server

# Verify secrets are set
fly secrets list -a construct-server

# Check machine status
fly status -a construct-server
```

### Kafka Connection Issues

```bash
# Test Kafka connectivity
fly ssh console -a construct-server
nc -zv <KAFKA_BROKERS>

# Check Kafka secrets
fly secrets list -a construct-server | grep KAFKA
```

### Database Connection Issues

```bash
# Test PostgreSQL connectivity
fly ssh console -a construct-server
psql $DATABASE_URL -c "SELECT 1"

# Check if migrations ran
fly ssh console -a construct-server
cd /app && ls migrations/
```

### Redis Connection Issues

```bash
# Test Redis connectivity
fly ssh console -a construct-server
redis-cli -u $REDIS_URL PING
```

## 📈 Performance Tuning

### Auto-Scaling Configuration

Edit `fly.toml` autoscaling section:

```toml
[autoscaling]
  min_instances = 2
  max_instances = 10

  [[autoscaling.metrics]]
    type = "concurrency"
    target = 500  # Adjust based on load testing
```

### VM Size Adjustment

```bash
# Increase memory for WebSocket server
fly scale memory 2048 -a construct-server

# Increase CPU cores
fly scale vm shared-cpu-2x -a construct-server
```

## 🔄 Rollback

If deployment fails or introduces bugs:

```bash
# List recent deployments
fly releases -a construct-server

# Rollback to previous version
fly releases rollback <version> -a construct-server
```

## 📚 Additional Resources

- [Fly.io Documentation](https://fly.io/docs/)
- [Confluent Kafka Docs](https://docs.confluent.io/)
- [Construct Server README](../README.md)
- [Kafka Migration Plan](../KAFKA_MIGRATION_PHASE_4_6_PLAN.md)
- [Delivery ACK Security](../KAFKA_DELIVERY_ACK_SECURITY_AUDIT.md)

## 💡 Common Workflows

### Development Workflow

```bash
# 1. Start local stack
make docker-up

# 2. Make changes to code
# 3. Restart services
make docker-rebuild

# 4. View logs
make docker-logs
```

### Deployment Workflow

```bash
# 1. Update .env with new secrets (if needed)
# 2. Set secrets
make secrets-all

# 3. Deploy all services
make deploy-all

# 4. Monitor deployment
make status-all
make logs-server
```

### Emergency Rollback

```bash
# 1. Check recent releases
fly releases -a construct-server

# 2. Rollback to stable version
fly releases rollback <stable-version> -a construct-server

# 3. Verify rollback
make status-server
make logs-server
```
