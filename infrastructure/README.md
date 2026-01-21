# Construct Server - Production Deployment

This directory contains Terraform configuration and Docker Compose setup for deploying Construct Server microservices to a VPS (DigitalOcean).

## 🚀 Quick Start

### Prerequisites

1. **DigitalOcean Account** with API token
2. **SSH Key Pair** for server access
3. **Domain Name** (optional but recommended)
4. **Terraform** installed locally
5. **Git** repository access

### 1. Clone and Setup

```bash
git clone <your-repo-url>
cd construct-server/infrastructure/terraform

# Copy environment file and fill in values
cp ../.env.prod.example ../.env.prod
# Edit .env.prod with your production values
```

### 2. Configure Terraform Variables

Create a `terraform.tfvars` file:

```hcl
do_token = "your-digitalocean-api-token"
ssh_public_key_path = "~/.ssh/id_rsa.pub"
ssh_allowed_ips = ["your-ip/32"]  # Restrict SSH access
region = "nyc1"
droplet_size = "s-2vcpu-4gb"
domain_name = "your-domain.com"
admin_username = "construct"

# Sensitive variables
db_password = "your-secure-db-password"
jwt_secret = "your-256-bit-jwt-secret-hex"
```

### 3. Deploy Infrastructure

```bash
# Initialize Terraform
terraform init

# Plan the deployment
terraform plan

# Apply the changes
terraform apply
```

### 4. Deploy Application

After Terraform creates the server:

```bash
# Get the server IP from Terraform output
terraform output droplet_ip

# SSH to the server
ssh construct@<server-ip>

# Clone your repository
git clone <your-repo-url>
cd construct-server

# Copy production environment
cp infrastructure/.env.prod.example infrastructure/.env.prod
# Edit .env.prod with production values

# Deploy services
docker-compose -f infrastructure/docker-compose.prod.yml up -d
```

## 📋 Services Overview

| Service | Port | Purpose |
|---------|------|---------|
| API Gateway | 80/443 | Entry point, routing, middleware |
| Auth Service | 8001 | Authentication & JWT tokens |
| Messaging Service | 8002 | Message sending & long polling |
| User Service | 8003 | User profiles & key management |
| Notification Service | 8004 | Push notifications |
| Media Service | 8005 | File uploads & storage |
| Delivery Worker | N/A | Background message processing |

## 🔧 Configuration

### Required Environment Variables

Copy `.env.prod.example` to `.env.prod` and configure:

- **DATABASE_URL**: PostgreSQL connection string
- **REDIS_URL**: Redis connection with password
- **JWT_SECRET**: 256-bit hex secret for JWT signing
- **DB_PASSWORD**: Secure database password
- **REDIS_PASSWORD**: Redis password
- **DOMAIN_NAME**: Your domain name

### Optional Services

- **Kafka**: For reliable message delivery (Confluent Cloud recommended)
- **Vault**: For key management rotation
- **APNs**: For iOS push notifications

## 🔒 Security Considerations

### Firewall
- SSH access restricted to specified IPs
- HTTP/HTTPS open to all
- Internal service ports not exposed externally

### Secrets Management
- Use strong passwords for database and Redis
- Generate secure JWT secrets
- Consider using Vault for secrets management

### SSL/TLS
- Use Caddy or Nginx as reverse proxy for SSL termination
- Configure Let's Encrypt certificates

## 📊 Monitoring

### Health Checks
All services expose health endpoints:
- `/health` - Basic health check
- `/health/ready` - Readiness probe
- `/health/live` - Liveness probe

### Logs
```bash
# View all service logs
docker-compose -f infrastructure/docker-compose.prod.yml logs -f

# View specific service logs
docker-compose -f infrastructure/docker-compose.prod.yml logs -f gateway
```

### Metrics
- Prometheus metrics available at `/metrics` on gateway
- Configure monitoring dashboard (Grafana recommended)

## 🔄 Updates

### Rolling Updates
```bash
# Pull latest code
git pull origin main

# Rebuild and restart services
docker-compose -f infrastructure/docker-compose.prod.yml build --no-cache
docker-compose -f infrastructure/docker-compose.prod.yml up -d
```

### Database Migrations
Migrations run automatically on service startup. For manual control:
```bash
docker-compose -f infrastructure/docker-compose.prod.yml exec auth-service sqlx migrate run
```

## 🆘 Troubleshooting

### Common Issues

1. **Services won't start**
   - Check environment variables in `.env.prod`
   - Verify database connectivity
   - Check Docker logs: `docker-compose logs <service-name>`

2. **Database connection errors**
   - Ensure PostgreSQL is healthy: `docker-compose ps postgres`
   - Check DATABASE_URL format
   - Verify network connectivity between containers

3. **Redis connection errors**
   - Check REDIS_URL format (include password)
   - Verify Redis is running: `docker-compose ps redis`

4. **Gateway routing errors**
   - Check MICROSERVICES_ENABLED=true
   - Verify service URLs in environment
   - Check service health: `curl http://localhost:<port>/health`

### Logs and Debugging
```bash
# View all logs
docker-compose -f infrastructure/docker-compose.prod.yml logs

# View logs for specific service
docker-compose -f infrastructure/docker-compose.prod.yml logs auth-service

# Follow logs in real-time
docker-compose -f infrastructure/docker-compose.prod.yml logs -f

# Check container status
docker-compose -f infrastructure/docker-compose.prod.yml ps

# Enter container for debugging
docker-compose -f infrastructure/docker-compose.prod.yml exec auth-service bash
```

## 🏗️ Architecture

```
Internet
    ↓
[API Gateway] (Port 80/443)
    ↓
[Auth|Messaging|User|Notification Services]
    ↓
[PostgreSQL + Redis]
```

All services communicate internally via Docker network. External access only through API Gateway.

## 📝 Next Steps

1. **SSL/TLS**: Configure HTTPS with Let's Encrypt
2. **Monitoring**: Set up Prometheus + Grafana
3. **Backup**: Configure database backups
4. **Scaling**: Add load balancer for multiple instances
5. **CDN**: Configure CDN for media files