# Construct Server - Production Deployment

This directory contains Terraform configuration and Docker Compose setup for deploying Construct Server microservices across multiple VPS servers (DigitalOcean/Hetzner).

## 🏗️ Architecture Overview

The production deployment uses a **5-server architecture** for optimal performance, security, and scalability:

```
Internet
    ↓
┌─────────────────────────────────────┐
│   Gateway Server  (VPS #1)         │
│  ┌─────────────────────────────────┐ │
│  │   Load Balancer (Caddy)        │ │
│  │   • SSL/TLS Termination        │ │
│  │   • Rate Limiting              │ │
│  │   • Request Routing            │ │
│  └─────────────────────────────────┘ │
└─────────────────────────────────────┘
                    │
          Private Network (10.x.x.x)
                    │
    ┌───────────────┼───────────────┐
    │               │               │
┌───▼───┐       ┌───▼───┐       ┌───▼───┐
│  App  │       │  DB   │       │Message│
│Server │       │Server │       │Server │
│(VPS#2)│       │(VPS#5)│       │(VPS#3)│
│       │       │       │       │       │
│ Auth  │◄─────►│  DB   │◄──────┤ Queue │
│ User  │       │ Cache │       │       │
│ Notify│       │       │       │Messaging
└───────┘       └───────┘       │Delivery│
                                │Worker │
                    ┌───────────┼────────┐
                    │           │        │
                ┌───▼───┐   ┌───▼───┐
                │ Media │   │Monitoring
                │Server │   │(Optional)
                │(VPS#4)│   └────────┘
                │ Files │
                └───────┘
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Gateway VPS   │    │   Core VPS      │    │ Message VPS     │    │  Media VPS      │
│                 │    │                 │    │                 │    │  (Optional)     │
│ • Load Balancer │    │ • PostgreSQL    │    │ • Redpanda      │    │ • Media Service │
│ • API Gateway   │    │ • Redis Primary │    │ • Redis Replica │    │ • Monitoring    │
│ • SSL/TLS       │    │ • Auth Service  │    │ • Messaging     │    │                 │
│ • Rate Limiting │    │ • User Service  │    │ • Delivery      │    └─────────────────┘
│                 │    │ • Notification  │    │   Worker        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Domain Name   │
                    │ your-domain.com │
                    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites

1. **Cloud Provider Account** (DigitalOcean/Hetzner) with API access
2. **SSH Key Pair** for server access
3. **Domain Name** (required for production)
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
# Provider settings
do_token = "your-digitalocean-api-token"
region = "nyc1"

# SSH Configuration
ssh_public_key_path = "~/.ssh/id_rsa.pub"
ssh_allowed_ips = ["your-ip/32"]  # Restrict SSH access
admin_username = "construct"

# Domain Configuration
domain_name = "your-domain.com"

# Server Specifications
gateway_droplet_size = "s-1vcpu-1gb"    # Gateway server
core_droplet_size = "s-2vcpu-4gb"       # Core services + DB
message_droplet_size = "s-2vcpu-4gb"    # Message services + Queue
media_droplet_size = "s-2vcpu-4gb"      # Media + monitoring

# Enable optional media server
enable_media_server = true

# Sensitive variables
db_password = "your-secure-db-password"
redis_password = "your-secure-redis-password"
jwt_secret = "your-256-bit-jwt-secret-hex"
apns_device_token_encryption_key = "your-64-char-apns-key"
log_hash_salt = "your-64-char-log-salt"
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

After Terraform creates the servers, deploy to each server individually:

#### Database Server Deployment (Start First):
```bash
# Get database server IP
terraform output db_server
# SSH: ssh construct@<db-ip>

git clone <your-repo-url>
cd construct-server

cp infrastructure/.env.prod.example infrastructure/.env.prod
# Edit .env.prod with production values

# Deploy database services
./infrastructure/deploy.sh db
```

#### Gateway Server Deployment:
```bash
# Get gateway server IP
terraform output gateway_server
# SSH: ssh construct@<gateway-ip>

# Same setup steps, then:
./infrastructure/deploy.sh gateway
```

#### Application Server Deployment:
```bash
# Get app server IP
terraform output app_server
# SSH: ssh construct@<app-ip>

# Same setup steps, then:
./infrastructure/deploy.sh app
```

#### Message Server Deployment:
```bash
# Get message server IP
terraform output message_server
# SSH: ssh construct@<message-ip>

# Same setup steps, then:
./infrastructure/deploy.sh message
```

#### Media Server Deployment (Optional):
```bash
# Get media server IP (if enabled)
terraform output media_server
# SSH: ssh construct@<media-ip>

# Same setup steps, then:
./infrastructure/deploy.sh media
```

## 📋 Services Overview

### Gateway Server (VPS #1)
| Service | Port | Purpose |
|---------|------|---------|
| API Gateway | 80/443 | Load balancer, SSL termination, routing |
| Caddy | 80/443 | Reverse proxy with automatic HTTPS |

### Application Server (VPS #2)
| Service | Port | Purpose |
|---------|------|---------|
| Auth Service | 8001 | Authentication & JWT tokens |
| User Service | 8002 | User profiles & key management |
| Notification Service | 8003 | Push notifications |

### Database Server (VPS #5)
| Service | Port | Purpose |
|---------|------|---------|
| PostgreSQL | 5432 | Primary database with optimizations |
| Redis Primary | 6379 | Primary cache & session storage |

### Message Server (VPS #3)
| Service | Port | Purpose |
|---------|------|---------|
| Redpanda | 9092 | Kafka-compatible message broker |
| Redis Replica | 6379 | Cache replica for message processing |
| Messaging Service | 8004 | Message sending & real-time updates |
| Delivery Worker | N/A | Background message processing |

### Media Server (VPS #4 - Optional)
| Service | Port | Purpose |
|---------|------|---------|
| Media Service | 8005 | File uploads & storage |
| Prometheus | 9090 | Metrics collection |
| Grafana | 3000 | Monitoring dashboard |

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

### Network Architecture
```
Internet
    ↓
┌─────────────────────────────────────┐
│         Gateway Server              │
│  ┌─────────────────────────────────┐ │
│  │   Load Balancer (Caddy)        │ │
│  │   • SSL/TLS Termination        │ │
│  │   • Rate Limiting              │ │
│  │   • Request Routing            │ │
│  └─────────────────────────────────┘ │
└─────────────────────────────────────┘
                    │
          Private Network (10.x.x.x)
                    │
    ┌───────────────┼───────────────┐──────┐
    │               │               │      │
┌───▼───┐       ┌───▼───┐       ┌───▼───┐  │
│  App  │       │  DB   │       │Message│  │
│Server │       │Server │       │Server │  │
│       │       │       │       │       │  │
│ Auth  │◄─────►│  DB   │◄──────┤ Queue │  │
│ User  │       │ Cache │       │       │  │
│ Notify│       │       │       │Messaging │
└───────┘       └───────┘       │Delivery│  │
                                │Worker  │  │
                                └────────┘  │
                                             │
                                         ┌───▼───┐
                                         │ Media │
                                         │Server │
                                         │(Opt.) │
                                         └───────┘
```

### Service Communication
- **Internal DNS**: Services communicate via private DNS names (app.internal, db.internal, message.internal)
- **Database**: PostgreSQL on dedicated DB server, accessed by application services
- **Cache**: Redis primary on DB server, replica on Message server
- **Message Queue**: Redpanda on Message server for reliable message delivery
- **Load Balancing**: All external traffic goes through Gateway server
- **Security**: Strict firewall rules between server roles

### Benefits of 5-Server Architecture
- **Performance**: Database isolation prevents resource contention
- **Scalability**: Each server role can be scaled independently
- **Security**: Database server accessible only to application servers
- **Reliability**: Failure in one server doesn't affect database operations
- **Maintenance**: Can update/backup database without affecting applications

All services communicate internally via Docker network. External access only through API Gateway.

## 📝 Next Steps

1. **SSL/TLS**: Configure HTTPS with Let's Encrypt
2. **Monitoring**: Set up Prometheus + Grafana
3. **Backup**: Configure database backups
4. **Scaling**: Add load balancer for multiple instances
5. **CDN**: Configure CDN for media files