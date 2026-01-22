# Infrastructure

Production deployment configuration for Construct Server microservices.

## Structure

- `docker-compose/` - Docker Compose files for each service
- `nginx/` - Nginx reverse proxy configurations  
- `monitoring/` - Prometheus, Grafana, and monitoring configs
- `backups/` - Backup and restore scripts
- `ansible/` - Ansible playbooks for automated deployment
- `security/` - Firewall, SSL, and security hardening configs

## Services

- API Gateway (port 80/443)
- Auth Service (internal)
- Messaging Service (internal) 
- User Service (internal)
- Notification Service (internal)
- Media Service (internal)
- Delivery Worker (internal)

## Prerequisites

- Ubuntu 22.04+ VPS
- Docker & Docker Compose
- Nginx
- PostgreSQL (external or containerized)
- Redis (external or containerized) 
- Kafka (external or containerized)
- SSL certificates (Let's Encrypt)

## Deployment

1. Run Ansible playbooks to setup servers
2. Deploy services with docker-compose
3. Configure nginx reverse proxy
4. Setup monitoring stack
5. Configure backups

## Security

- All services behind nginx reverse proxy
- Internal services not exposed publicly
- SSL/TLS encryption
- Firewall rules
- Secret management via environment variables

## Quick Start

1. **Setup inventory:**
   ```bash
   cp infrastructure/ansible/inventory/inventory.ini.example infrastructure/ansible/inventory/inventory.ini
   # Edit with your server IPs
   ```

2. **Run setup:**
   ```bash
   ansible-playbook -i infrastructure/ansible/inventory/inventory.ini infrastructure/ansible/playbooks/setup.yml
   ```

3. **Deploy services:**
   ```bash
   ansible-playbook -i infrastructure/ansible/inventory/inventory.ini infrastructure/ansible/playbooks/deploy.yml
   ```

4. **Configure SSL:**
   ```bash
   # Use certbot for Let's Encrypt
   certbot --nginx -d your-domain.com
   ```

## Scaling

- Use separate servers for each service
- Load balance with nginx upstream
- Monitor with Prometheus/Grafana
- Backup databases regularly

## Troubleshooting

- Check service logs: `docker-compose logs`
- Verify connectivity: `curl http://localhost:8080/health`
- Monitor resources: `htop`, `docker stats`
