# Outputs for Terraform deployment

output "droplet_ip" {
  description = "Public IP address of the droplet"
  value       = digitalocean_droplet.construct_server.ipv4_address
}

output "droplet_id" {
  description = "ID of the created droplet"
  value       = digitalocean_droplet.construct_server.id
}

output "droplet_name" {
  description = "Name of the created droplet"
  value       = digitalocean_droplet.construct_server.name
}

output "ssh_command" {
  description = "SSH command to connect to the server"
  value       = "ssh ${var.admin_username}@${digitalocean_droplet.construct_server.ipv4_address}"
}

output "domain_name" {
  description = "Domain name (if configured)"
  value       = var.domain_name != "" ? var.domain_name : null
}

# Service URLs (assuming standard ports)
output "gateway_url" {
  description = "API Gateway URL"
  value       = "http://${digitalocean_droplet.construct_server.ipv4_address}:80"
}

output "health_check_url" {
  description = "Health check URL"
  value       = "http://${digitalocean_droplet.construct_server.ipv4_address}/health"
}