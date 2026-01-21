# Terraform configuration for Construct Server production deployment
# Provider: DigitalOcean VPS

terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

# Configure the DigitalOcean Provider
provider "digitalocean" {
  token = var.do_token
}

# Create a new SSH key for the droplet
resource "digitalocean_ssh_key" "construct_ssh" {
  name       = "construct-server-key"
  public_key = file(var.ssh_public_key_path)
}

# Create a droplet (VPS)
resource "digitalocean_droplet" "construct_server" {
  image    = var.droplet_image
  name     = var.droplet_name
  region   = var.region
  size     = var.droplet_size
  ssh_keys = [digitalocean_ssh_key.construct_ssh.fingerprint]

  # User data script to initialize the server
  user_data = templatefile("${path.module}/cloud-init.yml", {
    admin_username = var.admin_username
  })

  tags = ["construct-server", "microservices"]
}

# Create a firewall
resource "digitalocean_firewall" "construct_firewall" {
  name = "construct-server-firewall"

  droplet_ids = [digitalocean_droplet.construct_server.id]

  # Inbound rules
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.ssh_allowed_ips
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Allow health checks from DigitalOcean monitoring
  inbound_rule {
    protocol         = "tcp"
    port_range       = "8080"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Outbound rules - allow all outbound
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# Optional: Create a domain record if domain is provided
resource "digitalocean_domain" "construct_domain" {
  count = var.domain_name != "" ? 1 : 0
  name  = var.domain_name
}

resource "digitalocean_record" "construct_a_record" {
  count  = var.domain_name != "" ? 1 : 0
  domain = digitalocean_domain.construct_domain[0].name
  type   = "A"
  name   = "@"
  value  = digitalocean_droplet.construct_server.ipv4_address
}

resource "digitalocean_record" "construct_www_record" {
  count  = var.domain_name != "" ? 1 : 0
  domain = digitalocean_domain.construct_domain[0].name
  type   = "A"
  name   = "www"
  value  = digitalocean_droplet.construct_server.ipv4_address
}