# Variables for Terraform configuration

variable "do_token" {
  description = "DigitalOcean API token"
  type        = string
  sensitive   = true
}

variable "ssh_public_key_path" {
  description = "Path to SSH public key file"
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}

variable "ssh_allowed_ips" {
  description = "List of IP addresses allowed to SSH"
  type        = list(string)
  default     = ["0.0.0.0/0"] # WARNING: Restrict this in production
}

variable "region" {
  description = "DigitalOcean region"
  type        = string
  default     = "nyc1"
}

variable "droplet_image" {
  description = "Droplet image (OS)"
  type        = string
  default     = "ubuntu-22-04-x64"
}

variable "droplet_size" {
  description = "Droplet size (RAM/CPU)"
  type        = string
  default     = "s-2vcpu-4gb" # 2 CPU, 4GB RAM - good for microservices
}

variable "droplet_name" {
  description = "Name of the droplet"
  type        = string
  default     = "construct-server"
}

variable "admin_username" {
  description = "Admin username for the server"
  type        = string
  default     = "construct"
}

variable "domain_name" {
  description = "Domain name (leave empty to skip domain setup)"
  type        = string
  default     = ""
}

# Database configuration
variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}

variable "jwt_secret" {
  description = "JWT secret key"
  type        = string
  sensitive   = true
}

variable "kafka_brokers" {
  description = "Kafka brokers URL"
  type        = string
  default     = ""
}

variable "kafka_sasl_username" {
  description = "Kafka SASL username"
  type        = string
  default     = ""
}

variable "kafka_sasl_password" {
  description = "Kafka SASL password"
  type        = string
  sensitive   = true
  default     = ""
}