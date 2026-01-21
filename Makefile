.PHONY: help build run-worker run-media-service test check clean \
	docker-up docker-down docker-logs docker-build docker-rebuild \
	deploy-worker check-before-deploy \
	deploy-api-gateway deploy-auth-service deploy-user-service deploy-messaging-service deploy-notification-service deploy-media-service \
	deploy-microservices \
	secrets-worker secrets-media-service \
	secrets-api-gateway secrets-auth-service secrets-user-service secrets-messaging-service secrets-notification-service secrets-media-service \
	logs-worker logs-media-service \
	logs-api-gateway logs-auth-service logs-user-service logs-messaging-service logs-notification-service \
	logs-microservices \
	status-worker status-media-service \
	status-api-gateway status-auth-service status-user-service status-messaging-service status-notification-service \
	status-microservices \
	db-migrate db-up db-down \
	generate-jwt-keys vault-dev-up vault-dev-down vault-dev-status vault-dev-init \
	key-mgmt-check key-mgmt-init

# ============================================================================
# Help
# ============================================================================

help:
	@echo "╔════════════════════════════════════════════════════════════════╗"
	@echo "║  Construct Server - Centralized Build & Deploy Commands       ║"
	@echo "╚════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "📦 Local Development:"
	@echo "  make build              Build all binaries (release mode)"
	@echo "  make run-worker         Run delivery worker locally"
	@echo "  make run-media-service  Run media service locally"
	@echo "  make test               Run all tests"
	@echo "  make check              Check code (clippy + fmt)"
	@echo "  make fmt                Format code"
	@echo "  make clean              Clean build artifacts"
	@echo ""
	@echo "🐳 Docker (Local Stack):"
	@echo "  make docker-up          Start all services (db + redis)"
	@echo "  make docker-down        Stop all docker-compose services"
	@echo "  make docker-logs        View docker-compose logs (tail -f)"
	@echo "  make docker-build       Rebuild docker images"
	@echo "  make docker-rebuild     Rebuild & restart all services"
	@echo ""
	@echo "🚀 Fly.io Deployment:"
	@echo "  make deploy-worker      Deploy delivery worker to Fly.io"
	@echo ""
	@echo "🚀 Microservices Deployment:"
	@echo "  make deploy-api-gateway         Deploy API Gateway to Fly.io"
	@echo "  make deploy-auth-service        Deploy Auth Service to Fly.io"
	@echo "  make deploy-user-service        Deploy User Service to Fly.io"
	@echo "  make deploy-messaging-service   Deploy Messaging Service to Fly.io"
	@echo "  make deploy-notification-service Deploy Notification Service to Fly.io"
	@echo "  make deploy-media-service       Deploy Media Service to Fly.io"
	@echo "  make deploy-microservices      Deploy all microservices"
	@echo ""
	@echo "🔐 Fly.io Secrets Management:"
	@echo "  make secrets-worker     Set secrets for construct-delivery-worker"
	@echo ""
	@echo "🔐 Microservices Secrets:"
	@echo "  make secrets-api-gateway         Set secrets for API Gateway"
	@echo "  make secrets-auth-service        Set secrets for Auth Service"
	@echo "  make secrets-user-service        Set secrets for User Service"
	@echo "  make secrets-messaging-service   Set secrets for Messaging Service"
	@echo "  make secrets-notification-service Set secrets for Notification Service"
	@echo "  make secrets-media-service       Set secrets for Media Service"
	@echo ""
	@echo "📊 Fly.io Monitoring:"
	@echo "  make logs-worker        View delivery worker logs"
	@echo "  make logs-media-service View media service logs"
	@echo "  make status-worker      Show construct-delivery-worker status"
	@echo "  make status-media-service Show construct-media-service status"
	@echo ""
	@echo "📊 Microservices Monitoring:"
	@echo "  make logs-api-gateway         View API Gateway logs"
	@echo "  make logs-auth-service        View Auth Service logs"
	@echo "  make logs-user-service        View User Service logs"
	@echo "  make logs-messaging-service   View Messaging Service logs"
	@echo "  make logs-notification-service View Notification Service logs"
	@echo "  make status-api-gateway       Show API Gateway status"
	@echo "  make status-auth-service      Show Auth Service status"
	@echo "  make status-user-service      Show User Service status"
	@echo "  make status-messaging-service Show Messaging Service status"
	@echo "  make status-notification-service Show Notification Service status"
	@echo "  make status-microservices     Show status of all microservices"
	@echo "  make logs-microservices       View recent logs from all microservices"
	@echo ""
	@echo "🗄️  Database:"
	@echo "  make db-migrate         Run database migrations"
	@echo "  make db-up              Start local PostgreSQL + Redis"
	@echo "  make db-down            Stop local databases"
	@echo ""
	@echo "🔑 Key Management & RS256:"
	@echo "  make generate-jwt-keys  Generate RSA keypair for RS256 (JWT_PRIVATE_KEY/JWT_PUBLIC_KEY)"
	@echo "  make vault-dev-up       Start Vault in dev mode (Docker)"
	@echo "  make vault-dev-down     Stop Vault dev container"
	@echo "  make vault-dev-status   Check Vault dev status"
	@echo "  make vault-dev-init     Initialize Vault dev with Transit keys"
	@echo "  make key-mgmt-check     Check Key Management System configuration"
	@echo "  make key-mgmt-init      Initialize Key Management System in database"
	@echo ""
	@echo "💡 Common Workflows:"
	@echo "  Development:   make docker-up && make docker-logs"
	@echo "  Deploy microservices: make deploy-microservices"
	@echo "  First deploy:  make secrets-api-gateway && make deploy-microservices"
	@echo "  RS256 setup:   make generate-jwt-keys && make vault-dev-up && make vault-dev-init"
	@echo "  Key Management: make vault-dev-up && make vault-dev-init && make key-mgmt-init"
	@echo "  Monitor microservices: make status-microservices && make logs-api-gateway"

# ============================================================================
# Local Development
# ============================================================================

build:
	@echo "🔨 Building all binaries..."
	cargo build --release --bins

run-worker:
	@echo "⚙️  Running delivery worker locally..."
	RUST_LOG=info cargo run --bin delivery-worker

run-media-service:
	@echo "📸 Running media service locally..."
	RUST_LOG=info MEDIA_UPLOAD_TOKEN_SECRET=dev-secret-minimum-32-chars-long cargo run --bin media-service

test:
	@echo "🧪 Running tests..."
	cargo test

check:
	@echo "🔍 Checking code..."
	cargo clippy -- -D warnings
	cargo fmt --check

fmt:
	@echo "✨ Formatting code..."
	cargo fmt

clean:
	@echo "🧹 Cleaning build artifacts..."
	cargo clean

# ============================================================================
# Docker (Local Development Stack)
# ============================================================================

docker-up:
	@echo "🐳 Starting all services with Docker Compose..."
	docker-compose -f ops/docker-compose.yml up -d
	@echo "✅ Services started. Use 'make docker-logs' to view logs."

docker-down:
	@echo "🛑 Stopping all Docker Compose services..."
	docker-compose -f ops/docker-compose.yml down

docker-logs:
	@echo "📋 Tailing Docker Compose logs..."
	docker-compose -f ops/docker-compose.yml logs -f

docker-build:
	@echo "🔨 Building Docker images..."
	docker-compose -f ops/docker-compose.yml build

docker-rebuild:
	@echo "🔄 Rebuilding and restarting all services..."
	docker-compose -f ops/docker-compose.yml up -d --build

# ============================================================================
# Fly.io Deployment
# ============================================================================

deploy-worker: check-before-deploy
	@echo "⚙️  Deploying delivery worker to Fly.io..."
	fly deploy . --config ops/fly.worker.toml --dockerfile ./ops/Dockerfile --app construct-delivery-worker
	@echo "✅ Worker deployed. View logs: make logs-worker"

check-before-deploy:
	@if [ -z "$$SKIP_CHECK" ]; then \
		echo "🔍 Checking code compilation before deploy..."; \
		cargo check --release || (echo "❌ Compilation failed! Fix errors before deploying." && exit 1); \
		echo "✓ Code compiles successfully"; \
	fi

# ============================================================================
# Microservices Deployment
# ============================================================================

deploy-api-gateway: check-before-deploy
	@echo "🚀 Deploying API Gateway to Fly.io..."
	@fly apps create construct-api-gateway 2>/dev/null || true
	@fly deploy . --config ops/fly.api-gateway.toml --dockerfile ./ops/Dockerfile --app construct-api-gateway
	@echo "✅ API Gateway deployed. View logs: make logs-api-gateway"

deploy-auth-service: check-before-deploy
	@echo "🚀 Deploying Auth Service to Fly.io..."
	@fly apps create construct-auth-service 2>/dev/null || true
	@fly deploy . --config ops/fly.auth-service.toml --dockerfile ./ops/Dockerfile --app construct-auth-service
	@echo "✅ Auth Service deployed. View logs: make logs-auth-service"

deploy-user-service: check-before-deploy
	@echo "🚀 Deploying User Service to Fly.io..."
	@fly apps create construct-user-service 2>/dev/null || true
	@fly deploy . --config ops/fly.user-service.toml --dockerfile ./ops/Dockerfile --app construct-user-service
	@echo "✅ User Service deployed. View logs: make logs-user-service"

deploy-messaging-service: check-before-deploy
	@echo "🚀 Deploying Messaging Service to Fly.io..."
	@fly apps create construct-messaging-service 2>/dev/null || true
	@fly deploy . --config ops/fly.messaging-service.toml --dockerfile ./ops/Dockerfile --app construct-messaging-service
	@echo "✅ Messaging Service deployed. View logs: make logs-messaging-service"

deploy-notification-service: check-before-deploy
	@echo "🚀 Deploying Notification Service to Fly.io..."
	@fly apps create construct-notification-service 2>/dev/null || true
	@fly deploy . --config ops/fly.notification-service.toml --dockerfile ./ops/Dockerfile --app construct-notification-service
	@echo "✅ Notification Service deployed. View logs: make logs-notification-service"

deploy-media-service: check-before-deploy
	@echo "📸 Deploying Media Service to Fly.io..."
	@fly apps create construct-media-service 2>/dev/null || true
	@fly deploy . --config ops/fly.media.toml --dockerfile ./ops/Dockerfile --app construct-media-service
	@echo "✅ Media Service deployed. View logs: make logs-media-service"

deploy-microservices:
	@echo "🔍 Checking code compilation before deploying all microservices..."
	@cargo check --release || (echo "❌ Compilation failed! Fix errors before deploying." && exit 1)
	@echo "✓ Code compiles successfully"
	@echo ""
	@echo "🚀 Deploying all microservices to Fly.io..."
	@echo ""
	@echo "1/6 Deploying API Gateway..."
	@SKIP_CHECK=1 make deploy-api-gateway
	@echo ""
	@echo "2/6 Deploying Auth Service..."
	@SKIP_CHECK=1 make deploy-auth-service
	@echo ""
	@echo "3/6 Deploying User Service..."
	@SKIP_CHECK=1 make deploy-user-service
	@echo ""
	@echo "4/6 Deploying Messaging Service..."
	@SKIP_CHECK=1 make deploy-messaging-service
	@echo ""
	@echo "5/6 Deploying Notification Service..."
	@SKIP_CHECK=1 make deploy-notification-service
	@echo ""
	@echo "6/6 Deploying Media Service..."
	@SKIP_CHECK=1 make deploy-media-service
	@echo ""
	@echo "✅ All microservices deployed!"

# ============================================================================
# Fly.io Secrets Management
# ============================================================================

secrets-worker:
	@echo "🔐 Setting secrets for construct-delivery-worker from .env..."
	@if [ ! -f .env ]; then echo "❌ Error: .env file not found"; exit 1; fi
	@bash ops/setup-fly-secrets.sh worker

# ============================================================================
# Microservices Secrets Management
# ============================================================================

secrets-api-gateway:
	@echo "🔐 Setting secrets for construct-api-gateway from .env..."
	@if [ ! -f .env ]; then echo "❌ Error: .env file not found"; exit 1; fi
	@bash ops/setup-fly-secrets.sh api-gateway

secrets-auth-service:
	@echo "🔐 Setting secrets for construct-auth-service from .env..."
	@if [ ! -f .env ]; then echo "❌ Error: .env file not found"; exit 1; fi
	@bash ops/setup-fly-secrets.sh auth-service

secrets-user-service:
	@echo "🔐 Setting secrets for construct-user-service from .env..."
	@if [ ! -f .env ]; then echo "❌ Error: .env file not found"; exit 1; fi
	@bash ops/setup-fly-secrets.sh user-service

secrets-messaging-service:
	@echo "🔐 Setting secrets for construct-messaging-service from .env..."
	@if [ ! -f .env ]; then echo "❌ Error: .env file not found"; exit 1; fi
	@bash ops/setup-fly-secrets.sh messaging-service

secrets-notification-service:
	@echo "🔐 Setting secrets for construct-notification-service from .env..."
	@if [ ! -f .env ]; then echo "❌ Error: .env file not found"; exit 1; fi
	@bash ops/setup-fly-secrets.sh notification-service

secrets-media-service:
	@echo "🔐 Setting secrets for construct-media-service from .env..."
	@if [ ! -f .env ]; then echo "❌ Error: .env file not found"; exit 1; fi
	@bash ops/setup-fly-secrets.sh media-service

# ============================================================================
# Fly.io Monitoring
# ============================================================================

logs-worker:
	@echo "📋 Viewing construct-delivery-worker logs..."
	fly logs -a construct-delivery-worker

logs-media-service:
	@echo "📋 Viewing construct-media-service logs..."
	fly logs -a construct-media-service

status-worker:
	@echo "📊 construct-delivery-worker status:"
	@fly status -a construct-delivery-worker

status-media-service:
	@echo "📊 construct-media-service status:"
	@fly status -a construct-media-service

# ============================================================================
# Microservices Monitoring
# ============================================================================

logs-api-gateway:
	@echo "📋 Viewing API Gateway logs..."
	@fly logs --app construct-api-gateway

logs-auth-service:
	@echo "📋 Viewing Auth Service logs..."
	@fly logs --app construct-auth-service

logs-user-service:
	@echo "📋 Viewing User Service logs..."
	@fly logs --app construct-user-service

logs-messaging-service:
	@echo "📋 Viewing Messaging Service logs..."
	@fly logs --app construct-messaging-service

logs-notification-service:
	@echo "📋 Viewing Notification Service logs..."
	@fly logs --app construct-notification-service

logs-media-service:
	@echo "📋 Viewing Media Service logs..."
	@fly logs --app construct-media-service

status-api-gateway:
	@echo "📊 API Gateway status:"
	@fly status --app construct-api-gateway || echo "❌ App not found or not deployed"

status-auth-service:
	@echo "📊 Auth Service status:"
	@fly status --app construct-auth-service || echo "❌ App not found or not deployed"

status-user-service:
	@echo "📊 User Service status:"
	@fly status --app construct-user-service || echo "❌ App not found or not deployed"

status-messaging-service:
	@echo "📊 Messaging Service status:"
	@fly status --app construct-messaging-service || echo "❌ App not found or not deployed"

status-notification-service:
	@echo "📊 Notification Service status:"
	@fly status --app construct-notification-service || echo "❌ App not found or not deployed"

status-media-service:
	@echo "📊 Media Service status:"
	@fly status --app construct-media-service || echo "❌ App not found or not deployed"

# Combined monitoring commands
logs-microservices:
	@echo "📋 Viewing all microservices logs..."
	@echo "Note: Use individual 'make logs-<service>' commands for better control"
	@echo ""
	@echo "=== API Gateway ==="
	@fly logs --app construct-api-gateway || true
	@echo ""
	@echo "=== Auth Service ==="
	@fly logs --app construct-auth-service || true
	@echo ""
	@echo "=== User Service ==="
	@fly logs --app construct-user-service || true
	@echo ""
	@echo "=== Messaging Service ==="
	@fly logs --app construct-messaging-service || true
	@echo ""
	@echo "=== Notification Service ==="
	@fly logs --app construct-notification-service || true

# ============================================================================
# Database Management
# ============================================================================

db-migrate:
	@echo "🗄️  Running database migrations..."
	sqlx migrate run

db-up:
	@echo "🗄️  Starting local PostgreSQL + Redis..."
	docker-compose -f ops/docker-compose.yml up postgres redis -d
	@echo "✅ Databases started."

db-down:
	@echo "🛑 Stopping local databases..."
	docker-compose -f ops/docker-compose.yml stop postgres redis

# ============================================================================
# Key Management & RS256
# ============================================================================

generate-jwt-keys:
	@echo "🔑 Generating RSA keypair for RS256..."
	@if [ -f jwt-private.pem ] || [ -f jwt-public.pem ]; then \
		echo "⚠️  Warning: jwt-private.pem or jwt-public.pem already exists"; \
		echo "   Delete them first if you want to regenerate:"; \
		echo "   rm -f jwt-private.pem jwt-public.pem"; \
		exit 1; \
	fi
	@openssl genrsa -out jwt-private.pem 4096
	@openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem
	@echo "✅ RSA keypair generated:"
	@echo "   Private key: jwt-private.pem"
	@echo "   Public key:  jwt-public.pem"
	@echo ""
	@echo "📝 Add to .env file:"
	@echo "   JWT_PRIVATE_KEY=\"\$$(cat jwt-private.pem)\""
	@echo "   JWT_PUBLIC_KEY=\"\$$(cat jwt-public.pem)\""
	@echo ""
	@echo "⚠️  Keep jwt-private.pem secure and never commit it to git!"

vault-dev-up:
	@echo "🔐 Starting Vault in dev mode (Docker)..."
	@if docker ps -a --format '{{.Names}}' | grep -q '^vault-dev$$'; then \
		echo "⚠️  Vault container already exists. Starting it..."; \
		docker start vault-dev || true; \
	else \
		docker run -d --name vault-dev \
			-p 8200:8200 \
			-e 'VAULT_DEV_ROOT_TOKEN_ID=dev-root-token' \
			-e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
			vault:latest; \
	fi
	@sleep 2
	@echo "✅ Vault started at http://127.0.0.1:8200"
	@echo "   Root token: dev-root-token"
	@echo ""
	@echo "📝 Add to .env file:"
	@echo "   VAULT_ADDR=http://127.0.0.1:8200"
	@echo "   VAULT_TOKEN=dev-root-token"
	@echo ""
	@echo "💡 Next steps:"
	@echo "   make vault-dev-init    Initialize Transit keys"

vault-dev-down:
	@echo "🛑 Stopping Vault dev container..."
	@docker stop vault-dev 2>/dev/null || echo "Vault container not running"
	@echo "✅ Vault stopped"

vault-dev-status:
	@echo "📊 Checking Vault dev status..."
	@if ! docker ps --format '{{.Names}}' | grep -q '^vault-dev$$'; then \
		echo "❌ Vault container is not running"; \
		echo "   Start it with: make vault-dev-up"; \
		exit 1; \
	fi
	@echo "✅ Vault container is running"
	@echo ""
	@echo "Testing connection..."
	@VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root-token vault status 2>/dev/null || \
		(echo "❌ Cannot connect to Vault. Is it running?" && exit 1)
	@echo "✅ Vault is accessible"
	@echo ""
	@echo "Checking Transit engine..."
	@VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root-token vault secrets list 2>/dev/null | grep -q transit && \
		echo "✅ Transit engine is enabled" || \
		echo "⚠️  Transit engine not enabled. Run: make vault-dev-init"

vault-dev-init:
	@echo "🔧 Initializing Vault dev with Transit keys..."
	@if ! docker ps --format '{{.Names}}' | grep -q '^vault-dev$$'; then \
		echo "❌ Vault container is not running"; \
		echo "   Start it first: make vault-dev-up"; \
		exit 1; \
	fi
	@export VAULT_ADDR=http://127.0.0.1:8200 && \
	export VAULT_TOKEN=dev-root-token && \
		echo "Enabling Transit secrets engine..." && \
		vault secrets enable transit 2>/dev/null || echo "Transit engine already enabled" && \
		echo "" && \
		echo "Creating Transit keys..." && \
		vault write transit/keys/jwt-signing type=rsa-4096 auto_rotate_period=0 deletion_allowed=false && \
		echo "✅ Created jwt-signing key" && \
		vault write transit/keys/apns-encryption type=chacha20-poly1305 auto_rotate_period=0 deletion_allowed=false && \
		echo "✅ Created apns-encryption key" && \
		vault write transit/keys/federation-signing type=ed25519 auto_rotate_period=0 deletion_allowed=false && \
		echo "✅ Created federation-signing key" && \
		vault write transit/keys/database-encryption type=aes256-gcm96 auto_rotate_period=0 deletion_allowed=false && \
		echo "✅ Created database-encryption key" && \
		echo "" && \
		echo "✅ Vault initialized with all Transit keys!"
	@echo ""
	@echo "💡 Next steps:"
	@echo "   1. Make sure VAULT_ADDR and VAULT_TOKEN are in .env"
	@echo "   2. Run database migrations: make db-migrate"
	@echo "   3. Initialize keys in database: make key-mgmt-init"

key-mgmt-check:
	@echo "🔍 Checking Key Management System configuration..."
	@if [ ! -f .env ]; then \
		echo "❌ .env file not found"; \
		exit 1; \
	fi
	@echo "Checking environment variables..."
	@grep -q "^VAULT_ADDR=" .env 2>/dev/null && \
		echo "✅ VAULT_ADDR is set" || \
		echo "⚠️  VAULT_ADDR is not set in .env"
	@grep -q "^VAULT_TOKEN=" .env 2>/dev/null && \
		echo "✅ VAULT_TOKEN is set" || \
		(grep -q "^VAULT_K8S_ROLE=" .env 2>/dev/null && \
			echo "✅ VAULT_K8S_ROLE is set (Kubernetes auth)" || \
			echo "⚠️  Neither VAULT_TOKEN nor VAULT_K8S_ROLE is set")
	@grep -q "^JWT_PRIVATE_KEY=" .env 2>/dev/null && \
		echo "✅ JWT_PRIVATE_KEY is set (RS256)" || \
		echo "⚠️  JWT_PRIVATE_KEY is not set (RS256 required for Key Management)"
	@grep -q "^JWT_PUBLIC_KEY=" .env 2>/dev/null && \
		echo "✅ JWT_PUBLIC_KEY is set (RS256)" || \
		echo "⚠️  JWT_PUBLIC_KEY is not set (RS256 required for Key Management)"
	@echo ""
	@echo "Checking Vault connection..."
	@if grep -q "^VAULT_ADDR=" .env 2>/dev/null; then \
		VAULT_ADDR=$$(grep "^VAULT_ADDR=" .env | cut -d'=' -f2 | tr -d '"' | tr -d "'"); \
		if grep -q "^VAULT_TOKEN=" .env 2>/dev/null; then \
			VAULT_TOKEN=$$(grep "^VAULT_TOKEN=" .env | cut -d'=' -f2 | tr -d '"' | tr -d "'"); \
			export VAULT_ADDR && export VAULT_TOKEN && \
			vault status >/dev/null 2>&1 && \
				echo "✅ Vault is accessible" || \
				echo "❌ Cannot connect to Vault at $$VAULT_ADDR"; \
		else \
			echo "⚠️  Cannot test Vault connection (VAULT_TOKEN not set)"; \
		fi; \
	else \
		echo "⚠️  Cannot test Vault connection (VAULT_ADDR not set)"; \
	fi

key-mgmt-init:
	@echo "🔧 Initializing Key Management System in database..."
	@echo "This will insert initial key records into the master_keys table."
	@echo ""
	@echo "⚠️  Make sure you have:"
	@echo "   1. Run database migrations: make db-migrate"
	@echo "   2. Initialized Vault with Transit keys: make vault-dev-init"
	@echo "   3. Set VAULT_ADDR and VAULT_TOKEN in .env"
	@echo ""
	@read -p "Continue? [y/N] " REPLY; \
	if [ "$$REPLY" != "y" ] && [ "$$REPLY" != "Y" ]; then \
		echo "Cancelled."; \
		exit 1; \
	fi
	@if [ -z "$$DATABASE_URL" ]; then \
		if [ -f .env ]; then \
			export $$(grep -v '^#' .env | xargs); \
		fi; \
	fi
	@if [ -z "$$DATABASE_URL" ]; then \
		echo "❌ DATABASE_URL not set. Set it in .env or environment."; \
		exit 1; \
	fi
	@echo "Connecting to database..."
	@psql "$$DATABASE_URL" -c "SELECT COUNT(*) FROM master_keys WHERE key_type = 'jwt' AND status = 'active';" >/dev/null 2>&1 || \
		(echo "❌ Cannot connect to database or master_keys table doesn't exist." && \
		 echo "   Run migrations first: make db-migrate" && exit 1)
	@echo "Inserting initial keys..."
	@TMPFILE=$$(mktemp) && \
	printf '%s\n' \
		"-- Insert initial JWT key" \
		"INSERT INTO master_keys (" \
		"    key_type, vault_path, vault_version, status, activated_at," \
		"    key_id, algorithm, rotation_reason, rotated_by" \
		") VALUES (" \
		"    'jwt', 'jwt-signing', 1, 'active', NOW()," \
		"    'jwt_' || gen_random_uuid(), 'RS256', 'initial', 'system:init'" \
		") ON CONFLICT DO NOTHING;" \
		"" \
		"-- Insert initial APNS key" \
		"INSERT INTO master_keys (" \
		"    key_type, vault_path, vault_version, status, activated_at," \
		"    key_id, algorithm, rotation_reason, rotated_by" \
		") VALUES (" \
		"    'apns', 'apns-encryption', 1, 'active', NOW()," \
		"    'apns_' || gen_random_uuid(), 'ChaCha20-Poly1305', 'initial', 'system:init'" \
		") ON CONFLICT DO NOTHING;" \
		"" \
		"-- Insert initial Federation key" \
		"INSERT INTO master_keys (" \
		"    key_type, vault_path, vault_version, status, activated_at," \
		"    key_id, algorithm, rotation_reason, rotated_by" \
		") VALUES (" \
		"    'federation', 'federation-signing', 1, 'active', NOW()," \
		"    'federation_' || gen_random_uuid(), 'Ed25519', 'initial', 'system:init'" \
		") ON CONFLICT DO NOTHING;" \
		"" \
		"-- Insert initial Database encryption key" \
		"INSERT INTO master_keys (" \
		"    key_type, vault_path, vault_version, status, activated_at," \
		"    key_id, algorithm, rotation_reason, rotated_by" \
		") VALUES (" \
		"    'database', 'database-encryption', 1, 'active', NOW()," \
		"    'database_' || gen_random_uuid(), 'AES-256-GCM', 'initial', 'system:init'" \
		") ON CONFLICT DO NOTHING;" \
		> $$TMPFILE && \
	psql "$$DATABASE_URL" -f $$TMPFILE && \
	rm -f $$TMPFILE
	@echo "✅ Key Management System initialized in database"
	@echo ""
	@echo "💡 Verify with:"
	@echo "   psql \$$DATABASE_URL -c \"SELECT key_type, key_id, status FROM master_keys;\""
