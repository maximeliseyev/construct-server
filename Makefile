.PHONY: help build run-server run-worker run-gateway test check clean \
	docker-up docker-down docker-logs docker-build docker-rebuild \
	deploy-server deploy-worker deploy-gateway deploy-all check-before-deploy \
	secrets-server secrets-worker secrets-gateway secrets-all \
	logs-server logs-worker logs-gateway \
	status-server status-worker status-gateway status-all \
	db-migrate db-up db-down

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
	@echo "  make run-server         Run WebSocket server locally"
	@echo "  make run-worker         Run delivery worker locally"
	@echo "  make run-gateway        Run message gateway locally"
	@echo "  make test               Run all tests"
	@echo "  make check              Check code (clippy + fmt)"
	@echo "  make fmt                Format code"
	@echo "  make clean              Clean build artifacts"
	@echo ""
	@echo "🐳 Docker (Local Stack):"
	@echo "  make docker-up          Start all services (server + worker + db + redis)"
	@echo "  make docker-down        Stop all docker-compose services"
	@echo "  make docker-logs        View docker-compose logs (tail -f)"
	@echo "  make docker-build       Rebuild docker images"
	@echo "  make docker-rebuild     Rebuild & restart all services"
	@echo ""
	@echo "🚀 Fly.io Deployment:"
	@echo "  make deploy-server      Deploy WebSocket server to Fly.io"
	@echo "  make deploy-worker      Deploy delivery worker to Fly.io"
	@echo "  make deploy-gateway     Deploy message gateway to Fly.io"
	@echo "  make deploy-all         Deploy all services (server + worker + gateway)"
	@echo ""
	@echo "🔐 Fly.io Secrets Management:"
	@echo "  make secrets-server     Set secrets for construct-server"
	@echo "  make secrets-worker     Set secrets for construct-delivery-worker"
	@echo "  make secrets-gateway    Set secrets for construct-message-gateway"
	@echo "  make secrets-all        Set secrets for all services (from .env.deploy)"
	@echo ""
	@echo "📊 Fly.io Monitoring:"
	@echo "  make logs-server        View WebSocket server logs"
	@echo "  make logs-worker        View delivery worker logs"
	@echo "  make logs-gateway       View message gateway logs"
	@echo "  make status-server      Show construct-server status"
	@echo "  make status-worker      Show construct-delivery-worker status"
	@echo "  make status-gateway     Show construct-message-gateway status"
	@echo "  make status-all         Show status of all services"
	@echo ""
	@echo "🗄️  Database:"
	@echo "  make db-migrate         Run database migrations"
	@echo "  make db-up              Start local PostgreSQL + Redis"
	@echo "  make db-down            Stop local databases"
	@echo ""
	@echo "💡 Common Workflows:"
	@echo "  Development:   make docker-up && make docker-logs"
	@echo "  Deploy:        make deploy-all"
	@echo "  First deploy:  make secrets-all && make deploy-all"
	@echo "  Monitoring:    make status-all && make logs-server"

# ============================================================================
# Local Development
# ============================================================================

build:
	@echo "🔨 Building all binaries..."
	cargo build --release --bins

run-server:
	@echo "🚀 Running WebSocket server locally..."
	RUST_LOG=info cargo run --bin construct-server

run-worker:
	@echo "⚙️  Running delivery worker locally..."
	RUST_LOG=info cargo run --bin delivery-worker

run-gateway:
	@echo "🌐 Running message gateway locally..."
	RUST_LOG=info cargo run --bin message-gateway

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

deploy-server: check-before-deploy
	@echo "🚀 Deploying WebSocket server to Fly.io..."
	fly deploy . --config ops/fly.toml --dockerfile ./ops/Dockerfile --app construct-server
	@echo "✅ Server deployed. View logs: make logs-server"

deploy-worker: check-before-deploy
	@echo "⚙️  Deploying delivery worker to Fly.io..."
	fly deploy . --config ops/fly.worker.toml --dockerfile ./ops/Dockerfile --app construct-delivery-worker
	@echo "✅ Worker deployed. View logs: make logs-worker"

deploy-gateway: check-before-deploy
	@echo "🌐 Deploying message gateway to Fly.io..."
	fly deploy . --config ops/fly.gateway.toml --dockerfile ./ops/Dockerfile --app construct-message-gateway
	@echo "✅ Gateway deployed. View logs: make logs-gateway"

check-before-deploy:
	@if [ -z "$$SKIP_CHECK" ]; then \
		echo "🔍 Checking code compilation before deploy..."; \
		cargo check --release || (echo "❌ Compilation failed! Fix errors before deploying." && exit 1); \
		echo "✓ Code compiles successfully"; \
	fi

deploy-all:
	@echo "🔍 Checking code compilation before deploying all services..."
	@cargo check --release || (echo "❌ Compilation failed! Fix errors before deploying." && exit 1)
	@echo "✓ Code compiles successfully"
	@echo ""
	@echo "🚀 Deploying all services to Fly.io..."
	@echo ""
	@echo "1/3 Deploying WebSocket server..."
	@SKIP_CHECK=1 make deploy-server
	@echo ""
	@echo "2/3 Deploying delivery worker..."
	@SKIP_CHECK=1 make deploy-worker
	@echo ""
	@echo "3/3 Deploying message gateway..."
	@SKIP_CHECK=1 make deploy-gateway
	@echo ""
	@echo "✅ All services deployed!"

# ============================================================================
# Fly.io Secrets Management
# ============================================================================

secrets-server:
	@echo "🔐 Setting secrets for construct-server from .env..."
	@if [ ! -f .env ]; then echo "❌ Error: .env file not found"; exit 1; fi
	@bash ops/setup-fly-secrets.sh server

secrets-worker:
	@echo "🔐 Setting secrets for construct-delivery-worker from .env..."
	@if [ ! -f .env ]; then echo "❌ Error: .env file not found"; exit 1; fi
	@bash ops/setup-fly-secrets.sh worker

secrets-gateway:
	@echo "🔐 Setting secrets for construct-message-gateway from .env..."
	@if [ ! -f .env ]; then echo "❌ Error: .env file not found"; exit 1; fi
	@bash ops/setup-fly-secrets.sh gateway

secrets-all:
	@echo "🔐 Setting secrets for all services from .env..."
	@if [ ! -f .env ]; then echo "❌ Error: .env file not found"; exit 1; fi
	@bash ops/setup-fly-secrets.sh
	@echo "✅ All secrets set!"

# ============================================================================
# Fly.io Monitoring
# ============================================================================

logs-server:
	@echo "📋 Viewing construct-server logs..."
	fly logs -a construct-server

logs-worker:
	@echo "📋 Viewing construct-delivery-worker logs..."
	fly logs -a construct-delivery-worker

logs-gateway:
	@echo "📋 Viewing construct-message-gateway logs..."
	fly logs -a construct-message-gateway

status-server:
	@echo "📊 construct-server status:"
	@fly status -a construct-server

status-worker:
	@echo "📊 construct-delivery-worker status:"
	@fly status -a construct-delivery-worker

status-gateway:
	@echo "📊 construct-message-gateway status:"
	@fly status -a construct-message-gateway

status-all:
	@echo "╔════════════════════════════════════════════════════════════════╗"
	@echo "║  Fly.io Services Status                                        ║"
	@echo "╚════════════════════════════════════════════════════════════════╝"
	@echo ""
	@make status-server
	@echo ""
	@make status-worker
	@echo ""
	@make status-gateway

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
