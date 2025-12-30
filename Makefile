.PHONY: help build run-server run-worker test check clean docker-up docker-down deploy-server deploy-worker logs

# Default target
help:
	@echo "Construct Server - Available commands:"
	@echo ""
	@echo "Development:"
	@echo "  make build          - Build both binaries in release mode"
	@echo "  make run-server     - Run main server locally"
	@echo "  make run-worker     - Run delivery worker locally"
	@echo "  make test           - Run all tests"
	@echo "  make check          - Check code (clippy + fmt)"
	@echo "  make clean          - Clean build artifacts"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-up      - Start all services with docker-compose"
	@echo "  make docker-down    - Stop all docker-compose services"
	@echo "  make docker-logs    - View docker-compose logs"
	@echo "  make docker-build   - Rebuild docker images"
	@echo ""
	@echo "Deployment (Fly.io):"
	@echo "  make deploy-server  - Deploy main server to Fly.io"
	@echo "  make deploy-worker  - Deploy delivery worker to Fly.io"
	@echo "  make deploy-all     - Deploy both server and worker"
	@echo "  make logs-server    - View main server logs on Fly.io"
	@echo "  make logs-worker    - View worker logs on Fly.io"

# Development commands
build:
	cargo build --release --bins

run-server:
	RUST_LOG=info cargo run --bin construct-server

run-worker:
	RUST_LOG=info cargo run --bin delivery-worker

test:
	cargo test

check:
	cargo clippy -- -D warnings
	cargo fmt --check

fmt:
	cargo fmt

clean:
	cargo clean

# Docker commands
docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

docker-build:
	docker-compose build

docker-rebuild:
	docker-compose up -d --build

# Fly.io deployment
deploy-server:
	fly deploy

deploy-worker:
	fly deploy --config fly.worker.toml

deploy-all: deploy-server deploy-worker

logs-server:
	fly logs -a construct-messenger

logs-worker:
	fly logs -a construct-delivery-worker

# Database commands
db-migrate:
	sqlx migrate run

# Development databases (via docker-compose)
db-up:
	docker-compose up postgres redis -d

db-down:
	docker-compose down postgres redis
