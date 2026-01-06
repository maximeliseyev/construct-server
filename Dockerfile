# Build stage
FROM rust:1.90-slim as builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libsasl2-dev \
    libsasl2-modules \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source
COPY src ./src
COPY migrations ./migrations

# Build all binaries in release mode
RUN cargo build --release --bins

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libsasl2-2 \
    && rm -rf /var/lib/apt/lists/*

# Copy both binaries from builder
COPY --from=builder /app/target/release/construct-server /usr/local/bin/construct-server
COPY --from=builder /app/target/release/delivery-worker /usr/local/bin/delivery-worker

# Copy migrations for the main server
COPY migrations /app/migrations

# Expose port (only needed for main server)
EXPOSE 8080

# Default command (can be overridden in docker-compose or fly.toml)
CMD ["construct-server"]
