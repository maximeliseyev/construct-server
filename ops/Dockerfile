# Build stage
FROM rust:1.90-slim-bookworm as builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libssl-dev \
    libsasl2-dev \
    libsasl2-modules \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy build script and proto files (needed for gRPC code generation)
COPY build.rs ./
COPY proto ./proto

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

# Ensure /usr/local/bin is in PATH (where binaries are installed)
ENV PATH="/usr/local/bin:${PATH}"

# Copy all binaries from builder with execute permissions
COPY --from=builder --chmod=+x /app/target/release/construct-server /usr/local/bin/construct-server
COPY --from=builder --chmod=+x /app/target/release/delivery-worker /usr/local/bin/delivery-worker
COPY --from=builder --chmod=+x /app/target/release/message-gateway /usr/local/bin/message-gateway

# Copy migrations for the main server
COPY migrations /app/migrations

# Expose port (used by all services)
EXPOSE 8080

# Default command (can be overridden in docker-compose or fly.toml)
# Each service (server, worker, gateway) uses its own process name from fly.toml
CMD ["construct-server"]
