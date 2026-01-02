# Construct Messenger

A privacy-focused, end-to-end encrypted messaging server built with Rust, designed for censorship resistance and minimal metadata exposure.

## ⚠️ **SECURITY WARNING**

> **This project is under active development and has NOT undergone any security audits.**
>
> ❌ **DO NOT use this software to transmit sensitive, confidential, or production data.**
>
> ❌ **DO NOT rely on this for communications requiring strong security guarantees.**
>
> This is an experimental implementation for educational and research purposes. While we implement industry-standard cryptographic primitives, the overall system security cannot be guaranteed without professional security audits. Use at your own risk.

## Key Features

- **End-to-End Encryption**: X25519 key exchange + ChaCha20-Poly1305 AEAD cipher
- **Zero-Knowledge Architecture**: Server cannot read message contents
- **Anonymous Routing**: Messages routed by UUID, not usernames
- **Offline Message Queue**: Redis-backed delivery for offline users
- **Modern Async Runtime**: Built on Tokio for high performance
- **Minimal Metadata**: Only essential routing information stored

## Architecture

### Two-Process Architecture

Construct Server consists of two separate processes:

1. **Main Server** (`construct-server`)
   - Handles WebSocket connections
   - Processes HTTP API requests (v2 and v3)
   - Manages database interactions
   - Delivers messages to online users
   - Publishes user online notifications to Redis Pub/Sub

2. **Delivery Worker** (`delivery-worker`)
   - Background process for offline message delivery
   - Listens to Redis Pub/Sub for user online events
   - Asynchronously processes offline message queues
   - Coordinates with main server instances via Redis

```
┌──────────┐                ┌─────────────────┐         ┌──────────────┐
│ Client A │                │ Main Server     │         │  PostgreSQL  │
│          │   WebSocket    │ (construct-     │◄────────┤  (accounts,  │
│          │◄──────────────►│  server)        │         │   keys)      │
└──────────┘                └────────┬────────┘         └──────────────┘
                                     │
                                     │ Redis
                                     │ Pub/Sub
                                     ▼
                            ┌────────────────┐
                            │     Redis      │
                            │  (queues +     │◄─────────┐
                            │   pub/sub)     │          │
                            └────────┬───────┘          │
                                     │                  │
                                     │ Subscribe        │ Process
                                     ▼                  │ queues
                            ┌────────────────┐          │
                            │ Delivery       │──────────┘
                            │ Worker         │
                            └────────────────┘
```

**Server sees only:**
- User IDs (UUIDs)
- Encrypted message blobs (base64)
- Timestamps

**Server cannot see:**
- Message content
- User relationships
- Communication patterns (with proper client implementation)

## Tech Stack

### Backend
- **Rust** - Memory-safe systems programming
- **Tokio** - Async runtime for high-concurrency
- **PostgreSQL** - User accounts and public keys
- **Redis** - Message queue for offline delivery
- **bcrypt** - Secure password hashing

### Cryptography
- **X25519** - Elliptic curve Diffie-Hellman key exchange
- **ChaCha20-Poly1305** - Authenticated encryption
- **Ed25519** - Digital signatures (planned)

### Protocols
- TCP with custom JSON protocol (current)
- WebSocket support (planned)
- QUIC with traffic obfuscation (planned)

## Installation

### Prerequisites
- Rust 1.75+
- Docker & Docker Compose
- PostgreSQL 16
- Redis 7

### Setup

#### Option 1: Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/construct-server.git
cd construct-server

# Configure environment
cp .env.example .env.local
# Edit .env.local with your configuration

# Start all services (server, worker, postgres, redis)
docker-compose up --build

# Server will be available at:
# - WebSocket/HTTP API: http://localhost:8080
# - Health check: http://localhost:3000/health
```

#### Option 2: Local Development

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/construct-server.git
cd construct-server

# 2. Start databases
docker-compose up postgres redis -d

# 3. Configure environment
cp .env.example .env
# Edit .env with your database credentials

# 4. Build both binaries
cargo build --release

# 5. Run main server (in one terminal)
cargo run --bin construct-server

# 6. Run delivery worker (in another terminal)
cargo run --bin delivery-worker
```

Server will start on `127.0.0.1:8080`


## Security Features

### Current Implementation
- ✅ End-to-end encryption (X25519 + ChaCha20-Poly1305)
- ✅ Ephemeral keys for each message
- ✅ bcrypt password hashing (cost factor 12)
- ✅ User ID-based routing (no username exposure)
- ✅ Server-side encrypted blob storage

### Planned Features
- 🔄 X3DH key agreement protocol
- 🔄 Double Ratchet for Perfect Forward Secrecy
- 🔄 Sealed sender (hide sender metadata)
- 🔄 Message padding (hide size patterns)
- 🔄 Traffic obfuscation (DPI resistance)

## Performance

- **Message throughput**: ~10,000 msg/sec (single instance)
- **Latency**: <10ms (local network)
- **Memory footprint**: ~50MB base + ~1KB per active connection
- **Encryption overhead**: ~2ms per message

## Development

### Run tests
```bash
cargo test
```

### Check code quality
```bash
cargo clippy
cargo fmt --check
```

### Build for production
```bash
cargo build --release
```

## 🚢 Deployment

### Docker Compose (Production)

```bash
# Build and start all services
docker-compose up -d --build

# View logs
docker-compose logs -f

# Stop all services
docker-compose down
```

### Fly.io (Recommended for Production)

Deploy two separate apps:

```bash
# 1. Deploy main server
fly deploy

# 2. Deploy delivery worker
fly deploy --config fly.worker.toml
```

**Important**: Both apps must share the same Redis instance for proper coordination.

### Manual Docker

```bash
# Build image (includes both binaries)
docker build -t construct-server .

# Run main server
docker run -p 8080:8080 -e DATABASE_URL=... -e REDIS_URL=... construct-server

# Run delivery worker
docker run -e REDIS_URL=... construct-server delivery-worker
```


## Contributing

Contributions are welcome! 

### Areas for contribution:
- Signal Protocol implementation (X3DH, Double Ratchet)
- iOS/Android clients
- WebSocket transport layer
- Traffic obfuscation techniques
- Documentation and tutorials

## License

MIT License - see [LICENSE](LICENSE) file for details

## Acknowledgments

- Signal Protocol specification
- libsignal implementation reference
- Rust cryptography ecosystem (dalek, ring)
- Tokio async runtime

## 📚 Resources

- [Signal Protocol Documentation](https://signal.org/docs/)
- [Noise Protocol Framework](https://noiseprotocol.org/)
- [X3DH Specification](https://signal.org/docs/specifications/x3dh/)
- [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)

---

**Built with ❤️ and Rust 🦀**
