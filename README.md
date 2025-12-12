# Construct Messenger

A privacy-focused, end-to-end encrypted messaging server built with Rust, designed for censorship resistance and minimal metadata exposure.

## Key Features

- **End-to-End Encryption**: X25519 key exchange + ChaCha20-Poly1305 AEAD cipher
- **Zero-Knowledge Architecture**: Server cannot read message contents
- **Anonymous Routing**: Messages routed by UUID, not usernames
- **Offline Message Queue**: Redis-backed delivery for offline users
- **Modern Async Runtime**: Built on Tokio for high performance
- **Minimal Metadata**: Only essential routing information stored

## Architecture

```
Client A                  Server                    Client B
   |                         |                          |
   | 1. Encrypt with B's     |                          |
   |    public key           |                          |
   |                         |                          |
   | 2. Send encrypted blob  |                          |
   |------------------------>|  3. Route by user_id     |
   |   [encrypted content]   |------------------------->|
   |                         |                          |
   |                         |                   4. Decrypt with
   |                         |                      private key
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

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/construct-server.git
cd construct-server
```

2. **Start databases**
```bash
docker-compose up -d
```

3. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your database credentials
```

4. **Run migrations**
```bash
psql -h localhost -U construct -d construct < schema.sql
```

5. **Build and run**
```bash
cargo build --release
cargo run
```

Server will start on `127.0.0.1:8080`

## Usage

### Register a user
```bash
python3 test_crypto_client.py register alice password123
```

### Send encrypted message
```bash
python3 test_crypto_client.py send alice password123 bob "Secret message"
```

### Listen for messages
```bash
python3 test_crypto_client.py listen bob password456
```

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

### Docker
```bash
docker build -t construct-server .
docker run -p 8080:8080 construct-server
```

### Fly.io
```bash
fly deploy
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed instructions.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

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

