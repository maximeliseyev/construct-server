# Construct Messenger

**Federated • Post-Quantum Ready • Minimal**

> *Messages wait for you, not you for them.*

---

## What is Construct?

Construct is a new kind of messenger built on three principles:

| Principle | What it means |
|-----------|---------------|
| **Email 2.0** | Federated identity (`you@your-server.com`), but with modern E2E encryption |
| **Post-Quantum Ready** | Hybrid cryptography protecting against "harvest now, decrypt later" |
| **Zen by Default** | No notification spam, no read receipts, no "typing..." — silence is the default |

```
Signal's Security + Email's Openness + Minimalist Philosophy
```

---

## Why Another Messenger?

### The Problem with Current Options

| Messenger | Issue |
|-----------|-------|
| **Signal** | Centralized, requires phone number, no federation |
| **Matrix** | Complex protocol, heavy servers, E2E optional, no PQ |
| **Telegram** | Not E2E by default, centralized |
| **Email** | No E2E, legacy protocol, spam |

### Construct's Position

```
                    Federated
                        ▲
                        │
           Matrix ●     │     ● Construct
                        │
    ◄───────────────────┼───────────────────►
    Complex             │           Minimal
                        │
           Telegram ●   │     ● Signal
                        │
                        ▼
                   Centralized
```

**Construct = Federated + Minimal + Secure**

---

## Key Features

### 🔐 Post-Quantum Cryptography

First federated messenger with hybrid post-quantum protection:

```
Classical (today)          +  Post-Quantum (2026)
─────────────────             ──────────────────
X25519 key exchange        +  ML-KEM-768 (Kyber)
Ed25519 signatures         +  ML-DSA-65 (Dilithium)
```

**Why it matters**: Nation-states are recording encrypted traffic today to decrypt with quantum computers tomorrow. Construct protects against this "harvest now, decrypt later" threat.

### 🌐 Federation (Email 2.0)

Your identity is yours:

```
alice@construct.example.com  ←→  bob@another-server.org
         │                              │
         └──────── E2E Encrypted ───────┘
```

- **Own your identity** — not tied to phone number or centralized service
- **Run your own server** — or use a trusted provider
- **No vendor lock-in** — switch servers, keep your identity

### 🧘 Zen Philosophy

| Traditional Messengers | Construct |
|------------------------|-----------|
| Push notification for every message | **No push by default** |
| "Alice is typing..." | **No typing indicators** |
| Blue checkmarks (read receipts) | **No read receipts** |
| "Online now" / "Last seen" | **No presence indicators** |
| Notification badges everywhere | **No badges** |
| Stories, reactions, stickers | **Just conversations** |

**Default mode**: You check messages when *you* want, like email. Not when your phone demands attention.

### ⚡ Lightweight

| | Matrix (Synapse) | Construct |
|-|------------------|-----------|
| Language | Python | Rust |
| RAM usage | 2-4 GB | ~100 MB |
| Min. server | $20/mo VPS | $5/mo VPS |

Run your own server on a Raspberry Pi.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Your Device                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Swift / Kotlin UI                       │    │
│  └───────────────────────┬─────────────────────────────┘    │
│                          │ FFI                               │
│  ┌───────────────────────▼─────────────────────────────┐    │
│  │              Rust Crypto Core                        │    │
│  │  • Double Ratchet (forward secrecy)                 │    │
│  │  • X3DH (async key exchange)                        │    │
│  │  • MLS (group chats) — planned                      │    │
│  │  • Post-quantum hybrid — planned                    │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ E2E Encrypted
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Your Home Server                          │
│  • Routes encrypted messages (can't read them)              │
│  • Stores key bundles                                       │
│  • Federates with other servers                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ Server-to-Server
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Other Federated Servers                    │
└─────────────────────────────────────────────────────────────┘
```

**Server sees**: Encrypted blobs, metadata (who, when, sizes)  
**Server never sees**: Message content, contact names, conversation topics

---

## Cryptography

### Current (v1) — Production

| Component | Algorithm | Security |
|-----------|-----------|----------|
| Key Exchange | X25519 | 128-bit |
| Signatures | Ed25519 | 128-bit |
| Encryption | ChaCha20-Poly1305 | 256-bit |
| KDF | HKDF-SHA256 | — |

### Planned (v2) — Q2 2026

| Component | Hybrid Scheme | Security |
|-----------|---------------|----------|
| Key Exchange | X25519 **+** ML-KEM-768 | 128-bit classical, 192-bit PQ |
| Signatures | Ed25519 **+** ML-DSA-65 | 128-bit classical, 192-bit PQ |

**Hybrid approach**: If post-quantum algorithms have undiscovered weaknesses → classical still protects. If quantum computers break classical → PQ still protects.

---

## Comparison

| Feature | Signal | Matrix | Telegram | **Construct** |
|---------|--------|--------|----------|---------------|
| E2E by default | ✅ | ❌ Optional | ❌ | ✅ |
| Federation | ❌ | ✅ | ❌ | ✅ |
| Post-quantum | 🔬 Experimental | ❌ | ❌ | ✅ Planned |
| Lightweight server | — | ❌ Heavy | — | ✅ |
| No phone required | ❌ | ✅ | ❌ | ✅ |
| Minimal UI | ✅ | ❌ Bloated | ❌ Bloated | ✅ |
| Group E2E protocol | Sender Keys | Megolm | ❌ | MLS (RFC 9420) |

---

## Roadmap

### ✅ Done
- Double Ratchet E2E encryption
- X3DH key exchange
- Crypto-agility architecture
- iOS client (Swift + Rust core)
- WebSocket server (Rust)

### 🚧 In Progress (Q1 2025)
- Kafka message infrastructure
- Session persistence
- Profile sharing (P2P, no server storage)

### 📋 Planned

| Quarter | Milestone |
|---------|-----------|
| Q2 2025 | Federation MVP (server-to-server) |
| Q3 2025 | MLS group chats |
| Q4 2025 | Android client |
| **Q2 2026** | **Post-quantum cryptography** |

---

## Quick Start

### Requirements

- Rust 1.75+
- Xcode 15+ (iOS)
- PostgreSQL 14+

### Run the Server

```bash
# Clone
git clone https://github.com/anthropic/construct-messenger
cd construct-messenger

# Setup database
createdb construct
cd construct-server
cp .env.example .env
# Edit .env with your settings

# Run
cargo run --release
```

### Build iOS Client

```bash
# Build Rust library for iOS
cd packages/core
cargo build --release --target aarch64-apple-ios

# Generate Swift bindings
cargo run --bin uniffi-bindgen generate \
  --library ../../target/aarch64-apple-ios/release/libconstruct_core.a \
  --language swift \
  --out-dir ../ios-bindings

# Open Xcode
open ../../ConstructMessenger.xcodeproj
```

---

## Project Structure

```
construct-messenger/
├── construct-server/        # Rust server (Axum + Kafka + PostgreSQL)
├── packages/
│   └── core/                # Rust crypto core
│       └── src/
│           ├── crypto/      # Double Ratchet, X3DH, providers
│           └── protocol/    # Message types
├── ConstructMessenger/      # iOS app (Swift + SwiftUI)
└── docs/                    # Documentation (Obsidian vault)
```

---

## Philosophy

### On Notifications

> "The smartphone is the most successful slot machine ever invented. Every notification is a pull of the lever."

Construct defaults to silence. You check messages when you're ready, not when your phone demands it.

### On Complexity

> "Perfection is achieved not when there is nothing more to add, but when there is nothing left to take away."

No stories. No reactions flooding the screen. No algorithmic feeds. Just conversations.

### On Federation

> "Email won because anyone could run a server. Walled gardens eventually fall."

Your identity shouldn't be owned by a corporation. `alice@gmail.com` works because email is federated. Messaging should be the same.

### On Quantum Threats

> "The best time to plant a tree was 20 years ago. The second best time is now."

Nation-states are recording encrypted traffic today. Quantum computers will break current encryption within 10-15 years. We're preparing now.

---

## Security

### What We Protect Against

- ✅ Network observers (ISP, WiFi snoopers)
- ✅ Server compromise (E2E encryption)
- ✅ Future quantum computers (hybrid PQ crypto)
- ✅ Message forgery (cryptographic signatures)

### What We Don't Protect Against

- ❌ Compromised device (malware on your phone)
- ❌ Screenshots by recipient
- ❌ Physical coercion

### Threat Model

See [docs/security/threat-model.md](docs/security/threat-model.md) for detailed analysis.

---

## Contributing

We welcome contributions! Priority areas:

| Priority | Area |
|----------|------|
| 🔴 High | Session persistence, message reliability |
| 🟡 Medium | Android client, UI/UX |
| 🟢 Future | Post-quantum implementation |

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Acknowledgments

- **Signal Foundation** — Double Ratchet protocol
- **IETF MLS Working Group** — RFC 9420
- **NIST** — Post-quantum cryptography standards
- **Mozilla** — UniFFI for Rust-Swift interop

---

<p align="center">
  <i>Built for people who believe privacy is a right, not a feature.</i>
</p>
