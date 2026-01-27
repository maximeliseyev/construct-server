# 📚 Документация проекта

> **Примечание:** Основная документация проекта перенесена в Obsidian vault для лучшей организации и связывания документов.

## 📍 Расположение документации

**Obsidian Vault:** `~/Documents/Konstruct/`

### Структура:

```
~/Documents/Konstruct/
├── 00_Project_Overview/          # Обзор проекта
├── 01_Architecture/               # Архитектура системы
├── 02_Core_Crypto_and_WASM/      # Криптография и WASM
├── 03_Server_Backend/             # Server Backend (основная документация)
│   ├── 00_Server_Architecture/
│   │   ├── 06_Phase4_Modular_Crates.md
│   │   ├── 06_Phase4_5_END_SESSION_Protocol.md
│   │   ├── SERVER_END_SESSION_SPEC.md
│   │   └── PROTOCOL_SPECIFICATION.md
│   ├── 01_Microservices/
│   ├── 02_Database/
│   └── ...
├── 04_Client_Applications/        # iOS/Android клиенты
├── 05_Deployment/                 # Deployment & DevOps
├── 06_Security/                   # Безопасность
├── 07_Reference/                  # Справочные материалы
└── _Archive/                      # Архивные документы
    └── Server_Docs_2026_01/       # Старые docs/ из репозитория
```

## 🔑 Ключевые документы

### Server Backend
- **Phase 4 Architecture:** `03_Server_Backend/00_Server_Architecture/06_Phase4_Modular_Crates.md`
- **Phase 4.5 END_SESSION:** `03_Server_Backend/00_Server_Architecture/06_Phase4_5_END_SESSION_Protocol.md`
- **Protocol Spec:** `03_Server_Backend/00_Server_Architecture/PROTOCOL_SPECIFICATION.md`

### Deployment
- **Deployment Guide:** `05_Deployment/`
- **Makefile Commands:** См. `make help` в корне проекта

### Security
- **E2EE Protocol:** `06_Security/02_E2EE_Protocol/`
- **Key Management:** `06_Security/03_Key_Management/`

## 🚀 Quick Start

### Development
```bash
make dev              # Start local stack (PostgreSQL + Redis + Kafka)
make build            # Build all services
make test             # Run tests
```

### Deployment
```bash
make secrets          # Setup Fly.io secrets (first time)
make deploy           # Deploy all microservices
make status           # Check deployment status
make logs-msg         # View messaging service logs
```

### Documentation
```bash
# Open Obsidian vault
open ~/Documents/Konstruct/
```

## 📝 Contributing

При добавлении новых функций обновляйте документацию в Obsidian vault:

1. **Архитектурные изменения** → `03_Server_Backend/00_Server_Architecture/`
2. **API изменения** → `03_Server_Backend/01_Microservices/`
3. **Протокол изменения** → `03_Server_Backend/00_Server_Architecture/PROTOCOL_SPECIFICATION.md`

## 🔗 Связанные ресурсы

- **Repository:** https://github.com/your-org/construct-server
- **Obsidian Vault:** `~/Documents/Konstruct/`
- **Copilot Session State:** `~/.copilot/session-state/`

---

**Последнее обновление:** 27 января 2026  
**Phase:** 4.5 (END_SESSION Protocol)
