# Post-Quantum Cryptography Module

## Обзор

Этот модуль содержит фундамент для post-quantum hybrid криптографии в Construct Server. Это наша главная killer feature - первый федеративный мессенджер с полной поддержкой post-quantum защиты.

## Статус

**Foundation:** ✅ Готов  
**Implementation:** ⏳ Pending (требуется выбор и интеграция PQ библиотеки)

## Структура модуля

```
src/pqc/
├── mod.rs          # Главный модуль (экспортирует типы и валидацию)
├── types.rs        # Типы данных для hybrid ключей и подписей
├── validation.rs   # Валидация формата для hybrid suite (server-side)
└── hybrid.rs       # Реализация hybrid операций (placeholder - будет реализовано позже)
```

## Типы данных

### HybridKemPublicKey
- Classical: X25519 public key (32 bytes)
- PQ: ML-KEM-768 public key (1184 bytes)
- Total: 1216 bytes

### HybridSignaturePublicKey
- Classical: Ed25519 public key (32 bytes)
- PQ: ML-DSA-65 public key (1952 bytes)
- Total: 1984 bytes

### HybridSignature
- Classical: Ed25519 signature (64 bytes)
- PQ: ML-DSA-65 signature (3293 bytes)
- Total: 3357 bytes

## Использование

### Без feature flag (по умолчанию):

```rust
// Код компилируется, но hybrid suite не поддерживается
// PQ_HYBRID_KYBER suite_id будет отклонен с ошибкой
```

### С feature flag:

```bash
cargo build --features post-quantum
```

```rust
#[cfg(feature = "post-quantum")]
use crate::pqc::{HybridKemPublicKey, HybridSignaturePublicKey};

// Валидация hybrid suite
crate::pqc::validation::validate_hybrid_suite_key_material(&suite)?;
```

## Следующие шаги

1. **Выбор PQ библиотеки:**
   - Оценить доступные библиотеки (saorsa-pqc, ml-kem/ml-dsa, liboqs-rust)
   - Выбрать наиболее подходящую (API, производительность, безопасность)
   - Интегрировать в Cargo.toml

2. **Реализация hybrid операций:**
   - Hybrid KEM key generation
   - Hybrid signature key generation
   - Hybrid signature verification
   - Hybrid KEM encapsulation/decapsulation

3. **Интеграция с существующим кодом:**
   - Обновление `validate_uploadable_key_bundle()` для полной верификации
   - Обновление схемы БД для hybrid ключей
   - Тесты

4. **Client-side интеграция:**
   - Обновление client-side для генерации hybrid ключей
   - Обновление протокола для hybrid key exchange

## Документация

- [POST_QUANTUM_FOUNDATION.md](../POST_QUANTUM_FOUNDATION.md) - Полная документация
- [Documents/Kostruct/architecture/post-quantum-hybrid-implementation.md](../../../Documents/Kostruct/architecture/post-quantum-hybrid-implementation.md) - Архитектура
