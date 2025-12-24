# Тесты Construct Server

## Требования для запуска тестов

Перед запуском тестов необходимо:

1. **PostgreSQL** - запущенная база данных
2. **Redis** - запущенный сервер Redis

### Быстрый запуск с Docker Compose

```bash
docker-compose up -d postgres redis
```

Или вручную:

```bash
# PostgreSQL
docker run -d \
  --name construct-postgres-test \
  -e POSTGRES_USER=construct \
  -e POSTGRES_PASSWORD=construct_dev_password \
  -e POSTGRES_DB=postgres \
  -p 5432:5432 \
  postgres:16

# Redis
docker run -d \
  --name construct-redis-test \
  -p 6379:6379 \
  redis:7-alpine
```

## Запуск тестов

### Тест регистрации пользователя

```bash
cargo test --test registration_test -- --nocapture
```

Этот тест проверяет:
- ✅ Успешную регистрацию нового пользователя
- ✅ Автоматическое обновление `user_id` в key bundle
- ✅ Создание JWT токена
- ✅ Отклонение дублирующихся username

### Интеграционные тесты

```bash
cargo test --test integration_test -- --nocapture
```

Проверяет:
- ✅ Отправку и получение сообщений
- ✅ Защиту от message spoofing

### Все тесты

```bash
cargo test -- --nocapture
```

## Примечания

- Тесты помечены `#[serial]` для последовательного выполнения (избегание конфликтов БД)
- Каждый тест создает временную БД с уникальным UUID
- После теста БД автоматически удаляется
- Redis используется общий (localhost:6379)

## Структура тестов

```
tests/
├── registration_test.rs    # Тесты регистрации и аутентификации
├── integration_test.rs     # Тесты сообщений и WebSocket
└── test_utils.rs          # Утилиты для тестов (TestClient, spawn_app)
```

## Что проверяют тесты регистрации

### test_user_registration_success

1. Создает WebSocket подключение к тестовому серверу
2. Генерирует валидный `UploadableKeyBundle` с placeholder user_id
3. Отправляет запрос регистрации
4. Сервер автоматически обновляет user_id в bundle_data
5. Проверяет успешный ответ с JWT токеном

### test_duplicate_username_rejected

1. Регистрирует первого пользователя
2. Пытается зарегистрировать второго с тем же username
3. Проверяет, что сервер отклоняет дубликат с ошибкой

## Формат UploadableKeyBundle для тестов

```rust
{
  "masterIdentityKey": "Base64<32 bytes Ed25519>",
  "bundleData": "Base64<JSON BundleData>",
  "signature": "Base64<64 bytes Ed25519 signature>"
}
```

Где `BundleData`:
```json
{
  "userId": "placeholder-will-be-updated",
  "timestamp": "2025-12-24T10:00:00Z",
  "supportedSuites": [{
    "suiteId": 1,
    "identityKey": "Base64<32 bytes>",
    "signedPrekey": "Base64<32 bytes>",
    "oneTimePrekeys": []
  }]
}
```

## Отладка

Для детального вывода логов:

```bash
RUST_LOG=debug cargo test --test registration_test -- --nocapture
```

Для запуска конкретного теста:

```bash
cargo test test_user_registration_success -- --nocapture
```
