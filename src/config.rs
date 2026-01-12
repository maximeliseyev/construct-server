use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

// ============================================================================
// Configuration Constants
// ============================================================================

// Default port values
const DEFAULT_PORT: u16 = 8080;
const DEFAULT_HEALTH_PORT: u16 = 8081;

// Default time intervals (in seconds)
// OPTIMIZED: Increased default heartbeat interval from 90s to 180s to reduce Redis commands
const DEFAULT_HEARTBEAT_INTERVAL_SECS: i64 = 180;
const DEFAULT_SERVER_REGISTRY_TTL_SECS: i64 = 270;

// Default TTL values (in days)
const DEFAULT_MESSAGE_TTL_DAYS: i64 = 7;
const DEFAULT_SESSION_TTL_DAYS: i64 = 30;
const DEFAULT_REFRESH_TOKEN_TTL_DAYS: i64 = 90;

// Default polling interval (in milliseconds)
// OPTIMIZED: Increased default polling interval from 10s to 30s to reduce Redis commands
// This reduces Redis command usage by ~66% while maintaining acceptable latency for real-time messaging
const DEFAULT_DELIVERY_POLL_INTERVAL_MS: u64 = 30000;

// Time conversion constants
pub const SECONDS_PER_MINUTE: i64 = 60;
pub const SECONDS_PER_HOUR: i64 = 3600;
pub const SECONDS_PER_DAY: i64 = 86400;

// Message size limits (in bytes)
// ============================================================================
// ВАЖНО: Разные лимиты для разных типов контента
// 
// WebSocket сообщения (текст + метаданные):
// - 64 KB достаточно для ~32K символов UTF-8 + криптографические метаданные
// - Больший размер указывает на атаку или медиафайлы (которые идут через CDN)
//
// HTTP запросы:
// - 2 MB для API endpoints (key bundles, etc.)
// - Медиафайлы загружаются отдельно на CDN (до 100 MB)
// ============================================================================
pub const MAX_WEBSOCKET_MESSAGE_SIZE: usize = 64 * 1024; // 64 KB - WebSocket text messages
pub const MAX_MESSAGE_SIZE: usize = MAX_WEBSOCKET_MESSAGE_SIZE; // Alias for backward compat
pub const MAX_REQUEST_BODY_SIZE: usize = 2 * 1024 * 1024; // 2 MB - HTTP API requests
pub const MAX_MEDIA_FILE_SIZE: usize = 100 * 1024 * 1024; // 100 MB - Media files on CDN

// ============================================================================
// Configuration Structures
// ============================================================================

#[derive(Clone, Debug)]
pub struct LoggingConfig {
    pub enable_message_metadata: bool,
    pub enable_user_identifiers: bool,
    pub hash_salt: String,
}

/// Database connection pool configuration
#[derive(Clone, Debug)]
pub struct DbConfig {
    /// Maximum number of connections in the pool
    pub max_connections: u32,
    /// Timeout for acquiring a connection from the pool (seconds)
    pub acquire_timeout_secs: u64,
    /// Timeout for idle connections before they are closed (seconds)
    pub idle_timeout_secs: u64,
}

/// Deep links configuration for Universal Links (iOS) and App Links (Android)
#[derive(Clone, Debug)]
pub struct DeepLinksConfig {
    /// Apple Team ID for Universal Links
    pub apple_team_id: String,
    /// Android package name (e.g., "com.konstruct.messenger")
    pub android_package_name: String,
    /// Android certificate SHA-256 fingerprint for App Links verification
    pub android_cert_fingerprint: String,
}

/// Delivery worker specific configuration
#[derive(Clone, Debug)]
pub struct WorkerConfig {
    /// Enable shadow-read mode (compare Kafka vs Redis for validation)
    pub shadow_read_enabled: bool,
}

/// Redis key prefixes configuration
#[derive(Clone, Debug)]
pub struct RedisKeyPrefixes {
    /// Prefix for processed message deduplication keys: "processed_msg:{message_id}"
    pub processed_msg: String,
    /// Prefix for user-related keys: "user:{user_id}:..."
    pub user: String,
    /// Prefix for session keys: "session:{jti}"
    pub session: String,
    /// Prefix for user sessions set: "user_sessions:{user_id}"
    pub user_sessions: String,
    /// Prefix for message hash replay protection: "msg_hash:{hash}"
    pub msg_hash: String,
    /// Prefix for rate limiting keys: "rate:{type}:{id}"
    pub rate: String,
    /// Prefix for blocked users: "blocked:{user_id}"
    pub blocked: String,
    /// Prefix for key bundle cache: "key_bundle:{user_id}"
    pub key_bundle: String,
    /// Prefix for connection tracking: "connections:{user_id}"
    pub connections: String,
    /// Prefix for direct delivery deduplication: "delivered_direct:{message_id}"
    /// Used to skip delivery-worker for messages already delivered via tx.send()
    pub delivered_direct: String,
}

/// Redis channel names configuration
#[derive(Clone, Debug)]
pub struct RedisChannels {
    /// Dead letter queue channel name
    pub dead_letter_queue: String,
    /// Delivery message channel template: "delivery_message:{server_instance_id}"
    pub delivery_message: String,
    /// Delivery notification channel template: "delivery_notification:{server_instance_id}"
    pub delivery_notification: String,
}

/// Security and rate limiting policies
#[derive(Clone, Debug)]
pub struct SecurityConfig {
    pub prekey_ttl_days: i64,
    #[allow(dead_code)]
    pub prekey_min_ttl_days: i64,
    #[allow(dead_code)]
    pub prekey_max_ttl_days: i64,
    pub max_messages_per_hour: u32,
    /// Maximum messages per IP address per hour (protects against distributed attacks)
    pub max_messages_per_ip_per_hour: u32,
    pub max_key_rotations_per_day: u32,
    pub max_password_changes_per_day: u32,
    pub max_failed_login_attempts: u32,
    #[allow(dead_code)]
    pub max_connections_per_user: u32,
    pub key_bundle_cache_hours: i64,
    pub rate_limit_block_duration_seconds: i64,
}

/// Media server configuration
#[derive(Clone, Debug)]
pub struct MediaConfig {
    /// Whether media uploads are enabled
    pub enabled: bool,
    /// Media server base URL (e.g., "https://media.example.com")
    pub base_url: String,
    /// Shared secret for generating upload tokens (must match MEDIA_UPLOAD_TOKEN_SECRET on media-server)
    pub upload_token_secret: String,
    /// Maximum file size in bytes (default: 100MB)
    pub max_file_size: usize,
    /// Rate limit: uploads per hour per user
    pub rate_limit_per_hour: u32,
}

/// Kafka configuration for reliable message delivery
#[derive(Clone, Debug)]
pub struct KafkaConfig {
    /// Whether Kafka is enabled (false = Redis-only mode for testing/rollback)
    pub enabled: bool,
    /// Comma-separated list of Kafka brokers (e.g., "kafka1:9092,kafka2:9092")
    pub brokers: String,
    /// Kafka topic name for messages
    pub topic: String,
    /// Consumer group ID for delivery workers
    pub consumer_group: String,
    /// SSL/TLS enabled
    pub ssl_enabled: bool,
    /// SASL mechanism (e.g., "SCRAM-SHA-256", "PLAIN")
    pub sasl_mechanism: Option<String>,
    /// SASL username
    pub sasl_username: Option<String>,
    /// SASL password
    pub sasl_password: Option<String>,
    // producer-specific settings
    pub producer_compression: String, // "zstd" | "snappy" | "gzip" | "lz4" | "none"
    pub producer_acks: String,        // "all" | "1" | "-1" | "0"
    pub producer_linger_ms: u32,
    pub producer_batch_size: u32,
    pub producer_max_in_flight: u32,
    pub producer_retries: u32,
    pub producer_request_timeout_ms: u32,
    pub producer_delivery_timeout_ms: u32,
    pub producer_enable_idempotence: bool,
}

/// APNs (Apple Push Notification service) configuration
#[derive(Clone, Debug)]
pub struct ApnsConfig {
    /// Whether APNs is enabled (default: false)
    pub enabled: bool,
    /// APNs environment: "production" or "development"
    pub environment: ApnsEnvironment,
    /// Path to .p8 authentication key file
    pub key_path: String,
    /// APNs Key ID (10 characters)
    pub key_id: String,
    /// APNs Team ID
    pub team_id: String,
    /// iOS app Bundle ID
    pub bundle_id: String,
    /// APNs topic (usually same as bundle_id)
    pub topic: String,
    /// Encryption key for device tokens in database (32 bytes hex = 64 chars)
    pub device_token_encryption_key: String,
}

/// Federation configuration
#[derive(Clone, Debug)]
pub struct FederationConfig {
    /// Instance domain (e.g., "eu.konstruct.cc")
    pub instance_domain: String,
    /// Base federation domain (e.g., "konstruct.cc")
    pub base_domain: String,
    /// Whether federation is enabled
    pub enabled: bool,
    /// Server signing key seed (base64-encoded 32 bytes for Ed25519)
    /// Generate with: openssl rand -base64 32
    pub signing_key_seed: Option<String>,
    /// mTLS configuration for S2S federation
    pub mtls: crate::federation::MtlsConfig,
}

/// APNs environment
#[derive(Clone, Debug, PartialEq)]
pub enum ApnsEnvironment {
    Production,
    Development,
}

impl std::str::FromStr for ApnsEnvironment {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "production" | "prod" => Ok(Self::Production),
            "development" | "dev" => Ok(Self::Development),
            _ => anyhow::bail!(
                "Invalid APNs environment: {}. Must be 'production' or 'development'",
                s
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    /// JWT secret (for HS256 - legacy, kept for backward compatibility)
    /// If JWT_PRIVATE_KEY is set, RS256 will be used instead
    pub jwt_secret: String,
    /// RSA private key for JWT signing (RS256)
    /// Path to PEM file or PEM string in environment variable
    pub jwt_private_key: Option<String>,
    /// RSA public key for JWT verification (RS256)
    /// Path to PEM file or PEM string in environment variable
    pub jwt_public_key: Option<String>,
    pub port: u16,
    pub health_port: u16,
    pub heartbeat_interval_secs: i64,
    pub server_registry_ttl_secs: i64,
    pub message_ttl_days: i64,
    pub session_ttl_days: i64,
    pub refresh_token_ttl_days: i64,
    pub jwt_issuer: String,
    pub online_channel: String,
    pub offline_queue_prefix: String,
    pub delivery_queue_prefix: String,
    pub delivery_poll_interval_ms: u64,
    pub rust_log: String,
    pub logging: LoggingConfig,
    pub security: SecurityConfig,
    pub kafka: KafkaConfig,
    pub apns: ApnsConfig,
    pub federation: FederationConfig,
    pub db: DbConfig,
    pub deeplinks: DeepLinksConfig,
    pub worker: WorkerConfig,
    pub redis_key_prefixes: RedisKeyPrefixes,
    pub redis_channels: RedisChannels,
    pub media: MediaConfig,

    // Legacy aliases (for backward compatibility)
    // TODO: Remove after updating all usages to config.federation.*
    /// Instance domain (e.g., "eu.konstruct.cc")
    pub instance_domain: String,
    /// Base federation domain (e.g., "konstruct.cc")
    pub federation_base_domain: String,
    /// Whether federation is enabled
    pub federation_enabled: bool,
    /// Deep link base URL (e.g., "https://konstruct.cc")
    pub deep_link_base_url: String,
}

impl Config {
    /// Get full federation ID for a user UUID
    pub fn federation_id(&self, user_uuid: &uuid::Uuid) -> String {
        format!("{}@{}", user_uuid, self.instance_domain)
    }

    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        Ok(Self {
            database_url: std::env::var("DATABASE_URL")?,
            redis_url: std::env::var("REDIS_URL")?,
            jwt_secret: {
                // Check if RSA keys are provided (RS256 mode)
                let has_rsa_keys = std::env::var("JWT_PRIVATE_KEY").is_ok() && std::env::var("JWT_PUBLIC_KEY").is_ok();
                
                let secret = if has_rsa_keys {
                    // JWT_SECRET is optional when using RS256 (for backward compatibility with old tokens)
                    std::env::var("JWT_SECRET").unwrap_or_default()
                } else {
                    // JWT_SECRET is required when using HS256 (legacy mode)
                    let secret = std::env::var("JWT_SECRET")?;
                    if secret.len() < 32 {
                        anyhow::bail!("JWT_SECRET must be at least 32 characters long, or use JWT_PRIVATE_KEY/JWT_PUBLIC_KEY for RS256");
                    }
                    // SECURITY: Validate secret strength (entropy, patterns)
                    if let Err(e) = crate::utils::validate_secret_strength(&secret, 32) {
                        anyhow::bail!("JWT_SECRET is too weak: {}. Please use a random secret generated with: openssl rand -base64 32, or use JWT_PRIVATE_KEY/JWT_PUBLIC_KEY for RS256", e);
                    }
                    secret
                };
                
                secret
            },
            jwt_private_key: {
                // Try to load from file path first, then from environment variable directly (PEM string)
                std::env::var("JWT_PRIVATE_KEY").ok().map(|key| {
                    // If it looks like a file path (contains path separators), try to read it
                    if key.contains(std::path::MAIN_SEPARATOR) || key.starts_with("-----BEGIN") {
                        if key.starts_with("-----BEGIN") {
                            // PEM string in environment variable
                            key
                        } else {
                            // File path - read the file
                            std::fs::read_to_string(&key)
                                .unwrap_or_else(|e| {
                                    tracing::warn!(
                                        error = %e,
                                        path = %key,
                                        "Failed to read JWT_PRIVATE_KEY from file, using as-is"
                                    );
                                    key
                                })
                        }
                    } else {
                        // Assume it's a PEM string in environment variable
                        key
                    }
                })
            },
            jwt_public_key: {
                // Try to load from file path first, then from environment variable directly (PEM string)
                std::env::var("JWT_PUBLIC_KEY").ok().map(|key| {
                    // If it looks like a file path (contains path separators), try to read it
                    if key.contains(std::path::MAIN_SEPARATOR) || key.starts_with("-----BEGIN") {
                        if key.starts_with("-----BEGIN") {
                            // PEM string in environment variable
                            key
                        } else {
                            // File path - read the file
                            std::fs::read_to_string(&key)
                                .unwrap_or_else(|e| {
                                    tracing::warn!(
                                        error = %e,
                                        path = %key,
                                        "Failed to read JWT_PUBLIC_KEY from file, using as-is"
                                    );
                                    key
                                })
                        }
                    } else {
                        // Assume it's a PEM string in environment variable
                        key
                    }
                })
            },
            port: std::env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(DEFAULT_PORT),
            health_port: std::env::var("HEALTH_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(DEFAULT_HEALTH_PORT),
            heartbeat_interval_secs: std::env::var("HEARTBEAT_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_HEARTBEAT_INTERVAL_SECS),
            server_registry_ttl_secs: std::env::var("SERVER_REGISTRY_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_SERVER_REGISTRY_TTL_SECS),
            message_ttl_days: std::env::var("MESSAGE_TTL_DAYS")
                .ok()
                .and_then(|d| d.parse().ok())
                .unwrap_or(DEFAULT_MESSAGE_TTL_DAYS),
            session_ttl_days: std::env::var("SESSION_TTL_DAYS")
                .ok()
                .and_then(|d| d.parse().ok())
                .unwrap_or(DEFAULT_SESSION_TTL_DAYS),
            refresh_token_ttl_days: std::env::var("REFRESH_TOKEN_TTL_DAYS")
                .ok()
                .and_then(|d| d.parse().ok())
                .unwrap_or(DEFAULT_REFRESH_TOKEN_TTL_DAYS),
            jwt_issuer: std::env::var("JWT_ISSUER")
                .unwrap_or_else(|_| "construct-server".to_string()),
            online_channel: std::env::var("ONLINE_CHANNEL")?,
            offline_queue_prefix: std::env::var("OFFLINE_QUEUE_PREFIX")
                .unwrap_or_else(|_| "queue:".to_string()),
            delivery_queue_prefix: std::env::var("DELIVERY_QUEUE_PREFIX")
                .unwrap_or_else(|_| "delivery_queue:".to_string()),
            delivery_poll_interval_ms: std::env::var("DELIVERY_POLL_INTERVAL_MS")
                .ok()
                .and_then(|d| d.parse().ok())
                .unwrap_or(DEFAULT_DELIVERY_POLL_INTERVAL_MS),
            rust_log: std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
            logging: LoggingConfig {
                enable_message_metadata: std::env::var("LOG_MESSAGE_METADATA")
                    .unwrap_or_else(|_| "false".to_string())
                    .parse()
                    .unwrap_or(false),
                enable_user_identifiers: std::env::var("LOG_USER_IDENTIFIERS")
                    .unwrap_or_else(|_| "false".to_string())
                    .parse()
                    .unwrap_or(false),
                hash_salt: {
                    let salt = std::env::var("LOG_HASH_SALT")
                        .unwrap_or_else(|_| "default-salt-please-change".to_string());
                    if salt.is_empty() || salt == "default-salt-please-change" {
                        anyhow::bail!("LOG_HASH_SALT must be set to a unique, secret value");
                    }
                    salt
                },
            },
            security: SecurityConfig {
                prekey_ttl_days: std::env::var("PREKEY_TTL_DAYS")
                    .ok()
                    .and_then(|d| d.parse().ok())
                    .unwrap_or(30),
                prekey_min_ttl_days: std::env::var("PREKEY_MIN_TTL_DAYS")
                    .ok()
                    .and_then(|d| d.parse().ok())
                    .unwrap_or(7),
                prekey_max_ttl_days: std::env::var("PREKEY_MAX_TTL_DAYS")
                    .ok()
                    .and_then(|d| d.parse().ok())
                    .unwrap_or(90),
                max_messages_per_hour: std::env::var("MAX_MESSAGES_PER_HOUR")
                    .ok()
                    .and_then(|m| m.parse().ok())
                    .unwrap_or(1000),
                max_messages_per_ip_per_hour: std::env::var("MAX_MESSAGES_PER_IP_PER_HOUR")
                    .ok()
                    .and_then(|m| m.parse().ok())
                    .unwrap_or(5000), // Higher limit for IP (shared IPs, NAT, etc.)
                max_key_rotations_per_day: std::env::var("MAX_KEY_ROTATIONS_PER_DAY")
                    .ok()
                    .and_then(|k| k.parse().ok())
                    .unwrap_or(10),
                max_password_changes_per_day: std::env::var("MAX_PASSWORD_CHANGES_PER_DAY")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(5),
                max_failed_login_attempts: std::env::var("MAX_FAILED_LOGIN_ATTEMPTS")
                    .ok()
                    .and_then(|f| f.parse().ok())
                    .unwrap_or(5),
                max_connections_per_user: std::env::var("MAX_CONNECTIONS_PER_USER")
                    .ok()
                    .and_then(|c| c.parse().ok())
                    .unwrap_or(5),
                key_bundle_cache_hours: std::env::var("KEY_BUNDLE_CACHE_HOURS")
                    .ok()
                    .and_then(|h| h.parse().ok())
                    .unwrap_or(1),
                rate_limit_block_duration_seconds: std::env::var("RATE_LIMIT_BLOCK_SECONDS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(3600),
            },
            kafka: KafkaConfig {
                enabled: std::env::var("KAFKA_ENABLED")
                    .unwrap_or_else(|_| "false".to_string())
                    .parse()
                    .unwrap_or(false),
                brokers: std::env::var("KAFKA_BROKERS")
                    .unwrap_or_else(|_| "localhost:9092".to_string()),
                topic: std::env::var("KAFKA_TOPIC")
                    .unwrap_or_else(|_| "construct-messages".to_string()),
                consumer_group: std::env::var("KAFKA_CONSUMER_GROUP")
                    .unwrap_or_else(|_| "construct-delivery-workers".to_string()),
                ssl_enabled: std::env::var("KAFKA_SSL_ENABLED")
                    .unwrap_or_else(|_| "false".to_string())
                    .parse()
                    .unwrap_or(false),
                sasl_mechanism: std::env::var("KAFKA_SASL_MECHANISM").ok(),
                sasl_username: std::env::var("KAFKA_SASL_USERNAME").ok(),
                sasl_password: std::env::var("KAFKA_SASL_PASSWORD").ok(),
                // producer-specific settings
                producer_compression: std::env::var("KAFKA_PRODUCER_COMPRESSION")
                    .unwrap_or_else(|_| "snappy".to_string()),
                producer_acks: std::env::var("KAFKA_PRODUCER_ACKS")
                    .unwrap_or_else(|_| "all".to_string()),
                producer_linger_ms: std::env::var("KAFKA_PRODUCER_LINGER_MS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()
                    .unwrap_or(10),
                producer_batch_size: std::env::var("KAFKA_PRODUCER_BATCH_SIZE")
                    .unwrap_or_else(|_| "16384".to_string())
                    .parse()
                    .unwrap_or(16384),
                producer_max_in_flight: std::env::var("KAFKA_PRODUCER_MAX_IN_FLIGHT")
                    .unwrap_or_else(|_| "5".to_string())
                    .parse()
                    .unwrap_or(5),
                producer_retries: std::env::var("KAFKA_PRODUCER_RETRIES")
                    .unwrap_or_else(|_| "2147483647".to_string())
                    .parse()
                    .unwrap_or(2147483647),
                producer_request_timeout_ms: std::env::var("KAFKA_PRODUCER_REQUEST_TIMEOUT_MS")
                    .unwrap_or_else(|_| "30000".to_string())
                    .parse()
                    .unwrap_or(30000),
                producer_delivery_timeout_ms: std::env::var("KAFKA_PRODUCER_DELIVERY_TIMEOUT_MS")
                    .unwrap_or_else(|_| "120000".to_string())
                    .parse()
                    .unwrap_or(120000),
                producer_enable_idempotence: std::env::var("KAFKA_PRODUCER_ENABLE_IDEMPOTENCE")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()
                    .unwrap_or(true),
            },
            apns: ApnsConfig {
                enabled: std::env::var("APNS_ENABLED")
                    .unwrap_or_else(|_| "false".to_string())
                    .parse()
                    .unwrap_or(false),
                environment: std::env::var("APNS_ENVIRONMENT")
                    .unwrap_or_else(|_| "development".to_string())
                    .parse()
                    .unwrap_or(ApnsEnvironment::Development),
                key_path: std::env::var("APNS_KEY_PATH")
                    .unwrap_or_else(|_| "AuthKey_XXXXXXXXXX.p8".to_string()),
                key_id: std::env::var("APNS_KEY_ID").unwrap_or_else(|_| "XXXXXXXXXX".to_string()),
                team_id: std::env::var("APNS_TEAM_ID").unwrap_or_else(|_| "XXXXXXXXXX".to_string()),
                bundle_id: std::env::var("APNS_BUNDLE_ID")
                    .unwrap_or_else(|_| "com.example.construct".to_string()),
                topic: std::env::var("APNS_TOPIC").unwrap_or_else(|_| {
                    std::env::var("APNS_BUNDLE_ID")
                        .unwrap_or_else(|_| "com.example.construct".to_string())
                }),
                device_token_encryption_key: {
                    let key =
                        std::env::var("APNS_DEVICE_TOKEN_ENCRYPTION_KEY").unwrap_or_else(|_| {
                            "0000000000000000000000000000000000000000000000000000000000000000"
                                .to_string()
                        });
                    if key.len() != 64 {
                        anyhow::bail!(
                            "APNS_DEVICE_TOKEN_ENCRYPTION_KEY must be 64 hex characters (32 bytes)"
                        );
                    }
                    if key == "0000000000000000000000000000000000000000000000000000000000000000" {
                        anyhow::bail!(
                            "APNS_DEVICE_TOKEN_ENCRYPTION_KEY must be changed from default value"
                        );
                    }
                    key
                },
            },

            // Federation configuration
            federation: {
                let instance_domain = std::env::var("INSTANCE_DOMAIN")
                    .unwrap_or_else(|_| "eu.konstruct.cc".to_string());
                let base_domain = std::env::var("FEDERATION_BASE_DOMAIN")
                    .unwrap_or_else(|_| "konstruct.cc".to_string());
                let enabled = std::env::var("FEDERATION_ENABLED")
                    .unwrap_or_else(|_| "false".to_string())
                    .parse()
                    .unwrap_or(false);
                let signing_key_seed = std::env::var("SERVER_SIGNING_KEY").ok();

                // SECURITY: Federation signing key is REQUIRED if federation is enabled
                // Disable federation if key is missing rather than allowing unsigned messages
                let (enabled, signing_key_seed) = if enabled && signing_key_seed.is_none() {
                    tracing::error!(
                        "FEDERATION_ENABLED=true but SERVER_SIGNING_KEY is not set. \
                         Federation will be DISABLED for security. \
                         Generate key with: openssl rand -base64 32"
                    );
                    (false, None)
                } else if enabled {
                    // Validate signing key strength if provided
                    if let Some(ref key) = signing_key_seed {
                        // Base64-encoded 32 bytes should be 44 characters (without padding) or 43-44 with padding
                        // Use the same validation logic as ServerSigner::from_seed_base64
                        let decoded = match BASE64.decode(key.trim()) {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                anyhow::bail!("SERVER_SIGNING_KEY is not valid base64: {}", e);
                            }
                        };
                        if decoded.len() != 32 {
                            anyhow::bail!(
                                "SERVER_SIGNING_KEY must decode to exactly 32 bytes (got {} bytes). \
                                 Generate with: openssl rand -base64 32",
                                decoded.len()
                            );
                        }
                    }
                    (true, signing_key_seed)
                } else {
                    (false, signing_key_seed)
                };

                FederationConfig {
                    instance_domain,
                    base_domain,
                    enabled,
                    signing_key_seed,
                    mtls: {
                        // Parse pinned certificates from environment variable
                        // Format: "domain1:fingerprint1,domain2:fingerprint2"
                        let pinned_certs = std::env::var("FEDERATION_PINNED_CERTS")
                            .ok()
                            .map(|certs_str| {
                                let mut pinned = std::collections::HashMap::new();
                                for entry in certs_str.split(',') {
                                    let parts: Vec<&str> = entry.split(':').collect();
                                    if parts.len() == 2 {
                                        let domain = parts[0].trim().to_string();
                                        let fingerprint = parts[1].trim().to_string();
                                        if !domain.is_empty() && !fingerprint.is_empty() {
                                            pinned.insert(domain, fingerprint);
                                        }
                                    }
                                }
                                pinned
                            })
                            .unwrap_or_default();

                        crate::federation::MtlsConfig {
                            required: std::env::var("FEDERATION_MTLS_REQUIRED")
                                .unwrap_or_else(|_| "false".to_string())
                                .parse()
                                .unwrap_or(false),
                            client_cert_path: std::env::var("FEDERATION_CLIENT_CERT_PATH").ok(),
                            client_key_path: std::env::var("FEDERATION_CLIENT_KEY_PATH").ok(),
                            verify_server_cert: std::env::var("FEDERATION_VERIFY_SERVER_CERT")
                                .unwrap_or_else(|_| "true".to_string())
                                .parse()
                                .unwrap_or(true),
                            pinned_certs,
                        }
                    },
                }
            },

            // Legacy aliases (for backward compatibility)
            instance_domain: std::env::var("INSTANCE_DOMAIN")
                .unwrap_or_else(|_| "eu.konstruct.cc".to_string()),

            federation_base_domain: std::env::var("FEDERATION_BASE_DOMAIN")
                .unwrap_or_else(|_| "konstruct.cc".to_string()),

            federation_enabled: std::env::var("FEDERATION_ENABLED")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),

            deep_link_base_url: std::env::var("DEEP_LINK_BASE_URL")
                .unwrap_or_else(|_| "https://konstruct.cc".to_string()),

            // Database configuration
            db: DbConfig {
                max_connections: std::env::var("DB_MAX_CONNECTIONS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(10),
                acquire_timeout_secs: std::env::var("DB_ACQUIRE_TIMEOUT_SECS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(30),
                idle_timeout_secs: std::env::var("DB_IDLE_TIMEOUT_SECS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(600),
            },

            // Deep links configuration
            deeplinks: DeepLinksConfig {
                apple_team_id: std::env::var("APPLE_TEAM_ID")
                    .unwrap_or_else(|_| String::new()),
                android_package_name: std::env::var("ANDROID_PACKAGE_NAME")
                    .unwrap_or_else(|_| "com.konstruct.messenger".to_string()),
                android_cert_fingerprint: std::env::var("ANDROID_CERT_FINGERPRINT")
                    .unwrap_or_else(|_| String::new()),
            },

            // Worker configuration
            worker: WorkerConfig {
                shadow_read_enabled: std::env::var("SHADOW_READ_ENABLED")
                    .unwrap_or_else(|_| "false".to_string())
                    .parse()
                    .unwrap_or(false),
            },

            // Redis key prefixes configuration
            redis_key_prefixes: RedisKeyPrefixes {
                processed_msg: std::env::var("REDIS_KEY_PREFIX_PROCESSED_MSG")
                    .unwrap_or_else(|_| "processed_msg:".to_string()),
                user: std::env::var("REDIS_KEY_PREFIX_USER")
                    .unwrap_or_else(|_| "user:".to_string()),
                session: std::env::var("REDIS_KEY_PREFIX_SESSION")
                    .unwrap_or_else(|_| "session:".to_string()),
                user_sessions: std::env::var("REDIS_KEY_PREFIX_USER_SESSIONS")
                    .unwrap_or_else(|_| "user_sessions:".to_string()),
                msg_hash: std::env::var("REDIS_KEY_PREFIX_MSG_HASH")
                    .unwrap_or_else(|_| "msg_hash:".to_string()),
                rate: std::env::var("REDIS_KEY_PREFIX_RATE")
                    .unwrap_or_else(|_| "rate:".to_string()),
                blocked: std::env::var("REDIS_KEY_PREFIX_BLOCKED")
                    .unwrap_or_else(|_| "blocked:".to_string()),
                key_bundle: std::env::var("REDIS_KEY_PREFIX_KEY_BUNDLE")
                    .unwrap_or_else(|_| "key_bundle:".to_string()),
                connections: std::env::var("REDIS_KEY_PREFIX_CONNECTIONS")
                    .unwrap_or_else(|_| "connections:".to_string()),
                delivered_direct: std::env::var("REDIS_KEY_PREFIX_DELIVERED_DIRECT")
                    .unwrap_or_else(|_| "delivered_direct:".to_string()),
            },

            // Redis channels configuration
            redis_channels: RedisChannels {
                dead_letter_queue: std::env::var("REDIS_CHANNEL_DEAD_LETTER_QUEUE")
                    .unwrap_or_else(|_| "dead_letter_queue".to_string()),
                delivery_message: std::env::var("REDIS_CHANNEL_DELIVERY_MESSAGE")
                    .unwrap_or_else(|_| "delivery_message:".to_string()),
                delivery_notification: std::env::var("REDIS_CHANNEL_DELIVERY_NOTIFICATION")
                    .unwrap_or_else(|_| "delivery_notification:".to_string()),
            },

            // Media server configuration
            media: MediaConfig {
                enabled: std::env::var("MEDIA_ENABLED")
                    .map(|v| v.to_lowercase() == "true")
                    .unwrap_or(false),
                base_url: std::env::var("MEDIA_BASE_URL")
                    .unwrap_or_else(|_| "".to_string()),
                upload_token_secret: std::env::var("MEDIA_UPLOAD_TOKEN_SECRET")
                    .unwrap_or_else(|_| "".to_string()),
                max_file_size: std::env::var("MEDIA_MAX_FILE_SIZE")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(100 * 1024 * 1024), // 100MB
                rate_limit_per_hour: std::env::var("MEDIA_RATE_LIMIT_PER_HOUR")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(50),
            },
        })
    }
}
