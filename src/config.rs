use anyhow::Result;

#[derive(Clone, Debug)]
pub struct LoggingConfig {
    pub enable_message_metadata: bool,
    pub enable_user_identifiers: bool,
    pub hash_salt: String,
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
    pub max_key_rotations_per_day: u32,
    pub max_password_changes_per_day: u32,
    pub max_failed_login_attempts: u32,
    #[allow(dead_code)]
    pub max_connections_per_user: u32,
    pub key_bundle_cache_hours: i64,
    pub rate_limit_block_duration_seconds: i64,
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
            _ => anyhow::bail!("Invalid APNs environment: {}. Must be 'production' or 'development'", s),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    pub port: u16,
    pub health_port: u16,
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
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        Ok(Self {
            database_url: std::env::var("DATABASE_URL")?,
            redis_url: std::env::var("REDIS_URL")?,
            jwt_secret: {
                let secret = std::env::var("JWT_SECRET")?;
                if secret.len() < 32 {
                    anyhow::bail!("JWT_SECRET must be at least 32 characters long");
                }
                secret
            },
            port: std::env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8080),
            health_port: std::env::var("HEALTH_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8081),
            message_ttl_days: std::env::var("MESSAGE_TTL_DAYS")
                .ok()
                .and_then(|d| d.parse().ok())
                .unwrap_or(7),
            session_ttl_days: std::env::var("SESSION_TTL_DAYS")
                .ok()
                .and_then(|d| d.parse().ok())
                .unwrap_or(30),
            refresh_token_ttl_days: std::env::var("REFRESH_TOKEN_TTL_DAYS")
                .ok()
                .and_then(|d| d.parse().ok())
                .unwrap_or(90),
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
                .unwrap_or(1000),
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
                key_id: std::env::var("APNS_KEY_ID")
                    .unwrap_or_else(|_| "XXXXXXXXXX".to_string()),
                team_id: std::env::var("APNS_TEAM_ID")
                    .unwrap_or_else(|_| "XXXXXXXXXX".to_string()),
                bundle_id: std::env::var("APNS_BUNDLE_ID")
                    .unwrap_or_else(|_| "com.example.construct".to_string()),
                topic: std::env::var("APNS_TOPIC")
                    .unwrap_or_else(|_| std::env::var("APNS_BUNDLE_ID")
                        .unwrap_or_else(|_| "com.example.construct".to_string())),
            },
        })
    }
}
