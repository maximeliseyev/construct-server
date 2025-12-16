use anyhow::Result;

#[derive(Clone, Debug)]
pub struct LoggingConfig {
    pub enable_message_metadata: bool,
    pub enable_user_identifiers: bool,
    pub hash_salt: String,
}

/// Security configuration for cryptographic operations
#[derive(Clone, Debug)]
pub struct SecurityConfig {
    pub prekey_ttl_days: i64,
    pub prekey_min_ttl_days: i64,
    pub prekey_max_ttl_days: i64,
    pub max_messages_per_hour: u32,
    pub max_key_rotations_per_day: u32,
    pub max_connections_per_user: u32,
    pub key_bundle_cache_hours: i64,
    pub rate_limit_block_duration_seconds: u64,
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
    pub logging: LoggingConfig,
    pub security: SecurityConfig,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        Ok(Self {
            database_url: std::env::var("DATABASE_URL")?,
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
            jwt_secret: std::env::var("JWT_SECRET")?,
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
            logging: LoggingConfig {
                enable_message_metadata: std::env::var("LOG_MESSAGE_METADATA")
                    .unwrap_or_else(|_| "false".to_string())
                    .parse()
                    .unwrap_or(false),
                enable_user_identifiers: std::env::var("LOG_USER_IDENTIFIERS")
                    .unwrap_or_else(|_| "false".to_string())
                    .parse()
                    .unwrap_or(false),
                hash_salt: std::env::var("LOG_HASH_SALT")
                    .unwrap_or_else(|_| "default-salt-please-change".to_string()),
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
        })
    }
}
