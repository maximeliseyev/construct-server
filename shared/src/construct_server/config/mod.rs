// ============================================================================
// Configuration Module - Phase 2.8 Refactoring
// ============================================================================
//
// Phase 2.8: Split large config.rs (987 lines) into logical modules:
// - constants.rs: Configuration constants
// - database.rs: Database configuration
// - kafka.rs: Kafka configuration
// - federation.rs: Federation and APNs configuration
// - security.rs: Security and CSRF configuration
// - logging.rs: Logging configuration
// - microservices.rs: Microservices configuration
// - media.rs: Media server configuration
// - redis.rs: Redis configuration
// - worker.rs: Worker configuration
// - deeplinks.rs: Deep links configuration
//
// ============================================================================

mod constants;
mod database;
mod deeplinks;
mod federation;
mod kafka;
mod logging;
mod media;
mod microservices;
mod redis;
mod security;
mod worker;

// Re-export all public types for backward compatibility
pub use constants::{
    MAX_MEDIA_FILE_SIZE, MAX_MESSAGE_SIZE, MAX_REQUEST_BODY_SIZE, MAX_WEBSOCKET_MESSAGE_SIZE,
    SECONDS_PER_DAY, SECONDS_PER_HOUR, SECONDS_PER_MINUTE,
};
pub use database::DbConfig;
pub use deeplinks::DeepLinksConfig;
pub use federation::{ApnsConfig, ApnsEnvironment, FederationConfig};
pub use kafka::KafkaConfig;
pub use logging::LoggingConfig;
pub use media::MediaConfig;
pub use microservices::{CircuitBreakerConfig, MicroservicesConfig};
pub use redis::{RedisChannels, RedisKeyPrefixes};
pub use security::{CsrfConfig, SecurityConfig};
pub use worker::WorkerConfig;

use anyhow::Result;
use constants::*;

/// Main configuration structure
#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    /// DEPRECATED: JWT_SECRET is no longer used. RS256 is now required.
    /// Kept for backward compatibility but ignored.
    #[allow(dead_code)]
    pub jwt_secret: String,
    /// RSA private key for JWT signing (RS256)
    /// Required for auth-service (to create tokens)
    /// Optional for other services (verify-only mode)
    pub jwt_private_key: Option<String>,
    /// RSA public key for JWT verification (RS256)
    /// REQUIRED for all services
    pub jwt_public_key: Option<String>,
    pub port: u16,
    pub bind_address: String,
    pub health_port: u16,
    pub heartbeat_interval_secs: i64,
    pub server_registry_ttl_secs: i64,
    pub message_ttl_days: i64,
    /// Access token TTL in hours (for REST API - short-lived for security)
    pub access_token_ttl_hours: i64,
    /// Session TTL in days (for WebSocket sessions - legacy, kept for backward compatibility)
    pub session_ttl_days: i64,
    /// Refresh token TTL in days (long-lived for user convenience)
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
    pub csrf: CsrfConfig,
    /// Phase 2.6: Microservices configuration
    pub microservices: MicroservicesConfig,

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

        // Load sub-configurations
        let logging = LoggingConfig::from_env()?;
        let security = SecurityConfig::from_env();
        let kafka = KafkaConfig::from_env();
        let apns = ApnsConfig::from_env()?;
        let federation = FederationConfig::from_env()?;
        let db = DbConfig::from_env();
        let deeplinks = DeepLinksConfig::from_env();
        let worker = WorkerConfig::from_env();
        let redis_key_prefixes = RedisKeyPrefixes::from_env();
        let redis_channels = RedisChannels::from_env();
        let media = MediaConfig::from_env();
        let csrf = CsrfConfig::from_env()?;
        let microservices = MicroservicesConfig::from_env();

        // Legacy federation aliases
        let instance_domain = federation.instance_domain.clone();
        let federation_base_domain = federation.base_domain.clone();
        let federation_enabled = federation.enabled;

        Ok(Self {
            database_url: std::env::var("DATABASE_URL")?,
            redis_url: std::env::var("REDIS_URL")?,
            // JWT_SECRET is deprecated - RS256 is now required
            // Kept for backward compatibility but not used
            jwt_secret: std::env::var("JWT_SECRET").unwrap_or_default(),
            jwt_private_key: {
                // Try to load from file path first, then from environment variable directly (PEM string)
                std::env::var("JWT_PRIVATE_KEY").ok().map(|key| {
                    // Detect if PEM is stored directly in env var (security risk)
                    let is_pem_in_env = key.starts_with("-----BEGIN") ||
                        (!key.contains(std::path::MAIN_SEPARATOR) && !key.ends_with(".pem") && !key.ends_with(".key"));

                    if is_pem_in_env && key.contains("PRIVATE") {
                        // SECURITY WARNING: PEM in env var is visible in /proc, ps, logs
                        tracing::warn!(
                            "SECURITY: JWT_PRIVATE_KEY contains PEM data directly in environment variable. \
                            This is insecure - the key is visible in /proc/*/environ, `ps aux`, and logs. \
                            Recommended: Store key in a file and set JWT_PRIVATE_KEY=/path/to/private.pem"
                        );
                    }

                    // If it looks like a file path, try to read it
                    if key.contains(std::path::MAIN_SEPARATOR) || key.ends_with(".pem") || key.ends_with(".key") {
                        std::fs::read_to_string(&key).unwrap_or_else(|e| {
                            tracing::warn!(
                                error = %e,
                                path = %key,
                                "Failed to read JWT_PRIVATE_KEY from file, using as-is"
                            );
                            key
                        })
                    } else {
                        // PEM string directly in environment variable
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
                            std::fs::read_to_string(&key).unwrap_or_else(|e| {
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
            bind_address: format!(
                "[::]:{}",
                std::env::var("PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(DEFAULT_PORT)
            ),
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
            access_token_ttl_hours: std::env::var("ACCESS_TOKEN_TTL_HOURS")
                .ok()
                .and_then(|h| h.parse().ok())
                .unwrap_or(DEFAULT_ACCESS_TOKEN_TTL_HOURS),
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
            logging,
            security,
            kafka,
            apns,
            federation,
            db,
            deeplinks,
            worker,
            redis_key_prefixes,
            redis_channels,
            media,
            csrf,
            microservices,
            // Legacy aliases
            instance_domain,
            federation_base_domain,
            federation_enabled,
            deep_link_base_url: std::env::var("DEEP_LINK_BASE_URL")
                .unwrap_or_else(|_| "https://konstruct.cc".to_string()),
        })
    }
}
