// ============================================================================
// Federation and APNs Configuration
// ============================================================================
// Phase 2.8: Extracted from config.rs for better organization

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

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

impl ApnsConfig {
    pub(crate) fn from_env() -> anyhow::Result<Self> {
        let apns_enabled = std::env::var("APNS_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        let key = std::env::var("APNS_DEVICE_TOKEN_ENCRYPTION_KEY").unwrap_or_else(|_| {
            "0000000000000000000000000000000000000000000000000000000000000000".to_string()
        });

        // Only validate if APNs is enabled or if key is explicitly set (not default)
        let is_default = key == "0000000000000000000000000000000000000000000000000000000000000000";

        if !is_default {
            // Key is set - validate format
            if key.len() != 64 {
                anyhow::bail!(
                    "APNS_DEVICE_TOKEN_ENCRYPTION_KEY must be 64 hex characters (32 bytes)"
                );
            }
        } else if apns_enabled {
            // APNs is enabled but key is default - require it to be changed
            anyhow::bail!(
                "APNS_DEVICE_TOKEN_ENCRYPTION_KEY must be changed from default value (APNS_ENABLED=true requires a valid key)"
            );
        }
        // If APNs is disabled and key is default, allow it (service doesn't use APNs)

        Ok(Self {
            enabled: apns_enabled,
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
            device_token_encryption_key: key,
        })
    }
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

impl FederationConfig {
    pub(crate) fn from_env() -> anyhow::Result<Self> {
        let instance_domain =
            std::env::var("INSTANCE_DOMAIN").unwrap_or_else(|_| "eu.konstruct.cc".to_string());
        let base_domain =
            std::env::var("FEDERATION_BASE_DOMAIN").unwrap_or_else(|_| "konstruct.cc".to_string());
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

        Ok(Self {
            instance_domain,
            base_domain,
            enabled,
            signing_key_seed,
            mtls: crate::federation::MtlsConfig {
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
            },
        })
    }
}
