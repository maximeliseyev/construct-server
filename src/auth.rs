use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode_header, Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub jti: String, // JWT ID (unique per token)
    pub exp: i64,    // Expiration time
    pub iat: i64,    // Issued at
    pub iss: String, // Issuer
}

/// JWT algorithm version for key rotation support
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JwtAlgorithm {
    HS256, // Legacy symmetric algorithm
    RS256, // Modern asymmetric algorithm
}

pub struct AuthManager {
    /// Encoding key (private key for RS256, secret for HS256)
    /// None if service only verifies tokens (e.g., user-service with only public key)
    encoding_key: Option<EncodingKey>,
    /// Primary decoding key (public key for RS256, secret for HS256)
    decoding_key: DecodingKey,
    /// Legacy decoding key for HS256 (for backward compatibility during migration)
    legacy_decoding_key: Option<DecodingKey>,
    /// Current algorithm being used for verification (and new tokens if encoding_key is set)
    current_algorithm: JwtAlgorithm,
    /// Access token TTL in hours (for REST API)
    access_token_ttl_hours: i64,
    /// Session TTL in days (for WebSocket - legacy, kept for backward compatibility)
    #[allow(dead_code)]
    session_ttl_days: i64,
    /// Refresh token TTL in days
    refresh_token_ttl_days: i64,
    issuer: String,
}

impl AuthManager {
    pub fn new(config: &Config) -> Result<Self> {
        // Helper to check if a key string is valid (not empty, not whitespace-only)
        let is_valid_key = |key: &Option<String>| -> bool {
            key.as_ref().map(|k| !k.trim().is_empty()).unwrap_or(false)
        };

        let has_private_key = is_valid_key(&config.jwt_private_key);
        let has_public_key = is_valid_key(&config.jwt_public_key);
        let has_secret = !config.jwt_secret.is_empty();

        // Determine mode based on available keys:
        // 1. RS256 full (can sign + verify): private + public key
        // 2. RS256 verify-only (can only verify): public key only
        // 3. HS256 (can sign + verify): secret only
        let (current_algorithm, encoding_key, decoding_key, legacy_decoding_key) =
            if has_private_key && has_public_key {
                // RS256 full mode: Can create and verify tokens
                let private_key = config.jwt_private_key.as_ref().unwrap();
                let public_key = config.jwt_public_key.as_ref().unwrap();

                tracing::info!("Initializing JWT with RS256 algorithm (full mode: can sign and verify)");

                let encoding_key = EncodingKey::from_rsa_pem(private_key.as_bytes())
                    .context("Failed to parse JWT_PRIVATE_KEY as RSA PEM")?;

                let decoding_key = DecodingKey::from_rsa_pem(public_key.as_bytes())
                    .context("Failed to parse JWT_PUBLIC_KEY as RSA PEM")?;

                // For backward compatibility: also support HS256 tokens if JWT_SECRET is provided
                let legacy_key = if has_secret {
                    tracing::info!("Legacy HS256 support enabled for backward compatibility");
                    Some(DecodingKey::from_secret(config.jwt_secret.as_bytes()))
                } else {
                    None
                };

                (JwtAlgorithm::RS256, Some(encoding_key), decoding_key, legacy_key)
            } else if has_public_key {
                // RS256 verify-only mode: Can only verify tokens (e.g., user-service)
                let public_key = config.jwt_public_key.as_ref().unwrap();

                tracing::info!("Initializing JWT with RS256 algorithm (verify-only mode: no private key)");

                let decoding_key = DecodingKey::from_rsa_pem(public_key.as_bytes())
                    .context("Failed to parse JWT_PUBLIC_KEY as RSA PEM")?;

                // For backward compatibility: also support HS256 tokens if JWT_SECRET is provided
                let legacy_key = if has_secret {
                    tracing::info!("Legacy HS256 support enabled for backward compatibility");
                    Some(DecodingKey::from_secret(config.jwt_secret.as_bytes()))
                } else {
                    None
                };

                // No encoding key - this service cannot create tokens
                (JwtAlgorithm::RS256, None, decoding_key, legacy_key)
            } else if has_secret {
                // HS256 mode: Use symmetric secret (legacy)
                tracing::warn!(
                    "Using legacy HS256 algorithm. Consider migrating to RS256 with JWT_PRIVATE_KEY/JWT_PUBLIC_KEY"
                );

                let encoding_key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
                let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());

                (JwtAlgorithm::HS256, Some(encoding_key), decoding_key, None)
            } else {
                anyhow::bail!(
                    "No JWT configuration provided. Set either:\n\
                    - JWT_PUBLIC_KEY (for verify-only mode)\n\
                    - JWT_PRIVATE_KEY + JWT_PUBLIC_KEY (for RS256 full mode)\n\
                    - JWT_SECRET (for legacy HS256 mode)"
                );
            };

        Ok(Self {
            encoding_key,
            decoding_key,
            legacy_decoding_key,
            current_algorithm,
            access_token_ttl_hours: config.access_token_ttl_hours,
            session_ttl_days: config.session_ttl_days,
            refresh_token_ttl_days: config.refresh_token_ttl_days,
            issuer: config.jwt_issuer.clone(),
        })
    }

    /// Create access token (short-lived, for REST API)
    /// Returns error if this AuthManager was initialized in verify-only mode (no private key)
    pub fn create_token(&self, user_id: &Uuid) -> Result<(String, String, i64)> {
        let encoding_key = self.encoding_key.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "Cannot create tokens: AuthManager is in verify-only mode (no JWT_PRIVATE_KEY configured)"
            )
        })?;

        let now = Utc::now();
        // Use hours for access tokens (short-lived for security)
        let exp = now + Duration::hours(self.access_token_ttl_hours);
        let jti = Uuid::new_v4().to_string();

        let claims = Claims {
            sub: user_id.to_string(),
            jti: jti.clone(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            iss: self.issuer.clone(),
        };

        // Create header with current algorithm
        let mut header = Header::default();
        header.alg = match self.current_algorithm {
            JwtAlgorithm::HS256 => Algorithm::HS256,
            JwtAlgorithm::RS256 => Algorithm::RS256,
        };

        let token =
            encode(&header, &claims, encoding_key).context("Failed to encode JWT token")?;

        Ok((token, jti, exp.timestamp()))
    }

    /// Create refresh token (long-lived, for token refresh)
    /// Returns error if this AuthManager was initialized in verify-only mode (no private key)
    pub fn create_refresh_token(&self, user_id: &Uuid) -> Result<(String, String, i64)> {
        let encoding_key = self.encoding_key.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "Cannot create tokens: AuthManager is in verify-only mode (no JWT_PRIVATE_KEY configured)"
            )
        })?;

        let now = Utc::now();
        let exp = now + Duration::days(self.refresh_token_ttl_days);
        let jti = Uuid::new_v4().to_string();

        let claims = Claims {
            sub: user_id.to_string(),
            jti: jti.clone(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            iss: self.issuer.clone(),
        };

        // Create header with current algorithm
        let mut header = Header::default();
        header.alg = match self.current_algorithm {
            JwtAlgorithm::HS256 => Algorithm::HS256,
            JwtAlgorithm::RS256 => Algorithm::RS256,
        };

        let token = encode(&header, &claims, encoding_key)
            .context("Failed to encode JWT refresh token")?;

        Ok((token, jti, exp.timestamp()))
    }

    /// Verify JWT token with support for both RS256 and HS256 (backward compatibility)
    /// 
    /// This method first tries to decode the token header to determine the algorithm,
    /// then uses the appropriate key for verification. This ensures tokens created with
    /// RS256 can be verified even if the service was initialized in HS256 mode (and vice versa),
    /// as long as the appropriate keys are available.
    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        // First, try to decode the token header to determine algorithm
        let token_algorithm = match decode_header(token) {
            Ok(header) => Some(header.alg),
            Err(_) => {
                // If we can't decode the header, we'll try both algorithms
                None
            }
        };

        // Helper function to verify with a specific algorithm
        let verify_with_algorithm = |alg: Algorithm, key: &DecodingKey| -> Result<Claims> {
            let mut validation = Validation::new(alg);
            validation.set_issuer(&[self.issuer.clone()]);
            let token_data = decode::<Claims>(token, key, &validation)?;
            Ok(token_data.claims)
        };

        // If we know the algorithm from the header, try that first
        if let Some(alg) = token_algorithm {
            match alg {
                Algorithm::RS256 => {
                    // Token is RS256 - need RSA public key
                    if matches!(self.current_algorithm, JwtAlgorithm::RS256) {
                        // We have RSA keys configured
                        match verify_with_algorithm(Algorithm::RS256, &self.decoding_key) {
                            Ok(claims) => return Ok(claims),
                            Err(e) => {
                                tracing::debug!(error = %e, "RS256 verification failed with primary key");
                                // Try legacy HS256 if available
                                if let Some(ref legacy_key) = self.legacy_decoding_key {
                                    tracing::debug!("Trying legacy HS256 as fallback");
                                    if let Ok(claims) = verify_with_algorithm(Algorithm::HS256, legacy_key) {
                                        tracing::info!(
                                            "Successfully verified legacy HS256 token - user should re-login for RS256 token"
                                        );
                                        return Ok(claims);
                                    }
                                }
                                return Err(anyhow::anyhow!(
                                    "Failed to verify RS256 token: {}. Make sure JWT_PUBLIC_KEY matches the key used to sign the token.",
                                    e
                                ));
                            }
                        }
                    } else {
                        // Token is RS256 but we don't have RSA keys configured
                        return Err(anyhow::anyhow!(
                            "Token uses RS256 algorithm, but JWT_PUBLIC_KEY is not configured. \
                            Please set JWT_PUBLIC_KEY to verify RS256 tokens, or ensure tokens are created with HS256."
                        ));
                    }
                }
                Algorithm::HS256 => {
                    // Token is HS256 - need symmetric secret
                    if let Some(ref legacy_key) = self.legacy_decoding_key {
                        // We have legacy HS256 support
                        match verify_with_algorithm(Algorithm::HS256, legacy_key) {
                            Ok(claims) => return Ok(claims),
                            Err(e) => {
                                tracing::debug!(error = %e, "HS256 verification failed with legacy key");
                            }
                        }
                    }
                    if matches!(self.current_algorithm, JwtAlgorithm::HS256) {
                        // We're in HS256 mode
                        match verify_with_algorithm(Algorithm::HS256, &self.decoding_key) {
                            Ok(claims) => return Ok(claims),
                            Err(e) => {
                                return Err(anyhow::anyhow!(
                                    "Failed to verify HS256 token: {}. Make sure JWT_SECRET matches the secret used to sign the token.",
                                    e
                                ));
                            }
                        }
                    } else {
                        // Token is HS256 but we don't have JWT_SECRET configured
                        return Err(anyhow::anyhow!(
                            "Token uses HS256 algorithm, but JWT_SECRET is not configured. \
                            Please set JWT_SECRET to verify HS256 tokens, or ensure tokens are created with RS256."
                        ));
                    }
                }
                _ => {
                    return Err(anyhow::anyhow!(
                        "Unsupported JWT algorithm: {:?}. Only RS256 and HS256 are supported.",
                        alg
                    ));
                }
            }
        }

        // If we couldn't determine the algorithm from the header, try both (if available)
        // This provides backward compatibility for tokens with malformed headers
        tracing::debug!("Could not determine algorithm from token header, trying both algorithms");

        // Try RS256 first if we have RSA keys
        if matches!(self.current_algorithm, JwtAlgorithm::RS256) {
            if let Ok(claims) = verify_with_algorithm(Algorithm::RS256, &self.decoding_key) {
                return Ok(claims);
            }
        }

        // Try HS256 if we have a secret
        if let Some(ref legacy_key) = self.legacy_decoding_key {
            if let Ok(claims) = verify_with_algorithm(Algorithm::HS256, legacy_key) {
                tracing::info!("Successfully verified token as HS256 (fallback)");
                return Ok(claims);
            }
        }
        if matches!(self.current_algorithm, JwtAlgorithm::HS256) {
            if let Ok(claims) = verify_with_algorithm(Algorithm::HS256, &self.decoding_key) {
                return Ok(claims);
            }
        }

        // Both failed
        Err(anyhow::anyhow!(
            "Token verification failed: Could not verify token with any available algorithm. \
            Token may be invalid, expired, or signed with a different key. \
            Ensure JWT_PUBLIC_KEY (for RS256) or JWT_SECRET (for HS256) matches the key used to sign the token."
        ))
    }
}
