use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
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
    encoding_key: EncodingKey,
    /// Primary decoding key (public key for RS256, secret for HS256)
    decoding_key: DecodingKey,
    /// Legacy decoding key for HS256 (for backward compatibility during migration)
    legacy_decoding_key: Option<DecodingKey>,
    /// Current algorithm being used for new tokens
    current_algorithm: JwtAlgorithm,
    session_ttl_days: i64,
    #[allow(dead_code)]
    refresh_token_ttl_days: i64,
    issuer: String,
}

impl AuthManager {
    pub fn new(config: &Config) -> Result<Self> {
        // Check if RSA keys are provided (RS256 mode)
        let (current_algorithm, encoding_key, decoding_key, legacy_decoding_key) = 
            if let (Some(private_key), Some(public_key)) = (&config.jwt_private_key, &config.jwt_public_key) {
                // RS256 mode: Use RSA keypair
                tracing::info!("Initializing JWT with RS256 algorithm (RSA keypair)");
                
                let encoding_key = EncodingKey::from_rsa_pem(private_key.as_bytes())
                    .context("Failed to parse JWT_PRIVATE_KEY as RSA PEM")?;
                
                let decoding_key = DecodingKey::from_rsa_pem(public_key.as_bytes())
                    .context("Failed to parse JWT_PUBLIC_KEY as RSA PEM")?;
                
                // For backward compatibility: also support HS256 tokens if JWT_SECRET is provided
                let legacy_key = if !config.jwt_secret.is_empty() {
                    tracing::info!("Legacy HS256 support enabled for backward compatibility");
                    Some(DecodingKey::from_secret(config.jwt_secret.as_bytes()))
                } else {
                    None
                };
                
                (JwtAlgorithm::RS256, encoding_key, decoding_key, legacy_key)
            } else {
                // HS256 mode: Use symmetric secret (legacy)
                tracing::warn!("Using legacy HS256 algorithm. Consider migrating to RS256 with JWT_PRIVATE_KEY/JWT_PUBLIC_KEY");
                
                if config.jwt_secret.is_empty() {
                    anyhow::bail!("JWT_SECRET is required when not using RS256 keys (JWT_PRIVATE_KEY/JWT_PUBLIC_KEY)");
                }
                
                let encoding_key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
                let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());
                
                (JwtAlgorithm::HS256, encoding_key, decoding_key, None)
            };
        
        Ok(Self {
            encoding_key,
            decoding_key,
            legacy_decoding_key,
            current_algorithm,
            session_ttl_days: config.session_ttl_days,
            refresh_token_ttl_days: config.refresh_token_ttl_days,
            issuer: config.jwt_issuer.clone(),
        })
    }

    pub fn create_token(&self, user_id: &Uuid) -> Result<(String, String, i64)> {
        let now = Utc::now();
        let exp = now + Duration::days(self.session_ttl_days);
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

        let token = encode(&header, &claims, &self.encoding_key)
            .context("Failed to encode JWT token")?;

        Ok((token, jti, exp.timestamp()))
    }

    #[allow(dead_code)]
    pub fn create_refresh_token(&self, user_id: &Uuid) -> Result<(String, String, i64)> {
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

        let token = encode(&header, &claims, &self.encoding_key)
            .context("Failed to encode JWT refresh token")?;

        Ok((token, jti, exp.timestamp()))
    }

    /// Verify JWT token with support for both RS256 and HS256 (backward compatibility)
    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        // First, try to decode the token header to determine algorithm
        // If we can't decode the header, try both algorithms
        
        // Try primary algorithm first (current algorithm)
        match self.current_algorithm {
            JwtAlgorithm::RS256 => {
                // Try RS256 first
                let mut validation = Validation::new(Algorithm::RS256);
                validation.set_issuer(&[self.issuer.clone()]);
                
                match decode::<Claims>(token, &self.decoding_key, &validation) {
                    Ok(token_data) => Ok(token_data.claims),
                    Err(_) => {
                        // If RS256 fails and we have legacy HS256 support, try that
                        if let Some(ref legacy_key) = self.legacy_decoding_key {
                            tracing::debug!("RS256 verification failed, trying legacy HS256");
                            let mut legacy_validation = Validation::new(Algorithm::HS256);
                            legacy_validation.set_issuer(&[self.issuer.clone()]);
                            match decode::<Claims>(token, legacy_key, &legacy_validation) {
                                Ok(token_data) => {
                                    tracing::info!("Successfully verified legacy HS256 token - user should re-login for RS256 token");
                                    Ok(token_data.claims)
                                }
                                Err(e) => {
                                    Err(anyhow::anyhow!("Token verification failed (RS256 and HS256): {}", e))
                                }
                            }
                        } else {
                            // No legacy support, return RS256 error
                            Err(anyhow::anyhow!("Token verification failed: RS256 decode error"))
                        }
                    }
                }
            }
            JwtAlgorithm::HS256 => {
                // Legacy HS256 mode
                let mut validation = Validation::new(Algorithm::HS256);
                validation.set_issuer(&[self.issuer.clone()]);
                let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
                    .context("Failed to verify HS256 token")?;
                Ok(token_data.claims)
            }
        }
    }
}
