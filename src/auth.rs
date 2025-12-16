use anyhow::Result;
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

pub struct AuthManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    session_ttl_days: i64,
    #[allow(dead_code)]
    refresh_token_ttl_days: i64,
    issuer: String,
}

impl AuthManager {
    pub fn new(config: &Config) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(config.jwt_secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(config.jwt_secret.as_bytes()),
            session_ttl_days: config.session_ttl_days,
            refresh_token_ttl_days: config.refresh_token_ttl_days,
            issuer: config.jwt_issuer.clone(),
        }
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

        let token = encode(&Header::default(), &claims, &self.encoding_key)?;

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

        let token = encode(&Header::default(), &claims, &self.encoding_key)?;

        Ok((token, jti, exp.timestamp()))
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[self.issuer.clone()]);
        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }
}
