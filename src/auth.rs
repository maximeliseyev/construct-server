use anyhow::Result;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const TOKEN_ALIVE_DAYS: i64 = 30;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub jti: String, // JWT ID (unique per token)
    pub exp: i64,    // Expiration time
    pub iat: i64,    // Issued at
}

pub struct AuthManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl AuthManager {
    pub fn new(secret: &str) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
        }
    }

    pub fn create_token(&self, user_id: &Uuid) -> Result<(String, String, i64)> {
        let now = Utc::now();
        let exp = now + Duration::days(TOKEN_ALIVE_DAYS);
        let jti = Uuid::new_v4().to_string(); // Уникаль

        let claims = Claims {
            sub: user_id.to_string(),
            jti: jti.clone(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        let token = encode(&Header::default(), &claims, &self.encoding_key)?;

        Ok((token, jti, exp.timestamp()))
    }

    // Проверить JWT токен (только подпись, без Redis)
    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }
}
