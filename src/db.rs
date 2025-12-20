use crate::crypto::StoredKeyBundle;
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bcrypt::{DEFAULT_COST, hash};
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

pub type DbPool = Pool<Postgres>;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub password_hash: String,
    #[allow(dead_code)]
    pub identity_key: Vec<u8>,
    #[allow(dead_code)]
    pub avatar_url: Option<String>,
    #[allow(dead_code)]
    pub bio: Option<String>,
    #[allow(dead_code)]
    pub created_at: Option<chrono::NaiveDateTime>,
    #[allow(dead_code)]
    pub last_seen: Option<chrono::NaiveDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct PublicUserInfo {
    #[serde(with = "uuid_as_string")]
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
}

// Helper module для сериализации UUID как строки
mod uuid_as_string {
    use serde::{Deserialize, Deserializer, Serializer};
    use uuid::Uuid;

    pub fn serialize<S>(uuid: &Uuid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&uuid.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Uuid::parse_str(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct KeyBundleRecord {
    pub user_id: Uuid,
    pub identity_public: Vec<u8>,
    pub signed_prekey_public: Vec<u8>,
    pub signature: Vec<u8>,
    pub verifying_key: Vec<u8>,
    pub registered_at: chrono::NaiveDateTime,
    pub expires_at: chrono::NaiveDateTime,
}

pub async fn create_pool(database_url: &str) -> Result<DbPool> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;
    Ok(pool)
}

pub async fn create_user(
    pool: &DbPool,
    username: &str,
    display_name: &str,
    password: &str,
    identity_key_base64: &str,
) -> Result<User> {
    let password_hash = hash(password, DEFAULT_COST)?;
    let identity_key = BASE64
        .decode(identity_key_base64)
        .context("Failed to decode identity_key from base64")?;

    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (username, display_name, password_hash, identity_key)
        VALUES ($1, $2, $3, $4)
        RETURNING id, username, display_name, password_hash, identity_key,
                  avatar_url, bio, created_at, last_seen
           "#,
    )
    .bind(username)
    .bind(display_name)
    .bind(password_hash)
    .bind(identity_key)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

pub async fn get_user_by_username(pool: &DbPool, username: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        r#"
        -- CREATE INDEX idx_users_username ON users(username);
        -- CREATE INDEX idx_users_display_name ON users(display_name);
        SELECT id, username, display_name, password_hash, identity_key,
               avatar_url, bio, created_at, last_seen
        FROM users
        WHERE username = $1
        "#,
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

pub async fn get_user_by_id(pool: &DbPool, user_id: &Uuid) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        r#"
        SELECT id, username, display_name, password_hash, identity_key,
               avatar_url, bio, created_at, last_seen
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

pub async fn search_users_by_display_name(
    pool: &DbPool,
    query: &str,
) -> Result<Vec<PublicUserInfo>> {
    let users = sqlx::query_as::<_, PublicUserInfo>(
        r#"
        SELECT id, username, display_name, avatar_url, bio
        FROM users
        WHERE display_name ILIKE $1
        LIMIT 20
        "#,
    )
    .bind(format!("%{}%", query))
    .fetch_all(pool)
    .await?;

    Ok(users)
}

pub async fn verify_password(user: &User, password: &str) -> Result<bool> {
    Ok(bcrypt::verify(password, &user.password_hash)?)
}

pub async fn store_key_bundle(
    pool: &DbPool,
    user_id: &Uuid,
    bundle: &StoredKeyBundle,
) -> Result<()> {
    // Декодируем base64 строки в Vec<u8> для хранения в БД
    let identity_public = BASE64
        .decode(&bundle.identity_public)
        .context("Failed to decode identity_public from base64")?;

    let signed_prekey_public = BASE64
        .decode(&bundle.signed_prekey_public)
        .context("Failed to decode signed_prekey_public from base64")?;

    let signature = BASE64
        .decode(&bundle.signature)
        .context("Failed to decode signature from base64")?;

    let verifying_key = BASE64
        .decode(&bundle.verifying_key)
        .context("Failed to decode verifying_key from base64")?;

    sqlx::query(
        r#"
        INSERT INTO user_key_bundles
         (user_id, identity_public, signed_prekey_public, signature, verifying_key, registered_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (user_id) DO UPDATE SET
           signed_prekey_public = EXCLUDED.signed_prekey_public,
           signature = EXCLUDED.signature,
           registered_at = EXCLUDED.registered_at,
           expires_at = EXCLUDED.expires_at
        "#,
    )
    .bind(user_id)
    .bind(identity_public)
    .bind(signed_prekey_public)
    .bind(signature)
    .bind(verifying_key)
    .bind(bundle.registered_at.naive_utc())
    .bind(bundle.prekey_expires_at.naive_utc())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_user_key_bundle(pool: &DbPool, user_id: &Uuid) -> Result<Option<StoredKeyBundle>> {
    let record = sqlx::query_as::<_, KeyBundleRecord>(
        r#"
        SELECT user_id, identity_public, signed_prekey_public, signature,
                verifying_key, registered_at, expires_at
         FROM user_key_bundles
         WHERE user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(record.map(|r| StoredKeyBundle {
        user_id: r.user_id.to_string(),
        // Кодируем Vec<u8> в base64 строки
        identity_public: BASE64.encode(r.identity_public),
        signed_prekey_public: BASE64.encode(r.signed_prekey_public),
        signature: BASE64.encode(r.signature),
        verifying_key: BASE64.encode(r.verifying_key),
        // Преобразуем NaiveDateTime в DateTime<Utc>
        registered_at: Utc.from_utc_datetime(&r.registered_at),
        prekey_expires_at: Utc.from_utc_datetime(&r.expires_at),
    }))
}

// ============================================================================
// Pending Messages
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingMessage {
    pub id: Uuid,
    pub recipient_id: Uuid,
    pub message_payload: Vec<u8>, // Stored as raw MessagePack bytes
    pub created_at: chrono::DateTime<Utc>,
}

pub async fn store_pending_message(
    pool: &DbPool,
    recipient_id: &Uuid,
    message_payload: Vec<u8>,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO pending_messages (recipient_id, message_payload)
        VALUES ($1, $2)
        "#,
    )
    .bind(recipient_id)
    .bind(message_payload)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_pending_messages(
    pool: &DbPool,
    recipient_id: &Uuid,
) -> Result<Vec<PendingMessage>> {
    let messages = sqlx::query_as::<_, PendingMessage>(
        r#"
        SELECT id, recipient_id, message_payload, created_at
        FROM pending_messages
        WHERE recipient_id = $1
        ORDER BY created_at ASC
        "#,
    )
    .bind(recipient_id)
    .fetch_all(pool)
    .await?;
    Ok(messages)
}

pub async fn delete_pending_message(pool: &DbPool, message_id: &Uuid) -> Result<()> {
    sqlx::query(
        r#"
        DELETE FROM pending_messages
        WHERE id = $1
        "#,
    )
    .bind(message_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn has_pending_messages(pool: &DbPool, recipient_id: &Uuid) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM pending_messages
        WHERE recipient_id = $1
        "#,
    )
    .bind(recipient_id)
    .fetch_one(pool)
    .await?;
    Ok(count > 0)
}



// ============================================================================
// Tests - Verify MessagePack Format for PublicUserInfo
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_user_info_format() {
        let user = PublicUserInfo {
            id: Uuid::parse_str("32980b95-e467-4f28-8e50-d73033e07a2a").unwrap(),
            username: "eva".to_string(),
            display_name: "eva".to_string(),
            avatar_url: None,
            bio: None,
        };

        let bytes = rmp_serde::to_vec(&user).unwrap();
        let json = serde_json::to_string(&user).unwrap();

        // Проверяем camelCase
        assert!(json.contains("\"displayName\""));
        assert!(json.contains("\"avatarUrl\""));
        assert!(!json.contains("\"display_name\""));
        assert!(!json.contains("\"avatar_url\""));

        // UUID должен быть string в JSON
        assert!(json.contains("\"32980b95-e467-4f28-8e50-d73033e07a2a\""));

        // Декодируем из MessagePack и проверяем
        let decoded: PublicUserInfo = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded.id.to_string(), "32980b95-e467-4f28-8e50-d73033e07a2a");
        assert_eq!(decoded.username, "eva");
        assert_eq!(decoded.display_name, "eva");
    }
}
