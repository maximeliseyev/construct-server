use crate::e2e::StoredKeyBundle;
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
    pub password_hash: String,
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

pub async fn create_user(pool: &DbPool, username: &str, password: &str) -> Result<User> {
    let password_hash = hash(password, DEFAULT_COST)?;
    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (username, password_hash)
        VALUES ($1, $2)
        RETURNING id, username, password_hash           "#,
    )
    .bind(username)
    .bind(password_hash)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

pub async fn get_user_by_username(pool: &DbPool, username: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        r#"
        -- CREATE INDEX idx_users_username ON users(username);
        SELECT id, username, password_hash
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
        SELECT id, username, password_hash
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(user)
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

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct PublicUser {
    #[serde(with = "uuid_as_string")]
    pub id: Uuid,
    pub username: String,
}

pub async fn search_users_by_username(
    pool: &DbPool,
    query: &str,
) -> Result<Vec<PublicUser>> {
    let users = sqlx::query_as::<_, PublicUser>(
        r#"
        SELECT id, username
        FROM users
        WHERE username ILIKE $1
        LIMIT 10
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
