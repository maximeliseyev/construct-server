use crate::e2e::{BundleData, UploadableKeyBundle};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bcrypt::{DEFAULT_COST, hash};
use chrono::{DateTime, Utc};
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

pub async fn search_users_by_username(pool: &DbPool, query: &str) -> Result<Vec<PublicUser>> {
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

/// Updates user password (requires valid old password)
pub async fn update_user_password(
    pool: &DbPool,
    user_id: &Uuid,
    new_password: &str,
) -> Result<()> {
    let new_password_hash = hash(new_password, DEFAULT_COST)?;

    sqlx::query(
        r#"
        UPDATE users
        SET password_hash = $1
        WHERE id = $2
        "#,
    )
    .bind(new_password_hash)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Key Bundle Functions for Crypto-Agility
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
struct KeyBundleRecord {
    pub user_id: Uuid,
    pub master_identity_key: Vec<u8>,
    pub bundle_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub registered_at: DateTime<Utc>,
}

/// Stores a key bundle in the crypto-agile format
pub async fn store_key_bundle(
    pool: &DbPool,
    user_id: &Uuid,
    bundle: &UploadableKeyBundle,
) -> Result<()> {
    // Decode base64 strings to Vec<u8> for storage
    let master_identity_key = BASE64
        .decode(&bundle.master_identity_key)
        .context("Failed to decode master_identity_key from base64")?;

    let bundle_data_bytes = BASE64
        .decode(&bundle.bundle_data)
        .context("Failed to decode bundle_data from base64")?;

    let signature = BASE64
        .decode(&bundle.signature)
        .context("Failed to decode signature from base64")?;

    // Verify that bundle_data contains valid JSON and extract the user_id
    let bundle_data: BundleData = serde_json::from_slice(&bundle_data_bytes)
        .context("Failed to parse bundle_data as JSON")?;

    // Security check: ensure the user_id in bundle_data matches the authenticated user
    if bundle_data.user_id != user_id.to_string() {
        return Err(anyhow::anyhow!(
            "User ID mismatch: bundle contains '{}' but user is '{}'",
            bundle_data.user_id,
            user_id
        ));
    }

    sqlx::query(
        r#"
        INSERT INTO key_bundles (user_id, master_identity_key, bundle_data, signature, registered_at, updated_at)
        VALUES ($1, $2, $3, $4, NOW(), NOW())
        ON CONFLICT (user_id) DO UPDATE SET
            bundle_data = EXCLUDED.bundle_data,
            signature = EXCLUDED.signature,
            updated_at = NOW()
        "#,
    )
    .bind(user_id)
    .bind(master_identity_key)
    .bind(bundle_data_bytes)
    .bind(signature)
    .execute(pool)
    .await?;

    Ok(())
}

// Record for key bundle with username
#[derive(sqlx::FromRow)]
struct KeyBundleWithUsername {
    pub master_identity_key: Vec<u8>,
    pub bundle_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub username: String,
}

/// Retrieves a key bundle in the crypto-agile format along with username
/// Returns (bundle, username) tuple
pub async fn get_key_bundle(
    pool: &DbPool,
    user_id: &Uuid,
) -> Result<Option<(UploadableKeyBundle, String)>> {
    let record = sqlx::query_as::<_, KeyBundleWithUsername>(
        r#"
        SELECT
            kb.master_identity_key,
            kb.bundle_data,
            kb.signature,
            u.username
        FROM key_bundles kb
        JOIN users u ON kb.user_id = u.id
        WHERE kb.user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(record.map(|r| (
        UploadableKeyBundle {
            master_identity_key: BASE64.encode(r.master_identity_key),
            bundle_data: BASE64.encode(r.bundle_data),
            signature: BASE64.encode(r.signature),
        },
        r.username
    )))
}
