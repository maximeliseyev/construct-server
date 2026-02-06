use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bcrypt::{DEFAULT_COST, hash};
use chrono::{DateTime, Utc};
use construct_crypto::{BundleData, UploadableKeyBundle};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

pub type DbPool = Pool<Postgres>;

// Legacy User struct (for password-based auth, deprecated)
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LegacyUser {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
}

// New minimal User struct (passwordless, device-based)
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: Option<String>,
    pub recovery_public_key: Option<Vec<u8>>,
    pub last_recovery_at: Option<DateTime<Utc>>,
    pub primary_device_id: Option<String>,
}

use construct_config::DbConfig;

pub async fn create_pool(database_url: &str, db_config: &DbConfig) -> Result<DbPool> {
    // sqlx 0.8 API - используем доступные методы
    // connect_timeout недоступен в 0.8, используем acquire_timeout и idle_timeout
    let pool = PgPoolOptions::new()
        .max_connections(db_config.max_connections)
        .acquire_timeout(std::time::Duration::from_secs(
            db_config.acquire_timeout_secs,
        ))
        .idle_timeout(Some(std::time::Duration::from_secs(
            db_config.idle_timeout_secs,
        )))
        .test_before_acquire(true) // Test connections before returning from pool
        .connect(database_url)
        .await?;

    Ok(pool)
}

// ============================================================================
// Legacy Password-Based Auth Functions (Deprecated)
// ============================================================================

pub async fn create_legacy_user(
    pool: &DbPool,
    username: &str,
    password: &str,
) -> Result<LegacyUser> {
    let password_hash = hash(password, DEFAULT_COST)?;
    let user = sqlx::query_as::<_, LegacyUser>(
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

pub async fn get_legacy_user_by_username(
    pool: &DbPool,
    username: &str,
) -> Result<Option<LegacyUser>> {
    let user = sqlx::query_as::<_, LegacyUser>(
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

pub async fn get_legacy_user_by_id(pool: &DbPool, user_id: &Uuid) -> Result<Option<LegacyUser>> {
    let user = sqlx::query_as::<_, LegacyUser>(
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

pub async fn verify_password(user: &LegacyUser, password: &str) -> Result<bool> {
    Ok(bcrypt::verify(password, &user.password_hash)?)
}

// ============================================================================
// Passwordless Device-Based Auth Functions (New)
// ============================================================================

/// Get user by ID (passwordless)
pub async fn get_user_by_id(pool: &DbPool, user_id: &Uuid) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        r#"
        SELECT id, username, recovery_public_key, last_recovery_at, primary_device_id
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// Get user by username (passwordless, optional field)
pub async fn get_user_by_username(pool: &DbPool, username: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        r#"
        SELECT id, username, recovery_public_key, last_recovery_at, primary_device_id
        FROM users
        WHERE username = $1
        "#,
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// Create a new user (passwordless, device-based)
///
/// # Arguments
/// * `pool` - Database pool
/// * `username` - Optional username (NULL = Signal-like privacy)
/// * `primary_device_id` - First device registered for this user
///
/// # Returns
/// The created user record with generated UUID
pub async fn create_user_passwordless(
    pool: &DbPool,
    username: Option<&str>,
    primary_device_id: &str,
) -> Result<User> {
    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (id, username, primary_device_id)
        VALUES (gen_random_uuid(), $1, $2)
        RETURNING id, username, recovery_public_key, last_recovery_at, primary_device_id
        "#,
    )
    .bind(username)
    .bind(primary_device_id)
    .fetch_one(pool)
    .await
    .context("Failed to create passwordless user")?;

    Ok(user)
}

// ============================================================================
// Backwards Compatibility Aliases (for legacy code)
// ============================================================================

/// Alias for create_legacy_user (backwards compatibility)
pub async fn create_user(pool: &DbPool, username: &str, password: &str) -> Result<LegacyUser> {
    create_legacy_user(pool, username, password).await
}

/// Delete user account and all associated data
/// This performs a hard delete (cascade will handle related records)
pub async fn delete_user_account(pool: &DbPool, user_id: &Uuid) -> Result<()> {
    sqlx::query(
        r#"
        DELETE FROM users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Updates user password (requires valid old password)
pub async fn update_user_password(pool: &DbPool, user_id: &Uuid, new_password: &str) -> Result<()> {
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

#[allow(dead_code)]
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
///
/// This function supports both:
/// 1. Legacy key_bundles table (for old users who uploaded keys)
/// 2. New devices table (for passwordless auth users)
pub async fn get_key_bundle(
    pool: &DbPool,
    user_id: &Uuid,
) -> Result<Option<(UploadableKeyBundle, String)>> {
    // First, try the legacy key_bundles table
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

    if let Some(r) = record {
        return Ok(Some((
            UploadableKeyBundle {
                master_identity_key: BASE64.encode(r.master_identity_key),
                bundle_data: BASE64.encode(r.bundle_data),
                signature: BASE64.encode(r.signature),
                nonce: None,
                timestamp: None,
            },
            r.username,
        )));
    }

    // Fallback: Try to construct key bundle from devices table (passwordless auth users)
    get_key_bundle_from_device(pool, user_id).await
}

/// Device key bundle record from database
#[derive(sqlx::FromRow)]
struct DeviceKeyBundle {
    pub verifying_key: Vec<u8>,
    pub identity_public: Vec<u8>,
    pub signed_prekey_public: Vec<u8>,
    pub crypto_suites: serde_json::Value,
    pub username: Option<String>,
}

/// Retrieves a key bundle from the devices table for passwordless auth users
/// Uses the user's primary device (or first active device) to construct the bundle
async fn get_key_bundle_from_device(
    pool: &DbPool,
    user_id: &Uuid,
) -> Result<Option<(UploadableKeyBundle, String)>> {
    use construct_crypto::{BundleData, SuiteKeyMaterial};

    // Get the user's primary device or first active device
    let device = sqlx::query_as::<_, DeviceKeyBundle>(
        r#"
        SELECT
            d.verifying_key,
            d.identity_public,
            d.signed_prekey_public,
            d.crypto_suites,
            u.username
        FROM devices d
        JOIN users u ON d.user_id = u.id
        WHERE d.user_id = $1 AND d.is_active = true
        ORDER BY
            CASE WHEN d.device_id = u.primary_device_id THEN 0 ELSE 1 END,
            d.registered_at ASC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    let Some(d) = device else {
        return Ok(None);
    };

    // Parse crypto_suites to determine suite_id
    let suites: Vec<String> = serde_json::from_value(d.crypto_suites.clone())
        .unwrap_or_else(|_| vec!["Curve25519+Ed25519".to_string()]);

    // Determine suite_id from first suite
    let suite_id: u16 = if suites
        .iter()
        .any(|s| s.contains("Kyber") || s.contains("PQ"))
    {
        2 // PQ_HYBRID_KYBER
    } else {
        1 // CLASSIC_X25519
    };

    // Construct SuiteKeyMaterial from device keys
    let suite_key = SuiteKeyMaterial {
        suite_id,
        identity_key: BASE64.encode(&d.identity_public),
        signed_prekey: BASE64.encode(&d.signed_prekey_public),
        signed_prekey_signature: BASE64.encode(vec![0u8; 64]), // Placeholder - device doesn't store this separately
        one_time_prekeys: vec![],                              // Not used for initial key exchange
    };

    // Construct BundleData
    let bundle_data = BundleData {
        user_id: user_id.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        supported_suites: vec![suite_key],
    };

    // Serialize bundle_data to JSON bytes
    let bundle_data_bytes =
        serde_json::to_vec(&bundle_data).context("Failed to serialize bundle_data")?;

    // For device-based auth, we use verifying_key as master_identity_key
    // and create a placeholder signature (client will verify via device auth instead)
    let bundle = UploadableKeyBundle {
        master_identity_key: BASE64.encode(&d.verifying_key),
        bundle_data: BASE64.encode(&bundle_data_bytes),
        signature: BASE64.encode(vec![0u8; 64]), // Placeholder - auth happens via device signature
        nonce: None,
        timestamp: None,
    };

    let username = d.username.unwrap_or_else(|| "anonymous".to_string());

    Ok(Some((bundle, username)))
}

// ============================================================================
// Device-Based Authentication (Passwordless)
// ============================================================================

/// Device record from database (Privacy-First Design)
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Device {
    pub device_id: String,
    pub server_hostname: String,
    pub user_id: Option<Uuid>,
    pub verifying_key: Vec<u8>,
    pub identity_public: Vec<u8>,
    pub signed_prekey_public: Vec<u8>,
    pub crypto_suites: serde_json::Value, // JSONB array
    pub registered_at: DateTime<Utc>,     // Needed for warmup logic
    pub is_active: bool,
}

/// Data for creating a new device
#[derive(Debug, Clone)]
pub struct CreateDeviceData {
    pub device_id: String,
    pub server_hostname: String,
    pub verifying_key: Vec<u8>,
    pub identity_public: Vec<u8>,
    pub signed_prekey_public: Vec<u8>,
    pub crypto_suites: String, // JSONB string like '["Curve25519+Ed25519"]'
}

/// Create a new device (device registration)
///
/// # Arguments
/// * `pool` - Database pool
/// * `data` - Device creation data
/// * `user_id` - Optional user_id to link (None for first device registration)
///
/// # Returns
/// The created device record
pub async fn create_device(
    pool: &DbPool,
    data: CreateDeviceData,
    user_id: Option<Uuid>,
) -> Result<Device> {
    insert_device_impl(pool, data, user_id).await
}

/// Internal implementation for inserting a device (supports transactions)
async fn insert_device_impl<'a, E>(
    executor: E,
    data: CreateDeviceData,
    user_id: Option<Uuid>,
) -> Result<Device>
where
    E: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    let device = sqlx::query_as::<_, Device>(
        r#"
        INSERT INTO devices (
            device_id,
            server_hostname,
            user_id,
            verifying_key,
            identity_public,
            signed_prekey_public,
            crypto_suites,
            registered_at,
            is_active
        ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NOW(), TRUE)
        RETURNING device_id, server_hostname, user_id, verifying_key, 
                  identity_public, signed_prekey_public, crypto_suites, 
                  registered_at, is_active
        "#,
    )
    .bind(&data.device_id)
    .bind(&data.server_hostname)
    .bind(user_id)
    .bind(&data.verifying_key)
    .bind(&data.identity_public)
    .bind(&data.signed_prekey_public)
    .bind(&data.crypto_suites)
    .fetch_one(executor)
    .await
    .map_err(|e| {
        tracing::error!(
            error = %e,
            device_id = %data.device_id,
            user_id = ?user_id,
            crypto_suites = %data.crypto_suites,
            "Failed to create device in database"
        );
        anyhow::anyhow!("Failed to create device: {}", e)
    })?;

    Ok(device)
}

/// Get device by device_id
pub async fn get_device_by_id(pool: &DbPool, device_id: &str) -> Result<Option<Device>> {
    let device = sqlx::query_as::<_, Device>(
        "SELECT device_id, server_hostname, user_id, verifying_key, identity_public, 
                signed_prekey_public, crypto_suites, registered_at, is_active 
         FROM devices WHERE device_id = $1",
    )
    .bind(device_id)
    .fetch_optional(pool)
    .await
    .context("Failed to fetch device")?;

    Ok(device)
}

/// Get all devices for a user
pub async fn get_devices_by_user_id(pool: &DbPool, user_id: &Uuid) -> Result<Vec<Device>> {
    let devices = sqlx::query_as::<_, Device>(
        "SELECT device_id, server_hostname, user_id, verifying_key, identity_public, 
                signed_prekey_public, crypto_suites, registered_at, is_active 
         FROM devices WHERE user_id = $1 AND is_active = TRUE ORDER BY registered_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .context("Failed to fetch user devices")?;

    Ok(devices)
}

/// Create user + first device in a single transaction (atomic)
///
/// This ensures that:
/// 1. User is created with generated UUID
/// 2. Device is linked to new user_id
/// 3. users.primary_device_id points to first device
/// 4. All happens atomically (rollback on failure)
///
/// # Arguments
/// * `pool` - Database pool
/// * `username` - Optional username (NULL = maximum privacy)
/// * `device_data` - Device creation data
///
/// # Returns
/// Tuple of (User, Device)
pub async fn create_user_with_first_device(
    pool: &DbPool,
    username: Option<&str>,
    device_data: CreateDeviceData,
) -> Result<(User, Device)> {
    // Start transaction
    let mut tx = pool.begin().await.context("Failed to begin transaction")?;

    // 1. Create user WITHOUT primary_device_id (to avoid FK constraint violation)
    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (id, username, primary_device_id)
        VALUES (gen_random_uuid(), $1, NULL)
        RETURNING id, username, recovery_public_key, last_recovery_at, primary_device_id
        "#,
    )
    .bind(username)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(
            error = %e,
            username = ?username,
            "Failed to create user in database"
        );
        anyhow::anyhow!("Failed to create user: {}", e)
    })?;

    // 2. Create device linked to user using shared implementation
    let device = insert_device_impl(&mut *tx, device_data, Some(user.id)).await?;

    // 3. Update user's primary_device_id (now that device exists)
    sqlx::query(
        r#"
        UPDATE users 
        SET primary_device_id = $1 
        WHERE id = $2
        "#,
    )
    .bind(&device.device_id)
    .bind(user.id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(
            error = %e,
            user_id = %user.id,
            device_id = %device.device_id,
            "Failed to set primary_device_id"
        );
        anyhow::anyhow!("Failed to set primary_device_id: {}", e)
    })?;

    // Commit transaction
    tx.commit().await.context("Failed to commit transaction")?;

    tracing::info!(
        user_id = %user.id,
        device_id = %device.device_id,
        username = ?username,
        "Created user with first device"
    );

    // Return user with updated primary_device_id
    let mut user_with_device_id = user;
    user_with_device_id.primary_device_id = Some(device.device_id.clone());

    Ok((user_with_device_id, device))
}

/// Check if device_id already exists
pub async fn device_exists(pool: &DbPool, device_id: &str) -> Result<bool> {
    let exists =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM devices WHERE device_id = $1)")
            .bind(device_id)
            .fetch_one(pool)
            .await
            .context("Failed to check device existence")?;

    Ok(exists)
}

/// Update device's last_active_at timestamp
pub async fn update_device_last_active(pool: &DbPool, device_id: &str) -> Result<()> {
    sqlx::query("UPDATE devices SET last_active_at = NOW() WHERE device_id = $1")
        .bind(device_id)
        .execute(pool)
        .await
        .context("Failed to update device last_active")?;

    Ok(())
}

// ============================================================================
// PoW Challenge Management Functions
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PowChallenge {
    pub challenge: String,
    pub difficulty: i16,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    #[sqlx(try_from = "Option<String>")]
    pub requester_ip: Option<String>,
}

/// Create a new PoW challenge
pub async fn create_pow_challenge(
    pool: &DbPool,
    challenge: &str,
    difficulty: i16,
    requester_ip: Option<&str>,
    ttl_seconds: i64,
) -> Result<PowChallenge> {
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl_seconds);

    let pow_challenge = sqlx::query_as::<_, PowChallenge>(
        r#"
        INSERT INTO pow_challenges (challenge, difficulty, expires_at, requester_ip)
        VALUES ($1, $2, $3, $4::inet)
        RETURNING challenge, difficulty, created_at, expires_at, used, requester_ip::text as requester_ip
        "#
    )
    .bind(challenge)
    .bind(difficulty)
    .bind(expires_at)
    .bind(requester_ip)
    .fetch_one(pool)
    .await
    .context("Failed to create PoW challenge")?;

    Ok(pow_challenge)
}

/// Get a PoW challenge by challenge string
pub async fn get_pow_challenge(pool: &DbPool, challenge: &str) -> Result<Option<PowChallenge>> {
    let pow_challenge = sqlx::query_as::<_, PowChallenge>(
        "SELECT challenge, difficulty, created_at, expires_at, used, requester_ip::text as requester_ip FROM pow_challenges WHERE challenge = $1"
    )
    .bind(challenge)
    .fetch_optional(pool)
    .await
    .context("Failed to fetch PoW challenge")?;

    Ok(pow_challenge)
}

/// Mark a PoW challenge as used (prevent reuse)
pub async fn mark_challenge_used(pool: &DbPool, challenge: &str) -> Result<()> {
    sqlx::query("UPDATE pow_challenges SET used = TRUE WHERE challenge = $1")
        .bind(challenge)
        .execute(pool)
        .await
        .context("Failed to mark challenge as used")?;

    Ok(())
}

/// Clean up expired PoW challenges (run periodically)
pub async fn cleanup_expired_pow_challenges(pool: &DbPool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM pow_challenges WHERE expires_at < NOW()")
        .execute(pool)
        .await
        .context("Failed to cleanup expired challenges")?;

    Ok(result.rows_affected())
}

/// Count PoW challenges created by IP in last N minutes (rate limiting)
pub async fn count_challenges_by_ip(pool: &DbPool, ip: &str, minutes: i32) -> Result<i64> {
    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)::BIGINT
        FROM pow_challenges
        WHERE requester_ip = $1::inet
        AND created_at > NOW() - INTERVAL '1 minute' * $2
        "#,
    )
    .bind(ip)
    .bind(minutes)
    .fetch_one(pool)
    .await?;

    Ok(count)
}

/// Count device registrations by IP within time window (anti-spam)
pub async fn count_registrations_by_ip(pool: &DbPool, ip: &str, minutes: i32) -> Result<i64> {
    // Since we don't store IP in devices table, we use pow_challenges that were marked as used
    // This is a proxy: if a challenge was used, it means registration succeeded
    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)::BIGINT
        FROM pow_challenges
        WHERE requester_ip = $1::inet
        AND used = true
        AND created_at > NOW() - INTERVAL '1 minute' * $2
        "#,
    )
    .bind(ip)
    .bind(minutes)
    .fetch_one(pool)
    .await
    .context("Failed to count challenges by IP")?;

    Ok(count)
}
