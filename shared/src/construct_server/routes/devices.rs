// ============================================================================
// Device Registration Routes - Passwordless Authentication
// ============================================================================
//
// Endpoints:
// - POST /api/v1/register/v2 - Register new device (passwordless)
// - GET /api/v1/users/:device_id/profile - Get device profile (public)
// - PATCH /api/v1/users/me/profile - Update own profile
//
// Security:
// - PoW validation (TODO: add later to prevent bots)
// - Rate limiting per IP
// - Unique device_id enforcement
//
// ============================================================================

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};

use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::context::AppContext;
use crate::db::{self, CreateDeviceData};
use construct_error::AppError;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Public keys for device registration
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePublicKeys {
    /// Ed25519 verifying key for request signature verification (base64, 32 bytes)
    pub verifying_key: String,

    /// Identity public key for E2EE (base64, varies by suite)
    pub identity_public: String,

    /// Signed prekey public for Double Ratchet (base64)
    pub signed_prekey_public: String,

    /// Crypto suite identifier (e.g., "Curve25519+Ed25519", "ML-KEM-768+Ed25519")
    #[serde(default = "default_suite_id")]
    pub suite_id: String,
}

fn default_suite_id() -> String {
    "Curve25519+Ed25519".to_string()
}

/// Request to register a new device
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceRequest {
    /// Username (display name, NOT unique)
    pub username: String,

    /// Device ID (client-computed: SHA256(identity_public)[0..16])
    pub device_id: String,

    /// Public keys for authentication and E2EE
    pub public_keys: DevicePublicKeys,

    /// Platform info (optional)
    pub platform: Option<String>,

    /// Device name (optional, e.g., "iPhone 15 Pro")
    pub device_name: Option<String>,

    /// Display name (optional, full name)
    pub display_name: Option<String>,

    /// Proof of Work solution
    pub pow_solution: PowSolution,
}

/// Proof of Work solution
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PowSolution {
    /// Original challenge from GET /challenge
    pub challenge: String,

    /// Nonce that solves the puzzle
    pub nonce: u64,

    /// Argon2id hash (hex-encoded)
    pub hash: String,
}

/// Response for successful device registration
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceResponse {
    pub success: bool,
    pub device_id: String,
    pub server: String,
    pub federated_id: String, // device_id@server
    pub registered_at: String,
}

/// Public profile response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceProfileResponse {
    pub device_id: String,
    pub server: String,
    pub registered_at: String,

    // Public keys for establishing E2EE
    pub public_keys: DevicePublicKeys,
}

/// Request to update user profile
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProfileRequest {
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub bio: Option<String>,
}

// ============================================================================
// Registration Endpoint
// ============================================================================

/// POST /api/v1/register/v2
///
/// Register a new device with passwordless authentication.
///
/// Security:
/// - Validates device_id format (16 hex chars)
/// - Checks device_id uniqueness
/// - Validates public keys (base64, correct lengths)
/// - TODO: PoW validation to prevent bots
/// - Rate limiting: 1 registration per IP per 10 minutes
pub async fn register_device_v2(
    State(app_context): State<Arc<AppContext>>,
    Json(request): Json<RegisterDeviceRequest>,
) -> Result<impl IntoResponse, AppError> {
    let client_ip = "127.0.0.1".to_string();

    tracing::info!(
        device_id = %request.device_id,
        username = %request.username,
        client_ip = %client_ip,
        "Device registration attempt"
    );

    // 1. Validate device_id format (16 lowercase hex characters)
    if request.device_id.len() != 16 {
        return Err(AppError::Validation(
            "device_id must be exactly 16 characters".to_string(),
        ));
    }

    if !request.device_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::Validation(
            "device_id must be hex characters (0-9a-f)".to_string(),
        ));
    }

    if request.device_id.to_lowercase() != request.device_id {
        return Err(AppError::Validation(
            "device_id must be lowercase".to_string(),
        ));
    }

    // 2. Validate username (3-20 chars, alphanumeric + underscore)
    if request.username.len() < 3 || request.username.len() > 20 {
        return Err(AppError::Validation(
            "username must be 3-20 characters".to_string(),
        ));
    }

    if !request
        .username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_')
    {
        return Err(AppError::Validation(
            "username can only contain letters, numbers, and underscores".to_string(),
        ));
    }

    // 3. Decode and validate public keys
    let verifying_key = BASE64
        .decode(&request.public_keys.verifying_key)
        .map_err(|_| AppError::Validation("verifying_key must be valid base64".to_string()))?;

    if verifying_key.len() != 32 {
        return Err(AppError::Validation(
            "verifying_key must be exactly 32 bytes (Ed25519)".to_string(),
        ));
    }

    let identity_public = BASE64
        .decode(&request.public_keys.identity_public)
        .map_err(|_| AppError::Validation("identity_public must be valid base64".to_string()))?;

    let signed_prekey_public = BASE64
        .decode(&request.public_keys.signed_prekey_public)
        .map_err(|_| {
            AppError::Validation("signed_prekey_public must be valid base64".to_string())
        })?;

    // 4. Verify device_id matches identity_public (SHA256 first 16 bytes)
    let computed_device_id = {
        let hash = Sha256::digest(&identity_public);
        hex::encode(&hash[0..8]) // First 8 bytes = 16 hex chars
    };

    if computed_device_id != request.device_id {
        tracing::warn!(
            provided = %request.device_id,
            computed = %computed_device_id,
            "device_id mismatch with identity_public"
        );
        return Err(AppError::Validation(
            "device_id must be SHA256(identity_public)[0..16]".to_string(),
        ));
    }

    // 5. Check if device_id already exists
    if db::device_exists(&app_context.db_pool, &request.device_id)
        .await
        .unwrap_or(false)
    {
        tracing::warn!(
            device_id = %request.device_id,
            "Attempted to register existing device_id"
        );
        return Err(AppError::Validation(
            "Device already registered".to_string(),
        ));
    }

    // 6. Verify PoW solution
    let pow_challenge =
        crate::db::get_pow_challenge(&app_context.db_pool, &request.pow_solution.challenge)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to fetch PoW challenge: {}", e)))?
            .ok_or_else(|| AppError::Validation("Invalid or expired PoW challenge".to_string()))?;

    // Check challenge not expired
    if pow_challenge.expires_at < chrono::Utc::now() {
        return Err(AppError::Validation("PoW challenge expired".to_string()));
    }

    // Check challenge not already used
    if pow_challenge.used {
        return Err(AppError::Validation(
            "PoW challenge already used".to_string(),
        ));
    }

    // Verify PoW solution
    if !crate::pow::verify_pow_solution(
        &request.pow_solution.challenge,
        request.pow_solution.nonce,
        &request.pow_solution.hash,
        pow_challenge.difficulty as u32,
    ) {
        tracing::warn!(
            device_id = %request.device_id,
            challenge = %request.pow_solution.challenge,
            nonce = %request.pow_solution.nonce,
            "Invalid PoW solution"
        );
        return Err(AppError::Validation("Invalid PoW solution".to_string()));
    }

    // Mark challenge as used (prevent reuse)
    crate::db::mark_challenge_used(&app_context.db_pool, &request.pow_solution.challenge)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to mark challenge as used: {}", e)))?;

    // 7. Create user + device atomically
    let server_hostname = "localhost:8080".to_string(); // TODO: Add server_hostname to Config

    let device_data = CreateDeviceData {
        device_id: request.device_id.clone(),
        server_hostname: server_hostname.clone(),
        verifying_key,
        identity_public,
        signed_prekey_public,
        suite_id: request.public_keys.suite_id.clone(),
        platform: request.platform,
        device_name: request.device_name,
    };

    // Convert username to Option<&str> for database
    // Empty string becomes None (maximum privacy)
    let username_opt = if request.username.is_empty() {
        None
    } else {
        Some(request.username.as_str())
    };

    let (user, device) =
        db::create_user_with_first_device(&app_context.db_pool, username_opt, device_data)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to create user with device");
                AppError::Unknown(e)
            })?;

    tracing::info!(
        user_id = %user.id,
        device_id = %device.device_id,
        username = ?user.username,
        "User + device registered successfully (passwordless)"
    );

    // 8. Return success response
    let federated_id = format!("{}@{}", device.device_id, server_hostname);

    Ok((
        StatusCode::CREATED,
        Json(RegisterDeviceResponse {
            success: true,
            device_id: device.device_id,
            server: server_hostname,
            federated_id,
            registered_at: device.registered_at.to_rfc3339(),
        }),
    ))
}

// ============================================================================
// Profile Endpoints
// ============================================================================

/// GET /api/v1/users/:device_id/profile
///
/// Get public profile for a device.
///
/// This is a PUBLIC endpoint - no authentication required.
/// Used for looking up users before starting a chat.
pub async fn get_device_profile(
    State(app_context): State<Arc<AppContext>>,
    Path(device_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    // Fetch device from database
    let device = db::get_device_by_id(&app_context.db_pool, &device_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to fetch device");
            AppError::Unknown(e)
        })?
        .ok_or_else(|| AppError::NotFound("Device not found".to_string()))?;

    let server_hostname = "localhost:8080".to_string();

    // Return public profile
    Ok(Json(DeviceProfileResponse {
        device_id: device.device_id,
        server: server_hostname,
        registered_at: device.registered_at.to_rfc3339(),
        public_keys: DevicePublicKeys {
            verifying_key: BASE64.encode(&device.verifying_key),
            identity_public: BASE64.encode(&device.identity_public),
            signed_prekey_public: BASE64.encode(&device.signed_prekey_public),
            suite_id: device.suite_id,
        },
    }))
}

// ============================================================================
// TODO: Add authenticated endpoints
// ============================================================================
// - PATCH /api/v1/users/me/profile - Update profile
// - GET /api/v1/users/me/devices - List user's devices
// - PATCH /api/v1/users/me/devices/:device_id/public-key - Update keys
//
// These will require DeviceAuth extractor (X-Device-ID, X-Signature headers)

// ============================================================================
// PoW Challenge Endpoint
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub challenge: String,
    pub difficulty: u32,
    pub expires_at: i64, // Unix timestamp
}

/// GET /api/v1/register/challenge
///
/// Generate a PoW challenge for registration
///
/// Rate limiting: 5 challenges per hour per IP
pub async fn get_pow_challenge(
    State(app_context): State<Arc<AppContext>>,
) -> Result<Json<ChallengeResponse>, AppError> {
    let client_ip = "127.0.0.1".to_string(); // TODO: Extract from headers

    // 1. Check rate limiting (5 challenges per hour)
    let count = crate::db::count_challenges_by_ip(&app_context.db_pool, &client_ip, 60)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to check rate limit: {}", e)))?;

    if count >= 5 {
        return Err(AppError::Validation(
            "Rate limit exceeded: max 5 challenges per hour".to_string(),
        ));
    }

    // 2. Determine difficulty (normal = 8, could be dynamic)
    let difficulty = crate::pow::POW_DIFFICULTY_NORMAL;

    // 3. Generate challenge
    let challenge = crate::pow::generate_challenge();

    // 4. Store challenge in DB with 10-minute TTL
    let ttl_seconds = 600; // 10 minutes
    let pow_challenge = crate::db::create_pow_challenge(
        &app_context.db_pool,
        &challenge,
        difficulty as i16,
        Some(&client_ip),
        ttl_seconds,
    )
    .await
    .map_err(|e| AppError::Internal(format!("Failed to create challenge: {}", e)))?;

    tracing::info!(
        challenge = %challenge,
        difficulty = %difficulty,
        client_ip = %client_ip,
        "PoW challenge generated"
    );

    // 5. Return challenge
    Ok(Json(ChallengeResponse {
        challenge,
        difficulty,
        expires_at: pow_challenge.expires_at.timestamp(),
    }))
}
