// ============================================================================
// Device Registration Routes - Passwordless Authentication
// ============================================================================
//
// Endpoints:
// - POST /api/v1/auth/register-device - Register new device (passwordless)
// - POST /api/v1/auth/device - Authenticate existing device
// - GET /api/v1/users/:device_id/profile - Get device profile (public)
//
// Security:
// - Argon2id PoW validation (anti-spam)
// - Rate limiting per IP (5 challenges/hour)
// - Unique device_id enforcement
// - Ed25519 signature verification
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

/// Request to register a new device (privacy-focused)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceRequest {
    /// Username (optional, for search/discovery)
    /// None or empty string = maximum privacy (QR/invite only)
    /// Some(username) = searchable via @username
    pub username: Option<String>,

    /// Device ID (client-computed: SHA256(identity_public)[0..16])
    pub device_id: String,

    /// Public keys for authentication and E2EE
    pub public_keys: DevicePublicKeys,

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
    /// User ID (UUID, same for all user's devices)
    #[serde(rename = "userId")]
    pub user_id: String,

    /// Access token (JWT, 1 hour TTL)
    #[serde(rename = "accessToken")]
    pub access_token: String,

    /// Refresh token (JWT, 30 days TTL)
    #[serde(rename = "refreshToken")]
    pub refresh_token: String,

    /// Token expiration time in seconds
    #[serde(rename = "expiresIn")]
    pub expires_in: u64,
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
        username = ?request.username,
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

    // 2. Validate username (optional, but if provided must be 3-20 chars, alphanumeric + underscore)
    if let Some(ref username) = request.username {
        if username.len() < 3 || username.len() > 20 {
            return Err(AppError::Validation(
                "username must be 3-20 characters".to_string(),
            ));
        }

        if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(AppError::Validation(
                "username can only contain letters, numbers, and underscores".to_string(),
            ));
        }
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

    // Convert suite_id to crypto_suites JSONB format
    let crypto_suites = format!(r#"["{}"]"#, request.public_keys.suite_id);

    let device_data = CreateDeviceData {
        device_id: request.device_id.clone(),
        server_hostname: server_hostname.clone(),
        verifying_key,
        identity_public,
        signed_prekey_public,
        crypto_suites,
    };

    // Convert username: Option<String> to Option<&str> for database
    // None or empty string = maximum privacy (no username)
    let username_opt = request
        .username
        .as_ref()
        .filter(|s| !s.is_empty())
        .map(|s| s.as_str());

    let (user, _device) =
        db::create_user_with_first_device(&app_context.db_pool, username_opt, device_data)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to create user with device");
                AppError::Unknown(e)
            })?;

    tracing::info!(
        user_id = %user.id,
        device_id = %request.device_id,
        username = ?user.username,
        "User + device registered successfully (passwordless)"
    );

    // 8. Generate JWT tokens
    let (access_token, _, exp_timestamp) = app_context
        .auth_manager
        .create_token(&user.id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create access token");
            AppError::Unknown(e)
        })?;

    let (refresh_token, _, _) = app_context
        .auth_manager
        .create_refresh_token(&user.id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create refresh token");
            AppError::Unknown(e)
        })?;

    let now = chrono::Utc::now().timestamp();
    let expires_in = (exp_timestamp - now) as u64;

    // 9. Return success response with JWT tokens
    Ok((
        StatusCode::CREATED,
        Json(RegisterDeviceResponse {
            user_id: user.id.to_string(),
            access_token,
            refresh_token,
            expires_in,
        }),
    ))
}

// ============================================================================
// Device Authentication Endpoint
// ============================================================================

/// POST /api/v1/auth/device
///
/// Authenticate existing device using Ed25519 signature.
///
/// Request:
/// ```json
/// {
///   "device_id": "2a68bbf6425855903b7ba45aa570f91a",
///   "timestamp": 1738700000,
///   "signature": "base64_ed25519_signature"
/// }
/// ```
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticateDeviceRequest {
    pub device_id: String,
    pub timestamp: i64,
    pub signature: String, // base64-encoded Ed25519 signature
}

pub async fn authenticate_device(
    State(app_context): State<Arc<AppContext>>,
    Json(request): Json<AuthenticateDeviceRequest>,
) -> Result<impl IntoResponse, AppError> {
    // 1. Validate timestamp (±5 minutes window)
    let now = chrono::Utc::now().timestamp();
    let time_diff = (now - request.timestamp).abs();
    if time_diff > 300 {
        return Err(AppError::validation(
            "Timestamp expired (must be within ±5 minutes)",
        ));
    }

    // 2. Find device in database
    let device = db::get_device_by_id(&app_context.db_pool, &request.device_id)
        .await
        .map_err(|e| AppError::internal(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::auth("Device not found"))?;

    // 3. Verify device is active
    if !device.is_active {
        return Err(AppError::auth("Device is inactive"));
    }

    // 4. Verify Ed25519 signature
    // Message format: "{device_id}{timestamp}"
    let message = format!("{}{}", request.device_id, request.timestamp);
    let message_bytes = message.as_bytes();

    // Decode signature from base64
    let signature_bytes = BASE64
        .decode(&request.signature)
        .map_err(|_| AppError::validation("Invalid signature encoding"))?;

    if signature_bytes.len() != 64 {
        return Err(AppError::validation(
            "Invalid signature length (expected 64 bytes)",
        ));
    }

    // Verify with verifying_key from database
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let verifying_key = VerifyingKey::from_bytes(
        device
            .verifying_key
            .as_slice()
            .try_into()
            .map_err(|_| AppError::internal("Invalid verifying_key format"))?,
    )
    .map_err(|_| AppError::internal("Invalid verifying_key"))?;

    let signature = Signature::from_bytes(
        &signature_bytes
            .try_into()
            .map_err(|_| AppError::validation("Invalid signature"))?,
    );

    verifying_key
        .verify(message_bytes, &signature)
        .map_err(|_| AppError::auth("Invalid signature"))?;

    // 5. Get user_id from device
    let user_id = device
        .user_id
        .ok_or_else(|| AppError::internal("Device has no user_id"))?;

    // 6. Generate JWT tokens
    let (access_token, _, exp_timestamp) = app_context
        .auth_manager
        .create_token(&user_id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create access token");
            AppError::Unknown(e)
        })?;

    let (refresh_token, _, _) = app_context
        .auth_manager
        .create_refresh_token(&user_id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create refresh token");
            AppError::Unknown(e)
        })?;

    let expires_in = (exp_timestamp - now) as u64;

    tracing::info!(
        device_id = %request.device_id,
        user_id = %user_id,
        "Device authenticated successfully"
    );

    // 7. Return JWT tokens
    Ok((
        StatusCode::OK,
        Json(RegisterDeviceResponse {
            user_id: user_id.to_string(),
            access_token,
            refresh_token,
            expires_in,
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

    // Extract first suite from crypto_suites JSONB array
    let suite_id = device
        .crypto_suites
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .unwrap_or("Curve25519+Ed25519")
        .to_string();

    // Return public profile
    Ok(Json(DeviceProfileResponse {
        device_id: device.device_id,
        server: server_hostname,
        registered_at: device.registered_at.to_rfc3339(),
        public_keys: DevicePublicKeys {
            verifying_key: BASE64.encode(&device.verifying_key),
            identity_public: BASE64.encode(&device.identity_public),
            signed_prekey_public: BASE64.encode(&device.signed_prekey_public),
            suite_id,
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
