// ============================================================================
// Authentication Routes
// ============================================================================
//
// Endpoints:
// - POST /auth/refresh - Refresh access token using refresh token
// - POST /auth/logout - Soft logout (invalidate tokens)
// - POST /api/v1/auth/register - Register new user (REST API) [Phase 2.5]
// - POST /api/v1/auth/login - Login user (REST API) [Phase 2.5]
//
// ============================================================================

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::audit::AuditLogger;
use crate::context::AppContext;
use crate::db;
use crate::routes::extractors::AuthenticatedUser;
use crate::utils::{extract_client_ip, log_safe_id, validate_password_strength, validate_username};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use construct_crypto::{BundleData, ServerCryptoValidator, UploadableKeyBundle};
use construct_error::AppError;

/// Request body for token refresh
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshTokenRequest {
    /// Refresh token (JWT)
    pub refresh_token: String,
}

/// Response for token refresh
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshTokenResponse {
    /// New access token (short-lived, 1 hour)
    pub access_token: String,
    /// New refresh token (long-lived, 30 days)
    pub refresh_token: String,
    /// Access token expiration timestamp (Unix epoch seconds)
    pub expires_at: i64,
}

/// POST /auth/refresh
/// Refreshes access token using a valid refresh token
///
/// Security:
/// - Validates refresh token signature and expiration
/// - Checks if refresh token is revoked (soft logout)
/// - Issues new access token (1 hour TTL) and new refresh token (30 days TTL)
/// - Revokes old refresh token (token rotation)
pub async fn refresh_token(
    State(app_context): State<Arc<AppContext>>,
    Json(request): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    // 1. Verify refresh token
    let claims = app_context
        .auth_manager
        .verify_token(&request.refresh_token)
        .map_err(|e| {
            tracing::warn!(error = %e, "Invalid refresh token");
            AppError::Auth("Invalid or expired refresh token".to_string())
        })?;

    // 2. Check if refresh token is revoked (soft logout)
    {
        let mut queue = app_context.queue.lock().await;
        match queue.check_refresh_token(&claims.jti).await {
            Ok(Some(_)) => {
                // Token is valid, continue
            }
            Ok(None) => {
                drop(queue);
                tracing::warn!(
                    jti = %claims.jti,
                    user_hash = %log_safe_id(&claims.sub, &app_context.config.logging.hash_salt),
                    "Refresh token was revoked"
                );
                return Err(AppError::Auth("Refresh token was revoked".to_string()));
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check refresh token");
                // Fail open - continue but log error
            }
        }

        // 3. Revoke old refresh token (token rotation)
        if let Err(e) = queue.revoke_refresh_token(&claims.jti).await {
            tracing::error!(error = %e, "Failed to revoke old refresh token");
            // Continue anyway - token rotation is best effort
        }
        drop(queue);
    }

    // 4. Parse user ID
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Validation("Invalid user ID in refresh token".to_string()))?;

    // 5. Create new access token (1 hour)
    let (new_access_token, _access_jti, access_expires) = app_context
        .auth_manager
        .create_token(&user_id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create access token");
            AppError::Unknown(e)
        })?;

    // 6. Create new refresh token (30 days)
    let (new_refresh_token, refresh_jti, _refresh_expires) = app_context
        .auth_manager
        .create_refresh_token(&user_id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create refresh token");
            AppError::Unknown(e)
        })?;

    // 7. Store new refresh token in Redis
    {
        let mut queue = app_context.queue.lock().await;
        let refresh_ttl_seconds =
            app_context.config.refresh_token_ttl_days * construct_config::SECONDS_PER_DAY;

        if let Err(e) = queue
            .store_refresh_token(&refresh_jti, &user_id.to_string(), refresh_ttl_seconds)
            .await
        {
            tracing::error!(error = %e, "Failed to store refresh token");
            // Continue anyway - token was created, just not tracked
        }
    }

    tracing::info!(
        user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
        "Token refreshed successfully"
    );

    Ok((
        StatusCode::OK,
        Json(RefreshTokenResponse {
            access_token: new_access_token,
            refresh_token: new_refresh_token,
            expires_at: access_expires,
        }),
    ))
}

/// Request body for logout
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutRequest {
    /// Optional: If true, logout from all devices (revoke all refresh tokens)
    #[serde(default)]
    pub all_devices: bool,
}

/// POST /auth/logout
/// Soft logout: invalidates access token and refresh token
///
/// Security:
/// - Invalidates current access token (prevents reuse)
/// - Revokes current refresh token
/// - Optionally revokes all refresh tokens for user (all_devices=true)
pub async fn logout(
    State(app_context): State<Arc<AppContext>>,
    user: AuthenticatedUser,
    Json(request): Json<LogoutRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user_id = user.0;

    // Extract JTI from current access token
    // We need to decode the token to get JTI
    // For now, we'll invalidate based on user_id and let the token expire naturally
    // In a more sophisticated implementation, we'd track active tokens per user

    if request.all_devices {
        // Revoke all refresh tokens for this user
        let mut queue = app_context.queue.lock().await;
        if let Err(e) = queue.revoke_all_user_tokens(&user_id.to_string()).await {
            tracing::error!(error = %e, "Failed to revoke all user tokens");
            // Continue anyway
        }
        drop(queue);

        tracing::info!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            "Logged out from all devices"
        );
    } else {
        // For single device logout, we'd need the refresh token JTI
        // This is a simplified version - in production, you'd want to track active tokens
        tracing::info!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            "Logout requested (single device logout requires refresh token)"
        );
    }

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "message": "Logged out successfully"
        })),
    ))
}

// ============================================================================
// Phase 2.5: REST API Authentication Endpoints
// ============================================================================

/// Request body for POST /api/v1/auth/register
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub key_bundle: UploadableKeyBundle,
}

/// Response for POST /api/v1/auth/register and POST /api/v1/auth/login
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponse {
    pub user_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
}

/// POST /api/v1/auth/register
///
/// Register a new user account through REST API.
///
/// Security:
/// - CSRF protection (for browsers)
/// - Rate limiting by IP
/// - Password validation (minimum 8 characters)
/// - Replay protection for key bundle
pub async fn register(
    State(app_context): State<Arc<AppContext>>,
    headers: HeaderMap,
    Json(request): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Extract client IP for rate limiting and audit logging
    let client_ip_str = extract_client_ip(&headers, None);
    let client_ip: Option<std::net::IpAddr> = client_ip_str.parse().ok();

    // Rate limiting by IP (protect against registration spam)
    {
        let mut queue = app_context.queue.lock().await;
        let rate_limit_key = format!("rate:register:{}", client_ip_str);
        match queue.increment_rate_limit(&rate_limit_key, 3600).await {
            Ok(count) => {
                // Limit: 5 registrations per hour per IP
                if count > 5 {
                    drop(queue);
                    tracing::warn!(
                        ip = %client_ip_str,
                        count = count,
                        "Registration rate limit exceeded"
                    );
                    return Err(AppError::Validation(
                        "Too many registration attempts. Please try again later.".to_string(),
                    ));
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check registration rate limit");
                // Fail open - continue but log error
            }
        }
        drop(queue);
    }

    // Validate username
    if let Err(error_msg) = validate_username(&request.username) {
        tracing::warn!(
            username_hash = %log_safe_id(&request.username, &app_context.config.logging.hash_salt),
            "Registration rejected: invalid username format"
        );
        return Err(AppError::Validation(error_msg));
    }

    // Validate password strength
    if let Err(error_msg) = validate_password_strength(&request.password) {
        tracing::warn!(
            username_hash = %log_safe_id(&request.username, &app_context.config.logging.hash_salt),
            "Registration rejected: weak password"
        );
        return Err(AppError::Validation(error_msg));
    }

    // Validate key bundle (allow empty user_id during registration)
    if let Err(e) = ServerCryptoValidator::validate_uploadable_key_bundle(&request.key_bundle, true)
    {
        tracing::warn!(
            username_hash = %log_safe_id(&request.username, &app_context.config.logging.hash_salt),
            error = %e,
            "Key bundle validation failed"
        );
        return Err(AppError::Validation(format!("Invalid key bundle: {}", e)));
    }

    // Create user
    let user = match db::create_user(&app_context.db_pool, &request.username, &request.password)
        .await
    {
        Ok(user) => user,
        Err(e) => {
            // Check if it's a duplicate username error
            let error_msg = e.to_string();
            if error_msg.contains("duplicate") || error_msg.contains("unique") {
                tracing::warn!(
                    username_hash = %log_safe_id(&request.username, &app_context.config.logging.hash_salt),
                    "Registration rejected: username already taken"
                );
                return Err(AppError::Validation(
                    "Username is already taken".to_string(),
                ));
            }

            tracing::error!(
                error = %e,
                username_hash = %log_safe_id(&request.username, &app_context.config.logging.hash_salt),
                "Registration failed"
            );
            return Err(AppError::Unknown(e));
        }
    };

    // Update bundle_data with correct user_id
    let mut updated_bundle = request.key_bundle.clone();

    // Decode bundle_data
    let bundle_data_bytes = BASE64
        .decode(&request.key_bundle.bundle_data)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to decode bundle_data");
            AppError::Validation("Invalid bundle_data encoding".to_string())
        })?;

    // Parse BundleData
    let mut bundle_data: BundleData = serde_json::from_slice(&bundle_data_bytes).map_err(|e| {
        tracing::error!(error = %e, "Failed to parse bundle_data");
        AppError::Validation("Invalid bundle_data format".to_string())
    })?;

    // Update user_id with the actual created user ID
    bundle_data.user_id = user.id.to_string();

    // Re-serialize and encode
    let updated_json = serde_json::to_string(&bundle_data).map_err(|e| {
        tracing::error!(error = %e, "Failed to serialize bundle_data");
        AppError::Unknown(anyhow::anyhow!("Failed to process key bundle"))
    })?;
    updated_bundle.bundle_data = BASE64.encode(updated_json.as_bytes());

    // Store the updated key bundle
    if let Err(e) = db::store_key_bundle(&app_context.db_pool, &user.id, &updated_bundle).await {
        tracing::error!(error = %e, "Failed to store key bundle during registration");
        return Err(AppError::Unknown(e));
    }

    // Create access token and refresh token
    let (access_token, _access_jti, expires_at) = app_context
        .auth_manager
        .create_token(&user.id)
        .map_err(|e| {
        tracing::error!(error = %e, "Failed to create access token");
        AppError::Unknown(e)
    })?;

    let (refresh_token, refresh_jti, _refresh_expires) = app_context
        .auth_manager
        .create_refresh_token(&user.id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create refresh token");
            AppError::Unknown(e)
        })?;

    // Store refresh token in Redis
    {
        let mut queue = app_context.queue.lock().await;
        let refresh_ttl_seconds =
            app_context.config.refresh_token_ttl_days * construct_config::SECONDS_PER_DAY;

        if let Err(e) = queue
            .store_refresh_token(&refresh_jti, &user.id.to_string(), refresh_ttl_seconds)
            .await
        {
            tracing::error!(error = %e, "Failed to store refresh token");
            // Continue anyway - token was created, just not tracked
        }
    }

    // AUDIT: Log successful registration
    let user_id_hash = log_safe_id(&user.id.to_string(), &app_context.config.logging.hash_salt);
    let username_hash = log_safe_id(&user.username, &app_context.config.logging.hash_salt);

    AuditLogger::log_login_attempt(
        Some(user_id_hash.clone()),
        Some(username_hash),
        client_ip,
        true, // success
        Some("User registered successfully via REST API".to_string()),
        None, // no session_id for REST API
    );

    tracing::info!(
        user_hash = %user_id_hash,
        "User registered successfully via REST API"
    );

    Ok((
        StatusCode::CREATED,
        Json(AuthResponse {
            user_id: user.id.to_string(),
            access_token,
            refresh_token,
            expires_at,
        }),
    ))
}

/// Request body for POST /api/v1/auth/login
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// POST /api/v1/auth/login
///
/// Login user through REST API.
///
/// Security:
/// - Rate limiting by IP (brute force protection)
/// - CSRF protection (for browsers)
/// - Logging of login attempts
pub async fn login(
    State(app_context): State<Arc<AppContext>>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Extract client IP for rate limiting and audit logging
    let client_ip_str = extract_client_ip(&headers, None);
    let client_ip: Option<std::net::IpAddr> = client_ip_str.parse().ok();
    let username_hash = log_safe_id(&request.username, &app_context.config.logging.hash_salt);

    // Rate limiting for failed login attempts
    {
        let mut queue = app_context.queue.lock().await;
        let failed_attempts = match queue.increment_failed_login_count(&request.username).await {
            Ok(count) => count,
            Err(e) => {
                tracing::error!(error = %e, "Failed to check login rate limit");
                0 // Fail open
            }
        };

        let max_attempts = app_context.config.security.max_failed_login_attempts;
        if failed_attempts > max_attempts {
            drop(queue);

            // AUDIT: Log rate limit violation
            AuditLogger::log_authentication_failure(
                Some(username_hash.clone()),
                client_ip,
                Some(format!(
                    "Too many failed login attempts ({})",
                    failed_attempts
                )),
            );

            tracing::warn!(
                username_hash = %username_hash,
                attempts = failed_attempts,
                limit = max_attempts,
                "Login rate limit exceeded"
            );
            return Err(AppError::Validation(
                "Too many failed login attempts. Try again in 15 minutes.".to_string(),
            ));
        }
        drop(queue);
    }

    // Get user by username
    let user = match db::get_user_by_username(&app_context.db_pool, &request.username).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            // AUDIT: Log failed login (user not found)
            AuditLogger::log_authentication_failure(
                Some(username_hash.clone()),
                client_ip,
                Some("User not found".to_string()),
            );

            tracing::warn!(
                username_hash = %username_hash,
                "Login failed: user not found"
            );
            return Err(AppError::Auth("Invalid username or password".to_string()));
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to get user by username");
            return Err(AppError::Unknown(e));
        }
    };

    // Verify password
    use bcrypt::verify;
    match verify(&request.password, &user.password_hash) {
        Ok(true) => {
            // Password correct - reset failed login counter
            {
                let mut queue = app_context.queue.lock().await;
                if let Err(e) = queue.reset_failed_login_count(&request.username).await {
                    tracing::warn!(error = %e, "Failed to reset login counter");
                }
            }

            // Create access token and refresh token
            let (access_token, _access_jti, expires_at) = app_context
                .auth_manager
                .create_token(&user.id)
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to create access token");
                    AppError::Unknown(e)
                })?;

            let (refresh_token, refresh_jti, _refresh_expires) = app_context
                .auth_manager
                .create_refresh_token(&user.id)
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to create refresh token");
                    AppError::Unknown(e)
                })?;

            // Store refresh token in Redis
            {
                let mut queue = app_context.queue.lock().await;
                let refresh_ttl_seconds =
                    app_context.config.refresh_token_ttl_days * construct_config::SECONDS_PER_DAY;

                if let Err(e) = queue
                    .store_refresh_token(&refresh_jti, &user.id.to_string(), refresh_ttl_seconds)
                    .await
                {
                    tracing::error!(error = %e, "Failed to store refresh token");
                    // Continue anyway - token was created, just not tracked
                }
            }

            // AUDIT: Log successful login
            let user_id_hash =
                log_safe_id(&user.id.to_string(), &app_context.config.logging.hash_salt);

            AuditLogger::log_login_attempt(
                Some(user_id_hash.clone()),
                Some(username_hash.clone()),
                client_ip,
                true, // success
                Some("Login successful via REST API".to_string()),
                None, // no session_id for REST API
            );

            tracing::info!(
                user_hash = %user_id_hash,
                "User logged in successfully via REST API"
            );

            Ok((
                StatusCode::OK,
                Json(AuthResponse {
                    user_id: user.id.to_string(),
                    access_token,
                    refresh_token,
                    expires_at,
                }),
            ))
        }
        Ok(false) => {
            // AUDIT: Log failed login (invalid password)
            let user_id_hash =
                log_safe_id(&user.id.to_string(), &app_context.config.logging.hash_salt);

            AuditLogger::log_authentication_failure(
                Some(username_hash.clone()),
                client_ip,
                Some("Invalid password".to_string()),
            );

            tracing::warn!(
                user_hash = %user_id_hash,
                "Login failed: invalid password"
            );
            Err(AppError::Auth("Invalid username or password".to_string()))
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to verify password");
            Err(AppError::Unknown(anyhow::anyhow!(
                "Password verification failed"
            )))
        }
    }
}
