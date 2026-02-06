// ============================================================================
// Account Management Routes
// ============================================================================
//
// Endpoints:
// - GET /api/v1/account - Get account information
// - PUT /api/v1/account - Update account (username, password)
// - DELETE /api/v1/account - Delete account (requires request signing)
//
// ============================================================================

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::context::AppContext;
use crate::db;
use crate::routes::extractors::AuthenticatedUser;
use crate::routes::request_signing::{
    compute_body_hash, extract_request_signature, verify_request_signature,
};
use crate::utils::{extract_client_ip, log_safe_id};
use construct_error::AppError;

/// Account information response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    /// User ID (UUID)
    pub user_id: String,
    /// Username
    pub username: String,
    /// Account creation timestamp (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// GET /api/v1/account
/// Get current user's account information
///
/// Security:
/// - Requires JWT authentication
/// - Returns only non-sensitive information (no password hash)
pub async fn get_account(
    State(app_context): State<Arc<AppContext>>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AppError> {
    let user_id = user.0;

    // Fetch user from database
    let user_record = db::get_legacy_user_by_id(&app_context.db_pool, &user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                "Failed to fetch user from database"
            );
            AppError::Unknown(e)
        })?;

    let user_record = user_record.ok_or_else(|| {
        tracing::warn!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            "User not found in database"
        );
        // SECURITY: Don't reveal whether user exists - use generic error
        AppError::Auth("Session is invalid or expired".to_string())
    })?;

    tracing::debug!(
        user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
        "Account information retrieved"
    );

    Ok((
        StatusCode::OK,
        Json(AccountInfo {
            user_id: user_record.id.to_string(),
            username: user_record.username,
            created_at: None, // TODO: Add created_at to User struct if needed
        }),
    ))
}

/// Request body for account update
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAccountRequest {
    /// New username (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// New password (optional, requires old_password)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_password: Option<String>,
    /// Old password (required if updating password)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_password: Option<String>,
}

/// PUT /api/v1/account
/// Update account information (username, password)
///
/// Security:
/// - Requires JWT authentication
/// - Requires CSRF protection (via middleware)
/// - Password update requires old password verification
/// - Username changes should be rate-limited
pub async fn update_account(
    State(app_context): State<Arc<AppContext>>,
    user: AuthenticatedUser,
    _headers: HeaderMap, // Reserved for future request signing
    Json(request): Json<UpdateAccountRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user_id = user.0;

    // Fetch current user
    let user_record = db::get_legacy_user_by_id(&app_context.db_pool, &user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to fetch user");
            AppError::Unknown(e)
        })?
        .ok_or_else(
            || // SECURITY: Don't reveal whether user exists - use generic error
        AppError::Auth("Session is invalid or expired".to_string()),
        )?;

    // Update username if provided
    if let Some(new_username) = &request.username {
        if new_username.is_empty() {
            return Err(AppError::Validation("Username cannot be empty".to_string()));
        }

        // Check if username is already taken
        if let Ok(Some(existing_user)) =
            db::get_legacy_user_by_username(&app_context.db_pool, new_username).await
            && existing_user.id != user_id
        {
            return Err(AppError::Validation(
                "Username is already taken".to_string(),
            ));
        }

        // Update username (TODO: Add update_username function to db.rs)
        // For now, we'll skip username updates until the function is added
        tracing::warn!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            "Username update not yet implemented"
        );
        return Err(AppError::Validation(
            "Username update is not yet implemented".to_string(),
        ));
    }

    // Update password if provided
    if let Some(new_password) = &request.new_password {
        if new_password.len() < 8 {
            return Err(AppError::Validation(
                "Password must be at least 8 characters long".to_string(),
            ));
        }

        // Verify old password
        let old_password = request.old_password.ok_or_else(|| {
            AppError::Validation("Old password is required to change password".to_string())
        })?;

        let password_valid = db::verify_password(&user_record, &old_password)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to verify password");
                AppError::Unknown(e)
            })?;

        if !password_valid {
            tracing::warn!(
                user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                "Invalid old password during password update"
            );
            return Err(AppError::Auth("Invalid old password".to_string()));
        }

        // Update password
        db::update_user_password(&app_context.db_pool, &user_id, new_password)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to update password");
                AppError::Unknown(e)
            })?;

        tracing::info!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            "Password updated successfully"
        );
    }

    // If no updates were requested
    if request.username.is_none() && request.new_password.is_none() {
        return Err(AppError::Validation(
            "No update fields provided".to_string(),
        ));
    }

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "message": "Account updated successfully"
        })),
    ))
}

/// Request body for account deletion
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteAccountRequest {
    /// Password confirmation (required for account deletion)
    pub password: String,
    /// Confirmation flag (must be true)
    #[serde(default)]
    pub confirm: bool,
}

/// DELETE /api/v1/account
/// Delete user account and all associated data
///
/// Security:
/// - Requires JWT authentication
/// - Requires CSRF protection (via middleware)
/// - Requires request signature (Ed25519) if enabled
/// - Requires password confirmation
/// - Requires explicit confirmation flag
/// - Revokes all tokens and sessions
/// - Deletes all user data (GDPR compliance)
pub async fn delete_account(
    State(app_context): State<Arc<AppContext>>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Json(request): Json<DeleteAccountRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user_id = user.0;

    // 1. Verify confirmation flag
    if !request.confirm {
        return Err(AppError::Validation(
            "Account deletion requires explicit confirmation (confirm: true)".to_string(),
        ));
    }

    // 2. Verify password
    let user_record = db::get_legacy_user_by_id(&app_context.db_pool, &user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to fetch user");
            AppError::Unknown(e)
        })?
        .ok_or_else(
            || // SECURITY: Don't reveal whether user exists - use generic error
        AppError::Auth("Session is invalid or expired".to_string()),
        )?;

    let password_valid = db::verify_password(&user_record, &request.password)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to verify password");
            AppError::Unknown(e)
        })?;

    if !password_valid {
        tracing::warn!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            "Invalid password during account deletion"
        );
        // SECURITY: Use generic error to prevent confirmation of user existence
        return Err(AppError::Auth("Verification failed".to_string()));
    }

    // 3. Request signing verification (if enabled)
    if app_context.config.security.request_signing_required {
        let request_sig = extract_request_signature(&headers)
            .ok_or_else(|| {
                tracing::warn!(
                    user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                    "Request signature missing for account deletion"
                );
                AppError::Validation(
                    "Request signature is required for account deletion. Please sign the request with your master_identity_key.".to_string(),
                )
            })?;

        // Compute body hash
        let body_json = serde_json::to_string(&request).map_err(|e| {
            tracing::error!(error = %e, "Failed to serialize request for signature verification");
            AppError::Unknown(e.into())
        })?;
        let body_hash = compute_body_hash(body_json.as_bytes());

        // Get user's master_identity_key from key bundle
        let (bundle, _) = db::get_key_bundle(&app_context.db_pool, &user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to fetch key bundle");
                AppError::Unknown(e)
            })?
            .ok_or_else(|| {
                AppError::Validation(
                    "Key bundle not found. Cannot verify request signature.".to_string(),
                )
            })?;

        // Verify request signature
        match verify_request_signature(
            &bundle.master_identity_key,
            "DELETE",
            "/api/v1/account",
            request_sig.timestamp,
            &body_hash,
            &request_sig.signature,
        ) {
            Ok(()) => {
                tracing::debug!(
                    user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                    "Request signature verified for account deletion"
                );
            }
            Err(e) => {
                tracing::warn!(
                    user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                    error = %e,
                    "Request signature verification failed for account deletion"
                );
                return Err(AppError::Validation(format!(
                    "Request signature verification failed: {}",
                    e
                )));
            }
        }

        // Verify public_key matches master_identity_key
        use subtle::ConstantTimeEq;
        if !bool::from(
            request_sig
                .public_key
                .as_bytes()
                .ct_eq(bundle.master_identity_key.as_bytes()),
        ) {
            tracing::warn!(
                user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                "Request signature public key does not match bundle master_identity_key"
            );
            return Err(AppError::Validation(
                "Request signature public key must match bundle master_identity_key".to_string(),
            ));
        }
    }

    // 4. Revoke all tokens and sessions
    {
        let mut queue = app_context.queue.lock().await;

        // Revoke all refresh tokens
        if let Err(e) = queue.revoke_all_user_tokens(&user_id.to_string()).await {
            tracing::warn!(error = %e, "Failed to revoke all user tokens");
        }

        // Revoke all sessions
        if let Err(e) = queue.revoke_all_sessions(&user_id.to_string()).await {
            tracing::warn!(
                error = %e,
                user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                "Failed to revoke all sessions"
            );
        }
        drop(queue);
    }

    // 5. Delete delivery ACK data (GDPR compliance)
    if let Some(ack_manager) = &app_context.delivery_ack_manager
        && let Err(e) = ack_manager.delete_user_data(&user_id.to_string()).await
    {
        tracing::warn!(
            error = %e,
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            "Failed to delete delivery ACK data"
        );
    }

    // 6. Untrack user online status
    {
        let mut queue = app_context.queue.lock().await;
        if let Err(e) = queue.untrack_user_online(&user_id.to_string()).await {
            tracing::warn!(
                error = %e,
                user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                "Failed to untrack user online status"
            );
        }
        drop(queue);
    }

    // 7. Delete user account from database (cascade will handle related records)
    db::delete_user_account(&app_context.db_pool, &user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                "Failed to delete user account"
            );
            AppError::Unknown(e)
        })?;

    tracing::info!(
        user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
        "Account deleted successfully"
    );

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "message": "Account deleted successfully"
        })),
    ))
}

// ============================================================================
// Username Availability Check
// ============================================================================

/// Query parameters for username availability check
#[derive(Debug, Deserialize)]
pub struct UsernameAvailabilityQuery {
    pub username: String,
}

/// Response for username availability check
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsernameAvailabilityResponse {
    /// Original username as provided by client
    pub username: String,
    /// Normalized username (lowercase, trimmed)
    pub normalized: String,
    /// Whether the username is available
    pub available: bool,
}

/// Error response for username validation
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsernameValidationError {
    pub error: String,
    pub message: String,
}

/// Rate limit error response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitError {
    pub error: String,
    pub retry_after_seconds: i64,
}

/// GET /api/v1/users/username/availability?username=<string>
///
/// Check if a username is available for registration.
///
/// Security:
/// - Rate limited: 10 requests/min per IP, 10 requests/min per device
/// - Username is normalized to lowercase
/// - Anti-enumeration: slight jitter on responses
/// - Audit logging for mass checks
pub async fn check_username_availability(
    State(app_context): State<Arc<AppContext>>,
    headers: HeaderMap,
    Query(query): Query<UsernameAvailabilityQuery>,
) -> Result<impl IntoResponse, AppError> {
    let client_ip = extract_client_ip(&headers, None);
    let device_id = headers
        .get("X-Device-Id")
        .or_else(|| headers.get("X-Client-Id"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    // 1. Rate limiting (10 requests/min per IP)
    {
        let mut queue = app_context.queue.lock().await;
        let rate_key = format!("username_check:ip:{}", client_ip);
        match queue.increment_rate_limit(&rate_key, 60).await {
            Ok(count) => {
                if count > 10 {
                    drop(queue);
                    tracing::warn!(
                        ip = %client_ip,
                        count = count,
                        "Username availability rate limit exceeded (IP)"
                    );
                    return Ok((
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(json!({
                            "error": "rate_limited",
                            "retryAfterSeconds": 60
                        })),
                    ));
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check rate limit");
            }
        }

        // Rate limit per device (if provided)
        if device_id != "unknown" {
            let device_key = format!("username_check:device:{}", device_id);
            match queue.increment_rate_limit(&device_key, 60).await {
                Ok(count) => {
                    if count > 10 {
                        drop(queue);
                        tracing::warn!(
                            device_id = %device_id,
                            count = count,
                            "Username availability rate limit exceeded (device)"
                        );
                        return Ok((
                            StatusCode::TOO_MANY_REQUESTS,
                            Json(json!({
                                "error": "rate_limited",
                                "retryAfterSeconds": 60
                            })),
                        ));
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to check device rate limit");
                }
            }
        }
        drop(queue);
    }

    // 2. Normalize username (trim + lowercase)
    let original = query.username.clone();
    let normalized = query.username.trim().to_lowercase();

    // 3. Validate format: ^[a-z0-9_]{3,30}$
    if normalized.len() < 3 || normalized.len() > 30 {
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "invalid_username",
                "message": "Username must be 3-30 characters long."
            })),
        ));
    }

    if !normalized.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "invalid_username",
                "message": "Username can only contain letters, numbers, and underscores."
            })),
        ));
    }

    // 4. Anti-enumeration: add slight random jitter (10-50ms)
    let jitter_ms = rand::random::<u64>() % 40 + 10;
    tokio::time::sleep(tokio::time::Duration::from_millis(jitter_ms)).await;

    // 5. Check database for existing username
    let available = match db::get_user_by_username(&app_context.db_pool, &normalized).await {
        Ok(None) => true,  // Username not found = available
        Ok(Some(_)) => false, // Username exists = not available
        Err(e) => {
            tracing::error!(error = %e, "Database error checking username");
            return Err(AppError::Unknown(e));
        }
    };

    // 6. Log mass check attempts (for audit)
    tracing::debug!(
        ip = %client_ip,
        device_id = %device_id,
        username_hash = %log_safe_id(&normalized, &app_context.config.logging.hash_salt),
        available = available,
        "Username availability check"
    );

    // 7. Return response
    Ok((
        StatusCode::OK,
        Json(json!({
            "username": original,
            "normalized": normalized,
            "available": available
        })),
    ))
}
