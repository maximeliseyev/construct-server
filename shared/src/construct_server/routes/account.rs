// ============================================================================
// Account Management Routes
// ============================================================================
//
// Endpoints:
// - GET /api/v1/account - Get account information
// - PUT /api/v1/account - Update account (username, password)
// - GET /api/v1/users/username/availability - Check username availability
//
// Note: Account deletion moved to account_deletion.rs (device-signed flow)
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
use crate::routes::extractors::TrustedUser;
use crate::utils::{extract_client_ip, log_safe_id};
use construct_error::AppError;

/// Account information response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    /// User ID (UUID)
    pub user_id: String,
    /// Username (optional in passwordless architecture)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Account creation timestamp (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// GET /api/v1/account
/// Get current user's account information
///
/// Security:
/// - Requires authentication (via Gateway X-User-Id header)
/// - Returns only non-sensitive information (no password hash)
///
/// Note: Uses TrustedUser extractor (Trust Boundary pattern).
/// Gateway verifies JWT and propagates user identity via X-User-Id header.
pub async fn get_account(
    State(app_context): State<Arc<AppContext>>,
    user: TrustedUser,
) -> Result<impl IntoResponse, AppError> {
    let user_id = user.0;

    // Fetch user from database (using get_user_by_id for passwordless auth)
    let user_record = db::get_user_by_id(&app_context.db_pool, &user_id)
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
/// - Requires authentication (via Gateway X-User-Id header)
/// - Requires CSRF protection (via middleware)
/// - Password update requires old password verification
/// - Username changes should be rate-limited
///
/// Note: Uses TrustedUser extractor (Trust Boundary pattern).
/// Gateway verifies JWT and propagates user identity via X-User-Id header.
pub async fn update_account(
    State(app_context): State<Arc<AppContext>>,
    user: TrustedUser,
    _headers: HeaderMap, // Reserved for future request signing
    Json(request): Json<UpdateAccountRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user_id = user.0;

    // Fetch current user (passwordless)
    let _user_record = db::get_user_by_id(&app_context.db_pool, &user_id)
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
            db::get_user_by_username(&app_context.db_pool, new_username).await
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

    // Password updates are not supported in passwordless architecture
    if request.new_password.is_some() || request.old_password.is_some() {
        return Err(AppError::Validation(
            "Password updates are not supported in passwordless authentication".to_string(),
        ));
    }

    // If no updates were requested
    if request.username.is_none() {
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

// NOTE: Legacy DELETE /api/v1/account removed in Phase 5.0.1
// Use device-signed deletion instead:
// - GET /api/v1/users/me/delete-challenge
// - POST /api/v1/users/me/delete-confirm
// See: account_deletion.rs

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

    if !normalized
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
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
        Ok(None) => true,     // Username not found = available
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
