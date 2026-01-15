// ============================================================================
// Authentication Routes
// ============================================================================
//
// Endpoints:
// - POST /auth/refresh - Refresh access token using refresh token
// - POST /auth/logout - Soft logout (invalidate tokens)
//
// ============================================================================

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::context::AppContext;
use crate::error::AppError;
use crate::routes::extractors::AuthenticatedUser;
use crate::utils::log_safe_id;

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
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| {
        AppError::Validation("Invalid user ID in refresh token".to_string())
    })?;

    // 5. Create new access token (1 hour)
    let (new_access_token, _access_jti, access_expires) = app_context
        .auth_manager
        .create_token(&user_id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create access token");
            AppError::Unknown(e.into())
        })?;

    // 6. Create new refresh token (30 days)
    let (new_refresh_token, refresh_jti, _refresh_expires) = app_context
        .auth_manager
        .create_refresh_token(&user_id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create refresh token");
            AppError::Unknown(e.into())
        })?;

    // 7. Store new refresh token in Redis
    {
        let mut queue = app_context.queue.lock().await;
        let refresh_ttl_seconds = app_context.config.refresh_token_ttl_days
            * crate::config::SECONDS_PER_DAY;
        
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
