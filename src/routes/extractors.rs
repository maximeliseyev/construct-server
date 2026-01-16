// ============================================================================
// Axum Extractors
// ============================================================================
//
// Custom extractors for Axum routes:
// - AuthenticatedUser: Extracts and validates JWT token from Authorization header
// - AppContextExtractor: Extracts AppContext from State (helper)
//
// ============================================================================

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{HeaderMap, header::AUTHORIZATION, request::Parts},
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::context::AppContext;
use crate::error::AppError;

/// Extractor for authenticated user ID from JWT token
///
/// Usage:
/// ```rust
/// async fn handler(user: AuthenticatedUser, ...) -> Result<...> {
///     let user_id = user.0;
///     // ...
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AuthenticatedUser(pub Uuid);

// Also implement for AuthServiceContext (via conversion to AppContext)
#[async_trait]
impl FromRequestParts<Arc<crate::auth_service::AuthServiceContext>> for AuthenticatedUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<crate::auth_service::AuthServiceContext>,
    ) -> Result<Self, Self::Rejection> {
        // Convert to AppContext for reuse of existing logic
        let app_context = Arc::new(state.to_app_context());
        <AuthenticatedUser as FromRequestParts<Arc<AppContext>>>::from_request_parts(
            parts,
            &app_context,
        )
        .await
    }
}

// Also implement for UserServiceContext (via conversion to AppContext)
#[async_trait]
impl FromRequestParts<Arc<crate::user_service::UserServiceContext>> for AuthenticatedUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<crate::user_service::UserServiceContext>,
    ) -> Result<Self, Self::Rejection> {
        // Convert to AppContext for reuse of existing logic
        let app_context = Arc::new(state.to_app_context());
        <AuthenticatedUser as FromRequestParts<Arc<AppContext>>>::from_request_parts(
            parts,
            &app_context,
        )
        .await
    }
}

// Also implement for MessagingServiceContext (via conversion to AppContext)
#[async_trait]
impl FromRequestParts<Arc<crate::messaging_service::MessagingServiceContext>>
    for AuthenticatedUser
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<crate::messaging_service::MessagingServiceContext>,
    ) -> Result<Self, Self::Rejection> {
        // Convert to AppContext for reuse of existing logic
        let app_context = Arc::new(state.to_app_context());
        <AuthenticatedUser as FromRequestParts<Arc<AppContext>>>::from_request_parts(
            parts,
            &app_context,
        )
        .await
    }
}

// Also implement for NotificationServiceContext (via conversion to AppContext)
#[async_trait]
impl FromRequestParts<Arc<crate::notification_service::NotificationServiceContext>>
    for AuthenticatedUser
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<crate::notification_service::NotificationServiceContext>,
    ) -> Result<Self, Self::Rejection> {
        // Convert to AppContext for reuse of existing logic
        let app_context = Arc::new(state.to_app_context());
        <AuthenticatedUser as FromRequestParts<Arc<AppContext>>>::from_request_parts(
            parts,
            &app_context,
        )
        .await
    }
}

#[async_trait]
impl FromRequestParts<Arc<AppContext>> for AuthenticatedUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppContext>,
    ) -> Result<Self, Self::Rejection> {
        // Extract Authorization header
        let headers =
            HeaderMap::from_iter(parts.headers.iter().map(|(k, v)| (k.clone(), v.clone())));

        // Extract JWT token
        let user_id = extract_user_id_from_jwt(state, &headers).map_err(|e| {
            tracing::warn!(error = %e, "JWT authentication failed");
            let status = e.status_code();
            let body = json!({
                "error": e.user_message(),
                "code": e.error_code(),
            });
            (status, axum::Json(body)).into_response()
        })?;

        // Check if token is invalidated (soft logout)
        // Extract token to get JTI
        if let Some(auth_header) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
            if let Some(token) = auth_header.strip_prefix("Bearer ") {
                // Try to decode token to get JTI (without full validation, we already validated above)
                if let Ok(claims) = state.auth_manager.verify_token(token) {
                    let mut queue = state.queue.lock().await;
                    if let Ok(true) = queue.is_token_invalidated(&claims.jti).await {
                        drop(queue);
                        let body = json!({
                            "error": "Token was revoked (logged out)",
                            "code": "TOKEN_REVOKED",
                        });
                        return Err((axum::http::StatusCode::UNAUTHORIZED, axum::Json(body))
                            .into_response());
                    }
                }
            }
        }

        Ok(AuthenticatedUser(user_id))
    }
}

/// Helper function to extract user ID from JWT token
/// (Migrated from handlers to be reusable)
/// Also checks if token is invalidated (soft logout)
fn extract_user_id_from_jwt(ctx: &AppContext, headers: &HeaderMap) -> Result<Uuid, AppError> {
    // Get Authorization header
    let auth_header = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Auth("Missing Authorization header".to_string()))?;

    // Extract token (format: "Bearer <token>")
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Auth("Invalid Authorization header format".to_string()))?;

    // Verify and decode JWT
    let claims = ctx
        .auth_manager
        .verify_token(token)
        .map_err(|e| AppError::Auth(format!("Invalid or expired token: {}", e)))?;

    // Note: Token invalidation check is done in middleware or handler level
    // because this function is synchronous and Redis operations are async.
    // The token invalidation check can be added as a separate middleware
    // or in the AuthenticatedUser extractor's async from_request_parts method.

    // Extract user_id from claims (sub is a String, not Option)
    let user_id = Uuid::parse_str(&claims.sub).map_err(|e| AppError::Uuid(e))?;

    Ok(user_id)
}
