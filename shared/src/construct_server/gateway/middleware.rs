// ============================================================================
// Gateway Middleware - Phase 2.6.1
// ============================================================================
//
// Middleware for API Gateway:
// - JWT authentication verification
// - Rate limiting (IP-based, user-based)
// - CSRF protection
//
// ============================================================================

use crate::auth::AuthManager;
use crate::config::Config;
use crate::queue::MessageQueue;
use crate::routes::csrf::{
    extract_csrf_token, has_custom_header, is_browser_request, validate_csrf_token,
};
use crate::utils::extract_client_ip;
use axum::{
    extract::{Request, State},
    http::{StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Gateway state with dependencies for middleware
pub struct GatewayMiddlewareState {
    pub config: Arc<Config>,
    pub auth_manager: Arc<AuthManager>,
    pub queue: Arc<Mutex<MessageQueue>>,
}

/// JWT authentication verification middleware
pub async fn jwt_verification(
    State(state): State<Arc<GatewayMiddlewareState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path();

    // Skip authentication for public endpoints
    if is_public_endpoint(path) {
        return Ok(next.run(request).await);
    }

    // Extract Authorization header
    let headers = request.headers();
    let auth_header = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            // Only warn for known API endpoints that require auth
            // Unknown endpoints (like /api/v1/config) might be client-side routes or health checks
            // Log at debug level to reduce noise
            if path.starts_with("/api/v1/") && !path.contains("/health") {
                tracing::debug!(path = %path, "Missing Authorization header for API endpoint");
            }
            StatusCode::UNAUTHORIZED
        })?;

    // Extract token
    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        tracing::warn!(path = %path, "Invalid Authorization header format");
        StatusCode::UNAUTHORIZED
    })?;

    // ✅ DEBUG: Log token info for diagnostics
    tracing::debug!(
        path = %path,
        token_length = token.len(),
        token_prefix = &token[..token.len().min(30)],
        "Attempting to verify JWT token"
    );

    // Verify JWT token
    let claims = state.auth_manager.verify_token(token).map_err(|e| {
        tracing::error!(
            error = %e,
            path = %path,
            token_length = token.len(),
            "JWT verification failed"
        );
        StatusCode::UNAUTHORIZED
    })?;

    // Check if token is invalidated (soft logout)
    let mut queue = state.queue.lock().await;
    if let Ok(true) = queue.is_token_invalidated(&claims.jti).await {
        drop(queue);
        tracing::warn!(path = %path, jti = %claims.jti, "Token was revoked");
        return Err(StatusCode::UNAUTHORIZED);
    }
    drop(queue);

    // Add user_id to request extensions for downstream use
    let _user_id = Uuid::parse_str(&claims.sub).map_err(|_| {
        tracing::error!("Invalid user ID in token");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Continue with authenticated request
    Ok(next.run(request).await)
}

/// Rate limiting middleware
pub async fn rate_limiting(
    State(state): State<Arc<GatewayMiddlewareState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = request.headers();

    // Extract client IP
    let client_ip = extract_client_ip(headers, None);

    // Extract user_id from JWT token in Authorization header (for rate limiting)
    let user_id = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .and_then(|token| state.auth_manager.verify_token(token).ok())
        .and_then(|claims| Uuid::parse_str(&claims.sub).ok())
        .map(|id| id.to_string());

    // Check rate limiting
    let mut queue = state.queue.lock().await;

    // IP-based rate limiting
    let ip_rate_key = format!("rate:ip:{}", client_ip);
    if let Ok(count) = queue.increment_rate_limit(&ip_rate_key, 3600).await {
        let max_per_hour = state.config.security.max_requests_per_ip_per_hour as i64;
        if count > max_per_hour {
            drop(queue);
            tracing::warn!(
                ip = %client_ip,
                count = count,
                limit = max_per_hour,
                "IP rate limit exceeded"
            );
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }

    // User-based rate limiting (if authenticated)
    if let Some(user_id_str) = user_id {
        let user_rate_key = format!("rate:user:{}", user_id_str);
        if let Ok(count) = queue.increment_rate_limit(&user_rate_key, 3600).await {
            // Use max_requests_per_user_ip_per_hour as user limit (combined rate limiting)
            let max_per_hour = state.config.security.max_requests_per_user_ip_per_hour as i64;
            if count > max_per_hour {
                drop(queue);
                tracing::warn!(
                    user_id = %user_id_str,
                    count = count,
                    limit = max_per_hour,
                    "User rate limit exceeded"
                );
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
        }
    }

    drop(queue);

    Ok(next.run(request).await)
}

/// CSRF protection middleware
pub async fn csrf_protection(
    State(state): State<Arc<GatewayMiddlewareState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method();
    let path = request.uri().path();
    let headers = request.headers();

    // Skip for safe methods (GET, HEAD, OPTIONS)
    if matches!(
        method,
        &axum::http::Method::GET | &axum::http::Method::HEAD | &axum::http::Method::OPTIONS
    ) {
        return Ok(next.run(request).await);
    }

    // Skip CSRF for non-browser requests (mobile/API) if custom header is present
    if !is_browser_request(headers) && has_custom_header(headers) {
        return Ok(next.run(request).await);
    }

    // For browser requests, validate CSRF token
    if is_browser_request(headers) {
        let token = extract_csrf_token(
            headers,
            &state.config.csrf.header_name,
            &state.config.csrf.cookie_name,
        );

        match token {
            Some(ref t) => {
                // Extract user_id from JWT token (for CSRF validation)
                let user_id = headers
                    .get(AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|h| h.strip_prefix("Bearer "))
                    .and_then(|token| state.auth_manager.verify_token(token).ok())
                    .and_then(|claims| Uuid::parse_str(&claims.sub).ok());

                if let Some(user_id) = user_id {
                    if let Err(e) = validate_csrf_token(&state.config.csrf, t, &user_id.to_string())
                    {
                        tracing::warn!(
                            path = %path,
                            error = %e,
                            "CSRF token validation failed"
                        );
                        return Err(StatusCode::FORBIDDEN);
                    }
                }
            }
            None => {
                tracing::warn!(path = %path, "Missing CSRF token for browser request");
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }

    Ok(next.run(request).await)
}

/// Check if endpoint is public (doesn't require authentication)
fn is_public_endpoint(path: &str) -> bool {
    matches!(
        path,
        "/api/v1/auth/register"
            | "/api/v1/auth/login"
            | "/health"
            | "/health/ready"
            | "/health/live"
    )
}
