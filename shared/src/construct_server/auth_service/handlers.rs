// ============================================================================
// Auth Service Handlers - Phase 2.6.2
// ============================================================================
//
// Wrapper handlers that convert AuthServiceContext to AppContext
// for use with existing auth route handlers.
//
// This is a temporary solution until handlers are refactored to use traits.
//
// ============================================================================

use axum::{Json, extract::State, http::HeaderMap, response::IntoResponse};
use std::sync::Arc;

use crate::auth_service::AuthServiceContext;
use crate::routes::auth;
use crate::routes::extractors::AuthenticatedUser;
use construct_error::AppError;

/// Wrapper for refresh_token handler
pub async fn refresh_token(
    State(context): State<Arc<AuthServiceContext>>,
    Json(request): Json<auth::RefreshTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    auth::refresh_token(State(app_context), Json(request)).await
}

/// Wrapper for logout handler
pub async fn logout(
    State(context): State<Arc<AuthServiceContext>>,
    user: AuthenticatedUser,
    Json(request): Json<auth::LogoutRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    auth::logout(State(app_context), user, Json(request)).await
}

/// Wrapper for register handler
pub async fn register(
    State(context): State<Arc<AuthServiceContext>>,
    headers: HeaderMap,
    Json(request): Json<auth::RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    auth::register(State(app_context), headers, Json(request)).await
}

/// Wrapper for login handler
pub async fn login(
    State(context): State<Arc<AuthServiceContext>>,
    headers: HeaderMap,
    Json(request): Json<auth::LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    auth::login(State(app_context), headers, Json(request)).await
}
