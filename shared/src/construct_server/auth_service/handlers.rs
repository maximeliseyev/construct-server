// ============================================================================
// Auth Service Handlers - Passwordless Authentication
// ============================================================================
//
// Wrapper handlers that convert AuthServiceContext to AppContext
// for use with existing device-based authentication handlers.
//
// This service handles ONLY passwordless device-based authentication:
// - PoW challenge generation
// - Device registration (with Ed25519 keys)
// - Device authentication (Ed25519 signature verification)
// - JWT token management (refresh, logout)
//
// ============================================================================

use axum::{Json, extract::State, response::IntoResponse};
use std::sync::Arc;

use crate::auth_service::AuthServiceContext;
use crate::routes::auth;
use crate::routes::devices;
use crate::routes::extractors::TrustedUser;
use construct_error::AppError;

/// Wrapper for get_pow_challenge handler
pub async fn get_pow_challenge(
    State(context): State<Arc<AuthServiceContext>>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    devices::get_pow_challenge(State(app_context)).await
}

/// Wrapper for register_device handler
pub async fn register_device(
    State(context): State<Arc<AuthServiceContext>>,
    Json(request): Json<devices::RegisterDeviceRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    devices::register_device_v2(State(app_context), Json(request)).await
}

/// Wrapper for authenticate_device handler
pub async fn authenticate_device(
    State(context): State<Arc<AuthServiceContext>>,
    Json(request): Json<devices::AuthenticateDeviceRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    devices::authenticate_device(State(app_context), Json(request)).await
}

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
    user: TrustedUser,
    Json(request): Json<auth::LogoutRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    auth::logout(State(app_context), user, Json(request)).await
}
