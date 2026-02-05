// ============================================================================
// User Service Handlers - Phase 2.6.3
// ============================================================================
//
// Wrapper handlers that convert UserServiceContext to AppContext
// for use with existing user-related route handlers.
//
// This is a temporary solution until handlers are refactored to use traits.
//
// ============================================================================

use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
};
use std::sync::Arc;

use crate::routes::account;
use crate::routes::devices;
use crate::routes::extractors::AuthenticatedUser;
use crate::routes::keys;
use crate::user_service::UserServiceContext;
use construct_error::AppError;

/// Wrapper for get_account handler
pub async fn get_account(
    State(context): State<Arc<UserServiceContext>>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    account::get_account(State(app_context), user).await
}

/// Wrapper for update_account handler
pub async fn update_account(
    State(context): State<Arc<UserServiceContext>>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Json(request): Json<account::UpdateAccountRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    account::update_account(State(app_context), user, headers, Json(request)).await
}

/// Wrapper for delete_account handler
pub async fn delete_account(
    State(context): State<Arc<UserServiceContext>>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Json(request): Json<account::DeleteAccountRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    account::delete_account(State(app_context), user, headers, Json(request)).await
}

/// Wrapper for get_public_key_bundle handler (GET /api/v1/users/:id/public-key)
/// Also handles legacy GET /keys/:user_id
pub async fn get_public_key_bundle(
    State(context): State<Arc<UserServiceContext>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    keys::get_public_key_bundle(State(app_context), user, Path(id)).await
}

/// Wrapper for legacy get_keys handler (GET /keys/:user_id)
/// This is the same as get_public_key_bundle, but kept for backward compatibility
pub async fn get_keys_legacy(
    State(context): State<Arc<UserServiceContext>>,
    user: AuthenticatedUser,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    // Legacy endpoint uses same handler as modern API
    get_public_key_bundle(State(context), user, Path(user_id)).await
}

/// Wrapper for upload_keys handler (POST /api/v1/keys/upload)
pub async fn upload_keys(
    State(context): State<Arc<UserServiceContext>>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Json(bundle): Json<construct_crypto::UploadableKeyBundle>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    keys::upload_keys(State(app_context), user, headers, Json(bundle)).await
}

// Device registration handlers
pub async fn register_device_v2(
    State(context): State<Arc<UserServiceContext>>,
    Json(request): Json<devices::RegisterDeviceRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    devices::register_device_v2(State(app_context), Json(request)).await
}

pub async fn get_device_profile(
    State(context): State<Arc<UserServiceContext>>,
    Path(device_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    devices::get_device_profile(State(app_context), Path(device_id)).await
}

// PoW challenge handler
pub async fn get_pow_challenge(
    State(context): State<Arc<UserServiceContext>>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    devices::get_pow_challenge(State(app_context)).await
}

/// Wrapper for authenticate_device handler
pub async fn authenticate_device(
    State(context): State<Arc<UserServiceContext>>,
    Json(request): Json<devices::AuthenticateDeviceRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    devices::authenticate_device(State(app_context), Json(request)).await
}
