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
    extract::{Path, Query, State},
    http::HeaderMap,
    response::IntoResponse,
};
use std::sync::Arc;

use crate::routes::account;
use crate::routes::account_deletion;
use crate::routes::devices;
use crate::routes::extractors::TrustedUser;
use crate::routes::invites;
use crate::routes::keys;
use crate::user_service::UserServiceContext;
use construct_error::AppError;

/// Wrapper for get_account handler
/// Note: Uses TrustedUser (Trust Boundary pattern) - Gateway sets X-User-Id header
pub async fn get_account(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    account::get_account(State(app_context), user).await
}

/// Wrapper for update_account handler
/// Note: Uses TrustedUser (Trust Boundary pattern) - Gateway sets X-User-Id header
pub async fn update_account(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
    headers: HeaderMap,
    Json(request): Json<account::UpdateAccountRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    account::update_account(State(app_context), user, headers, Json(request)).await
}

// Note: Legacy delete_account removed - use device-signed deletion instead
// (GET /api/v1/users/me/delete-challenge + POST /api/v1/users/me/delete-confirm)

/// Wrapper for get_public_key_bundle handler (GET /api/v1/users/:id/public-key)
/// Also handles legacy GET /keys/:user_id
/// Note: Uses TrustedUser (Trust Boundary pattern) - Gateway sets X-User-Id header
pub async fn get_public_key_bundle(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    keys::get_public_key_bundle(State(app_context), user, Path(id)).await
}

/// Wrapper for legacy get_keys handler (GET /keys/:user_id)
/// This is the same as get_public_key_bundle, but kept for backward compatibility
/// Note: Uses TrustedUser (Trust Boundary pattern) - Gateway sets X-User-Id header
pub async fn get_keys_legacy(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    // Legacy endpoint uses same handler as modern API
    get_public_key_bundle(State(context), user, Path(user_id)).await
}

/// Wrapper for upload_keys handler (POST /api/v1/keys/upload)
/// Note: Uses TrustedUser (Trust Boundary pattern) - Gateway sets X-User-Id header
pub async fn upload_keys(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
    headers: HeaderMap,
    Json(bundle): Json<construct_crypto::UploadableKeyBundle>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    keys::upload_keys(State(app_context), user, headers, Json(bundle)).await
}

pub async fn get_device_profile(
    State(context): State<Arc<UserServiceContext>>,
    Path(device_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    devices::get_device_profile(State(app_context), Path(device_id)).await
}

/// Wrapper for check_username_availability handler
/// GET /api/v1/users/username/availability?username=<string>
/// This endpoint does NOT require authentication
pub async fn check_username_availability(
    State(context): State<Arc<UserServiceContext>>,
    headers: HeaderMap,
    Query(query): Query<account::UsernameAvailabilityQuery>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    account::check_username_availability(State(app_context), headers, Query(query)).await
}

/// Wrapper for generate_invite handler
/// POST /api/v1/invites/generate
/// Note: Uses TrustedUser (Trust Boundary pattern) - Gateway sets X-User-Id header
pub async fn generate_invite(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
    Json(request): Json<invites::GenerateInviteRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    invites::generate_invite(State(app_context), user, Json(request)).await
}

/// Wrapper for accept_invite handler
/// POST /api/v1/invites/accept
/// Note: Uses TrustedUser (Trust Boundary pattern) - Gateway sets X-User-Id header
pub async fn accept_invite(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
    Json(request): Json<invites::AcceptInviteRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    invites::accept_invite(State(app_context), user, Json(request)).await
}

// ============================================================================
// Device-Signed Account Deletion (Phase 5.0.1)
// ============================================================================

/// Wrapper for get_delete_challenge handler
/// GET /api/v1/users/me/delete-challenge
/// Note: Uses TrustedUser (Trust Boundary pattern)
pub async fn get_delete_challenge(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    account_deletion::get_delete_challenge(State(app_context), user).await
}

/// Wrapper for confirm_delete handler
/// POST /api/v1/users/me/delete-confirm
/// Note: Uses TrustedUser (Trust Boundary pattern)
pub async fn confirm_delete(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
    Json(request): Json<account_deletion::DeleteConfirmRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    account_deletion::confirm_delete(State(app_context), user, Json(request)).await
}
