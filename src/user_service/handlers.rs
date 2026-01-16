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
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;

use crate::error::AppError;
use crate::routes::account;
use crate::routes::extractors::AuthenticatedUser;
use crate::routes::keys;
use crate::user_service::UserServiceContext;

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

/// Wrapper for get_keys_v1 handler (GET /api/v1/users/:id/public-key)
/// Also handles legacy GET /keys/:user_id
pub async fn get_keys_v1(
    State(context): State<Arc<UserServiceContext>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    // get_keys_v1 uses Path(id: String), which matches both /api/v1/users/:id/public-key and /keys/:user_id
    keys::get_keys_v1(State(app_context), user, Path(id)).await
}

/// Wrapper for legacy get_keys handler (GET /keys/:user_id)
/// This is the same as get_keys_v1, but kept for clarity
pub async fn get_keys_legacy(
    State(context): State<Arc<UserServiceContext>>,
    user: AuthenticatedUser,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    // Legacy endpoint uses same handler as v1
    get_keys_v1(State(context), user, Path(user_id)).await
}

/// Wrapper for upload_keys handler (POST /api/v1/keys/upload)
pub async fn upload_keys(
    State(context): State<Arc<UserServiceContext>>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Json(bundle): Json<crate::e2e::UploadableKeyBundle>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    keys::upload_keys(State(app_context), user, headers, Json(bundle)).await
}
