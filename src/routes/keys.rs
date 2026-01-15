// ============================================================================
// Keys Routes
// ============================================================================
//
// Endpoints:
// - POST /keys/upload - Upload or update user's key bundle
// - GET /keys/:user_id - Retrieve user's public key bundle
//
// ============================================================================

use axum::{
    Json,
    extract::{Path, State},
    http::{StatusCode, HeaderMap},
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::context::AppContext;
use crate::db;
use crate::e2e::{BundleData, ServerCryptoValidator, UploadableKeyBundle};
use crate::error::AppError;
use crate::routes::extractors::AuthenticatedUser;
use crate::routes::request_signing::{extract_request_signature, verify_request_signature, compute_body_hash};
use crate::utils::log_safe_id;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

/// POST /keys/upload
/// Uploads or updates a user's key bundle
///
/// Security:
/// - Requires JWT authentication
/// - Requires CSRF protection (via middleware)
/// - Requires request signature (Ed25519) if enabled
/// - Replay protection (nonce + timestamp)
pub async fn upload_keys(
    State(app_context): State<Arc<AppContext>>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Json(bundle): Json<UploadableKeyBundle>,
) -> Result<impl IntoResponse, AppError> {
    let user_id = user.0;

    // Validate the bundle
    // Don't allow empty user_id for key updates (user must already exist)
    ServerCryptoValidator::validate_uploadable_key_bundle(&bundle, false).map_err(|e| {
        tracing::warn!(
            error = %e,
            user_id = %user_id,
            "Key bundle validation failed"
        );
        AppError::Validation(e.to_string())
    })?;

    // SECURITY: Verify that user_id in bundle matches authenticated user
    let bundle_data_bytes = BASE64.decode(&bundle.bundle_data).map_err(|e| {
        tracing::warn!(error = %e, "Failed to decode bundle_data");
        AppError::Validation("Invalid bundle_data encoding".to_string())
    })?;

    let bundle_data: BundleData = match serde_json::from_slice(&bundle_data_bytes) {
        Ok(data) => data,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse bundle_data");
            return Err(AppError::Validation(
                "Invalid bundle_data format".to_string(),
            ));
        }
    };

    // Verify that user_id in bundle matches the authenticated user
    if bundle_data.user_id != user_id.to_string() {
        tracing::warn!(
            authenticated_user = %user_id,
            bundle_user_id = %bundle_data.user_id,
            "user_id mismatch: authenticated user attempting to upload bundle for different user"
        );
        return Err(AppError::Auth(
            "user_id in bundle does not match authenticated user".to_string(),
        ));
    }

    // SECURITY: Request signing verification (if enabled)
    // Client signs the request with their master_identity_key (Ed25519)
    // This prevents request tampering and provides additional authentication
    if app_context.config.security.request_signing_required {
        // Extract request signature from header
        let request_sig = extract_request_signature(&headers)
            .ok_or_else(|| {
                tracing::warn!(
                    user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                    "Request signature missing for key upload"
                );
                AppError::Validation(
                    "Request signature is required for this operation. Please sign the request with your master_identity_key.".to_string(),
                )
            })?;

        // Compute body hash for signature verification
        // Note: We need to get the raw body bytes, but we've already consumed it as JSON
        // In a real implementation, we'd need to read body before JSON parsing
        // For now, we'll use the serialized bundle as body representation
        let body_json = serde_json::to_string(&bundle).map_err(|e| {
            tracing::error!(error = %e, "Failed to serialize bundle for signature verification");
            AppError::Unknown(e.into())
        })?;
        let body_hash = compute_body_hash(body_json.as_bytes());

        // Verify request signature
        // Use master_identity_key from bundle as the public key
        // This ensures the client signs with the same key they're uploading
        match verify_request_signature(
            &bundle.master_identity_key,
            "POST",
            "/keys/upload",
            request_sig.timestamp,
            &body_hash,
            &request_sig.signature,
        ) {
            Ok(()) => {
                // Signature is valid
                tracing::debug!(
                    user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                    "Request signature verified"
                );
            }
            Err(e) => {
                tracing::warn!(
                    user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                    error = %e,
                    "Request signature verification failed"
                );
                return Err(AppError::Validation(format!(
                    "Request signature verification failed: {}",
                    e
                )));
            }
        }

        // Additional check: verify that public_key in signature matches master_identity_key
        use subtle::ConstantTimeEq;
        if !bool::from(
            request_sig.public_key.as_bytes().ct_eq(bundle.master_identity_key.as_bytes())
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

    // SECURITY: Replay protection for critical operation (key upload)
    // Generate a unique request ID for this operation
    let request_id = uuid::Uuid::new_v4().to_string();
    let nonce = bundle.nonce.as_deref().unwrap_or(&request_id);
    let timestamp = bundle.timestamp.unwrap_or_else(|| chrono::Utc::now().timestamp());
    
    // Use bundle_data as content for replay protection (includes user_id, timestamp, suites)
    let content_for_replay = &bundle.bundle_data;
    
    {
        let mut queue = app_context.queue.lock().await;
        // Use 5 minutes (300 seconds) as max age for critical operations
        const MAX_AGE_SECONDS: i64 = 300;
        match queue
            .check_replay_with_timestamp(&request_id, content_for_replay, nonce, timestamp, MAX_AGE_SECONDS)
            .await
        {
            Ok(true) => {
                // Request is new and valid
            }
            Ok(false) => {
                drop(queue);
                tracing::warn!(
                    user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                    request_id = %request_id,
                    "Replay attack detected for key upload"
                );
                return Err(AppError::Validation(
                    "This request was already processed or is too old. Please generate a new request.".to_string(),
                ));
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check replay protection");
                // Fail open - continue but log error (security vs availability tradeoff)
            }
        }
        drop(queue);
    }

    // Store in database
    db::store_key_bundle(&app_context.db_pool, &user_id, &bundle)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                user_id = %user_id,
                "Failed to store key bundle"
            );
            AppError::Unknown(e)
        })?;

    // Invalidate cache
    let mut queue = app_context.queue.lock().await;
    if let Err(e) = queue
        .invalidate_key_bundle_cache(&user_id.to_string())
        .await
    {
        tracing::warn!(error = %e, "Failed to invalidate key bundle cache");
    }
    drop(queue);

    // SECURITY: Always use hashed user_id in logs
    tracing::info!(
        user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
        "Key bundle uploaded successfully"
    );

    // Return success
    Ok((StatusCode::OK, Json(json!({"status": "ok"}))))
}

/// GET /keys/:user_id
/// Retrieves a user's public key bundle
pub async fn get_keys(
    State(app_context): State<Arc<AppContext>>,
    user: AuthenticatedUser,
    Path(user_id_str): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let authenticated_user_id = user.0;

    // SECURITY: Rate limiting to prevent enumeration attacks
    {
        let mut queue = app_context.queue.lock().await;
        match queue
            .increment_message_count(&authenticated_user_id.to_string())
            .await
        {
            Ok(count) => {
                let max_messages = app_context.config.security.max_messages_per_hour;
                if count > max_messages {
                    drop(queue);
                    tracing::warn!(
                        user_hash = %log_safe_id(&authenticated_user_id.to_string(), &app_context.config.logging.hash_salt),
                        count = count,
                        limit = max_messages,
                        "Key bundle request rate limit exceeded"
                    );
                    return Err(AppError::Validation(format!(
                        "Rate limit exceeded: maximum {} requests per hour",
                        max_messages
                    )));
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check rate limit for key bundle request");
                // Fail open - continue but log error
            }
        }
        drop(queue);
    }

    // Parse user_id
    let user_id = Uuid::parse_str(&user_id_str)
        .map_err(|_| AppError::Validation("Invalid user ID format".to_string()))?;

    // Fetch from database
    match db::get_key_bundle(&app_context.db_pool, &user_id).await {
        Ok(Some(bundle)) => {
            // SECURITY: Always use hashed user_id in logs
            tracing::debug!(
                target_user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                "Key bundle retrieved"
            );
            Ok((StatusCode::OK, Json(json!(bundle))))
        }
        Ok(None) => {
            // SECURITY: Always use hashed user_id in logs
            tracing::warn!(
                target_user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                "Key bundle not found"
            );
            Err(AppError::Validation("Key bundle not found".to_string()))
        }
        Err(e) => {
            // SECURITY: Always use hashed user_id in logs
            tracing::error!(
                error = %e,
                target_user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                "Database error"
            );
            Err(AppError::Unknown(e.into()))
        }
    }
}
