use crate::context::AppContext;
use crate::db;
use crate::e2e::{ServerCryptoValidator, UploadableKeyBundle};
use crate::utils::add_security_headers;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming as IncomingBody, HeaderMap, Response, StatusCode};
use serde_json::json;
use uuid::Uuid;
use crate::handlers::connection::ConnectionHandler;
use crate::message::{PublicKeyBundleData, ServerMessage};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

/// POST /keys/upload
/// Uploads or updates a user's key bundle
pub async fn handle_upload_keys(
    ctx: &AppContext,
    headers: &HeaderMap,
    body: IncomingBody,
) -> Response<Full<Bytes>> {
    // 1. Extract and verify JWT token
    let user_id = match extract_user_id_from_jwt(ctx, headers) {
        Ok(id) => id,
        Err(response) => return response,
    };

    // 2. Read request body
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to read request body");
            return error_response(StatusCode::BAD_REQUEST, "Failed to read request body");
        }
    };

    // 3. Parse JSON to UploadableKeyBundle
    let bundle: UploadableKeyBundle = match serde_json::from_slice(&body_bytes) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "Invalid JSON in request body");
            return error_response(StatusCode::BAD_REQUEST, "Invalid JSON format");
        }
    };

    // 4. Validate the bundle
    // Don't allow empty user_id for key updates (user must already exist)
    if let Err(e) = ServerCryptoValidator::validate_uploadable_key_bundle(&bundle, false) {
        tracing::warn!(
            error = %e,
            user_id = %user_id,
            "Key bundle validation failed"
        );
        return error_response(StatusCode::BAD_REQUEST, &e.to_string());
    }

    // 4.5. SECURITY: Verify that user_id in bundle matches authenticated user
    use crate::e2e::BundleData;

    let bundle_data_bytes = match BASE64.decode(&bundle.bundle_data) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to decode bundle_data");
            return error_response(StatusCode::BAD_REQUEST, "Invalid bundle_data encoding");
        }
    };

    let bundle_data: BundleData = match serde_json::from_slice(&bundle_data_bytes) {
        Ok(data) => data,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse bundle_data");
            return error_response(StatusCode::BAD_REQUEST, "Invalid bundle_data format");
        }
    };

    // Verify that user_id in bundle matches the authenticated user
    if bundle_data.user_id != user_id.to_string() {
        tracing::warn!(
            authenticated_user = %user_id,
            bundle_user_id = %bundle_data.user_id,
            "user_id mismatch: authenticated user attempting to upload bundle for different user"
        );
        return error_response(
            StatusCode::FORBIDDEN,
            "user_id in bundle does not match authenticated user"
        );
    }

    // 5. Store in database
    if let Err(e) = db::store_key_bundle(&ctx.db_pool, &user_id, &bundle).await {
        tracing::error!(
            error = %e,
            user_id = %user_id,
            "Failed to store key bundle"
        );
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to store key bundle");
    }

    // 6. Invalidate cache
    let mut queue = ctx.queue.lock().await;
    if let Err(e) = queue.invalidate_key_bundle_cache(&user_id.to_string()).await {
        tracing::warn!(error = %e, "Failed to invalidate key bundle cache");
    }
    drop(queue);

    // SECURITY: Always use hashed user_id in logs
    tracing::info!(
        user_hash = %crate::utils::log_safe_id(&user_id.to_string(), &ctx.config.logging.hash_salt),
        "Key bundle uploaded successfully"
    );

    // 7. Return success
    json_response(StatusCode::OK, json!({"status": "ok"}))
}

/// GET /keys/{userId}
/// Retrieves a user's public key bundle
pub async fn handle_get_keys(
    ctx: &AppContext,
    headers: &HeaderMap,
    user_id_str: &str,
) -> Response<Full<Bytes>> {
    // 1. Verify JWT token (must be authenticated to get keys)
    let authenticated_user_id = match extract_user_id_from_jwt(ctx, headers) {
        Ok(id) => id,
        Err(response) => return response,
    };

    // 1.5. SECURITY: Rate limiting to prevent enumeration attacks
    // Check rate limit before parsing user_id (DoS protection)
    {
        let mut queue = ctx.queue.lock().await;
        match queue.increment_message_count(&authenticated_user_id.to_string()).await {
            Ok(count) => {
                let max_messages = ctx.config.security.max_messages_per_hour;
                if count > max_messages {
                    drop(queue);
                    tracing::warn!(
                        user_hash = %crate::utils::log_safe_id(&authenticated_user_id.to_string(), &ctx.config.logging.hash_salt),
                        count = count,
                        limit = max_messages,
                        "Key bundle request rate limit exceeded"
                    );
                    return error_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        &format!("Rate limit exceeded: maximum {} requests per hour", max_messages)
                    );
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check rate limit for key bundle request");
                // Fail open - continue but log error
            }
        }
        drop(queue);
    }

    // 2. Parse user_id
    let user_id = match Uuid::parse_str(user_id_str) {
        Ok(id) => id,
        Err(_) => {
            return error_response(StatusCode::BAD_REQUEST, "Invalid user ID format");
        }
    };

    // 3. Fetch from database
    match db::get_key_bundle(&ctx.db_pool, &user_id).await {
        Ok(Some(bundle)) => {
            // SECURITY: Always use hashed user_id in logs
            tracing::debug!(
                target_user_hash = %crate::utils::log_safe_id(&user_id.to_string(), &ctx.config.logging.hash_salt),
                "Key bundle retrieved"
            );
            json_response(StatusCode::OK, json!(bundle))
        }
        Ok(None) => {
            // SECURITY: Always use hashed user_id in logs
            tracing::warn!(
                target_user_hash = %crate::utils::log_safe_id(&user_id.to_string(), &ctx.config.logging.hash_salt),
                "Key bundle not found"
            );
            error_response(StatusCode::NOT_FOUND, "Key bundle not found")
        }
        Err(e) => {
            // SECURITY: Always use hashed user_id in logs
            tracing::error!(
                error = %e,
                target_user_hash = %crate::utils::log_safe_id(&user_id.to_string(), &ctx.config.logging.hash_salt),
                "Database error"
            );
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extracts user_id from JWT token in Authorization header
fn extract_user_id_from_jwt(
    ctx: &AppContext,
    headers: &HeaderMap,
) -> Result<Uuid, Response<Full<Bytes>>> {
    // Extract Authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "Missing authorization header"))?;

    // Extract token from "Bearer <token>"
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "Invalid authorization format"))?;

    // Verify and decode JWT
    let claims = ctx
        .auth_manager
        .verify_token(token)
        .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "Invalid or expired token"))?;

    // Parse user_id from claims
    Uuid::parse_str(&claims.sub).map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid user ID in token",
        )
    })
}

/// Creates a JSON response
fn json_response(status: StatusCode, body: serde_json::Value) -> Response<Full<Bytes>> {
    let json_bytes = serde_json::to_vec(&body).unwrap_or_default();
    let mut response = Response::new(Full::new(Bytes::from(json_bytes)));
    *response.status_mut() = status;
    // SECURITY: Handle header parsing errors gracefully
    match "application/json".parse() {
        Ok(content_type) => {
            response.headers_mut().insert("content-type", content_type);
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to parse Content-Type header (this should never happen)");
            // This should never happen, but if it does, we continue without the header
        }
    }
    
    // SECURITY: Add security headers to protect against XSS, clickjacking, etc.
    // For API endpoints, assume HTTPS in production (can be made configurable)
    add_security_headers(response.headers_mut(), true);
    
    response
}

/// Creates an error JSON response
fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    json_response(status, json!({"error": message}))
}

/// Helper function to extract PublicKeyBundleData from UploadableKeyBundle
/// Decodes the bundle_data and extracts the first cipher suite's keys
fn extract_first_suite_data(bundle: &UploadableKeyBundle, username: &str) -> Result<PublicKeyBundleData, String> {
    // 1. Decode bundle_data from base64
    let bundle_data_bytes = BASE64
        .decode(&bundle.bundle_data)
        .map_err(|_| "Invalid base64 in bundle_data".to_string())?;

    // 2. Parse JSON to get BundleData
    let bundle_data: crate::e2e::BundleData = serde_json::from_slice(&bundle_data_bytes)
        .map_err(|e| format!("Invalid JSON in bundle_data: {}", e))?;

    // 3. Get the first suite (suite_id = 1, CLASSIC_X25519)
    let first_suite = bundle_data
        .supported_suites
        .first()
        .ok_or("No cipher suites in bundle".to_string())?;

    // 4. Return data in the format expected by WebSocket clients
    Ok(PublicKeyBundleData {
        user_id: bundle_data.user_id,
        username: username.to_string(),
        identity_public: first_suite.identity_key.clone(),
        signed_prekey_public: first_suite.signed_prekey.clone(),
        signature: bundle.signature.clone(),
        verifying_key: bundle.master_identity_key.clone(),
    })
}

pub async fn handle_get_public_key(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    user_id: String,
) {
    let uuid = match Uuid::parse_str(&user_id) {
        Ok(u) => u,
        Err(_) => {
            handler
                .send_error("INVALID_USER_ID", "Invalid user ID format")
                .await;
            return;
        }
    };

    match crate::db::get_key_bundle(&ctx.db_pool, &uuid).await {
        Ok(Some((bundle, username))) => {
            match extract_first_suite_data(&bundle, &username) {
                Ok(data) => {
                    let response = ServerMessage::PublicKeyBundle(data);
                    if handler.send_msgpack(&response).await.is_err() {
                        // client disconnected
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to extract suite data from key bundle");
                    handler
                        .send_error("INVALID_BUNDLE", "Invalid key bundle format")
                        .await;
                }
            }
        }
        Ok(None) => {
            handler.send_error("USER_NOT_FOUND", "User not found").await;
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to get user key bundle");
            handler
                .send_error("SERVER_ERROR", "Failed to get user key bundle")
                .await;
        }
    }
}
