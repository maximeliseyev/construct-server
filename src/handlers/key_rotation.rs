use crate::context::AppContext;
use crate::handlers::connection::ConnectionHandler;
use crate::message::ServerMessage;
use crate::e2e::{ServerCryptoValidator, UploadableKeyBundle};
use uuid::Uuid;

/// Handles key bundle update request (API v3)
///
/// This allows users to rotate their entire key bundle.
/// The server validates the format and rate-limits the request,
/// but does not verify the cryptographic signature.
pub async fn handle_rotate_prekey(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    user_id: String,
    bundle_base64: String,
) {
    // 1. Validate user_id
    let uuid = match Uuid::parse_str(&user_id) {
        Ok(u) => u,
        Err(_) => {
            tracing::warn!(user_id = %user_id, "Invalid user ID format for key rotation");
            handler.send_error("INVALID_USER_ID", "Invalid user ID format").await;
            return;
        }
    };

    // 2. Rate limiting for key updates
    let mut queue = ctx.queue.lock().await;
    let key_update_count = match queue.increment_key_update_count(&user_id).await {
        Ok(count) => count,
        Err(e) => {
            tracing::error!(error = %e, "Failed to check key update rate limit");
            // Fail open, but log it.
            0 
        }
    };

    let max_updates = ctx.config.security.max_key_rotations_per_day;
    if key_update_count > max_updates {
        tracing::warn!(
            user_id = %user_id,
            count = key_update_count,
            limit = max_updates,
            "Key update rate limit exceeded"
        );
        drop(queue);
        handler.send_error(
            "RATE_LIMIT_EXCEEDED",
            &format!("Too many key updates. Limit: {}/day", max_updates),
        ).await;
        return;
    }
    drop(queue);

    // 3. Decode base64 to get the JSON bytes for the UploadableKeyBundle
    let key_bundle_bytes = match crate::e2e::decode_base64(&bundle_base64) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(error = %e, "Invalid base64 in key bundle update");
            handler.send_error("INVALID_BUNDLE", "Invalid base64").await;
            return;
        }
    };

    // 4. Deserialize JSON to UploadableKeyBundle
    let bundle: UploadableKeyBundle = match serde_json::from_slice(&key_bundle_bytes) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "Invalid key bundle update (JSON)");
            handler.send_error("INVALID_BUNDLE", "Invalid bundle format").await;
            return;
        }
    };

    // 5. Validate the new bundle
    // Don't allow empty user_id for key rotation (user must already exist)
    if let Err(e) = ServerCryptoValidator::validate_uploadable_key_bundle(&bundle, false) {
        tracing::warn!(
            error = %e,
            user_id = %user_id,
            "Invalid key bundle after rotation"
        );
        handler.send_error("INVALID_KEY_BUNDLE", &e.to_string()).await;
        return;
    }

    // 6. Store the new bundle in the database
    if let Err(e) = crate::db::store_key_bundle(&ctx.db_pool, &uuid, &bundle).await {
        tracing::error!(
            error = %e,
            user_id = %user_id,
            "Failed to store rotated key bundle"
        );
        handler.send_error("SERVER_ERROR", "Failed to update key").await;
        return;
    }

    // 7. Invalidate the Redis cache for this user's key bundle
    let mut queue = ctx.queue.lock().await;
    if let Err(e) = queue.invalidate_key_bundle_cache(&user_id).await {
        tracing::warn!(error = %e, "Failed to invalidate key bundle cache");
    }
    drop(queue);

    // 8. Send success response
    if handler.send_msgpack(&ServerMessage::KeyRotationSuccess).await.is_err() {
        return;
    }
    
    tracing::info!(user_id = %user_id, "Key bundle updated successfully");
}