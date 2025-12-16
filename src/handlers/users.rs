use crate::context::AppContext;
use crate::crypto::ServerCryptoValidator;
use crate::handlers::connection::ConnectionHandler;
use crate::message::ServerMessage;
use uuid::Uuid;

/// Handles user search by display name
/// Returns list of matching users with their public info
pub async fn handle_search_users(handler: &mut ConnectionHandler, ctx: &AppContext, query: String) {
    match crate::db::search_users_by_display_name(&ctx.db_pool, &query).await {
        Ok(users) => {
            let count = users.len();
            let response = ServerMessage::SearchResults { users };
            if handler.send_msgpack(&response).await.is_err() {
                return;
            }
            if ctx.config.logging.enable_user_identifiers {
                tracing::debug!(query = %query, count = count, "Search completed");
            } else {
                tracing::debug!(count = count, "Search completed");
            }
        }
        Err(e) => {
            if ctx.config.logging.enable_user_identifiers {
                tracing::error!(error = %e, query = %query, "Search error");
            } else {
                tracing::error!(error = %e, "Search error");
            }
            handler
                .send_error("SEARCH_FAILED", "Failed to search for users")
                .await;
        }
    }
}

/// Handles request for user's X25519 public key
/// Returns user info and base64-encoded public key for encryption
pub async fn handle_get_public_key(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    user_id: String,
) {
    let uuid = match Uuid::parse_str(&user_id) {
        Ok(u) => u,
        Err(_) => {
            handler.send_error("INVALID_USER_ID", "Invalid user ID format").await;
            return;
        }
    };

    let mut queue = ctx.queue.lock().await;
    if let Ok(Some(cached_bundle)) = queue.get_cached_key_bundle(&user_id).await {
        drop(queue);
        
        let response = ServerMessage::PublicKeyBundle {
            user_id: cached_bundle.user_id.clone(),
            identity_public: cached_bundle.identity_public,
            signed_prekey_public: cached_bundle.signed_prekey_public,
            signature: cached_bundle.signature,
            verifying_key: cached_bundle.verifying_key,
        };
        if handler.send_msgpack(&response).await.is_err() {
            return;
        }
        tracing::debug!(user_id = %user_id, "Key bundle served from cache");
        return;
    }
    drop(queue);

    match crate::db::get_user_key_bundle(&ctx.db_pool, &uuid).await {
        Ok(Some(bundle)) => {
            if let Err(e) = ServerCryptoValidator::validate_key_bundle(&bundle) {
                tracing::warn!("Stored key bundle invalid: {}", e);
                handler.send_error("INVALID_KEY_BUNDLE", "Key expired or invalid").await;
                return;
            }

            let mut queue = ctx.queue.lock().await;
            let cache_hours = ctx.config.security.key_bundle_cache_hours;
            if let Err(e) = queue.cache_key_bundle(&user_id, &bundle, cache_hours).await {
                tracing::warn!(error = %e, "Failed to cache key bundle");
            }
            drop(queue);

            let response = ServerMessage::PublicKeyBundle {
                user_id: bundle.user_id.clone(),
                identity_public: bundle.identity_public,
                signed_prekey_public: bundle.signed_prekey_public,
                signature: bundle.signature,
                verifying_key: bundle.verifying_key,
            };
            if handler.send_msgpack(&response).await.is_err() {
                return;
            }
            tracing::debug!(user_id = %user_id, "Key bundle served from database");
        }
        Ok(None) => {
            handler.send_error("USER_NOT_FOUND", "User not found").await;
        }
        Err(e) => {
            tracing::error!("DB error: {}", e);
            handler.send_error("SERVER_ERROR", "Database error").await;
        }
    }
}
