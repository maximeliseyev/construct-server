use crate::context::AppContext;
use crate::crypto::encode_base64;
use crate::handlers::connection::ConnectionHandler;
use crate::message::ServerMessage;
use crate::utils::log_safe_id;
use uuid::Uuid;

/// Handles user search by display name
/// Returns list of matching users with their public info
pub async fn handle_search_users(handler: &mut ConnectionHandler, ctx: &AppContext, query: String) {
    match crate::db::search_users_by_display_name(&ctx.db_pool, &query).await {
        Ok(users) => {
            let count = users.len();
            let response = ServerMessage::SearchResults { users };
            let _ = handler.send_msgpack(&response).await;
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
    match Uuid::parse_str(&user_id) {
        Ok(uuid) => match crate::db::get_user_by_id(&ctx.db_pool, &uuid).await {
            Ok(Some(user)) => {
                let public_key_b64 = encode_base64(&user.identity_key);
                let response = ServerMessage::PublicKey {
                    user_id: user.id.to_string(),
                    username: user.username.clone(),
                    display_name: user.display_name.clone(),
                    public_key: public_key_b64,
                };
                let _ = handler.send_msgpack(&response).await;
                if ctx.config.logging.enable_user_identifiers {
                    tracing::debug!(user_id = %user_id, "Public key retrieved");
                } else {
                    tracing::debug!(
                        user_hash = %log_safe_id(&user_id, &ctx.config.logging.hash_salt),
                        "Public key retrieved"
                    );
                }
            }
            Ok(None) => {
                handler
                    .send_error("USER_NOT_FOUND", &format!("User {} not found", user_id))
                    .await;
            }
            Err(e) => {
                if ctx.config.logging.enable_user_identifiers {
                    tracing::error!(error = %e, user_id = %user_id, "Database error");
                } else {
                    tracing::error!(
                        error = %e,
                        user_hash = %log_safe_id(&user_id, &ctx.config.logging.hash_salt),
                        "Database error"
                    );
                }
                handler
                    .send_error("SERVER_ERROR", "A server error occurred")
                    .await;
            }
        },
        Err(_) => {
            handler
                .send_error("INVALID_USER_ID", "Invalid user ID format")
                .await;
        }
    }
}
