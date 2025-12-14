use crate::crypto::encode_base64;
use crate::db::DbPool;
use crate::handlers::connection::ConnectionHandler;
use crate::message::ServerMessage;
use uuid::Uuid;

/// Handles user search by display name
/// Returns list of matching users with their public info
pub async fn handle_search_users(handler: &mut ConnectionHandler, db_pool: &DbPool, query: String) {
    match crate::db::search_users_by_display_name(db_pool, &query).await {
        Ok(users) => {
            let count = users.len();
            let response = ServerMessage::SearchResults { users };
            let _ = handler.send_msgpack(&response).await;
            tracing::debug!(query = %query, count = count, "Search completed");
        }
        Err(e) => {
            tracing::error!(error = %e, query = %query, "Search error");
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
    db_pool: &DbPool,
    user_id: String,
) {
    match Uuid::parse_str(&user_id) {
        Ok(uuid) => match crate::db::get_user_by_id(db_pool, &uuid).await {
            Ok(Some(user)) => {
                let public_key_b64 = encode_base64(&user.identity_key);
                let response = ServerMessage::PublicKey {
                    user_id: user.id.to_string(),
                    username: user.username.clone(),
                    display_name: user.display_name.clone(),
                    public_key: public_key_b64,
                };
                let _ = handler.send_msgpack(&response).await;
                tracing::debug!(user_id = %user_id, "Public key retrieved");
            }
            Ok(None) => {
                handler
                    .send_error("USER_NOT_FOUND", &format!("User {} not found", user_id))
                    .await;
            }
            Err(e) => {
                tracing::error!(error = %e, user_id = %user_id, "Database error");
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
