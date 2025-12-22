use crate::context::AppContext;
use crate::handlers::connection::ConnectionHandler;
use crate::message::{self, ServerMessage};
use uuid::Uuid;

pub async fn handle_search_users(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    query: String,
) {
    match crate::db::search_users_by_username(&ctx.db_pool, &query).await {
        Ok(users) => {
            let response = ServerMessage::SearchResults(message::SearchResultsData { users });
            if handler.send_msgpack(&response).await.is_err() {
                // client disconnected
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to search users");
            handler
                .send_error("SEARCH_FAILED", "Failed to search for users")
                .await;
        }
    }
}

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

    match crate::db::get_user_key_bundle(&ctx.db_pool, &uuid).await {
        Ok(Some(bundle)) => {
            let response = ServerMessage::PublicKeyBundle(message::PublicKeyBundleData {
                user_id: bundle.user_id,
                identity_public: bundle.identity_public,
                signed_prekey_public: bundle.signed_prekey_public,
                signature: bundle.signature,
                verifying_key: bundle.verifying_key,
            });
            if handler.send_msgpack(&response).await.is_err() {
                // client disconnected
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
