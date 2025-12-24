use crate::context::AppContext;
use crate::e2e::{BundleData, UploadableKeyBundle};
use crate::handlers::connection::ConnectionHandler;
use crate::message::{self, ServerMessage};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use uuid::Uuid;

/// Helper function to extract PublicKeyBundleData from UploadableKeyBundle
/// Decodes the bundle_data and extracts the first cipher suite's keys
fn extract_first_suite_data(bundle: &UploadableKeyBundle) -> Result<message::PublicKeyBundleData, String> {
    // 1. Decode bundle_data from base64
    let bundle_data_bytes = BASE64
        .decode(&bundle.bundle_data)
        .map_err(|_| "Invalid base64 in bundle_data".to_string())?;

    // 2. Parse JSON to get BundleData
    let bundle_data: BundleData = serde_json::from_slice(&bundle_data_bytes)
        .map_err(|e| format!("Invalid JSON in bundle_data: {}", e))?;

    // 3. Get the first suite (suite_id = 1, CLASSIC_X25519)
    let first_suite = bundle_data
        .supported_suites
        .first()
        .ok_or("No cipher suites in bundle".to_string())?;

    // 4. Return data in the format expected by WebSocket clients
    Ok(message::PublicKeyBundleData {
        user_id: bundle_data.user_id,
        identity_public: first_suite.identity_key.clone(),
        signed_prekey_public: first_suite.signed_prekey.clone(),
        signature: bundle.signature.clone(),
        verifying_key: bundle.master_identity_key.clone(),
    })
}

pub async fn handle_search_users(handler: &mut ConnectionHandler, ctx: &AppContext, query: String) {
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
            handler
                .send_error("INVALID_USER_ID", "Invalid user ID format")
                .await;
            return;
        }
    };

    match crate::db::get_key_bundle(&ctx.db_pool, &uuid).await {
        Ok(Some(bundle)) => {
            match extract_first_suite_data(&bundle) {
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
