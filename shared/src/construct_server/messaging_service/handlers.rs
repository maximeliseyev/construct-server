// ============================================================================
// Messaging Service Handlers - Phase 2.6.4 + APNs Integration
// ============================================================================
//
// Wrapper handlers that convert MessagingServiceContext to AppContext
// for use with existing messaging-related route handlers.
//
// Phase 2.9: Added APNs push notification support
// - send_push_notification: Send silent push when message arrives
// - Non-blocking push sends (don't fail message delivery if push fails)
//
// ============================================================================

use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
    response::IntoResponse,
};
use std::sync::Arc;

use crate::messaging_service::MessagingServiceContext;
use crate::routes::extractors::AuthenticatedUser;
use crate::routes::messages;
use crate::utils::log_safe_id;
use construct_crypto::EncryptedMessage;
use construct_error::AppError;
use construct_types::message::EndSessionData;

/// Wrapper for send_message handler (POST /api/v1/messages)
pub async fn send_message(
    State(context): State<Arc<MessagingServiceContext>>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Json(message): Json<EncryptedMessage>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());

    // Store recipient_id before message is consumed
    let recipient_id = message.recipient_id.clone();

    // Send message (existing handler)
    let result = messages::send_message(State(app_context), user, headers, Json(message)).await?;

    // ✅ NEW: Send push notification asynchronously (non-blocking)
    if context.config.apns.enabled {
        let context_clone = context.clone();
        tokio::spawn(async move {
            if let Err(e) = send_push_notification(&context_clone, &recipient_id).await {
                tracing::warn!(
                    recipient_hash = %log_safe_id(&recipient_id, &context_clone.config.logging.hash_salt),
                    error = %e,
                    "Failed to send push notification (non-fatal)"
                );
            }
        });
    }

    Ok(result)
}

/// Wrapper for get_messages handler (GET /api/v1/messages?since=<id>)
pub async fn get_messages(
    State(context): State<Arc<MessagingServiceContext>>,
    user: AuthenticatedUser,
    query: Query<messages::GetMessagesParams>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    messages::get_messages(State(app_context), user, query).await
}

// ============================================================================
// APNs Push Notification Helper
// ============================================================================

/// Send silent push notification to wake up recipient's app
///
/// This is called asynchronously after message is stored, so failures don't
/// affect message delivery. The push notification is silent (no content)
/// and only wakes the app to fetch messages via long-polling.
async fn send_push_notification(
    context: &MessagingServiceContext,
    recipient_id: &str,
) -> anyhow::Result<()> {
    // ✅ FIXED: Query encrypted device tokens (not plain text)
    #[derive(sqlx::FromRow)]
    struct DeviceTokenRow {
        device_token_encrypted: Vec<u8>,
    }

    let rows = sqlx::query_as::<_, DeviceTokenRow>(
        "SELECT device_token_encrypted FROM device_tokens 
         WHERE user_id = $1::uuid AND enabled = true",
    )
    .bind(recipient_id)
    .fetch_all(&*context.db_pool)
    .await?;

    if rows.is_empty() {
        tracing::debug!(
            recipient_hash = %log_safe_id(recipient_id, &context.config.logging.hash_salt),
            "No active device tokens for recipient - push not sent"
        );
        return Ok(());
    }

    tracing::debug!(
        recipient_hash = %log_safe_id(recipient_id, &context.config.logging.hash_salt),
        token_count = rows.len(),
        "Sending push notification to {} device(s)",
        rows.len()
    );

    // ✅ Decrypt each token before sending
    // TODO: Implement DeviceTokenEncryption::decrypt()
    // For now, we'll skip push if encryption not implemented
    tracing::warn!(
        recipient_hash = %log_safe_id(recipient_id, &context.config.logging.hash_salt),
        "Device token decryption not yet implemented - push notifications disabled"
    );

    // NOTE: Temporarily disabled until encryption is implemented
    // The schema is ready (device_token_encrypted), but we need to:
    // 1. Implement DeviceTokenEncryption module
    // 2. Decrypt tokens before sending to APNs
    // 3. Re-enable this code

    /* PLACEHOLDER for future implementation:

    use crate::device_token_encryption::DeviceTokenEncryption;

    let mut send_errors = 0;
    for row in &rows {
        // Decrypt the token
        let token = match DeviceTokenEncryption::decrypt(&row.device_token_encrypted) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to decrypt device token: {}", e);
                send_errors += 1;
                continue;
            }
        };

        match context.apns_client
            .send_silent_push(&token, None)
            .await
        {
            Ok(_) => {
                tracing::debug!(
                    recipient_hash = %log_safe_id(recipient_id, &context.config.logging.hash_salt),
                    "Silent push notification sent successfully"
                );
            }
            Err(e) => {
                send_errors += 1;
                tracing::warn!(
                    recipient_hash = %log_safe_id(recipient_id, &context.config.logging.hash_salt),
                    error = %e,
                    "Failed to send push notification to device"
                );
            }
        }
    }

    if send_errors > 0 {
        tracing::warn!(
            recipient_hash = %log_safe_id(recipient_id, &context.config.logging.hash_salt),
            total_devices = rows.len(),
            failed = send_errors,
            "Push notification partially failed"
        );
    }
    */

    Ok(())
}

// ============================================================================
// Phase 4.5: Control Messages Handler
// ============================================================================

/// Wrapper for send_control_message handler (POST /api/v1/control)
pub async fn send_control_message(
    State(context): State<Arc<MessagingServiceContext>>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Json(data): Json<EndSessionData>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    messages::send_control_message(State(app_context), user, headers, Json(data)).await
}
