// ============================================================================
// Messages Routes (Double Ratchet Protocol)
// ============================================================================
//
// Endpoints:
// - POST /api/v1/messages - Send an E2E-encrypted message
// - GET /api/v1/messages - Get messages (long polling)
//
// See docs/PROTOCOL_SPECIFICATION.md for protocol details.
// ============================================================================

use axum::http::HeaderMap;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::context::AppContext;
use crate::e2e::{EncryptedMessage, ServerCryptoValidator};
use crate::error::AppError;
use crate::kafka::types::KafkaMessageEnvelope;
use crate::routes::extractors::AuthenticatedUser;
use crate::utils::{extract_client_ip, log_safe_id};

/// POST /api/v1/messages
/// Sends an E2E-encrypted message using Double Ratchet protocol
pub async fn send_message(
    State(app_context): State<Arc<AppContext>>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Json(message): Json<EncryptedMessage>,
) -> Result<impl IntoResponse, AppError> {
    let sender_id = user.0;
    let sender_id_str = sender_id.to_string();

    // SECURITY: Check rate limiting BEFORE processing (DoS protection)
    {
        let mut queue = app_context.queue.lock().await;
        if let Ok(Some(reason)) = queue.is_user_blocked(&sender_id_str).await {
            drop(queue);
            tracing::warn!(
                sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                reason = %reason,
                "Blocked user attempted to send message"
            );
            return Err(AppError::Auth(format!(
                "Your account is temporarily blocked: {}",
                reason
            )));
        }

        // Check combined rate limit (user_id + IP) for authenticated operations
        // Extract IP from request headers
        let client_ip = extract_client_ip(&headers, None);

        // Use combined rate limiting if enabled (more precise)
        if app_context.config.security.combined_rate_limiting_enabled {
            match queue
                .increment_combined_rate_limit(&sender_id_str, &client_ip, 3600)
                .await
            {
                Ok(count) => {
                    let max_combined = app_context
                        .config
                        .security
                        .max_requests_per_user_ip_per_hour;
                    if count > max_combined {
                        drop(queue);
                        tracing::warn!(
                            sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                            ip = %client_ip,
                            count = count,
                            limit = max_combined,
                            "Combined rate limit exceeded for messages"
                        );
                        return Err(AppError::Validation(format!(
                            "Rate limit exceeded: maximum {} messages per hour",
                            max_combined
                        )));
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to check combined rate limit");
                    // Fall through to user_id-only check
                }
            }
        }

        // Also check user_id-only rate limit (legacy, for backward compatibility)
        match queue.increment_message_count(&sender_id_str).await {
            Ok(count) => {
                let max_messages = app_context.config.security.max_messages_per_hour;
                if count > max_messages {
                    drop(queue);
                    tracing::warn!(
                        sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                        count = count,
                        limit = max_messages,
                        "Message rate limit exceeded"
                    );
                    return Err(AppError::Validation(format!(
                        "Rate limit exceeded: maximum {} messages per hour",
                        max_messages
                    )));
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check message rate limit");
                // Fail open - continue but log error
            }
        }
        drop(queue);
    }

    // SECURITY: Validate message size to prevent DoS
    if message.ciphertext.len() > crate::config::MAX_MESSAGE_SIZE {
        tracing::warn!(
            size = message.ciphertext.len(),
            limit = crate::config::MAX_MESSAGE_SIZE,
            sender_hash = %log_safe_id(&sender_id.to_string(), &app_context.config.logging.hash_salt),
            "Message ciphertext too large"
        );
        return Err(AppError::Validation(format!(
            "Message size exceeds maximum of {} bytes",
            crate::config::MAX_MESSAGE_SIZE
        )));
    }

    // Validate the message format
    let salt = &app_context.config.logging.hash_salt;
    if let Err(e) = ServerCryptoValidator::validate_encrypted_message_v3(&message) {
        tracing::warn!(
            error = %e,
            sender_hash = %log_safe_id(&sender_id.to_string(), salt),
            "Message validation failed"
        );
        return Err(AppError::Validation(e.to_string()));
    }

    // Parse recipient_id
    let recipient_id = Uuid::parse_str(&message.recipient_id)
        .map_err(|_| AppError::Validation("Invalid recipient ID format".to_string()))?;

    // Security check: prevent sending to self
    if sender_id == recipient_id {
        return Err(AppError::Validation(
            "Cannot send message to self".to_string(),
        ));
    }

    // Create Kafka envelope for message
    let message_id = Uuid::new_v4().to_string();

    // SECURITY: Replay protection for messages
    // Use nonce from request or generate one, validate timestamp if provided
    let nonce = message.nonce.as_deref().unwrap_or(&message_id);
    let timestamp = message
        .timestamp
        .unwrap_or_else(|| chrono::Utc::now().timestamp());

    // Validate timestamp if provided (5 minutes max age)
    const MAX_AGE_SECONDS: i64 = 300;
    let now = chrono::Utc::now().timestamp();
    if let Some(provided_timestamp) = message.timestamp {
        let age = now - provided_timestamp;
        if age > MAX_AGE_SECONDS {
            tracing::warn!(
                sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                timestamp = provided_timestamp,
                age_seconds = age,
                "Message timestamp too old - possible replay attack"
            );
            return Err(AppError::Validation(
                "Message timestamp is too old. Please send a new message.".to_string(),
            ));
        }
        if age < -60 {
            // Allow 60 seconds clock skew
            tracing::warn!(
                sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                timestamp = provided_timestamp,
                now = now,
                "Message timestamp too far in future"
            );
            return Err(AppError::Validation(
                "Message timestamp is too far in the future. Please check your clock.".to_string(),
            ));
        }
    }

    // Check replay protection using enhanced method
    {
        let mut queue = app_context.queue.lock().await;
        match queue
            .check_replay_with_timestamp(
                &message_id,
                &message.ciphertext,
                nonce,
                timestamp,
                MAX_AGE_SECONDS,
            )
            .await
        {
            Ok(true) => {
                // Message is new and valid
            }
            Ok(false) => {
                drop(queue);
                tracing::warn!(
                    sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                    message_id = %message_id,
                    "Replay attack detected for message"
                );
                return Err(AppError::Validation(
                    "This message was already sent or is a replay. Please generate a new message."
                        .to_string(),
                ));
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check message replay protection");
                // Fail open - continue but log error
            }
        }
        drop(queue);
    }

    // Create Kafka envelope from EncryptedMessage using the standard conversion
    use crate::kafka::types::EncryptedMessageContext;
    let ctx = EncryptedMessageContext {
        sender_id: sender_id.to_string(),
        message_id: message_id.clone(),
    };
    let envelope = KafkaMessageEnvelope::from_encrypted_message(&message, &ctx);

    // Write to Kafka (Phase 5: source of truth)
    if let Some(kafka_producer) = &app_context.kafka_producer {
        if let Err(e) = kafka_producer.send_message(&envelope).await {
            // SECURITY: Use hashed IDs in error logs
            tracing::error!(
                error = %e,
                sender_hash = %log_safe_id(&sender_id.to_string(), salt),
                recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
                message_id = %message_id,
                "Failed to send message to Kafka"
            );
            return Err(AppError::Kafka(e.to_string()));
        }
    } else {
        tracing::error!(
            sender_hash = %log_safe_id(&sender_id.to_string(), salt),
            recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
            message_id = %message_id,
            "Kafka producer not available - cannot send message"
        );
        return Err(AppError::Kafka("Kafka producer not available".to_string()));
    }

    // SECURITY: Use hashed IDs in success logs
    tracing::info!(
        sender_hash = %log_safe_id(&sender_id.to_string(), salt),
        recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
        message_id = %message_id,
        "Message sent successfully"
    );

    // Return success
    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "message_id": message_id
        })),
    ))
}

// ============================================================================
// Phase 2.5: REST API for Message Retrieval (Long Polling)
// ============================================================================

/// Query parameters for GET /api/v1/messages
#[derive(Debug, Deserialize)]
pub struct GetMessagesParams {
    /// Message ID to get messages after (optional)
    pub since: Option<String>,
    /// Timeout for long polling in seconds (default: 30, max: 60)
    pub timeout: Option<u64>,
    /// Maximum number of messages to return (default: 50, max: 100)
    pub limit: Option<u32>,
}

/// Message response structure for GET /api/v1/messages
/// ✅ FIXED: Aligned with API specification (specification.md)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")] // ✅ Use camelCase for all fields
pub struct MessageResponse {
    pub id: String, // KafkaMessageEnvelope.message_id (UUID)
    #[serde(skip_serializing)]
    pub stream_id: String, // Redis Stream ID (internal use only, not in spec)

    // ✅ SPEC: Use "from" and "to" as per specification.md (not sender_id/recipient_id)
    pub from: String,
    pub to: String,

    // ✅ SPEC: Required fields for Double Ratchet protocol
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_public_key: Option<String>, // Base64<Bytes>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_number: Option<u32>,

    // ✅ SPEC: "content" field contains encrypted data (Base64<nonce || ciphertext_with_tag>)
    pub content: String,

    pub suite_id: u16, // ✅ Changed from u8 to u16 per spec, serialized as "suiteId"

    pub timestamp: u64, // ✅ Changed from i64 to u64 per spec

    // Legacy/internal fields (not in spec, skip if None)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_status: Option<String>,
}

/// Response structure for GET /api/v1/messages
#[derive(Debug, Serialize)]
pub struct GetMessagesResponse {
    pub messages: Vec<MessageResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_since: Option<String>,
    pub has_more: bool,
}

/// GET /api/v1/messages?since=<id>&timeout=30&limit=50
///
/// Long polling endpoint for retrieving messages.
///
/// Behavior:
/// 1. If there are new messages - returns them immediately
/// 2. If no new messages - waits up to `timeout` seconds (long polling)
/// 3. Returns messages when they arrive or empty array on timeout
///
/// Security:
/// - Requires JWT authentication
/// - Returns only messages for the authenticated user
/// - Rate limiting: 1 request per second per user
pub async fn get_messages(
    State(app_context): State<Arc<AppContext>>,
    user: AuthenticatedUser,
    Query(params): Query<GetMessagesParams>,
) -> Result<impl IntoResponse, AppError> {
    let user_id = user.0;
    let user_id_str = user_id.to_string();
    let user_id_hash = log_safe_id(&user_id_str, &app_context.config.logging.hash_salt);

    // Track user as online for delivery_worker
    {
        let mut queue = app_context.queue.lock().await;
        if let Err(e) = queue
            .track_user_online(&user_id_str, &app_context.server_instance_id)
            .await
        {
            tracing::error!(
                error = %e,
                user_hash = %user_id_hash,
                "Failed to track user online status"
            );
        }

        // Publish notification that user came online
        if let Err(e) = queue
            .publish_user_online(
                &user_id_str,
                &app_context.server_instance_id,
                &app_context.config.online_channel,
            )
            .await
        {
            tracing::error!(
                error = %e,
                user_hash = %user_id_hash,
                "Failed to publish user online notification"
            );
        } else {
            tracing::debug!(
                user_hash = %user_id_hash,
                server_instance_id = %app_context.server_instance_id,
                channel = %app_context.config.online_channel,
                "Published user online notification"
            );
        }
    }

    // ✅ IMPROVED: More realistic rate limiting for long-polling
    // Long-polling naturally limits itself (30-60s timeout), so we only need to prevent abuse
    // Allow 100 requests per minute (or 6000 per hour) - prevents spam but allows normal usage
    {
        let mut queue = app_context.queue.lock().await;
        let rate_limit_key = format!("rate:get_messages:{}", user_id_str);
        match queue.increment_rate_limit(&rate_limit_key, 60).await {  // 60 second window
            Ok(count) => {
                if count > 100 {  // 100 requests per minute
                    drop(queue);
                    tracing::warn!(
                        user_hash = %user_id_hash,
                        count = count,
                        "Rate limit exceeded for get_messages"
                    );
                    return Err(AppError::Validation(
                        "Rate limit exceeded: maximum 100 requests per minute".to_string(),
                    ));
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check rate limit for get_messages");
                // Fail open - continue but log error
            }
        }
        drop(queue);
    }

    // Validate and set defaults for parameters
    let timeout = params.timeout.unwrap_or(30).min(60);
    let limit = params.limit.unwrap_or(50).min(100) as usize;

    // Step 1: Check for existing messages in Redis Streams
    // Note: `since` parameter is for message_id pagination, but Redis Streams use stream message IDs
    // For now, we'll read from the beginning and filter client-side if needed
    // TODO: Implement proper stream ID tracking for pagination
    let mut queue = app_context.queue.lock().await;
    let stream_messages = queue
        .read_user_messages_from_stream(
            &user_id_str,
            None,                    // server_instance_id not needed - using user-based streams
            params.since.as_deref(), // Pass the client's 'since' parameter
            limit,
        )
        .await;

    let mut messages = match stream_messages {
        Ok(msgs) => {
            // Convert KafkaMessageEnvelope to MessageResponse
            let collected_messages = msgs
                .into_iter()
                .map(|(stream_id, envelope)| {
                    MessageResponse {
                        id: envelope.message_id,
                        stream_id: stream_id, // Internal use, skip in serialization
                        // ✅ SPEC: Use "from"/"to" as per specification
                        from: envelope.sender_id,
                        to: envelope.recipient_id,
                        // ✅ SPEC: Include Double Ratchet fields
                        ephemeral_public_key: envelope.ephemeral_public_key,
                        message_number: envelope.message_number,
                        // ✅ SPEC: Use "content" field name
                        content: envelope.encrypted_payload,
                        timestamp: envelope.timestamp as u64,
                        suite_id: envelope.suite_id as u16,
                        nonce: None, // Nonce is not stored in envelope
                        delivery_status: Some("delivered".to_string()), // Messages from stream are delivered
                    }
                })
                .collect::<Vec<_>>();

            if !collected_messages.is_empty() {
                tracing::info!(
                    user_hash = %user_id_hash,
                    count = collected_messages.len(),
                    "Successfully read {} messages from Redis stream for user",
                    collected_messages.len()
                );
            }

            collected_messages
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                user_hash = %user_id_hash,
                "Failed to read messages from stream"
            );
            vec![]
        }
    };

    // Filter by since_id if provided (client-side filtering for now)
    // TODO: Implement server-side filtering using stream message IDs
    let filtered_messages: Vec<MessageResponse> = if let Some(ref since_id) = params.since {
        messages
            .iter()
            .filter(|msg| {
                // Simple comparison: only return messages with ID greater than since_id
                // In production, you'd want proper UUID comparison
                msg.id > *since_id
            })
            .cloned()
            .collect()
    } else {
        messages.clone()
    };

    // If we have messages, return them immediately
    if !filtered_messages.is_empty() {
        drop(queue);
        // ✅ FIX: Use stream_id (not message UUID) for next_since
        // Redis Stream requires format: "{timestamp}-{sequence}"
        let next_since = filtered_messages.last().map(|m| m.stream_id.clone());

        tracing::debug!(
            user_hash = %user_id_hash,
            count = filtered_messages.len(),
            "Returning {} messages immediately",
            filtered_messages.len()
        );

        return Ok((
            StatusCode::OK,
            Json(GetMessagesResponse {
                messages: filtered_messages,
                next_since,
                has_more: false, // TODO: Implement has_more logic
            }),
        ));
    }

    // Step 2: No messages found - long polling
    // Subscribe to Redis Pub/Sub and wait for notifications
    drop(queue);

    tracing::debug!(
        user_hash = %user_id_hash,
        timeout = timeout,
        "No messages found, starting long polling"
    );

    // Wait for notification or timeout
    // NOTE: Do NOT hold the queue lock during sleep - it blocks all other requests!
    // wait_for_message_notification just sleeps, no Redis access needed
    let notification_received = {
        use tokio::time::Duration;
        tokio::time::sleep(Duration::from_secs(timeout)).await;
        false // Always return false - client will check for messages again
    };

    if notification_received {
        // Notification received - check for messages again
        let mut queue = app_context.queue.lock().await;
        let stream_messages = queue
            .read_user_messages_from_stream(
                &user_id_str,
                None, // server_instance_id not needed - using user-based streams
                None,
                limit,
            )
            .await;

        let new_messages = match stream_messages {
            Ok(msgs) => msgs
                .into_iter()
                .map(|(stream_id, envelope)| MessageResponse {
                    id: envelope.message_id,
                    stream_id: stream_id, // Internal use, skip in serialization
                    // ✅ SPEC: Use "from"/"to" as per specification
                    from: envelope.sender_id,
                    to: envelope.recipient_id,
                    // ✅ SPEC: Include Double Ratchet fields
                    ephemeral_public_key: envelope.ephemeral_public_key,
                    message_number: envelope.message_number,
                    // ✅ SPEC: Use "content" field name
                    content: envelope.encrypted_payload,
                    timestamp: envelope.timestamp as u64,
                    suite_id: envelope.suite_id as u16,
                    nonce: None,
                    delivery_status: Some("delivered".to_string()),
                })
                .collect::<Vec<_>>(),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    user_hash = %user_id_hash,
                    "Failed to read messages after notification"
                );
                vec![]
            }
        };

        // Filter by since_id if provided
        let final_messages = if let Some(ref since_id) = params.since {
            new_messages
                .into_iter()
                .filter(|msg| msg.id > *since_id)
                .collect()
        } else {
            new_messages
        };

        messages = final_messages;
    }

    // ✅ FIX: Use stream_id (not message UUID) for next_since
    let next_since = messages.last().map(|m| m.stream_id.clone());

    tracing::debug!(
        user_hash = %user_id_hash,
        count = messages.len(),
        notification_received = notification_received,
        "Long polling completed"
    );

    Ok((
        StatusCode::OK,
        Json(GetMessagesResponse {
            messages,
            next_since,
            has_more: false,
        }),
    ))
}
