// ============================================================================
// Messages Routes
// ============================================================================
//
// Endpoints:
// - POST /messages/send - Send an E2E-encrypted message
//
// ============================================================================

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use axum::http::HeaderMap;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use crate::context::AppContext;
use crate::e2e::{EncryptedMessageV3, ServerCryptoValidator};
use crate::error::AppError;
use crate::kafka::types::{KafkaMessageEnvelope, MessageType};
use crate::routes::extractors::AuthenticatedUser;
use crate::utils::{log_safe_id, extract_client_ip};

/// POST /messages/send
/// Sends an E2E-encrypted message
pub async fn send_message(
    State(app_context): State<Arc<AppContext>>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Json(message): Json<EncryptedMessageV3>,
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
                    let max_combined = app_context.config.security.max_requests_per_user_ip_per_hour;
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
    let timestamp = message.timestamp.unwrap_or_else(|| chrono::Utc::now().timestamp());
    
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
            .check_replay_with_timestamp(&message_id, &message.ciphertext, nonce, timestamp, MAX_AGE_SECONDS)
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
                    "This message was already sent or is a replay. Please generate a new message.".to_string(),
                ));
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check message replay protection");
                // Fail open - continue but log error
            }
        }
        drop(queue);
    }

    // Calculate content hash for deduplication (used by delivery worker)
    let mut hasher = Sha256::new();
    hasher.update(message_id.as_bytes());
    hasher.update(message.ciphertext.as_bytes());
    if let Some(ref nonce_str) = message.nonce {
        hasher.update(nonce_str.as_bytes());
    }
    let content_hash = format!("{:x}", hasher.finalize());

    let envelope = KafkaMessageEnvelope {
        message_id: message_id.clone(),
        sender_id: sender_id.to_string(),
        recipient_id: recipient_id.to_string(),
        timestamp: chrono::Utc::now().timestamp(),
        message_type: MessageType::DirectMessage,
        // REST API v3 doesn't provide ephemeral key - use placeholder
        ephemeral_public_key: None,
        message_number: None,
        mls_payload: None,
        group_id: None,
        encrypted_payload: message.ciphertext.clone(),
        content_hash,
        suite_id: message.suite_id as u8, // Convert u16 to u8 (valid range 0-255)
        origin_server: None,
        federated: false,
        server_signature: None,
    };

    // Write to Kafka (Phase 5: source of truth)
    if let Err(e) = app_context.kafka_producer.send_message(&envelope).await {
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
