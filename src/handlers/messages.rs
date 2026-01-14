use crate::IncomingBody;
use crate::context::AppContext;
use crate::e2e::{EncryptedMessageV3, ServerCryptoValidator};
use crate::error::AppError;
use crate::kafka::types::{KafkaMessageEnvelope, MessageType};
use crate::utils::{add_security_headers, log_safe_id};
use axum::http::HeaderMap;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// POST /messages/send
/// Sends an E2E-encrypted message
pub async fn handle_send_message(
    ctx: &AppContext,
    headers: HeaderMap,
    body: IncomingBody,
) -> Result<Response<Full<Bytes>>, AppError> {
    // 1. Extract and verify JWT token
    let sender_id = extract_user_id_from_jwt(ctx, &headers)?;

    // 1.5. SECURITY: Check rate limiting BEFORE reading body (DoS protection)
    // This prevents attackers from sending large requests before rate limit check
    {
        let mut queue = ctx.queue.lock().await;
        if let Ok(Some(reason)) = queue.is_user_blocked(&sender_id.to_string()).await {
            drop(queue);
            tracing::warn!(
                sender_hash = %log_safe_id(&sender_id.to_string(), &ctx.config.logging.hash_salt),
                reason = %reason,
                "Blocked user attempted to send message"
            );
            return Err(AppError::Auth(format!(
                "Your account is temporarily blocked: {}",
                reason
            )));
        }

        // Check message rate limit
        match queue.increment_message_count(&sender_id.to_string()).await {
            Ok(count) => {
                let max_messages = ctx.config.security.max_messages_per_hour;
                if count > max_messages {
                    drop(queue);
                    tracing::warn!(
                        sender_hash = %log_safe_id(&sender_id.to_string(), &ctx.config.logging.hash_salt),
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

    // 2. Read request body with size limit
    let body_bytes = match body.collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            let bytes_vec = bytes.to_vec();
            // SECURITY: Validate request body size to prevent DoS
            if bytes_vec.len() > crate::config::MAX_REQUEST_BODY_SIZE {
                tracing::warn!(
                    size = bytes_vec.len(),
                    limit = crate::config::MAX_REQUEST_BODY_SIZE,
                    sender_hash = %log_safe_id(&sender_id.to_string(), &ctx.config.logging.hash_salt),
                    "Request body too large"
                );
                return Err(AppError::Validation(format!(
                    "Request body exceeds maximum size of {} bytes",
                    crate::config::MAX_REQUEST_BODY_SIZE
                )));
            }
            bytes_vec
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to read request body");
            return Err(AppError::Validation(
                "Failed to read request body".to_string(),
            ));
        }
    };

    // 3. Parse JSON to EncryptedMessageV3
    let message: EncryptedMessageV3 = match serde_json::from_slice(&body_bytes) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "Invalid JSON in request body");
            return Err(AppError::Validation("Invalid JSON format".to_string()));
        }
    };

    // 4. Validate message size
    // SECURITY: Validate ciphertext size to prevent DoS
    if message.ciphertext.len() > crate::config::MAX_MESSAGE_SIZE {
        tracing::warn!(
            size = message.ciphertext.len(),
            limit = crate::config::MAX_MESSAGE_SIZE,
            sender_hash = %log_safe_id(&sender_id.to_string(), &ctx.config.logging.hash_salt),
            "Message ciphertext too large"
        );
        return Err(AppError::Validation(format!(
            "Message size exceeds maximum of {} bytes",
            crate::config::MAX_MESSAGE_SIZE
        )));
    }

    // 5. Validate the message format
    // SECURITY: Hash sender_id for privacy in logs
    let salt = &ctx.config.logging.hash_salt;
    if let Err(e) = ServerCryptoValidator::validate_encrypted_message_v3(&message) {
        tracing::warn!(
            error = %e,
            sender_hash = %log_safe_id(&sender_id.to_string(), salt),
            "Message validation failed"
        );
        return Err(AppError::Validation(e.to_string()));
    }

    // 6. Parse recipient_id
    let recipient_id = match Uuid::parse_str(&message.recipient_id) {
        Ok(id) => id,
        Err(_) => {
            return Err(AppError::Validation(
                "Invalid recipient ID format".to_string(),
            ));
        }
    };

    // 6. Security check: prevent sending to self
    if sender_id == recipient_id {
        return Err(AppError::Validation(
            "Cannot send message to self".to_string(),
        ));
    }

    // 7. Create Kafka envelope for message (Phase 5+)
    let message_id = Uuid::new_v4().to_string();

    // Calculate content hash for deduplication
    let mut hasher = Sha256::new();
    hasher.update(message_id.as_bytes());
    hasher.update(message.ciphertext.as_bytes());
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

    // 8. Write to Kafka (Phase 5: source of truth)
    if let Err(e) = ctx.kafka_producer.send_message(&envelope).await {
        // SECURITY: Use hashed IDs in error logs
        tracing::error!(
            error = %e,
            message_id = %message_id,
            sender_hash = %log_safe_id(&sender_id.to_string(), salt),
            recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
            kafka_enabled = ctx.kafka_producer.is_enabled(),
            "Kafka write FAILED - message NOT persisted (REST API v3)"
        );
        return Err(AppError::Internal("Failed to queue message".to_string()));
    }

    tracing::debug!(
        message_id = %message_id,
        "Message persisted to Kafka (REST API v3)"
    );

    // 9. Log the operation (with privacy in mind)
    if ctx.config.logging.enable_user_identifiers {
        tracing::info!(
            message_id = %message_id,
            sender_id = %sender_id,
            recipient_id = %recipient_id,
            suite_id = message.suite_id,
            "Message accepted (REST API v3, Kafka)"
        );
    } else {
        tracing::info!(
            message_id = %message_id,
            sender_hash = %log_safe_id(&sender_id.to_string(), &ctx.config.logging.hash_salt),
            recipient_hash = %log_safe_id(&recipient_id.to_string(), &ctx.config.logging.hash_salt),
            suite_id = message.suite_id,
            "Message accepted (REST API v3, Kafka)"
        );
    }

    // 10. Return success (202 Accepted - message is queued for delivery)
    Ok(json_response(
        StatusCode::ACCEPTED,
        json!({
            "status": "accepted",
            "message_id": message_id,
            "message": "Message queued for delivery"
        }),
    ))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extracts user_id from JWT token in Authorization header
fn extract_user_id_from_jwt(ctx: &AppContext, headers: &HeaderMap) -> Result<Uuid, AppError> {
    // Extract Authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::Auth("Missing authorization header".to_string()))?;

    // Extract token from "Bearer <token>"
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Auth("Invalid authorization format".to_string()))?;

    // Verify and decode JWT
    let claims = ctx
        .auth_manager
        .verify_token(token)
        .map_err(|_| AppError::Auth("Invalid or expired token".to_string()))?;

    // Parse user_id from claims
    Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Internal("Invalid user ID in token".to_string()))
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
