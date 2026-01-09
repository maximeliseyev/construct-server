use crate::context::AppContext;
use crate::e2e::{EncryptedMessageV3, ServerCryptoValidator};
use crate::kafka::types::{KafkaMessageEnvelope, MessageType};
use crate::utils::log_safe_id;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming as IncomingBody, HeaderMap, Response, StatusCode};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// POST /messages/send
/// Sends an E2E-encrypted message
pub async fn handle_send_message(
    ctx: &AppContext,
    headers: &HeaderMap,
    body: IncomingBody,
) -> Response<Full<Bytes>> {
    // 1. Extract and verify JWT token
    let sender_id = match extract_user_id_from_jwt(ctx, headers) {
        Ok(id) => id,
        Err(response) => return response,
    };

    // 2. Read request body
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to read request body");
            return error_response(StatusCode::BAD_REQUEST, "Failed to read request body");
        }
    };

    // 3. Parse JSON to EncryptedMessageV3
    let message: EncryptedMessageV3 = match serde_json::from_slice(&body_bytes) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "Invalid JSON in request body");
            return error_response(StatusCode::BAD_REQUEST, "Invalid JSON format");
        }
    };

    // 4. Validate the message
    // SECURITY: Hash sender_id for privacy in logs
    let salt = &ctx.config.logging.hash_salt;
    if let Err(e) = ServerCryptoValidator::validate_encrypted_message_v3(&message) {
        tracing::warn!(
            error = %e,
            sender_hash = %log_safe_id(&sender_id.to_string(), salt),
            "Message validation failed"
        );
        return error_response(StatusCode::BAD_REQUEST, &e.to_string());
    }

    // 5. Parse recipient_id
    let recipient_id = match Uuid::parse_str(&message.recipient_id) {
        Ok(id) => id,
        Err(_) => {
            return error_response(StatusCode::BAD_REQUEST, "Invalid recipient ID format");
        }
    };

    // 6. Security check: prevent sending to self
    if sender_id == recipient_id {
        return error_response(StatusCode::BAD_REQUEST, "Cannot send message to self");
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
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to queue message");
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
    json_response(
        StatusCode::ACCEPTED,
        json!({
            "status": "accepted",
            "message_id": message_id,
            "message": "Message queued for delivery"
        }),
    )
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extracts user_id from JWT token in Authorization header
fn extract_user_id_from_jwt(
    ctx: &AppContext,
    headers: &HeaderMap,
) -> Result<Uuid, Response<Full<Bytes>>> {
    // Extract Authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "Missing authorization header"))?;

    // Extract token from "Bearer <token>"
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "Invalid authorization format"))?;

    // Verify and decode JWT
    let claims = ctx
        .auth_manager
        .verify_token(token)
        .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "Invalid or expired token"))?;

    // Parse user_id from claims
    Uuid::parse_str(&claims.sub).map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid user ID in token",
        )
    })
}

/// Creates a JSON response
fn json_response(status: StatusCode, body: serde_json::Value) -> Response<Full<Bytes>> {
    let json_bytes = serde_json::to_vec(&body).unwrap_or_default();
    let mut response = Response::new(Full::new(Bytes::from(json_bytes)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        "content-type",
        "application/json".parse().unwrap(),
    );
    response
}

/// Creates an error JSON response
fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    json_response(status, json!({"error": message}))
}
