// ============================================================================
// Federation Handlers - Server-to-Server Protocol
// ============================================================================
//
// Implements federation protocol for cross-instance messaging:
// 1. Discovery: .well-known/konstruct endpoint
// 2. Receive: /federation/v1/messages endpoint (incoming from remote servers)
// 3. Health: Server status and capabilities
//
// ============================================================================

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming as IncomingBody, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use crate::{
    context::AppContext,
    federation::{FederatedEnvelope, ServerSigner},
    kafka::KafkaMessageEnvelope,
    message::ChatMessage,
    user_id::UserId,
    utils::log_safe_id,
};

fn json_response(status: StatusCode, body: serde_json::Value) -> hyper::Response<Full<Bytes>> {
    let body_str = serde_json::to_string(&body).unwrap_or_else(|_| "{}".to_string());
    let mut response = hyper::Response::new(Full::new(Bytes::from(body_str)));
    *response.status_mut() = status;
    
    // SECURITY: Handle header parsing errors gracefully
    match "application/json".parse() {
        Ok(content_type) => {
            response.headers_mut().insert("Content-Type", content_type);
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to parse Content-Type header (this should never happen)");
            // This should never happen, but if it does, we continue without the header
        }
    }
    
    response
}

/// Federation discovery endpoint
/// Served at: /.well-known/konstruct
///
/// Returns server capabilities and federation endpoints
pub async fn well_known_konstruct(ctx: AppContext) -> hyper::Response<Full<Bytes>> {
    // Get public key if server signer is configured
    let public_key = ctx
        .server_signer
        .as_ref()
        .map(|signer| signer.public_key_base64());

    let info = json!({
        "server": ctx.config.instance_domain,
        "version": "1.0",
        "public_key": public_key,
        "federation": {
            "enabled": ctx.config.federation_enabled,
            "protocol_version": "1.0",
            "public_key": public_key,
            "endpoints": {
                "messages": format!("https://{}/federation/v1/messages", ctx.config.instance_domain),
                "health": format!("https://{}/federation/health", ctx.config.instance_domain),
                "keys": format!("https://{}/federation/v1/keys", ctx.config.instance_domain)
            }
        },
        "features": [
            "end_to_end_encryption",
            "double_ratchet",
            "message_delivery",
            "offline_queue",
            "server_signatures"
        ],
        "limits": {
            "max_message_size": 100_000,
            "rate_limit_per_hour": ctx.config.security.max_messages_per_hour
        }
    });

    json_response(StatusCode::OK, info)
}

/// Federation health check
/// Served at: /federation/health
pub async fn federation_health(ctx: AppContext) -> hyper::Response<Full<Bytes>> {
    let health = json!({
        "status": "healthy",
        "instance": ctx.config.instance_domain,
        "federation_enabled": ctx.config.federation_enabled,
        "version": "1.0"
    });

    json_response(StatusCode::OK, health)
}

/// Receive federated message from remote server
/// Served at: POST /federation/v1/messages
///
/// Remote server sends message here when recipient is on this instance
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FederatedMessageRequest {
    pub message_id: String,
    pub from: String,  // alice@remote.konstruct.cc
    pub to: String,    // bob@eu.konstruct.cc
    pub ephemeral_public_key: Vec<u8>,
    pub ciphertext: String,  // base64
    pub message_number: u32,
    pub timestamp: u64,

    // S2S authentication fields
    /// Origin server domain (who sent this S2S request)
    #[serde(default)]
    pub origin_server: Option<String>,
    /// Hash of the ciphertext for integrity verification
    #[serde(default)]
    pub payload_hash: Option<String>,
    /// Ed25519 signature over the canonical envelope (base64)
    #[serde(default)]
    pub server_signature: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederatedMessageResponse {
    pub status: String,
    pub message_id: String,
}

/// Receive federated message from remote server
/// Served at: POST /federation/v1/messages
pub async fn receive_federated_message_http(
    ctx: &AppContext,
    body: IncomingBody,
) -> hyper::Response<Full<Bytes>> {
    // 1. Read request body
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to read request body");
            return json_response(StatusCode::BAD_REQUEST, json!({"error": "Failed to read request body"}));
        }
    };

    // 2. Parse JSON to FederatedMessageRequest
    let req: FederatedMessageRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "Invalid JSON in federated message request");
            return json_response(StatusCode::BAD_REQUEST, json!({"error": "Invalid JSON format"}));
        }
    };

    // SECURITY: Hash user IDs for privacy in logs
    let salt = &ctx.config.logging.hash_salt;
    tracing::info!(
        message_id = %req.message_id,
        from_hash = %log_safe_id(&req.from, salt),
        to_hash = %log_safe_id(&req.to, salt),
        "Received federated message from remote server"
    );

    // 3. Validate sender is from their claimed domain
    let sender = match UserId::parse(&req.from) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(error = %e, from_hash = %log_safe_id(&req.from, salt), "Invalid sender user ID");
            return json_response(StatusCode::BAD_REQUEST, json!({"error": "Invalid sender ID"}));
        }
    };

    if !sender.is_federated() {
        tracing::warn!(from_hash = %log_safe_id(&req.from, salt), "Sender must be federated (must have @domain)");
        return json_response(StatusCode::BAD_REQUEST, json!({"error": "Sender must be federated"}));
    }

    // 3.5 Verify server signature (if provided)
    // SECURITY: In production, signatures MUST be required
    if let (Some(origin_server), Some(payload_hash), Some(signature)) = (
        &req.origin_server,
        &req.payload_hash,
        &req.server_signature,
    ) {
        // SECURITY: Validate that origin_server matches sender's domain
        // Prevent envelope tampering by ensuring origin_server matches the sender's federated domain
        let sender_domain = sender.domain().unwrap_or_default();
        if *origin_server != sender_domain {
            tracing::warn!(
                message_id = %req.message_id,
                origin_server = %origin_server,
                sender_domain = %sender_domain,
                "origin_server mismatch: envelope claims different origin than sender's domain"
            );
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "origin_server does not match sender's domain"}),
            );
        }

        // Reconstruct envelope for verification
        let envelope = FederatedEnvelope {
            message_id: req.message_id.clone(),
            from: req.from.clone(),
            to: req.to.clone(),
            origin_server: origin_server.clone(),
            destination_server: ctx.config.instance_domain.clone(),
            timestamp: req.timestamp,
            payload_hash: payload_hash.clone(),
        };

        // Verify payload hash integrity
        let expected_hash = FederatedEnvelope::hash_payload(&req.ciphertext);
        if expected_hash != *payload_hash {
            tracing::warn!(
                message_id = %req.message_id,
                origin_server = %origin_server,
                "Payload hash mismatch - message may have been tampered"
            );
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "Payload integrity check failed"}),
            );
        }

        // Fetch origin server's public key and verify signature
        match ctx.public_key_cache.get_public_key(origin_server).await {
            Ok(public_key) => {
                match ServerSigner::verify_signature(&public_key, &envelope, signature) {
                    Ok(()) => {
                        tracing::debug!(
                            message_id = %req.message_id,
                            origin_server = %origin_server,
                            "S2S signature verified successfully"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            message_id = %req.message_id,
                            origin_server = %origin_server,
                            error = %e,
                            "S2S signature verification FAILED"
                        );
                        return json_response(
                            StatusCode::UNAUTHORIZED,
                            json!({"error": "Invalid server signature"}),
                        );
                    }
                }
            }
            Err(e) => {
                // SECURITY: If federation is enabled, signature verification is mandatory
                // Cannot proceed without verifying the signature
                tracing::error!(
                    message_id = %req.message_id,
                    origin_server = %origin_server,
                    error = %e,
                    "Failed to fetch origin server's public key - cannot verify signature"
                );
                return json_response(
                    StatusCode::BAD_GATEWAY,
                    json!({"error": "Cannot verify origin server: failed to fetch public key"}),
                );
            }
        }
    } else if req.server_signature.is_some() {
        // Signature provided but missing required fields (origin_server or payload_hash)
        tracing::warn!(
            message_id = %req.message_id,
            "Incomplete signature data: missing origin_server or payload_hash"
        );
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "Incomplete signature data: origin_server and payload_hash are required when server_signature is provided"}),
        );
    } else {
        // SECURITY: Server signature is REQUIRED for federated messages
        // This endpoint only accepts messages from remote federation servers
        tracing::warn!(
            message_id = %req.message_id,
            from_hash = %log_safe_id(&req.from, salt),
            "Received unsigned federated message - server signature is required"
        );
        return json_response(
            StatusCode::UNAUTHORIZED,
            json!({"error": "Server signature is required for federation messages"}),
        );
    }

    // 4. Validate recipient is local to this instance
    let recipient = match UserId::parse(&req.to) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(error = %e, to_hash = %log_safe_id(&req.to, salt), "Invalid recipient user ID");
            return json_response(StatusCode::BAD_REQUEST, json!({"error": "Invalid recipient ID"}));
        }
    };

    // Check if recipient is on this instance
    if recipient.is_federated() {
        let recipient_domain = recipient.domain().unwrap();
        if recipient_domain != ctx.config.instance_domain {
            tracing::warn!(
                recipient_domain = %recipient_domain,
                instance_domain = %ctx.config.instance_domain,
                "Recipient is not on this instance"
            );
            return json_response(StatusCode::BAD_REQUEST, json!({"error": "Recipient not on this instance"}));
        }
    }

    // 5. Convert to ChatMessage format
    let chat_message = ChatMessage {
        id: req.message_id.clone(),
        from: req.from.clone(),
        to: req.to.clone(),
        ephemeral_public_key: req.ephemeral_public_key,
        message_number: req.message_number,
        content: req.ciphertext,
        timestamp: req.timestamp,
    };

    // 6. Validate message structure
    if !chat_message.is_valid() {
        tracing::warn!(message_id = %req.message_id, "Invalid message structure");
        return json_response(StatusCode::BAD_REQUEST, json!({"error": "Invalid message structure"}));
    }

    // 7. Phase 5: Write to Kafka first (source of truth)
    let envelope = KafkaMessageEnvelope::from(&chat_message);
    if let Err(e) = ctx.kafka_producer.send_message(&envelope).await {
        tracing::error!(
            error = %e,
            message_id = %req.message_id,
            kafka_enabled = ctx.kafka_producer.is_enabled(),
            "Kafka write FAILED - federated message NOT persisted"
        );
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "Failed to persist message"})
        );
    }

    tracing::debug!(
        message_id = %req.message_id,
        "Federated message persisted to Kafka"
    );

    // 8. Route to local delivery - try to deliver directly to online recipient
    let recipient_uuid = recipient.uuid();
    let recipient_tx = {
        let clients_read = ctx.clients.read().await;
        clients_read.get(&recipient_uuid.to_string()).cloned()
    };

    if let Some(tx) = recipient_tx {
        // Recipient is online - deliver directly
        match tx.send(crate::message::ServerMessage::Message(chat_message.clone())) {
            Ok(_) => {
                // SECURITY: Hash user IDs for privacy
                tracing::info!(
                    message_id = %req.message_id,
                    from_hash = %log_safe_id(&req.from, salt),
                    to_hash = %log_safe_id(&req.to, salt),
                    "Federated message delivered to online recipient"
                );

                return json_response(
                    StatusCode::OK,
                    json!(FederatedMessageResponse {
                        status: "delivered".to_string(),
                        message_id: req.message_id,
                    })
                );
            }
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    message_id = %req.message_id,
                    "Direct delivery failed, message persisted to Kafka for later delivery"
                );
            }
        }
    }

    // 9. Recipient offline - message already persisted to Kafka
    // delivery_worker will read from Kafka when recipient comes online
    // SECURITY: Hash user IDs for privacy
    tracing::info!(
        message_id = %req.message_id,
        from_hash = %log_safe_id(&req.from, salt),
        to_hash = %log_safe_id(&req.to, salt),
        "Federated message queued in Kafka for offline recipient"
    );

    json_response(
        StatusCode::OK,
        json!(FederatedMessageResponse {
            status: "queued".to_string(),
            message_id: req.message_id,
        })
    )
}
