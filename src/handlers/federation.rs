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
    message::ChatMessage,
    user_id::UserId,
};

fn json_response(status: StatusCode, body: serde_json::Value) -> hyper::Response<Full<Bytes>> {
    let body_str = serde_json::to_string(&body).unwrap_or_else(|_| "{}".to_string());
    let mut response = hyper::Response::new(Full::new(Bytes::from(body_str)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        "Content-Type",
        "application/json".parse().unwrap()
    );
    response
}

/// Federation discovery endpoint
/// Served at: /.well-known/konstruct
///
/// Returns server capabilities and federation endpoints
pub async fn well_known_konstruct(ctx: AppContext) -> hyper::Response<Full<Bytes>> {
    let info = json!({
        "server": ctx.config.instance_domain,
        "version": "1.0",
        "federation": {
            "enabled": ctx.config.federation_enabled,
            "protocol_version": "1.0",
            "endpoints": {
                "messages": format!("https://{}/federation/v1/messages", ctx.config.instance_domain),
                "health": format!("https://{}/federation/health", ctx.config.instance_domain)
            }
        },
        "features": [
            "end_to_end_encryption",
            "double_ratchet",
            "message_delivery",
            "offline_queue"
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

    // Server signature (optional for MVP, required for production)
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

    tracing::info!(
        message_id = %req.message_id,
        from = %req.from,
        to = %req.to,
        "Received federated message from remote server"
    );

    // 3. Validate sender is from their claimed domain
    let sender = match UserId::parse(&req.from) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(error = %e, from = %req.from, "Invalid sender user ID");
            return json_response(StatusCode::BAD_REQUEST, json!({"error": "Invalid sender ID"}));
        }
    };

    if !sender.is_federated() {
        tracing::warn!(from = %req.from, "Sender must be federated (must have @domain)");
        return json_response(StatusCode::BAD_REQUEST, json!({"error": "Sender must be federated"}));
    }

    // 4. Validate recipient is local to this instance
    let recipient = match UserId::parse(&req.to) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(error = %e, to = %req.to, "Invalid recipient user ID");
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

    // 7. Route to local delivery
    // Try to deliver directly to online recipient
    let recipient_uuid = recipient.uuid();
    let recipient_tx = {
        let clients_read = ctx.clients.read().await;
        clients_read.get(&recipient_uuid.to_string()).cloned()
    };

    if let Some(tx) = recipient_tx {
        // Recipient is online - deliver directly
        match tx.send(crate::message::ServerMessage::Message(chat_message.clone())) {
            Ok(_) => {
                tracing::info!(
                    message_id = %req.message_id,
                    from = %req.from,
                    to = %req.to,
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
                tracing::warn!(
                    error = %e,
                    message_id = %req.message_id,
                    "Failed to deliver to online recipient, will queue"
                );
            }
        }
    }

    // 8. Recipient offline - queue for later delivery
    let mut queue = ctx.queue.lock().await;
    match queue.enqueue_message(&recipient_uuid.to_string(), &chat_message).await {
        Ok(_) => {
            tracing::info!(
                message_id = %req.message_id,
                from = %req.from,
                to = %req.to,
                "Federated message queued for offline recipient"
            );

            json_response(
                StatusCode::OK,
                json!(FederatedMessageResponse {
                    status: "queued".to_string(),
                    message_id: req.message_id,
                })
            )
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                message_id = %req.message_id,
                "Failed to queue federated message"
            );

            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "Failed to queue message"})
            )
        }
    }
}
