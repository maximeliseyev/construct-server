// ============================================================================
// Federation Routes
// ============================================================================
//
// Endpoints:
// - GET /.well-known/konstruct - Federation discovery
// - GET /federation/health - Federation health check
// - POST /federation/v1/messages - Receive federated message from remote server
//
// ============================================================================

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;
use std::sync::Arc;

use crate::context::AppContext;
use crate::error::AppError;

/// GET /.well-known/konstruct
/// Federation discovery endpoint
/// Returns server capabilities and federation endpoints
pub async fn well_known_konstruct(
    State(app_context): State<Arc<AppContext>>,
) -> Result<impl IntoResponse, AppError> {
    // Get public key if server signer is configured
    let public_key = app_context
        .server_signer
        .as_ref()
        .map(|signer| signer.public_key_base64());

    let info = json!({
        "server": app_context.config.instance_domain,
        "version": "1.0",
        "public_key": public_key,
        "federation": {
            "enabled": app_context.config.federation_enabled,
            "protocol_version": "1.0",
            "public_key": public_key,
            "endpoints": {
                "messages": format!("https://{}/federation/v1/messages", app_context.config.instance_domain),
                "health": format!("https://{}/federation/health", app_context.config.instance_domain),
                "keys": format!("https://{}/federation/v1/keys", app_context.config.instance_domain)
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
            "rate_limit_per_hour": app_context.config.security.max_messages_per_hour
        }
    });

    Ok((StatusCode::OK, Json(info)))
}

/// GET /federation/health
/// Federation health check
pub async fn federation_health(
    State(app_context): State<Arc<AppContext>>,
) -> Result<impl IntoResponse, AppError> {
    let health = json!({
        "status": "healthy",
        "instance": app_context.config.instance_domain,
        "federation_enabled": app_context.config.federation_enabled,
        "version": "1.0"
    });

    Ok((StatusCode::OK, Json(health)))
}

/// POST /federation/v1/messages
/// Receive federated message from remote server
///
/// This endpoint receives messages from other federation servers when
/// the recipient is on this instance.
pub async fn receive_federated_message(
    State(app_context): State<Arc<AppContext>>,
    body: axum::body::Body,
) -> Result<impl IntoResponse, AppError> {
    // Read body bytes
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|e| AppError::Hyper(format!("Failed to read body: {}", e)))?;

    // Use the helper function that accepts bytes directly
    use crate::handlers::federation::receive_federated_message_bytes;
    let response = receive_federated_message_bytes(&app_context, body_bytes).await?;

    // Convert hyper::Response to axum response
    let (parts, body) = response.into_parts();
    use http_body_util::BodyExt;
    let body_bytes = body
        .collect()
        .await
        .map_err(|e| AppError::Hyper(format!("Failed to collect response body: {}", e)))?
        .to_bytes();

    let mut axum_response = axum::response::Response::builder().status(parts.status);

    // Copy headers
    for (key, value) in parts.headers {
        if let (Some(name), Ok(val)) = (key, axum::http::HeaderValue::from_bytes(value.as_bytes()))
        {
            axum_response = axum_response.header(name, val);
        }
    }

    Ok(axum_response
        .body(axum::body::Body::from(body_bytes.to_vec()))
        .map_err(|e| AppError::Hyper(format!("Failed to build response: {}", e)))?)
}
