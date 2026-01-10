// ============================================================================
// Federation Client - Send messages to remote instances
// ============================================================================
//
// Sends S2S messages to remote federation instances with Ed25519 signatures
// for authentication and integrity verification.
//
// ============================================================================

use crate::federation::signing::{FederatedEnvelope, ServerSigner};
use crate::message::ChatMessage;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Federation client for sending messages to remote instances
#[derive(Clone)]
pub struct FederationClient {
    http_client: reqwest::Client,
    /// Server signer for authenticating S2S messages
    /// When None: messages are sent unsigned (for testing/development)
    server_signer: Option<Arc<ServerSigner>>,
    /// Our instance domain (for envelope origin_server field)
    instance_domain: String,
}

impl FederationClient {
    /// Create a new federation client without signing (legacy/testing mode)
    pub fn new() -> Self {
        Self {
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            server_signer: None,
            instance_domain: "unknown".to_string(),
        }
    }

    /// Create a new federation client with server signing
    pub fn new_with_signer(signer: Arc<ServerSigner>, instance_domain: String) -> Self {
        Self {
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            server_signer: Some(signer),
            instance_domain,
        }
    }

    /// Send message to remote instance
    ///
    /// If server_signer is configured, the message will be signed with Ed25519.
    /// The remote server should verify the signature using our public key from
    /// .well-known/konstruct.
    pub async fn send_message(&self, target_domain: &str, message: &ChatMessage) -> Result<()> {
        // Construct federation endpoint URL
        let url = format!("https://{}/federation/v1/messages", target_domain);

        // Create envelope for signing
        let envelope = FederatedEnvelope {
            message_id: message.id.clone(),
            from: message.from.clone(),
            to: message.to.clone(),
            origin_server: self.instance_domain.clone(),
            destination_server: target_domain.to_string(),
            timestamp: message.timestamp,
            payload_hash: FederatedEnvelope::hash_payload(&message.content),
        };

        // Sign if signer is available
        let server_signature = self.server_signer.as_ref().map(|signer| {
            let sig = signer.sign_message(&envelope);
            tracing::debug!(
                message_id = %message.id,
                origin = %self.instance_domain,
                "Message signed with server key"
            );
            sig
        });

        // Prepare request payload
        let payload = FederatedMessageRequest {
            message_id: message.id.clone(),
            from: message.from.clone(),
            to: message.to.clone(),
            ephemeral_public_key: message.ephemeral_public_key.clone(),
            ciphertext: message.content.clone(),
            message_number: message.message_number,
            timestamp: message.timestamp,
            origin_server: self.instance_domain.clone(),
            payload_hash: envelope.payload_hash,
            server_signature,
        };

        tracing::info!(
            message_id = %message.id,
            from = %message.from,
            to = %message.to,
            target_domain = %target_domain,
            signed = payload.server_signature.is_some(),
            "Sending federated message to remote server"
        );

        // Send HTTP POST request
        let response = self.http_client.post(&url).json(&payload).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!(
                "Federation request failed: HTTP {} - {}",
                status,
                error_text
            );
        }

        let response_body: FederatedMessageResponse = response.json().await?;

        tracing::info!(
            message_id = %message.id,
            status = %response_body.status,
            "Federated message accepted by remote server"
        );

        Ok(())
    }
}

impl Default for FederationClient {
    fn default() -> Self {
        Self::new()
    }
}

/// S2S message request sent to remote servers
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FederatedMessageRequest {
    pub message_id: String,
    pub from: String,
    pub to: String,
    pub ephemeral_public_key: Vec<u8>,
    pub ciphertext: String,
    pub message_number: u32,
    pub timestamp: u64,
    /// Origin server domain (for signature verification)
    pub origin_server: String,
    /// Hash of the ciphertext (for integrity verification)
    pub payload_hash: String,
    /// Ed25519 signature over the canonical envelope (base64)
    pub server_signature: Option<String>,
}

/// Response from remote server
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct FederatedMessageResponse {
    pub status: String,
    pub message_id: String,
}
