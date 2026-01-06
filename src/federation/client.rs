// ============================================================================
// Federation Client - Send messages to remote instances
// ============================================================================

use anyhow::Result;
use serde::{Deserialize, Serialize};
use crate::message::ChatMessage;

/// Federation client for sending messages to remote instances
#[derive(Clone)]
pub struct FederationClient {
    http_client: reqwest::Client,
}

impl FederationClient {
    pub fn new() -> Self {
        Self {
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Send message to remote instance
    pub async fn send_message(
        &self,
        target_domain: &str,
        message: &ChatMessage,
    ) -> Result<()> {
        // Construct federation endpoint URL
        let url = format!("https://{}/federation/v1/messages", target_domain);

        // Prepare request payload
        let payload = FederatedMessageRequest {
            message_id: message.id.clone(),
            from: message.from.clone(),
            to: message.to.clone(),
            ephemeral_public_key: message.ephemeral_public_key.clone(),
            ciphertext: message.content.clone(),
            message_number: message.message_number,
            timestamp: message.timestamp,
            server_signature: None, // TODO: Implement server signing
        };

        tracing::info!(
            message_id = %message.id,
            from = %message.from,
            to = %message.to,
            target_domain = %target_domain,
            "Sending federated message to remote server"
        );

        // Send HTTP POST request
        let response = self.http_client
            .post(&url)
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
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
    pub server_signature: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct FederatedMessageResponse {
    pub status: String,
    pub message_id: String,
}
