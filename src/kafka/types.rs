use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Type of message being sent through Kafka
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum MessageType {
    /// 1-on-1 chat using Double Ratchet protocol (current implementation)
    DirectMessage,

    /// MLS group message (application message)
    #[allow(dead_code)]
    MLSMessage,

    /// MLS KeyPackage for adding user to group
    #[allow(dead_code)]
    MLSKeyPackage,

    /// MLS Welcome message for new group members
    #[allow(dead_code)]
    MLSWelcome,

    /// MLS Commit (group state change)
    #[allow(dead_code)]
    MLSCommit,

    /// MLS Proposal (proposed group change)
    #[allow(dead_code)]
    MLSProposal,

    /// Federated S2S message from another server
    #[allow(dead_code)]
    FederatedMessage,
}

/// Kafka message envelope containing all message types
///
/// This structure is serialized to JSON and stored in Kafka.
/// The partition key is derived from `recipient_id` to ensure ordering per user/group.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KafkaMessageEnvelope {
    // ===== Identification =====
    /// Unique message ID (UUID v4)
    pub message_id: String,

    /// Sender ID (user UUID) or server name for S2S messages
    pub sender_id: String,

    /// Recipient ID (user UUID) or group ID
    /// Used as Kafka partition key for ordering guarantees
    pub recipient_id: String,

    /// Unix timestamp in seconds
    pub timestamp: i64,

    // ===== Message Type =====
    /// Type discriminator for routing and processing
    pub message_type: MessageType,

    // ===== Double Ratchet (DirectMessage) Fields =====
    /// Ephemeral public key for DH ratchet (32 bytes, base64-encoded)
    /// Only present for DirectMessage type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_public_key: Option<String>,

    /// Message number in symmetric-key ratchet chain
    /// Only present for DirectMessage type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_number: Option<u32>,

    // ===== MLS Fields =====
    /// MLS opaque payload (binary data, base64-encoded)
    /// Only present for MLS* types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_payload: Option<String>,

    /// MLS group ID (UUID)
    /// Only present for MLS* types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,

    // ===== Common Fields =====
    /// Base64-encoded encrypted content
    /// For DirectMessage: ChaCha20-Poly1305 sealed box
    /// For MLS: MLS-encrypted application data
    pub encrypted_payload: String,

    /// SHA-256 hash for deduplication (message_id + encrypted_payload + ephemeral_key)
    pub content_hash: String,

    /// Cryptographic suite identifier
    /// 0 = ChaCha20-Poly1305 (Double Ratchet)
    /// 1+ = MLS cipher suites (TBD)
    #[serde(default)]
    pub suite_id: u8,

    // ===== Federation Fields =====
    /// Origin server name (e.g., "server.example.com")
    /// Only present for FederatedMessage type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_server: Option<String>,

    /// Whether this message came from S2S API (true) or local client (false)
    #[serde(default)]
    pub federated: bool,

    /// Ed25519 signature from origin server
    /// Only present for FederatedMessage type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_signature: Option<String>,
}

impl KafkaMessageEnvelope {
    /// Create a new DirectMessage envelope (for Phase 1-2 compatibility)
    pub fn new_direct_message(
        message_id: String,
        sender_id: String,
        recipient_id: String,
        ephemeral_public_key: Vec<u8>,
        message_number: u32,
        encrypted_payload: String,
        content_hash: String,
    ) -> Self {
        Self {
            message_id,
            sender_id,
            recipient_id,
            timestamp: chrono::Utc::now().timestamp(),
            message_type: MessageType::DirectMessage,
            ephemeral_public_key: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                ephemeral_public_key,
            )),
            message_number: Some(message_number),
            mls_payload: None,
            group_id: None,
            encrypted_payload,
            content_hash,
            suite_id: 0, // ChaCha20-Poly1305
            origin_server: None,
            federated: false,
            server_signature: None,
        }
    }

    /// Validate message envelope structure
    pub fn validate(&self) -> Result<()> {
        // Check required fields
        if self.message_id.is_empty() {
            anyhow::bail!("message_id is required");
        }
        if self.sender_id.is_empty() {
            anyhow::bail!("sender_id is required");
        }
        if self.recipient_id.is_empty() {
            anyhow::bail!("recipient_id is required");
        }
        if self.encrypted_payload.is_empty() {
            anyhow::bail!("encrypted_payload is required");
        }
        if self.content_hash.is_empty() {
            anyhow::bail!("content_hash is required");
        }

        // Type-specific validation
        match self.message_type {
            MessageType::DirectMessage => {
                if self.ephemeral_public_key.is_none() {
                    anyhow::bail!("ephemeral_public_key required for DirectMessage");
                }
                if self.message_number.is_none() {
                    anyhow::bail!("message_number required for DirectMessage");
                }
            }
            MessageType::MLSMessage
            | MessageType::MLSKeyPackage
            | MessageType::MLSWelcome
            | MessageType::MLSCommit
            | MessageType::MLSProposal => {
                if self.mls_payload.is_none() {
                    anyhow::bail!("mls_payload required for MLS messages");
                }
            }
            MessageType::FederatedMessage => {
                if self.origin_server.is_none() {
                    anyhow::bail!("origin_server required for FederatedMessage");
                }
                if self.server_signature.is_none() {
                    anyhow::bail!("server_signature required for FederatedMessage");
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_message_envelope_creation() {
        let envelope = KafkaMessageEnvelope::new_direct_message(
            "msg-123".to_string(),
            "user-456".to_string(),
            "user-789".to_string(),
            vec![0u8; 32], // 32-byte ephemeral key
            42,            // message number
            "encrypted".to_string(),
            "hash123".to_string(),
        );

        assert_eq!(envelope.message_type, MessageType::DirectMessage);
        assert!(envelope.ephemeral_public_key.is_some());
        assert_eq!(envelope.message_number, Some(42));
        assert!(!envelope.federated);
    }

    #[test]
    fn test_envelope_validation() {
        let valid_envelope = KafkaMessageEnvelope::new_direct_message(
            "msg-123".to_string(),
            "user-456".to_string(),
            "user-789".to_string(),
            vec![0u8; 32],
            42,
            "encrypted".to_string(),
            "hash123".to_string(),
        );

        assert!(valid_envelope.validate().is_ok());

        // Test invalid: empty message_id
        let mut invalid = valid_envelope.clone();
        invalid.message_id = String::new();
        assert!(invalid.validate().is_err());
    }
}
