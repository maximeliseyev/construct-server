use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};

/// Encrypted message as stored on the server
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEncryptedMessage {
    /// Base64 encoded [ephemeral_public (32 bytes) || ciphertext]
    pub content: String,

    /// Base64 encoded nonce (12 bytes)
    pub nonce: String,

    /// Base64 encoded sender's identity public key (32 bytes)
    pub sender_identity: String,

    /// Recipient user ID
    pub recipient_id: String,

    /// Sender user ID
    pub sender_id: String,

    /// Message timestamp (server time)
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Message type for routing
    pub message_type: MessageType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    TextMessage,
    PrekeyBundle,  // Для обновления ключей
    MediaMessage,  // Для зашифрованных медиафайлов
    SystemMessage, // Системные уведомления
}

/// Public key bundle as stored on the server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKeyBundle {
    /// User ID
    pub user_id: String,

    /// Base64 encoded identity public key (32 bytes)
    pub identity_public: String,

    /// Base64 encoded signed prekey public key (32 bytes)
    pub signed_prekey_public: String,

    /// Base64 encoded signature (64 bytes)
    pub signature: String,

    /// Base64 encoded verifying key (32 bytes)
    pub verifying_key: String,

    /// When this bundle was registered
    pub registered_at: chrono::DateTime<chrono::Utc>,

    /// When the signed prekey expires (should be rotated)
    pub prekey_expires_at: chrono::DateTime<chrono::Utc>,
}

/// Server-side validation utilities
pub struct ServerCryptoValidator;

#[allow(dead_code)]
impl ServerCryptoValidator {
    /// Validates the format of an encrypted message
    ///
    /// Note: Server CANNOT validate cryptographic correctness,
    /// only basic format and length constraints.
    pub fn validate_encrypted_message(msg: &StoredEncryptedMessage) -> Result<()> {
        // 1. Декодируем base64
        let content_bytes = general_purpose::STANDARD
            .decode(&msg.content)
            .context("Invalid base64 in content")?;

        let nonce_bytes = general_purpose::STANDARD
            .decode(&msg.nonce)
            .context("Invalid base64 in nonce")?;

        let sender_bytes = general_purpose::STANDARD
            .decode(&msg.sender_identity)
            .context("Invalid base64 in sender_identity")?;

        // 2. Проверяем длины
        if content_bytes.len() < 32 + 16 {
            // min: ephemeral_public + minimal ciphertext
            return Err(anyhow::anyhow!("Content too short"));
        }

        if nonce_bytes.len() != 12 {
            return Err(anyhow::anyhow!("Nonce must be 12 bytes"));
        }

        if sender_bytes.len() != 32 {
            return Err(anyhow::anyhow!("Sender identity must be 32 bytes"));
        }

        // 3. Проверяем, что ephemeral_public имеет корректную длину
        // (первые 32 байта content должны быть публичным ключом)
        // Сервер не может проверить, что это валидная точка на кривой!

        // 4. Проверяем идентификаторы пользователей
        if msg.recipient_id.is_empty() || msg.sender_id.is_empty() {
            return Err(anyhow::anyhow!("User IDs cannot be empty"));
        }

        // 5. Проверяем, что отправитель не отправляет сообщение сам себе
        // (это могло бы быть признаком атаки)
        if msg.recipient_id == msg.sender_id {
            return Err(anyhow::anyhow!("Cannot send message to self"));
        }

        Ok(())
    }

    /// Validates the format of a public key bundle
    ///
    /// Note: Server CANNOT verify cryptographic signatures,
    /// only basic format validation.
    pub fn validate_key_bundle(bundle: &StoredKeyBundle) -> Result<()> {
        // 1. Проверяем base64 encoding
        let identity_bytes = general_purpose::STANDARD
            .decode(&bundle.identity_public)
            .context("Invalid base64 in identity_public")?;

        let prekey_bytes = general_purpose::STANDARD
            .decode(&bundle.signed_prekey_public)
            .context("Invalid base64 in signed_prekey_public")?;

        let signature_bytes = general_purpose::STANDARD
            .decode(&bundle.signature)
            .context("Invalid base64 in signature")?;

        let verifying_bytes = general_purpose::STANDARD
            .decode(&bundle.verifying_key)
            .context("Invalid base64 in verifying_key")?;

        // 2. Проверяем длины
        if identity_bytes.len() != 32 {
            return Err(anyhow::anyhow!("Identity public key must be 32 bytes"));
        }

        if prekey_bytes.len() != 32 {
            return Err(anyhow::anyhow!("Signed prekey must be 32 bytes"));
        }

        if signature_bytes.len() != 64 {
            return Err(anyhow::anyhow!("Signature must be 64 bytes"));
        }

        if verifying_bytes.len() != 32 {
            return Err(anyhow::anyhow!("Verifying key must be 32 bytes"));
        }

        // 3. Проверяем срок действия prekey
        let now = chrono::Utc::now();
        if now > bundle.prekey_expires_at {
            return Err(anyhow::anyhow!("Prekey has expired"));
        }

        // 4. Проверяем, что prekey не истекает слишком рано или слишком поздно
        let expiry_duration = bundle.prekey_expires_at - bundle.registered_at;
        if expiry_duration.num_days() < 7 {
            return Err(anyhow::anyhow!("Prekey expiry too short (min 7 days)"));
        }
        if expiry_duration.num_days() > 90 {
            return Err(anyhow::anyhow!("Prekey expiry too long (max 90 days)"));
        }

        Ok(())
    }

    /// Validates BundleData for API v3 (crypto-agility)
    ///
    /// Server validates format and key lengths based on suite_id,
    /// but DOES NOT verify the cryptographic signature.
    /// Signature verification is the responsibility of clients.
    pub fn validate_bundle_data(bundle_data: &BundleData) -> Result<()> {
        // 1. Check that we have at least one suite
        if bundle_data.supported_suites.is_empty() {
            return Err(anyhow::anyhow!(
                "Bundle must contain at least one cipher suite"
            ));
        }

        // 2. Check user_id is not empty
        if bundle_data.user_id.is_empty() {
            return Err(anyhow::anyhow!("User ID cannot be empty"));
        }

        // 3. Validate timestamp format (ISO8601)
        if chrono::DateTime::parse_from_rfc3339(&bundle_data.timestamp).is_err() {
            return Err(anyhow::anyhow!("Invalid timestamp format (expected ISO8601)"));
        }

        // 4. Validate each suite's key material
        for suite in &bundle_data.supported_suites {
            Self::validate_suite_key_material(suite)
                .with_context(|| format!("Invalid key material for suite_id {}", suite.suite_id))?;
        }

        Ok(())
    }

    /// Validates key material for a specific cipher suite
    fn validate_suite_key_material(suite: &SuiteKeyMaterial) -> Result<()> {
        match suite.suite_id {
            suite_ids::CLASSIC_X25519 => {
                // X25519 keys are 32 bytes, Ed25519 keys are 32 bytes
                let identity_bytes = general_purpose::STANDARD
                    .decode(&suite.identity_key)
                    .context("Invalid base64 in identity_key")?;

                let prekey_bytes = general_purpose::STANDARD
                    .decode(&suite.signed_prekey)
                    .context("Invalid base64 in signed_prekey")?;

                if identity_bytes.len() != 32 {
                    return Err(anyhow::anyhow!(
                        "Identity key must be 32 bytes for suite {}",
                        suite.suite_id
                    ));
                }

                if prekey_bytes.len() != 32 {
                    return Err(anyhow::anyhow!(
                        "Signed prekey must be 32 bytes for suite {}",
                        suite.suite_id
                    ));
                }

                // Validate one-time prekeys if present
                for (idx, otpk) in suite.one_time_prekeys.iter().enumerate() {
                    let otpk_bytes = general_purpose::STANDARD
                        .decode(otpk)
                        .with_context(|| format!("Invalid base64 in one_time_prekey[{}]", idx))?;

                    if otpk_bytes.len() != 32 {
                        return Err(anyhow::anyhow!(
                            "One-time prekey[{}] must be 32 bytes for suite {}",
                            idx,
                            suite.suite_id
                        ));
                    }
                }

                Ok(())
            }
            // Future: Add validation for other suite IDs (e.g., PQ-hybrid)
            _ => Err(anyhow::anyhow!("Unsupported suite_id: {}", suite.suite_id)),
        }
    }

    /// Validates UploadableKeyBundle for API v3
    ///
    /// Note: This does NOT verify the cryptographic signature.
    /// Signature verification is the responsibility of clients.
    pub fn validate_uploadable_key_bundle(bundle: &UploadableKeyBundle) -> Result<()> {
        // 1. Validate master_identity_key format
        let master_key_bytes = general_purpose::STANDARD
            .decode(&bundle.master_identity_key)
            .context("Invalid base64 in master_identity_key")?;

        if master_key_bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "Master identity key must be 32 bytes (Ed25519)"
            ));
        }

        // 2. Validate signature format
        let signature_bytes = general_purpose::STANDARD
            .decode(&bundle.signature)
            .context("Invalid base64 in signature")?;

        if signature_bytes.len() != 64 {
            return Err(anyhow::anyhow!("Signature must be 64 bytes (Ed25519)"));
        }

        // 3. Decode and deserialize bundle_data
        let bundle_data_bytes = general_purpose::STANDARD
            .decode(&bundle.bundle_data)
            .context("Invalid base64 in bundle_data")?;

        let bundle_data: BundleData = serde_json::from_slice(&bundle_data_bytes)
            .context("Invalid JSON in bundle_data")?;

        // 4. Validate the bundle_data content
        Self::validate_bundle_data(&bundle_data)?;

        Ok(())
    }

    /// Validates EncryptedMessageV3 for API v3
    pub fn validate_encrypted_message_v3(msg: &EncryptedMessageV3) -> Result<()> {
        // 1. Check recipient_id is not empty
        if msg.recipient_id.is_empty() {
            return Err(anyhow::anyhow!("Recipient ID cannot be empty"));
        }

        // 2. Check that suite_id is supported
        match msg.suite_id {
            suite_ids::CLASSIC_X25519 => {
                // For X25519 suite, we expect at least:
                // ephemeral_public (32 bytes) + minimal ciphertext (16 bytes AEAD tag minimum)
                let ciphertext_bytes = general_purpose::STANDARD
                    .decode(&msg.ciphertext)
                    .context("Invalid base64 in ciphertext")?;

                if ciphertext_bytes.len() < 32 + 16 {
                    return Err(anyhow::anyhow!(
                        "Ciphertext too short for suite {} (expected at least 48 bytes)",
                        msg.suite_id
                    ));
                }

                Ok(())
            }
            _ => Err(anyhow::anyhow!("Unsupported suite_id: {}", msg.suite_id)),
        }
    }
}

/// Update for signed prekey rotation (server-side representation)
/// This is what the server receives and validates (format only, not crypto correctness)
/// Fields are Base64-encoded strings as per CLIENT_API_v2.md
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPrekeyUpdate {
    /// Base64-encoded new X25519 signed prekey public key (32 bytes -> 44 chars)
    pub new_prekey_public: String,
    /// Base64-encoded Ed25519 signature of new_prekey_public (64 bytes -> 88 chars)
    pub signature: String,
}

/// Registration bundle sent by client during signup
/// Contains all necessary public keys for E2E encryption
/// Fields are Base64-encoded strings as per CLIENT_API_v2.md
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationBundle {
    /// Base64-encoded X25519 identity public key (32 bytes -> 44 chars)
    pub identity_public: String,
    /// Base64-encoded X25519 signed prekey public key (32 bytes -> 44 chars)
    pub signed_prekey_public: String,
    /// Base64-encoded Ed25519 signature of signed_prekey_public (64 bytes -> 88 chars)
    pub signature: String,
    /// Base64-encoded Ed25519 verifying key (32 bytes -> 44 chars)
    pub verifying_key: String,
}

pub fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    general_purpose::STANDARD
        .decode(input)
        .map_err(|e| format!("Base64 decode error: {}", e))
}

// ============================================================================
// API v3 Structures for Crypto-Agility
// ============================================================================

/// Suite ID identifies a set of cryptographic primitives (KEM, Signature, AEAD, Hash)
pub type SuiteId = u16;

/// Known Suite IDs
pub mod suite_ids {
    use super::SuiteId;

    /// X25519 + Ed25519 + AES-256-GCM + SHA-512 (baseline classic suite)
    pub const CLASSIC_X25519: SuiteId = 1;

    // Suite ID 2 is reserved for future PQ-hybrid implementation
    // pub const PQ_HYBRID_KYBER: SuiteId = 2;
}

/// Key material for a single cipher suite
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuiteKeyMaterial {
    /// Cipher suite identifier
    pub suite_id: SuiteId,

    /// Base64-encoded identity key (length depends on suite_id)
    pub identity_key: String,

    /// Base64-encoded signed prekey (length depends on suite_id)
    pub signed_prekey: String,

    /// Optional Base64-encoded one-time prekeys
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub one_time_prekeys: Vec<String>,
}

/// Bundle data that gets serialized and signed
/// This is the canonical format that the master identity key signs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleData {
    /// User ID this bundle belongs to
    pub user_id: String,

    /// Timestamp when bundle was created (ISO8601)
    pub timestamp: String,

    /// List of supported cipher suites with their key material
    pub supported_suites: Vec<SuiteKeyMaterial>,
}

/// Uploadable key bundle that the client sends to the server
/// Contains the bundle data and its cryptographic signature
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadableKeyBundle {
    /// Base64-encoded master identity key (Ed25519, 32 bytes)
    /// This key is used to verify the signature
    pub master_identity_key: String,

    /// Base64-encoded serialized BundleData
    pub bundle_data: String,

    /// Base64-encoded Ed25519 signature of bundle_data (64 bytes)
    pub signature: String,
}

/// Encrypted message for API v3
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedMessageV3 {
    /// Recipient user ID
    pub recipient_id: String,

    /// Suite ID used for encryption
    pub suite_id: SuiteId,

    /// Base64-encoded ciphertext (format depends on suite_id)
    pub ciphertext: String,
}
