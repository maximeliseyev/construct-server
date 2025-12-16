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
