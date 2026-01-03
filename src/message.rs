use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::e2e::UploadableKeyBundle;

// ============================================================================
// ChatMessage (formerly Message) - Updated for Double Ratchet Protocol
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatMessage {
    pub id: String,
    pub from: String,
    pub to: String,

    /// Ephemeral public key for DH ratchet (32 bytes raw bytes)
    /// Serialized as MessagePack bin format
    #[serde(with = "serde_bytes")]
    pub ephemeral_public_key: Vec<u8>,

    /// Message number in symmetric-key ratchet chain
    /// Used for out-of-order message handling and forward secrecy
    pub message_number: u32,

    /// Base64-encoded ChaChaPoly sealed box
    /// Contains: nonce (12 bytes) + ciphertext (variable) + tag (16 bytes)
    /// The nonce field is now REMOVED (included in sealed box)
    pub content: String,

    /// Unix timestamp in seconds (client-side timestamp)
    pub timestamp: u64,
}

#[allow(dead_code)]
impl ChatMessage {
    pub fn new(
        from: String,
        to: String,
        ephemeral_public_key: Vec<u8>,
        message_number: u32,
        content: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            from,
            to,
            ephemeral_public_key,
            message_number,
            content,
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.from.is_empty()
            && !self.to.is_empty()
            && !self.content.is_empty()
            && self.ephemeral_public_key.len() == 32
            && Uuid::parse_str(&self.id).is_ok()
            && Uuid::parse_str(&self.from).is_ok()
            && Uuid::parse_str(&self.to).is_ok()
    }
}

// ============================================================================
// Client Message Data Structures
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterData {
    pub username: String,
    pub password: String,
    /// Native UploadableKeyBundle structure (MessagePack serialized)
    pub public_key: UploadableKeyBundle,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginData {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectData {
    pub session_token: String,
}


#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPublicKeyData {
    pub user_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotatePrekeyData {
    pub user_id: String,
    /// Native UploadableKeyBundle structure (MessagePack serialized)
    pub update: UploadableKeyBundle,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutData {
    pub session_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceTokenData {
    /// APNs device token (hex string)
    pub device_token: String,
    /// Optional device name for user identification
    pub device_name: Option<String>,
    /// Notification filter preference
    pub notification_filter: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnregisterDeviceTokenData {
    /// APNs device token to remove
    pub device_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDeviceTokenPreferencesData {
    /// Device token to update
    pub device_token: String,
    /// New notification filter
    pub notification_filter: String,
    /// Whether push is enabled for this device
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordData {
    pub session_token: String,
    pub old_password: String,
    pub new_password: String,
    pub new_password_confirm: String,
}

// ============================================================================
// ClientMessage Enum - Internally Tagged Format
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
#[serde(rename_all = "camelCase")]
pub enum ClientMessage {
    Register(RegisterData),
    Login(LoginData),
    Connect(ConnectData),
    GetPublicKey(GetPublicKeyData),
    SendMessage(ChatMessage),
    RotatePrekey(RotatePrekeyData),
    ChangePassword(ChangePasswordData),
    Logout(LogoutData),
    RegisterDeviceToken(RegisterDeviceTokenData),
    UnregisterDeviceToken(UnregisterDeviceTokenData),
    UpdateDeviceTokenPreferences(UpdateDeviceTokenPreferencesData),
}

// ============================================================================
// Server Message Data Structures
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterSuccessData {
    pub user_id: String,
    pub username: String,
    pub session_token: String,
    pub expires: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginSuccessData {
    pub user_id: String,
    pub username: String,
    pub session_token: String,
    pub expires: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectSuccessData {
    pub user_id: String,
    pub username: String,
}


#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyBundleData {
    pub user_id: String,
    /// Username of the user (for display purposes, shared during key exchange)
    pub username: String,
    /// Base64-encoded X25519 identity public key (32 bytes)
    pub identity_public: String,
    /// Base64-encoded X25519 signed prekey public key (32 bytes)
    pub signed_prekey_public: String,
    /// Base64-encoded Ed25519 signature (64 bytes)
    pub signature: String,
    /// Base64-encoded Ed25519 verifying key (32 bytes)
    pub verifying_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AckData {
    pub message_id: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorData {
    pub code: String,
    pub message: String,
}

// ============================================================================
// ServerMessage Enum - Internally Tagged Format
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
#[serde(rename_all = "camelCase")]
pub enum ServerMessage {
    RegisterSuccess(RegisterSuccessData),
    LoginSuccess(LoginSuccessData),
    ConnectSuccess(ConnectSuccessData),
    SessionExpired,
    PublicKeyBundle(PublicKeyBundleData),
    Message(ChatMessage),
    EncryptedV3(crate::e2e::EncryptedMessageV3), // New variant for API v3 encrypted messages
    Ack(AckData),
    KeyRotationSuccess,
    ChangePasswordSuccess,
    Error(ErrorData),
    LogoutSuccess,
    DeviceTokenRegistered,
    DeviceTokenUnregistered,
    DeviceTokenPreferencesUpdated,
}

// ============================================================================
// Tests - Verify MessagePack Format
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_message_internally_tagged_format() {
        let msg = ServerMessage::RegisterSuccess(RegisterSuccessData {
            user_id: "test-id".to_string(),
            username: "test".to_string(),
            session_token: "token".to_string(),
            expires: 1234567890,
        });

        let bytes = rmp_serde::encode::to_vec_named(&msg).unwrap();

        // Должно начинаться с 0x82 (map{2}) а не 0x92 (array[2])
        assert_eq!(
            bytes[0], 0x82,
            "First byte должен быть 0x82 (map), got 0x{:02x}",
            bytes[0]
        );

        // Декодируем обратно чтобы убедиться что структура правильная
        let decoded: ServerMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            ServerMessage::RegisterSuccess(data) => {
                assert_eq!(data.user_id, "test-id");
                assert_eq!(data.username, "test");
            }
            _ => panic!("Wrong variant decoded"),
        }

        // Проверяем что в байтах есть "type" и "payload" ключи
        let hex = bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        // "type" = 74 79 70 65 в hex
        assert!(hex.contains("74797065"), "Should contain 'type' key");
        // "payload" = 70 61 79 6c 6f 61 64 в hex
        assert!(
            hex.contains("7061796c6f6164"),
            "Should contain 'payload' key"
        );
    }

    #[test]
    fn test_server_message_unit_variant_format() {
        let msg = ServerMessage::SessionExpired;
        let bytes = rmp_serde::encode::to_vec_named(&msg).unwrap();

        // Unit variant должен быть map{1} с только "type"
        assert_eq!(
            bytes[0], 0x81,
            "Unit variant should be 0x81 (map{{1}}), got 0x{:02x}",
            bytes[0]
        );

        // Декодируем обратно
        let decoded: ServerMessage = rmp_serde::from_slice(&bytes).unwrap();
        assert!(matches!(decoded, ServerMessage::SessionExpired));
    }

    #[test]
    fn test_client_message_internally_tagged_format() {
        let msg = ClientMessage::Login(LoginData {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        });

        let bytes = rmp_serde::encode::to_vec_named(&msg).unwrap();

        // Должно начинаться с 0x82 (map{2})
        assert_eq!(
            bytes[0], 0x82,
            "ClientMessage should be 0x82 (map), got 0x{:02x}",
            bytes[0]
        );

        // Декодируем обратно
        let decoded: ClientMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            ClientMessage::Login(data) => {
                assert_eq!(data.username, "testuser");
                assert_eq!(data.password, "testpass");
            }
            _ => panic!("Wrong variant decoded"),
        }
    }
}
