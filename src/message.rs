use chrono;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub password: String,
    /// Base64-encoded MessagePack of RegistrationBundle
    pub public_key: String,
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
pub struct SearchUsersData {
    pub query: String,
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
    /// Base64-encoded MessagePack of SignedPrekeyUpdate
    pub update: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutData {
    pub session_token: String,
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
    SearchUsers(SearchUsersData),
    GetPublicKey(GetPublicKeyData),
    SendMessage(ChatMessage),
    RotatePrekey(RotatePrekeyData),
    Logout(LogoutData),
}

// ============================================================================
// Server Message Data Structures
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterSuccessData {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
    pub session_token: String,
    pub expires: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginSuccessData {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
    pub session_token: String,
    pub expires: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectSuccessData {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResultsData {
    pub users: Vec<crate::db::PublicUserInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyBundleData {
    pub user_id: String,
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
    SearchResults(SearchResultsData),
    PublicKeyBundle(PublicKeyBundleData),
    Message(ChatMessage),
    Ack(AckData),
    KeyRotationSuccess,
    Error(ErrorData),
    LogoutSuccess,
}
