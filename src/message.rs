use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub from: String,
    pub to: String,
    /// Encrypted message content (base64 encoded)
    /// For E2E encryption, this contains the ciphertext that only the recipient can decrypt
    pub content: String,
    /// Nonce used for encryption (base64 encoded, 12 bytes)
    /// This is public and must be unique for each message
    /// The same nonce should never be reused with the same key
    pub nonce: Option<String>,
    pub timestamp: u64,
}

impl Message {
    pub fn new(from: String, to: String, content: String, nonce: Option<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            from,
            to,
            content,
            nonce,
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.from.is_empty()
            && !self.to.is_empty()
            && !self.content.is_empty()
            && Uuid::parse_str(&self.id).is_ok()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ClientMessage {
    Register {
        username: String,
        display_name: Option<String>,
        password: String,
        public_key: String,
    },
    Login {
        username: String,
        password: String,
    },
    Connect {
        session_token: String,
    },
    SearchUsers {
        query: String,
    },
    GetPublicKey {
        user_id: String,
    },
    SendMessage(Message),
    RotatePrekey {
        user_id: String,
        update: String,
    },
    Logout {
        session_token: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ServerMessage {
    RegisterSuccess {
        user_id: String,
        username: String,
        display_name: String,
        session_token: String,
        expires: i64,
    },
    LoginSuccess {
        user_id: String,
        username: String,
        display_name: String,
        session_token: String,
        expires: i64,
    },
    ConnectSuccess {
        user_id: String,
        username: String,
        display_name: String,
    },
    SessionExpired,
    SearchResults {
        users: Vec<crate::db::PublicUserInfo>,
    },
    #[deprecated(note = "Use PublicKeyBundle for proper E2EE")]
    PublicKey {
        user_id: String,
        username: String,
        display_name: String,
        public_key: String,
    },
    PublicKeyBundle {
        user_id: String, // Base64-encoded X25519 identity public key (32 bytes)
        identity_public: String, // Base64-encoded X25519 signed prekey public key (32 bytes)
        signed_prekey_public: String, // Base64-encoded Ed25519 signature (64 bytes)
        signature: String, // Base64-encoded Ed25519 verifying key (32 bytes)
        verifying_key: String,
    },
    Message(Message),
    Ack {
        message_id: String,
        status: String,
    },
    KeyRotationSuccess,
    Error {
        code: String,
        message: String,
    },
    LogoutSuccess,
}
