use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub from: String,
    pub to: String,
    pub content: String,
    pub timestamp: u64,
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
    PublicKey {
        user_id: String,
        username: String,
        display_name: String,
        public_key: String,
    },
    Message(Message),
    Ack {
        message_id: String,
        status: String,
    },
    Error {
        code: String,
        message: String,
    },
    LogoutSuccess,
}
