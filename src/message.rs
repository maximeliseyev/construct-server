use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub from: String,
    pub to: String,
    pub content: String,
    pub timestamp: u64,
    pub encrypted: bool,
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
        password: String
    },
    SearchUsers {
        query: String,
    },
    GetPublicKey {
        user_id: String,
    },
    SendMessage(Message),
    Logout,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ServerMessage {
    RegisterSuccess {
        user_id: String,
        username: String,
        display_name: String,
    },
    LoginSuccess {
        user_id: String,
        username: String,
        display_name: String,
    },
    SearchResults {
        users: Vec<crate::db::PublicUserInfo>,
    },
    PublicKey {
        user_id: String,
        username: String,
        display_name: String,
        public_key: String
    },
    Message(Message),
    Ack {id: String},
    Error {reason: String},
}
