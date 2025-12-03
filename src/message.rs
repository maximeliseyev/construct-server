use serde::{Deserialize, Serialize};

#[derive (Debug, Clone, Serialize, Deserialize)]

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
        password: String,
        public_key: String,
    },
    Login {
        username: String, 
        password: String
    },
    GetPublicKey {
        username: String
    },
    SendMessage(Message),
    Logout,
}

#[derive(Debug, Serialize, Deserialize)]

pub enum ServerMessage {
    RegisterSuccess { user_id: String },
    LoginSuccess { user_id: String },
    PublicKey {
        user_id: String,
        username: String,
        public_key: String
    },
    Message(Message),
    Ack {id: String},
    Error {reason: String},
}
