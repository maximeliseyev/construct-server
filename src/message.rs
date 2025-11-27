use serde::{Deserialize, Serialize};

#[derive (Debug, Clone, Serialize, Deserialize)]

pub struct Message {
    pub from: String,
    pub to: String,
    pub content: String,
    pub timestamp: u64,
}


#[derive(Debug, Serialize, Deserialize)]

pub enum ClientMessage {
    Login { user_id: String },
    SendMessage(Message),
    Logout,
}

#[derive(Debug, Serialize, Deserialize)]

pub enum ServerMessage {
    LoginSuccess { user_id: String },
    Message(Message),
    Ack {id: String},
    Error {reason: String},
}
