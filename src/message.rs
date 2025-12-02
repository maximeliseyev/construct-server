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
    Register { username: String, password: String },
    Login { username: String, password: String },
    SendMessage(Message),
    Logout,
}

#[derive(Debug, Serialize, Deserialize)]

pub enum ServerMessage {
    RegisterSuccess { user_id: String },
    LoginSuccess { user_id: String },
    Message(Message),
    Ack {id: String},
    Error {reason: String},
}
