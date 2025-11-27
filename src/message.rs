use serde::{Deserialize, Serialize};

#[derive (Debug, Clone, Serialize, Deserialize)]

pub struct Message {
    pub from: String,
    pub to: String,
    pub content: String,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]

pub enum ServerMessage {
    Message(Message),
    Ack {id: String},
    Error {reason: String},
}
