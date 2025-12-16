use crate::message::ServerMessage;
use futures_util::stream::SplitSink;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::WebSocketStream;

pub type WebSocketStreamType = WebSocketStream<TcpStream>;

pub struct ConnectionHandler {
    ws_sender: SplitSink<WebSocketStreamType, WsMessage>,
    tx: mpsc::UnboundedSender<ServerMessage>,
    user_id: Option<String>,
    #[allow(dead_code)]
    addr: SocketAddr,
}

impl ConnectionHandler {
    pub fn new(
        ws_sender: SplitSink<WebSocketStreamType, WsMessage>,
        tx: mpsc::UnboundedSender<ServerMessage>,
        addr: SocketAddr,
    ) -> Self {
        Self {
            ws_sender,
            tx,
            user_id: None,
            addr,
        }
    }

    pub async fn send_msgpack(&mut self, msg: &ServerMessage) -> Result<(), String> {
        use futures_util::SinkExt;

        let bytes = rmp_serde::to_vec(msg)
            .map_err(|e| format!("Failed to serialize message: {}", e))?;

        self.ws_sender
            .send(WsMessage::Binary(bytes))
            .await
            .map_err(|e| format!("Failed to send message: {}", e))?;

        Ok(())
    }

    pub async fn send_error(&mut self, code: &str, message: &str) {
        let error = ServerMessage::Error {
            code: code.to_string(),
            message: message.to_string(),
        };
        if self.send_msgpack(&error).await.is_err() {
            tracing::debug!("Failed to send error to disconnected client {}", self.addr);
            return;
        }
    }

    #[allow(dead_code)]
    pub fn user_id(&self) -> &Option<String> {
        &self.user_id
    }

    pub fn set_user_id(&mut self, id: String) {
        self.user_id = Some(id);
    }

    pub fn tx(&self) -> &mpsc::UnboundedSender<ServerMessage> {
        &self.tx
    }

    #[allow(dead_code)]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn ws_sender_mut(&mut self) -> &mut SplitSink<WebSocketStreamType, WsMessage> {
        &mut self.ws_sender
    }

    pub async fn disconnect(
        &mut self,
        clients: &Arc<RwLock<HashMap<String, mpsc::UnboundedSender<ServerMessage>>>>,
    ) {
        if let Some(uid) = &self.user_id {
            clients.write().await.remove(uid);
        }
    }

    #[allow(dead_code)]
    pub fn is_authenticated(&self) -> bool {
        self.user_id.is_some()
    }
}
