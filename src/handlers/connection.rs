use crate::message::ServerMessage;
use futures_util::stream::SplitSink;
use futures_util::{Stream, Sink};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::WebSocketStream;

// Support both direct TCP and upgraded HTTP connections
pub enum WebSocketStreamType {
    Direct(WebSocketStream<TcpStream>),
    Upgraded(WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>),
}

// Implement Stream for WebSocketStreamType
impl Stream for WebSocketStreamType {
    type Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.get_mut() {
            WebSocketStreamType::Direct(s) => Pin::new(s).poll_next(cx),
            WebSocketStreamType::Upgraded(s) => Pin::new(s).poll_next(cx),
        }
    }
}

// Implement Sink for WebSocketStreamType
impl Sink<WsMessage> for WebSocketStreamType {
    type Error = tokio_tungstenite::tungstenite::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.get_mut() {
            WebSocketStreamType::Direct(s) => Pin::new(s).poll_ready(cx),
            WebSocketStreamType::Upgraded(s) => Pin::new(s).poll_ready(cx),
        }
    }

    fn start_send(self: Pin<&mut Self>, item: WsMessage) -> Result<(), Self::Error> {
        match self.get_mut() {
            WebSocketStreamType::Direct(s) => Pin::new(s).start_send(item),
            WebSocketStreamType::Upgraded(s) => Pin::new(s).start_send(item),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.get_mut() {
            WebSocketStreamType::Direct(s) => Pin::new(s).poll_flush(cx),
            WebSocketStreamType::Upgraded(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.get_mut() {
            WebSocketStreamType::Direct(s) => Pin::new(s).poll_close(cx),
            WebSocketStreamType::Upgraded(s) => Pin::new(s).poll_close(cx),
        }
    }
}

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

        let bytes = rmp_serde::encode::to_vec_named(msg)
            .map_err(|e| format!("Failed to serialize message: {}", e))?;

        self.ws_sender
            .send(WsMessage::Binary(bytes))
            .await
            .map_err(|e| format!("Failed to send message: {}", e))?;

        Ok(())
    }

    pub async fn send_error(&mut self, code: &str, message: &str) {
        let error = ServerMessage::Error(crate::message::ErrorData {
            code: code.to_string(),
            message: message.to_string(),
        });
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
        // Note: user_id tracking removal is handled in the caller context
        // where we have access to AppContext and can call untrack_user_online
        if let Some(uid) = &self.user_id {
            clients.write().await.remove(uid);
        }
    }

    #[allow(dead_code)]
    pub fn is_authenticated(&self) -> bool {
        self.user_id.is_some()
    }
}
