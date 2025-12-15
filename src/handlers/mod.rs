mod auth;
mod connection;
mod messages;
pub mod session;
mod users;

use crate::context::AppContext;
use crate::message::ClientMessage;
use crate::metrics;
use connection::{ConnectionHandler, WebSocketStreamType};
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use uuid::Uuid;

// Re-export handle_websocket
pub async fn handle_websocket(
    ws_stream: WebSocketStreamType,
    addr: SocketAddr,
    ctx: AppContext,
) {
    metrics::CONNECTIONS_TOTAL.inc();
    let span = tracing::info_span!("websocket_connection", addr = %addr);
    let _enter = span.enter();

    tracing::info!("New connection from: {}", addr);

    let (ws_sender, mut ws_receiver) = ws_stream.split();
    let (tx, mut rx) = mpsc::unbounded_channel();

    let mut handler = ConnectionHandler::new(ws_sender, tx, addr);

    loop {
        tokio::select! {
            Some(msg) = ws_receiver.next() => {
                match msg {
                    Ok(WsMessage::Binary(data)) => {
                        tracing::debug!("Received {} bytes from {}", data.len(), addr);

                        match rmp_serde::from_slice::<ClientMessage>(&data) {
                            Ok(ClientMessage::Register {
                                username,
                                display_name,
                                password,
                                public_key,
                            }) => {
                                auth::handle_register(
                                    &mut handler,
                                    &ctx,
                                    username,
                                    display_name,
                                    password,
                                    public_key,
                                )
                                .await;
                            }

                            Ok(ClientMessage::Login { username, password }) => {
                                auth::handle_login(
                                    &mut handler,
                                    &ctx,
                                    username,
                                    password,
                                )
                                .await;
                            }

                            Ok(ClientMessage::Connect { session_token }) => {
                                auth::handle_connect(
                                    &mut handler,
                                    &ctx,
                                    session_token,
                                )
                                .await;
                            }

                            Ok(ClientMessage::Logout { session_token }) => {
                                auth::handle_logout(
                                    &mut handler,
                                    &ctx,
                                    session_token,
                                )
                                .await;
                            }

                            Ok(ClientMessage::SearchUsers { query }) => {
                                users::handle_search_users(&mut handler, &ctx, query).await;
                            }

                            Ok(ClientMessage::GetPublicKey { user_id }) => {
                                users::handle_get_public_key(&mut handler, &ctx, user_id).await;
                            }

                            Ok(ClientMessage::SendMessage(mut msg)) => {
                                metrics::MESSAGES_SENT_TOTAL.inc();
                                // Assign a new UUID to the message ID
                                msg.id = Uuid::new_v4().to_string();
                                messages::handle_send_message(&mut handler, &ctx, msg).await;
                            }

                            Err(e) => {
                                tracing::warn!("Failed to parse message from {}: {}", addr, e);
                                handler.send_error("INVALID_FORMAT", "Invalid message format").await;
                            }
                        }
                    }
                    Ok(WsMessage::Close(_)) => {
                        tracing::info!("Connection closed by client: {}", addr);
                        break;
                    }
                    Ok(WsMessage::Ping(data)) => {
                        let _ = handler.ws_sender_mut().send(WsMessage::Pong(data)).await;
                    }
                    Err(e) => {
                        tracing::error!("WebSocket error from {}: {}", addr, e);
                        break;
                    }
                    _ => {}
                }
            }

            Some(server_msg) = rx.recv() => {
                if let Ok(bytes) = rmp_serde::to_vec(&server_msg) {
                    if handler.ws_sender_mut().send(WsMessage::Binary(bytes)).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    handler.disconnect(&ctx.clients).await;
    tracing::info!("Connection closed: {}", addr);
}
