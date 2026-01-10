mod auth;
mod connection;
// pub mod deeplinks;  // TODO: Requires axum and qrcode dependencies
pub mod device_tokens;
pub mod federation;
mod key_rotation;
pub mod keys;
pub mod messages;
pub mod session;
mod ws_messages;

use crate::context::AppContext;
use crate::message::ClientMessage;
use crate::metrics;
use connection::ConnectionHandler;
pub use connection::WebSocketStreamType;
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;

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
                        #[cfg(debug_assertions)]
                        tracing::debug!("Received {} bytes from {}", data.len(), addr);
                        match rmp_serde::from_slice::<ClientMessage>(&data) {
                            Ok(ClientMessage::Register(data)) => {
                                auth::handle_register(
                                    &mut handler,
                                    &ctx,
                                    data.username,
                                    data.password,
                                    data.public_key,  // Now native UploadableKeyBundle
                                )
                                .await;
                            }

                            Ok(ClientMessage::Login(data)) => {
                                auth::handle_login(
                                    &mut handler,
                                    &ctx,
                                    data.username,
                                    data.password,
                                )
                                .await;
                            }

                            Ok(ClientMessage::Connect(data)) => {
                                auth::handle_connect(
                                    &mut handler,
                                    &ctx,
                                    data.session_token,
                                )
                                .await;
                            }

                            Ok(ClientMessage::Logout(data)) => {
                                auth::handle_logout(
                                    &mut handler,
                                    &ctx,
                                    data.session_token,
                                )
                                .await;
                            }

                            Ok(ClientMessage::ChangePassword(data)) => {
                                auth::handle_change_password(
                                    &mut handler,
                                    &ctx,
                                    data.session_token,
                                    data.old_password,
                                    data.new_password,
                                    data.new_password_confirm,
                                )
                                .await;
                            }

                            Ok(ClientMessage::DeleteAccount(data)) => {
                                auth::handle_delete_account(
                                    &mut handler,
                                    &ctx,
                                    data.session_token,
                                    data.password,
                                )
                                .await;
                            }

                            Ok(ClientMessage::GetPublicKey(data)) => {
                                keys::handle_get_public_key(&mut handler, &ctx, data.user_id).await;
                            }

                            Ok(ClientMessage::SendMessage(msg)) => {
                                metrics::MESSAGES_SENT_TOTAL.inc();
                                // ✅ Use client-provided message ID (don't overwrite!)
                                // Client generates UUID for offline-first and idempotency
                                ws_messages::handle_send_message(&mut handler, &ctx, msg).await;
                            }

                            Ok(ClientMessage::AcknowledgeMessage(ack_data)) => {
                                ws_messages::handle_acknowledge_message(&mut handler, &ctx, ack_data).await;
                            }

                            Ok(ClientMessage::RotatePrekey(data)) => {
                                key_rotation::handle_rotate_prekey(
                                    &mut handler,
                                    &ctx,
                                    data.user_id,
                                    data.update,  // Now native UploadableKeyBundle
                                )
                                .await;
                            }

                            Ok(ClientMessage::RegisterDeviceToken(data)) => {
                                device_tokens::handle_register_device_token(
                                    &mut handler,
                                    &ctx,
                                    data.device_token,
                                    data.device_name,
                                    data.notification_filter,
                                )
                                .await;
                            }

                            Ok(ClientMessage::UnregisterDeviceToken(data)) => {
                                device_tokens::handle_unregister_device_token(
                                    &mut handler,
                                    &ctx,
                                    data.device_token,
                                )
                                .await;
                            }

                            Ok(ClientMessage::UpdateDeviceTokenPreferences(data)) => {
                                device_tokens::handle_update_device_token_preferences(
                                    &mut handler,
                                    &ctx,
                                    data.device_token,
                                    data.notification_filter,
                                    data.enabled,
                                )
                                .await;
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
                        if handler.ws_sender_mut().send(WsMessage::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("WebSocket error from {}: {}", addr, e);
                        break;
                    }
                    _ => {}
                }
            }
            Some(server_msg) = rx.recv() => {
                if let Ok(bytes) = rmp_serde::encode::to_vec_named(&server_msg) {
                    if handler.ws_sender_mut().send(WsMessage::Binary(bytes)).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    // Phase 5: Untrack user online status when they disconnect
    if let Some(user_id) = handler.user_id() {
        let mut queue_lock = ctx.queue.lock().await;
        if let Err(e) = queue_lock.untrack_user_online(user_id).await {
            tracing::warn!(error = %e, user_id = %user_id, "Failed to untrack user online status");
        }
    }
    
    handler.disconnect(&ctx.clients).await;
    tracing::info!("Connection closed: {}", addr);
}
