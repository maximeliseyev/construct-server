mod auth;
mod connection;
// pub mod deeplinks;  // TODO: Requires axum and qrcode dependencies
pub mod device_tokens;
pub mod federation;
mod key_rotation;
pub mod keys;
pub mod media;
// pub mod messages;  // Removed: replaced by src/routes/messages.rs (Phase 2.8)
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

pub async fn handle_websocket(ws_stream: WebSocketStreamType, addr: SocketAddr, ctx: AppContext) {
    metrics::CONNECTIONS_TOTAL.inc();
    metrics::CONNECTIONS_ACTIVE.inc();

    let span = tracing::info_span!(
        "websocket_connection",
        addr = %addr,
        connection_id = %uuid::Uuid::new_v4()
    );
    let _enter = span.enter();

    // IMPROVED: Enhanced connection logging with structured fields
    tracing::info!(
        event = "websocket_connection_established",
        addr = %addr,
        "New WebSocket connection established"
    );

    let (ws_sender, mut ws_receiver) = ws_stream.split();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut handler = ConnectionHandler::new(ws_sender, tx, addr);

    // IMPROVED: Connection-level rate limiting tracking
    let mut messages_received = 0u64;
    let mut errors_count = 0u64;
    let connection_start = std::time::Instant::now();
    let max_messages_per_minute = 60; // Rate limit: 60 messages per minute per connection
    let max_errors_per_minute = 10; // Max errors before disconnecting

    loop {
        tokio::select! {
            Some(msg) = ws_receiver.next() => {
                match msg {
                    Ok(WsMessage::Binary(data)) => {
                        // IMPROVED: Connection-level rate limiting
                        let elapsed = connection_start.elapsed();
                        if elapsed.as_secs() < 60 {
                            // Within first minute - check rate limit
                            if messages_received >= max_messages_per_minute {
                                tracing::warn!(
                                    event = "websocket_rate_limit_exceeded",
                                    addr = %addr,
                                    messages_received = messages_received,
                                    limit = max_messages_per_minute,
                                    "Connection rate limit exceeded - disconnecting"
                                );
                                let _ = handler.send_error(
                                    "RATE_LIMIT_EXCEEDED",
                                    &format!("Too many messages ({}/min). Connection closed.", max_messages_per_minute)
                                ).await;
                                break;
                            }
                        } else {
                            // Reset counter after 1 minute
                            messages_received = 0;
                        }
                        messages_received += 1;

                        #[cfg(debug_assertions)]
                        tracing::debug!(
                            event = "websocket_message_received",
                            addr = %addr,
                            size_bytes = data.len(),
                            "Received WebSocket message"
                        );

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

                            Ok(ClientMessage::RequestMediaToken(request)) => {
                                media::handle_media_token_request(
                                    &mut handler,
                                    &ctx,
                                    request,
                                )
                                .await;
                            }

                            Ok(ClientMessage::Dummy(_data)) => {
                                // Dummy messages are for traffic analysis protection
                                // Server silently ignores them (no response needed)
                                #[cfg(debug_assertions)]
                                tracing::debug!("Received dummy message from {}", addr);
                            }

                            Err(e) => {
                                errors_count += 1;

                                // IMPROVED: Enhanced error logging with structured fields
                                tracing::warn!(
                                    event = "websocket_parse_error",
                                    addr = %addr,
                                    error = %e,
                                    error_count = errors_count,
                                    "Failed to parse WebSocket message"
                                );

                                // IMPROVED: Disconnect after too many parse errors (likely malicious client)
                                if errors_count >= max_errors_per_minute {
                                    tracing::error!(
                                        event = "websocket_too_many_errors",
                                        addr = %addr,
                                        error_count = errors_count,
                                        "Too many parse errors - disconnecting client"
                                    );
                                    let _ = handler.send_error(
                                        "TOO_MANY_ERRORS",
                                        "Too many invalid messages. Connection closed."
                                    ).await;
                                    break;
                                }

                                handler.send_error("INVALID_FORMAT", "Invalid message format").await;
                            }
                        }
                    }
                    Ok(WsMessage::Close(frame)) => {
                        // IMPROVED: Enhanced close frame logging
                        let (close_code, close_reason) = if let Some(ref close_frame) = frame {
                            (Some(close_frame.code), close_frame.reason.to_string())
                        } else {
                            (None, "No close frame".to_string())
                        };

                        tracing::info!(
                            event = "websocket_connection_closed",
                            addr = %addr,
                            close_code = ?close_code,
                            close_reason = %close_reason,
                            messages_received = messages_received,
                            duration_secs = connection_start.elapsed().as_secs(),
                            "Connection closed by client"
                        );
                        break;
                    }
                    Ok(WsMessage::Ping(data)) => {
                        // IMPROVED: Log ping/pong for connection health monitoring
                        #[cfg(debug_assertions)]
                        tracing::debug!(
                            event = "websocket_ping_received",
                            addr = %addr,
                            "Received WebSocket ping"
                        );

                        if handler.ws_sender_mut().send(WsMessage::Pong(data)).await.is_err() {
                            tracing::warn!(
                                event = "websocket_pong_send_failed",
                                addr = %addr,
                                "Failed to send pong - connection may be broken"
                            );
                            break;
                        }
                    }
                    Ok(WsMessage::Pong(_)) => {
                        // Client sent pong (unusual, but handle gracefully)
                        #[cfg(debug_assertions)]
                        tracing::debug!(
                            event = "websocket_pong_received",
                            addr = %addr,
                            "Received WebSocket pong from client"
                        );
                    }
                    Ok(WsMessage::Text(_)) => {
                        // IMPROVED: Log unsupported message types
                        tracing::warn!(
                            event = "websocket_unsupported_message_type",
                            addr = %addr,
                            message_type = "text",
                            "Received unsupported Text message (only Binary supported)"
                        );
                        handler.send_error("UNSUPPORTED_MESSAGE_TYPE", "Only binary messages are supported").await;
                    }
                    Err(e) => {
                        // IMPROVED: Enhanced error logging with error classification
                        let error_type = if e.to_string().contains("Connection reset") {
                            "connection_reset"
                        } else if e.to_string().contains("Broken pipe") {
                            "broken_pipe"
                        } else if e.to_string().contains("timeout") {
                            "timeout"
                        } else {
                            "unknown"
                        };

                        tracing::error!(
                            event = "websocket_stream_error",
                            addr = %addr,
                            error = %e,
                            error_type = error_type,
                            messages_received = messages_received,
                            duration_secs = connection_start.elapsed().as_secs(),
                            "WebSocket stream error"
                        );
                        break;
                    }
                    _ => {
                        // IMPROVED: Log unexpected message types
                        tracing::debug!(
                            event = "websocket_unexpected_message",
                            addr = %addr,
                            "Received unexpected WebSocket message type"
                        );
                    }
                }
            }
            Some(server_msg) = rx.recv() => {
                // IMPROVED: Enhanced error handling for outgoing messages
                match rmp_serde::encode::to_vec_named(&server_msg) {
                    Ok(bytes) => {
                        if let Err(e) = handler.ws_sender_mut().send(WsMessage::Binary(bytes)).await {
                            tracing::warn!(
                                event = "websocket_send_failed",
                                addr = %addr,
                                error = %e,
                                "Failed to send message to client - connection may be broken"
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            event = "websocket_serialization_error",
                            addr = %addr,
                            error = %e,
                            "Failed to serialize server message"
                        );
                        // Don't break connection for serialization errors - just log
                    }
                }
            }
        }
    }

    // IMPROVED: Enhanced cleanup logging
    let connection_duration = connection_start.elapsed();
    let was_authenticated = handler.user_id().is_some();

    // Phase 5: Untrack user online status when they disconnect
    if let Some(user_id) = handler.user_id() {
        let user_id_hash = crate::utils::log_safe_id(user_id, &ctx.config.logging.hash_salt);

        let mut queue_lock = ctx.queue.lock().await;
        if let Err(e) = queue_lock.untrack_user_online(user_id).await {
            tracing::warn!(
                event = "websocket_untrack_failed",
                user_hash = %user_id_hash,
                error = %e,
                "Failed to untrack user online status"
            );
        }
    }

    handler.disconnect(&ctx.clients).await;

    // IMPROVED: Comprehensive connection close logging
    tracing::info!(
        event = "websocket_connection_ended",
        addr = %addr,
        was_authenticated = was_authenticated,
        messages_received = messages_received,
        errors_count = errors_count,
        duration_secs = connection_duration.as_secs(),
        duration_ms = connection_duration.as_millis(),
        "WebSocket connection ended"
    );

    metrics::CONNECTIONS_ACTIVE.dec();
}
