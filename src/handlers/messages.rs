use crate::context::AppContext;
use crate::handlers::connection::ConnectionHandler;
use crate::message::{Message, ServerMessage};
use crate::crypto::{StoredEncryptedMessage, MessageType, ServerCryptoValidator};

/// Handles message sending
/// Delivers immediately if recipient is online, otherwise queues for later delivery
pub async fn handle_send_message(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    msg: Message,
) {
    let mut queue = ctx.queue.lock().await;

    // 1. Проверка блокировки пользователя
    if let Ok(Some(reason)) = queue.is_user_blocked(&msg.from).await {
        tracing::warn!(user_id = %msg.from, reason = %reason, "Blocked user attempted to send message");
        handler.send_error("USER_BLOCKED", &format!("Your account is temporarily blocked: {}", reason)).await;
        return;
    }

    // 2. Replay protection - проверка уникальности сообщения
    let nonce = msg.nonce.clone().unwrap_or_default();
    match queue.check_message_replay(&msg.id, &msg.content, &nonce).await {
        Ok(true) => {}, // Сообщение уникальное, продолжаем
        Ok(false) => {
            tracing::warn!(message_id = %msg.id, "Duplicate message detected");
            handler.send_error("DUPLICATE_MESSAGE", "This message was already sent").await;
            return;
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to check message replay");
            // Продолжаем, но логируем ошибку
        }
    }

    match queue.increment_message_count(&msg.from).await {
        Ok(count) => {
            let max_messages = ctx.config.security.max_messages_per_hour;
            let block_threshold = max_messages + (max_messages / 2);
            
            if count > block_threshold {
                let _ = queue.block_user_temporarily(&msg.from, 3600, "Rate limit exceeded").await;
                handler.send_error("RATE_LIMIT_BLOCKED", "Too many messages. Blocked for 1 hour.").await;
                return;
            } else if count > max_messages {
                tracing::warn!(user_id = %msg.from, count = count, "Rate limit warning");
                handler.send_error("RATE_LIMIT_WARNING", &format!("Slow down! ({}/{})", count, max_messages)).await;
                return;
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to check rate limit");
        }
    }

    let stored_msg = StoredEncryptedMessage {
        content: msg.content.clone(),
        nonce: nonce.clone(),
        sender_identity: msg.from.clone(),
        recipient_id: msg.to.clone(),
        sender_id: msg.from.clone(),
        timestamp: chrono::Utc::now(),
        message_type: MessageType::TextMessage,
    };

    if let Err(e) = ServerCryptoValidator::validate_encrypted_message(&stored_msg) {
        tracing::warn!(user_id = %msg.from, error = %e, "Invalid message format");
        handler.send_error("INVALID_MESSAGE_FORMAT", &e.to_string()).await;
        return;
    }

    drop(queue);

    let recipient_tx = {
        let clients_read = ctx.clients.read().await;
        clients_read.get(&msg.to).cloned()
    };

    if let Some(tx) = recipient_tx {
        match tx.send(ServerMessage::Message(msg.clone())) {
            Ok(_) => {
                let ack = ServerMessage::Ack {
                    message_id: msg.id.clone(),
                    status: "delivered".to_string(),
                };
                let _ = handler.send_msgpack(&ack).await;
                
                if ctx.config.logging.enable_message_metadata {
                    tracing::debug!(
                        message_id = %msg.id,
                        from = %msg.from,
                        to = %msg.to,
                        content_len = msg.content.len(),
                        "Message delivered to online recipient"
                    );
                } else {
                    tracing::debug!(message_id = %msg.id, "Message delivered to online recipient");
                }
            }
            Err(e) => {
                if ctx.config.logging.enable_message_metadata {
                    tracing::warn!(
                        error = %e,
                        message_id = %msg.id,
                        from = %msg.from,
                        to = %msg.to,
                        "Failed to deliver to online recipient, queueing message"
                    );
                } else {
                    tracing::warn!(
                        error = %e,
                        message_id = %msg.id,
                        "Failed to deliver to online recipient, queueing message"
                    );
                }

                let mut queue = ctx.queue.lock().await;
                if let Err(qe) = queue.enqueue_message(&msg.to, &msg).await {
                    tracing::error!(error = %qe, "Failed to queue message after delivery failure");
                    handler.send_error("DELIVERY_FAILED", "Failed to deliver message").await;
                } else {
                    let ack = ServerMessage::Ack {
                        message_id: msg.id.clone(),
                        status: "queued".to_string(),
                    };
                    let _ = handler.send_msgpack(&ack).await;
                }
            }
        }
    } else {
        let mut queue = ctx.queue.lock().await;
        match queue.enqueue_message(&msg.to, &msg).await {
            Ok(_) => {
                let ack = ServerMessage::Ack {
                    message_id: msg.id.clone(),
                    status: "queued".to_string(),
                };
                let _ = handler.send_msgpack(&ack).await;
                
                if ctx.config.logging.enable_message_metadata {
                    tracing::debug!(
                        message_id = %msg.id,
                        from = %msg.from,
                        to = %msg.to,
                        content_len = msg.content.len(),
                        "Message queued for offline recipient"
                    );
                } else {
                    tracing::debug!(message_id = %msg.id, "Message queued for offline recipient");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, message_id = %msg.id, "Error queuing message");
                handler.send_error("QUEUE_FAILED", "Failed to queue message").await;
            }
        }
    }
}
