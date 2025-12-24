// ============================================================================
// Message Handler - Ephemeral Delivery (No Database Persistence)
// ============================================================================
//
// SECURITY DESIGN:
// Messages are NEVER stored in the database. This handler implements
// ephemeral message delivery to protect user privacy:
//
// Delivery Flow:
// 1. Validate message (structure, rate limits, user not blocked)
// 2. Check if recipient is online
//    a) Online  → Send directly via WebSocket (no storage)
//    b) Offline → Queue in Redis with TTL (temporary only)
// 3. Send ACK to sender (delivered/queued status)
//
// Privacy Benefits:
// - No conversation metadata in database
// - No social graph reconstruction possible
// - Forward secrecy maintained
// - Messages disappear after delivery or TTL expiry
//
// ============================================================================

// ============================================================================
// Message Handler - Ephemeral Delivery (No Database Persistence)
// ============================================================================
//
// SECURITY DESIGN:
// Messages are NEVER stored in the database. This handler implements
// ephemeral message delivery to protect user privacy:
//
// Delivery Flow:
// 1. Validate message (structure, rate limits, user not blocked)
// 2. Check if recipient is online
//    a) Online  → Send directly via WebSocket (no storage)
//    b) Offline → Queue in Redis with TTL (temporary only)
// 3. Send ACK to sender (delivered/queued status)
//
// Privacy Benefits:
// - No conversation metadata in database
// - No social graph reconstruction possible
// - Forward secrecy maintained
// - Messages disappear after delivery or TTL expiry
//
// ============================================================================

use crate::context::AppContext;
use crate::handlers::connection::ConnectionHandler;
use crate::message::{ChatMessage, ServerMessage};
use base64::Engine;

/// Handles message sending
/// Delivers immediately if recipient is online, otherwise queues for later delivery
/// IMPORTANT: Messages are NEVER persisted to database (Redis queue only)
pub async fn handle_send_message(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    msg: ChatMessage,
) {
    // ========================================================================
    // CRITICAL: Prevent Message Spoofing (IDOR)
    // ========================================================================
    // Ensure the `from` field in the message matches the authenticated user's
    // ID associated with this WebSocket connection.
    let sender_id = match handler.user_id() {
        Some(id) => id.clone(),
        None => {
            // This should ideally not be reached if the connection logic is sound
            tracing::error!("Unauthenticated user attempted to send a message");
            handler
                .send_error("AUTH_REQUIRED", "Authentication is required to send messages")
                .await;
            return;
        }
    };

    if sender_id != msg.from {
        tracing::warn!(
            authenticated_user = %sender_id,
            message_sender = %msg.from,
            "Message spoofing attempt detected (IDOR)"
        );
        handler
            .send_error(
                "FORBIDDEN",
                "You are not allowed to send messages from another user's account.",
            )
            .await;
        return;
    }
    // ========================================================================

    let mut queue = ctx.queue.lock().await;

    // 1. Проверка блокировки пользователя
    if let Ok(Some(reason)) = queue.is_user_blocked(&msg.from).await {
        tracing::warn!(user_id = %msg.from, reason = %reason, "Blocked user attempted to send message");
        handler
            .send_error(
                "USER_BLOCKED",
                &format!("Your account is temporarily blocked: {}", reason),
            )
            .await;
        return;
    }

    // 2. Replay protection - проверка уникальности сообщения
    // For Double Ratchet, we use ephemeral_public_key and message_number for replay detection
    let ephemeral_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(&msg.ephemeral_public_key);
    match queue
        .check_message_replay(&msg.id, &msg.content, &ephemeral_key_b64)
        .await
    {
        Ok(true) => {} // Сообщение уникальное, продолжаем
        Ok(false) => {
            tracing::warn!(message_id = %msg.id, "Duplicate message detected");
            handler
                .send_error("DUPLICATE_MESSAGE", "This message was already sent")
                .await;
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
                let block_duration = ctx.config.security.rate_limit_block_duration_seconds;
                if let Err(e) = queue
                    .block_user_temporarily(&msg.from, block_duration, "Rate limit exceeded")
                    .await
                {
                    tracing::error!(error = %e, "Failed to block user for rate limiting");
                    handler
                        .send_error("SERVER_ERROR", "Failed to apply rate limit")
                        .await;
                } else {
                    let message =
                        format!("Too many messages. Blocked for {} seconds.", block_duration);
                    handler.send_error("RATE_LIMIT_BLOCKED", &message).await;
                }
                return;
            } else if count > max_messages {
                tracing::warn!(user_id = %msg.from, count = count, "Rate limit warning");
                handler
                    .send_error(
                        "RATE_LIMIT_WARNING",
                        &format!("Slow down! ({}/{})", count, max_messages),
                    )
                    .await;
                return;
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to check rate limit");
        }
    }

    // Validate ChatMessage structure
    if !msg.is_valid() {
        tracing::warn!(user_id = %msg.from, "Invalid chat message format");
        handler
            .send_error("INVALID_MESSAGE_FORMAT", "Message validation failed")
            .await;
        return;
    }

    // Additional validation: check ephemeral_public_key length
    if msg.ephemeral_public_key.len() != 32 {
        tracing::warn!(user_id = %msg.from, "Invalid ephemeral public key size");
        handler
            .send_error(
                "INVALID_MESSAGE_FORMAT",
                "Ephemeral public key must be 32 bytes",
            )
            .await;
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
                let ack = ServerMessage::Ack(crate::message::AckData {
                    message_id: msg.id.clone(),
                    status: "delivered".to_string(),
                });
                if handler.send_msgpack(&ack).await.is_err() {
                    return;
                }

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
                    handler
                        .send_error("DELIVERY_FAILED", "Failed to deliver message")
                        .await;
                } else {
                    let ack = ServerMessage::Ack(crate::message::AckData {
                        message_id: msg.id.clone(),
                        status: "queued".to_string(),
                    });
                    if handler.send_msgpack(&ack).await.is_err() {
                        return;
                    }
                }
            }
        }
    } else {
        let mut queue = ctx.queue.lock().await;
        match queue.enqueue_message(&msg.to, &msg).await {
            Ok(_) => {
                let ack = ServerMessage::Ack(crate::message::AckData {
                    message_id: msg.id.clone(),
                    status: "queued".to_string(),
                });
                if handler.send_msgpack(&ack).await.is_err() {
                    return;
                }

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
                handler
                    .send_error("QUEUE_FAILED", "Failed to queue message")
                    .await;
            }
        }
    }
}
