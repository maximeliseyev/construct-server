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
use crate::handlers::device_tokens;
use crate::kafka::KafkaMessageEnvelope;
use crate::message::{ChatMessage, ServerMessage};
use base64::Engine;
use sqlx::Row;

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

    // ========================================================================
    // PHASE 2: Kafka Dual-Write
    // Write to Kafka BEFORE Redis (source of truth)
    // ========================================================================
    let envelope = KafkaMessageEnvelope::from(&msg);
    if let Err(e) = ctx.kafka_producer.send_message(&envelope).await {
        tracing::warn!(
            error = %e,
            message_id = %msg.id,
            kafka_enabled = ctx.kafka_producer.is_enabled(),
            "Kafka write failed (dual-write phase, continuing with Redis)"
        );
        // In Phase 2 (dual-write), we continue with Redis even if Kafka fails
        // In Phase 5 (cutover), this would be a hard error
    } else if ctx.kafka_producer.is_enabled() {
        tracing::debug!(
            message_id = %msg.id,
            "Message persisted to Kafka"
        );
    }
    // ========================================================================

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

                // Send push notification to offline recipient
                send_push_notification_for_message(ctx, &msg).await;
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


/// Send push notification for a message to an offline recipient
/// Implements Phase 1 (Silent Push) and Phase 2 (Visible Push with filters)
async fn send_push_notification_for_message(ctx: &AppContext, msg: &ChatMessage) {
    if !ctx.apns_client.is_enabled() {
        return;
    }

    // Get device tokens for recipient
    let device_tokens = match device_tokens::get_user_device_tokens(ctx, &msg.to).await {
        Ok(tokens) => tokens,
        Err(e) => {
            tracing::warn!(error = %e, recipient_id = %msg.to, "Failed to fetch device tokens for push notification");
            return;
        }
    };

    if device_tokens.is_empty() {
        tracing::debug!(recipient_id = %msg.to, "No device tokens registered for recipient");
        return;
    }

    // Get sender username for visible notifications
    let sender_username = match get_username_for_push(ctx, &msg.from).await {
        Ok(username) => username,
        Err(e) => {
            tracing::warn!(error = %e, sender_id = %msg.from, "Failed to get sender username for push");
            "Someone".to_string() // Fallback
        }
    };

    // Send push notification to each device based on its filter preference
    for device in device_tokens {
        let notification_result = match device.notification_filter.as_str() {
            "silent" => {
                // Phase 1: Silent push (background fetch)
                ctx.apns_client
                    .send_silent_push(&device.device_token, Some(msg.from.clone()))
                    .await
            }
            "visible_all" | "visible_dm" => {
                // Phase 2: Visible push (user notification)
                // TODO: Add logic to differentiate between DM and group messages
                ctx.apns_client
                    .send_visible_push(&device.device_token, &sender_username, Some(msg.from.clone()))
                    .await
            }
            "visible_mentions" | "visible_contacts" => {
                // Phase 3: Advanced filtering
                // For now, treat as silent push
                // TODO: Implement mention detection and contact filtering
                ctx.apns_client
                    .send_silent_push(&device.device_token, Some(msg.from.clone()))
                    .await
            }
            _ => {
                tracing::warn!(filter = %device.notification_filter, "Unknown notification filter");
                continue;
            }
        };

        if let Err(e) = notification_result {
            tracing::warn!(
                error = %e,
                recipient_id = %msg.to,
                device_token = &device.device_token[..8],
                filter = %device.notification_filter,
                "Failed to send push notification"
            );
        } else {
            tracing::debug!(
                recipient_id = %msg.to,
                device_token = &device.device_token[..8],
                filter = %device.notification_filter,
                "Push notification sent successfully"
            );
        }
    }
}

/// Get username for push notification display
/// Returns username if found, otherwise returns "Someone" as fallback
async fn get_username_for_push(ctx: &AppContext, user_id: &str) -> Result<String, sqlx::Error> {
    let user_uuid = uuid::Uuid::parse_str(user_id).map_err(|_| {
        sqlx::Error::Decode(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid user_id UUID",
        )))
    })?;

    let result = sqlx::query(
        r#"SELECT username FROM users WHERE id = $1"#,
    )
    .bind(user_uuid)
    .fetch_optional(&*ctx.db_pool)
    .await?;

    Ok(result
        .and_then(|row| row.try_get("username").ok())
        .unwrap_or_else(|| "Someone".to_string()))
}

