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

use crate::audit::AuditLogger;
use crate::context::AppContext;
use crate::handlers::connection::ConnectionHandler;
use crate::handlers::device_tokens;
use crate::kafka::KafkaMessageEnvelope;
use crate::message::{ChatMessage, ServerMessage};
use crate::utils::log_safe_id;
use base64::Engine;
use sqlx::Row;

/// Handles message sending
/// Delivers immediately if recipient is online, otherwise queues for later delivery
/// IMPORTANT: Messages are NEVER persisted to database (Redis queue only)
///
/// Phase 2.8: Refactored into smaller functions for better maintainability
pub async fn handle_send_message(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    msg: ChatMessage,
) {
    // 1. Validate sender (prevent message spoofing)
    let sender_id = match validate_sender(handler, ctx, &msg).await {
        Ok(id) => id,
        Err(_) => return, // Error already sent to client
    };

    // 2. Validate message size
    if !validate_message_size(handler, ctx, &msg, &sender_id).await {
        return; // Error already sent to client
    }

    // 3. Check rate limiting and user blocking
    let mut queue = ctx.queue.lock().await;
    if !check_rate_limiting(handler, ctx, &mut queue, &msg, &sender_id).await {
        return; // Error already sent to client
    }

    // 4. Validate message structure
    drop(queue);
    if !validate_message_structure(handler, ctx, &msg).await {
        return; // Error already sent to client
    }

    // 5. Try Message Gateway path (if available)
    if try_message_gateway(handler, ctx, &msg, &sender_id).await {
        return; // Message handled by gateway
    }

    // 6. Hybrid architecture: Kafka + Direct delivery
    deliver_message_hybrid(handler, ctx, &msg).await;
}

// ============================================================================
// Helper Functions (Phase 2.8: Extracted from handle_send_message)
// ============================================================================

// ============================================================================
// Helper Functions (Phase 2.8: Extracted from handle_send_message)
// ============================================================================

/// Validates sender authentication and prevents message spoofing
/// Returns sender_id if validation passes, sends error and returns Err if not
async fn validate_sender(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    msg: &ChatMessage,
) -> Result<String, ()> {
    let sender_id = match handler.user_id() {
        Some(id) => id.clone(),
        None => {
            tracing::error!("Unauthenticated user attempted to send a message");
            handler
                .send_error(
                    "AUTH_REQUIRED",
                    "Authentication is required to send messages",
                )
                .await;
            return Err(());
        }
    };

    if sender_id != msg.from {
        // AUDIT: Log security violation (message spoofing attempt)
        let user_id_hash = log_safe_id(&sender_id, &ctx.config.logging.hash_salt);
        let message_sender_hash = log_safe_id(&msg.from, &ctx.config.logging.hash_salt);
        let client_ip = Some(handler.addr().ip());
        AuditLogger::log_security_violation(
            Some(user_id_hash.clone()),
            None,
            client_ip,
            "message_spoofing".to_string(),
            Some(format!(
                "Authenticated user (hash={}) attempted to send message as different user (hash={})",
                user_id_hash, message_sender_hash
            )),
        );

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
        return Err(());
    }

    Ok(sender_id)
}

/// Validates message size to prevent DoS attacks
/// Returns true if valid, sends error and returns false if not
async fn validate_message_size(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    msg: &ChatMessage,
    sender_id: &str,
) -> bool {
    let message_size = msg.content.len();
    if message_size > crate::config::MAX_WEBSOCKET_MESSAGE_SIZE {
        tracing::warn!(
            size_bytes = message_size,
            size_kb = message_size / 1024,
            limit_kb = crate::config::MAX_WEBSOCKET_MESSAGE_SIZE / 1024,
            sender_hash = %log_safe_id(sender_id, &ctx.config.logging.hash_salt),
            "Message content too large - possible abuse or media sent inline instead of via CDN"
        );
        handler
            .send_error(
                "MESSAGE_TOO_LARGE",
                &format!(
                    "Message size ({} KB) exceeds maximum of {} KB. For media files, use the media upload API.",
                    message_size / 1024,
                    crate::config::MAX_WEBSOCKET_MESSAGE_SIZE / 1024
                ),
            )
            .await;
        return false;
    }
    true
}

/// Checks rate limiting and user blocking
/// Returns true if message can proceed, sends error and returns false if not
async fn check_rate_limiting(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    queue: &mut tokio::sync::MutexGuard<'_, crate::queue::MessageQueue>,
    msg: &ChatMessage,
    _sender_id: &str,
) -> bool {
    // IP-based rate limiting
    let client_ip = handler.addr().ip().to_string();
    match queue.increment_ip_message_count(&client_ip).await {
        Ok(ip_count) => {
            let max_ip_messages = ctx.config.security.max_messages_per_ip_per_hour;
            if ip_count > max_ip_messages {
                tracing::warn!(
                    ip = %client_ip,
                    count = ip_count,
                    limit = max_ip_messages,
                    user_hash = %log_safe_id(&msg.from, &ctx.config.logging.hash_salt),
                    "IP rate limit exceeded - possible distributed attack"
                );
            }
        }
        Err(e) => {
            tracing::error!(error = %e, ip = %client_ip, "Failed to check IP rate limit");
        }
    }

    // Check if user is blocked
    if let Ok(Some(reason)) = queue.is_user_blocked(&msg.from).await {
        tracing::warn!(
            user_hash = %log_safe_id(&msg.from, &ctx.config.logging.hash_salt),
            reason = %reason,
            "Blocked user attempted to send message"
        );
        handler
            .send_error(
                "USER_BLOCKED",
                &format!("Your account is temporarily blocked: {}", reason),
            )
            .await;
        return false;
    }

    // Replay protection
    let ephemeral_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(&msg.ephemeral_public_key);
    match queue
        .check_message_replay(&msg.id, &msg.content, &ephemeral_key_b64)
        .await
    {
        Ok(true) => {} // Message is unique, continue
        Ok(false) => {
            tracing::warn!(message_id = %msg.id, "Duplicate message detected");
            handler
                .send_error("DUPLICATE_MESSAGE", "This message was already sent")
                .await;
            return false;
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to check message replay");
        }
    }

    // User-based rate limiting
    match queue.increment_message_count(&msg.from).await {
        Ok(count) => {
            let max_messages = ctx.config.security.max_messages_per_hour;
            let block_threshold = max_messages + (max_messages / 2);

            if count > block_threshold {
                // Block user
                let user_id_hash = log_safe_id(&msg.from, &ctx.config.logging.hash_salt);
                let client_ip = Some(handler.addr().ip());
                AuditLogger::log_rate_limit_violation(
                    Some(user_id_hash.clone()),
                    None,
                    client_ip,
                    "messages_per_hour".to_string(),
                    count,
                    max_messages,
                );

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
                return false;
            } else if count > max_messages {
                // Warning
                let user_id_hash = log_safe_id(&msg.from, &ctx.config.logging.hash_salt);
                let client_ip = Some(handler.addr().ip());
                AuditLogger::log_rate_limit_violation(
                    Some(user_id_hash.clone()),
                    None,
                    client_ip,
                    "messages_per_hour_warning".to_string(),
                    count,
                    max_messages,
                );

                tracing::warn!(
                    user_hash = %user_id_hash,
                    count = count,
                    "Rate limit warning"
                );
                handler
                    .send_error(
                        "RATE_LIMIT_WARNING",
                        &format!("Slow down! ({}/{})", count, max_messages),
                    )
                    .await;
                return false;
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to check rate limit");
        }
    }

    true
}

/// Validates message structure
/// Returns true if valid, sends error and returns false if not
async fn validate_message_structure(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    msg: &ChatMessage,
) -> bool {
    if !msg.is_valid() {
        tracing::warn!(
            user_hash = %log_safe_id(&msg.from, &ctx.config.logging.hash_salt),
            "Invalid chat message format"
        );
        handler
            .send_error("INVALID_MESSAGE_FORMAT", "Message validation failed")
            .await;
        return false;
    }

    if msg.ephemeral_public_key.len() != 32 {
        tracing::warn!(
            user_hash = %log_safe_id(&msg.from, &ctx.config.logging.hash_salt),
            "Invalid ephemeral public key size"
        );
        handler
            .send_error(
                "INVALID_MESSAGE_FORMAT",
                "Ephemeral public key must be 32 bytes",
            )
            .await;
        return false;
    }

    true
}

/// Tries to send message through Message Gateway
/// Returns true if message was handled by gateway, false if should fallback to local processing
async fn try_message_gateway(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    msg: &ChatMessage,
    sender_id: &str,
) -> bool {
    let gateway_client = match &ctx.gateway_client {
        Some(client) => client,
        None => return false, // No gateway, use local processing
    };

    tracing::debug!(
        message_id = %msg.id,
        "Forwarding message to Message Gateway service"
    );

    let mut client = gateway_client.lock().await;
    match client.submit_message(msg, sender_id).await {
        Ok(()) => {
            let ack = ServerMessage::Ack(crate::message::AckData {
                message_id: msg.id.clone(),
                status: "accepted".to_string(),
            });
            handler.send_msgpack(&ack).await.ok();

            tracing::info!(
                message_id = %msg.id,
                "Message accepted by Message Gateway"
            );
            return true;
        }
        Err(e) => {
            let error_msg = e.to_string();

            // Check if this is a connection/unavailability error (should fallback)
            let is_connection_error = error_msg.contains("Failed to connect")
                || error_msg.contains("gRPC call failed")
                || error_msg.contains("unavailable")
                || error_msg.contains("deadline")
                || error_msg.contains("timeout")
                || error_msg.contains("refused");

            if is_connection_error {
                tracing::warn!(
                    message_id = %msg.id,
                    error = %e,
                    "Message Gateway unavailable - falling back to local processing"
                );
                return false; // Fallback to local processing
            } else {
                // Gateway rejected the message - don't fallback
                tracing::warn!(
                    message_id = %msg.id,
                    error = %e,
                    "Message Gateway rejected message"
                );

                // Parse error to send appropriate error code
                if error_msg.contains("RATE_LIMIT") {
                    handler.send_error("RATE_LIMIT_WARNING", &error_msg).await;
                } else if error_msg.contains("USER_BLOCKED") {
                    handler.send_error("USER_BLOCKED", &error_msg).await;
                } else if error_msg.contains("DUPLICATE") {
                    handler.send_error("DUPLICATE_MESSAGE", &error_msg).await;
                } else {
                    handler.send_error("VALIDATION_ERROR", &error_msg).await;
                }
                return true; // Handled (rejected)
            }
        }
    }
}

/// Delivers message using hybrid architecture (Kafka + Direct delivery)
async fn deliver_message_hybrid(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    msg: &ChatMessage,
) {
    // STEP 1: Write to Kafka first (Source of Truth)
    let envelope = KafkaMessageEnvelope::from(msg);
    if let Some(kafka_producer) = &ctx.kafka_producer {
        if let Err(e) = kafka_producer.send_message(&envelope).await {
            tracing::error!(
                error = %e,
                message_id = %msg.id,
                kafka_enabled = kafka_producer.is_enabled(),
                "❌ Kafka write FAILED - message NOT persisted (source of truth unavailable)"
            );
            handler
                .send_error(
                    "DELIVERY_FAILED",
                    "Message could not be persisted. Please retry.",
                )
                .await;
            return;
        }
    } else {
        tracing::error!(
            message_id = %msg.id,
            "❌ Kafka producer not available - message NOT persisted (source of truth unavailable)"
        );
        handler
            .send_error(
                "DELIVERY_FAILED",
                "Message persistence unavailable. Please retry.",
            )
            .await;
        return;
    }

    tracing::debug!(
        message_id = %msg.id,
        "✅ Message persisted to Kafka (source of truth)"
    );

    // Record pending delivery for ACK tracking
    if let Some(ref delivery_ack_manager) = ctx.delivery_ack_manager {
        if let Err(e) = delivery_ack_manager
            .record_pending_delivery(&msg.id, &msg.from)
            .await
        {
            tracing::warn!(
                error = %e,
                message_id = %msg.id,
                "Failed to record pending delivery for ACK tracking"
            );
        }
    }

    // STEP 2: Try direct delivery (fast path for online recipients)
    let recipient_tx = {
        let clients_read = ctx.clients.read().await;
        clients_read.get(&msg.to).cloned()
    };

    if let Some(tx) = recipient_tx {
        match tx.send(ServerMessage::Message(msg.clone())) {
            Ok(_) => {
                tracing::info!(
                    message_id = %msg.id,
                    "📨 Message sent directly to online recipient (fast path) + persisted in Kafka"
                );

                // Mark as delivered directly to prevent duplicate delivery
                {
                    let mut queue = ctx.queue.lock().await;
                    if let Err(e) = queue.mark_delivered_direct(&msg.id).await {
                        tracing::warn!(
                            error = %e,
                            message_id = %msg.id,
                            "Failed to mark message as delivered directly (client may receive duplicate)"
                        );
                    }
                }

                // ACK "sent"
                let ack = ServerMessage::Ack(crate::message::AckData {
                    message_id: msg.id.clone(),
                    status: "sent".to_string(),
                });
                handler.send_msgpack(&ack).await.ok();
                return;
            }
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    message_id = %msg.id,
                    "Direct delivery failed (channel closed), delivery-worker will deliver from Kafka"
                );
            }
        }
    }

    // STEP 3: Recipient offline or direct delivery failed
    tracing::info!(
        message_id = %msg.id,
        recipient_hash = %log_safe_id(&msg.to, &ctx.config.logging.hash_salt),
        "📤 Message queued in Kafka - recipient offline, delivery-worker will deliver"
    );

    // ACK "queued"
    let ack = ServerMessage::Ack(crate::message::AckData {
        message_id: msg.id.clone(),
        status: "queued".to_string(),
    });
    if handler.send_msgpack(&ack).await.is_err() {
        return;
    }

    // Send push notification to offline recipient
    send_push_notification_for_message(ctx, msg).await;
}

/// Send push notification for a message to an offline recipient
/// Implements Phase 1 (Silent Push) and Phase 2 (Visible Push with filters)
async fn send_push_notification_for_message(ctx: &AppContext, msg: &ChatMessage) {
    if !ctx.apns_client.is_enabled() {
        return;
    }

    // SECURITY: Hash user IDs for privacy in push notification logs
    let salt = &ctx.config.logging.hash_salt;

    // Get device tokens for recipient
    let device_tokens = match device_tokens::get_user_device_tokens(ctx, &msg.to).await {
        Ok(tokens) => tokens,
        Err(e) => {
            tracing::warn!(error = %e, recipient_hash = %crate::utils::log_safe_id(&msg.to, salt), "Failed to fetch device tokens for push notification");
            return;
        }
    };

    if device_tokens.is_empty() {
        tracing::debug!(recipient_hash = %crate::utils::log_safe_id(&msg.to, salt), "No device tokens registered for recipient");
        return;
    }

    // Get sender username for visible notifications
    let sender_username = match get_username_for_push(ctx, &msg.from).await {
        Ok(username) => username,
        Err(e) => {
            tracing::warn!(error = %e, sender_hash = %crate::utils::log_safe_id(&msg.from, salt), "Failed to get sender username for push");
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
                    .send_visible_push(
                        &device.device_token,
                        &sender_username,
                        Some(msg.from.clone()),
                    )
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
                recipient_hash = %crate::utils::log_safe_id(&msg.to, salt),
                device_token_prefix = &device.device_token[..8.min(device.device_token.len())],
                filter = %device.notification_filter,
                "Failed to send push notification"
            );
        } else {
            tracing::debug!(
                recipient_hash = %crate::utils::log_safe_id(&msg.to, salt),
                device_token_prefix = &device.device_token[..8.min(device.device_token.len())],
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

    let result = sqlx::query(r#"SELECT username FROM users WHERE id = $1"#)
        .bind(user_uuid)
        .fetch_optional(&*ctx.db_pool)
        .await?;

    Ok(result
        .and_then(|row| row.try_get("username").ok())
        .unwrap_or_else(|| "Someone".to_string()))
}

/// Handles message delivery acknowledgment from recipient
///
/// When a recipient confirms they received a message, this handler:
/// 1. Validates the message_id format
/// 2. Looks up the original sender (if delivery ACK is enabled)
/// 3. Sends "delivered" ACK back to the sender
pub async fn handle_acknowledge_message(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    ack_data: crate::message::AcknowledgeMessageData,
) {
    // Validate user is authenticated
    let recipient_id = match handler.user_id() {
        Some(id) => id.clone(),
        None => {
            tracing::error!("Unauthenticated user attempted to acknowledge message");
            handler
                .send_error("AUTH_REQUIRED", "Authentication is required")
                .await;
            return;
        }
    };

    // SECURITY: Hash user IDs for privacy
    let salt = &ctx.config.logging.hash_salt;

    // Validate message ID format (should be UUID)
    if uuid::Uuid::parse_str(&ack_data.message_id).is_err() {
        tracing::warn!(
            recipient_hash = %crate::utils::log_safe_id(&recipient_id, salt),
            message_id = %ack_data.message_id,
            "Invalid message ID format in acknowledgment"
        );
        handler
            .send_error("INVALID_MESSAGE_ID", "Message ID must be a valid UUID")
            .await;
        return;
    }

    // Only process "delivered" status
    if ack_data.status != "delivered" {
        tracing::debug!(
            recipient_hash = %crate::utils::log_safe_id(&recipient_id, salt),
            message_id = %ack_data.message_id,
            status = %ack_data.status,
            "Ignoring non-delivered ACK status"
        );
        return;
    }

    tracing::debug!(
        recipient_hash = %crate::utils::log_safe_id(&recipient_id, salt),
        message_id = %ack_data.message_id,
        "Received delivery acknowledgment"
    );

    // Process acknowledgment if delivery ACK system is enabled
    let Some(ref delivery_ack_manager) = ctx.delivery_ack_manager else {
        tracing::debug!(
            message_id = %ack_data.message_id,
            "Delivery ACK system not enabled, ignoring acknowledgment"
        );
        return;
    };

    // Look up the original sender
    let sender_id = match delivery_ack_manager
        .process_acknowledgment(&ack_data.message_id)
        .await
    {
        Ok(Some(sender_id)) => sender_id,
        Ok(None) => {
            tracing::debug!(
                message_id = %ack_data.message_id,
                "No pending delivery found (already acknowledged or expired)"
            );
            return;
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                message_id = %ack_data.message_id,
                "Failed to process delivery acknowledgment"
            );
            return;
        }
    };

    // Send "delivered" ACK to the original sender
    let clients_guard = ctx.clients.read().await;
    if let Some(sender_tx) = clients_guard.get(&sender_id) {
        let delivered_ack = crate::message::ServerMessage::Ack(crate::message::AckData {
            message_id: ack_data.message_id.clone(),
            status: "delivered".to_string(),
        });

        if let Err(e) = sender_tx.send(delivered_ack) {
            tracing::warn!(
                error = %e,
                sender_hash = %crate::utils::log_safe_id(&sender_id, salt),
                message_id = %ack_data.message_id,
                "Failed to send delivery ACK to sender (channel closed)"
            );
        } else {
            tracing::info!(
                sender_hash = %crate::utils::log_safe_id(&sender_id, salt),
                recipient_hash = %crate::utils::log_safe_id(&recipient_id, salt),
                message_id = %ack_data.message_id,
                "Delivered ACK sent to sender"
            );
        }
    } else {
        tracing::debug!(
            sender_hash = %crate::utils::log_safe_id(&sender_id, salt),
            message_id = %ack_data.message_id,
            "Sender not online, delivery ACK not sent"
        );
    }
}
