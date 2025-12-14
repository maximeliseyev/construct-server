use crate::context::AppContext;
use crate::handlers::connection::ConnectionHandler;
use crate::message::{Message, ServerMessage};

/// Handles message sending
/// Delivers immediately if recipient is online, otherwise queues for later delivery
pub async fn handle_send_message(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    msg: Message,
) {
    // Check if recipient is online using scope to release read lock quickly
    let recipient_tx = {
        let clients_read = ctx.clients.read().await;
        clients_read.get(&msg.to).cloned()
    };

    if let Some(tx) = recipient_tx {
        // Recipient is online - deliver immediately
        match tx.send(ServerMessage::Message(msg.clone())) {
            Ok(_) => {
                let ack = ServerMessage::Ack {
                    message_id: msg.id.clone(),
                    status: "delivered".to_string(),
                };
                if let Err(e) = handler.send_msgpack(&ack).await {
                    tracing::error!(
                        error = %e,
                        message_id = %msg.id,
                        "Failed to send delivery ACK to sender"
                    );
                }
                tracing::debug!(
                    message_id = %msg.id,
                    from = %msg.from,
                    to = %msg.to,
                    content_len = msg.content.len(),
                    "Message delivered to online recipient"
                );
            }
            Err(e) => {
                // Failed to send to online recipient - queue it instead
                tracing::warn!(
                    error = %e,
                    message_id = %msg.id,
                    from = %msg.from,
                    to = %msg.to,
                    "Failed to deliver to online recipient, queueing message"
                );

                let mut queue_lock = ctx.queue.lock().await;
                match queue_lock.enqueue_message(&msg.to, &msg).await {
                    Ok(_) => {
                        let ack = ServerMessage::Ack {
                            message_id: msg.id.clone(),
                            status: "queued".to_string(),
                        };
                        if let Err(e) = handler.send_msgpack(&ack).await {
                            tracing::error!(
                                error = %e,
                                message_id = %msg.id,
                                "Failed to send queued ACK to sender"
                            );
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
    } else {
        // Recipient is offline - queue message
        let mut queue_lock = ctx.queue.lock().await;
        match queue_lock.enqueue_message(&msg.to, &msg).await {
            Ok(_) => {
                let ack = ServerMessage::Ack {
                    message_id: msg.id.clone(),
                    status: "queued".to_string(),
                };
                if let Err(e) = handler.send_msgpack(&ack).await {
                    tracing::error!(
                        error = %e,
                        message_id = %msg.id,
                        "Failed to send queued ACK to sender"
                    );
                }
                tracing::debug!(
                    message_id = %msg.id,
                    from = %msg.from,
                    to = %msg.to,
                    content_len = msg.content.len(),
                    "Message queued for offline recipient"
                );
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
