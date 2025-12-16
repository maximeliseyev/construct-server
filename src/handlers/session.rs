use crate::context::AppContext;
use crate::db::User;
use crate::message::ServerMessage;
use crate::utils::log_safe_id;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

pub type Clients = Arc<RwLock<HashMap<String, mpsc::UnboundedSender<ServerMessage>>>>;

pub const TOKEN_ALIVE_TIME: i64 = 2592000; // 30 days

/// Establishes a user session by:
/// 1. Creating session in the queue
/// 2. Dequeuing pending messages
/// 3. Adding user to online clients
pub async fn establish_session(
    ctx: &AppContext,
    tx: &mpsc::UnboundedSender<ServerMessage>,
    current_user_id: &mut Option<String>,
    user: &User,
    jti: &str,
) -> Result<(), String> {
    let uid_str = user.id.to_string();

    // Scope the lock to ensure it's dropped early
    {
        let mut queue_lock = ctx.queue.lock().await;
        if let Err(e) = queue_lock
            .create_session(jti, &uid_str, TOKEN_ALIVE_TIME)
            .await
        {
            return Err(format!("Failed to create session: {}", e));
        }

        if let Ok(messages) = queue_lock.dequeue_messages(&uid_str).await {
            let total = messages.len();
            let mut delivered = 0;
            let mut failed = 0;

            for msg in messages {
                match tx.send(ServerMessage::Message(msg.clone())) {
                    Ok(_) => {
                        delivered += 1;
                        #[cfg(debug_assertions)]
                        if ctx.config.logging.enable_message_metadata {
                            tracing::debug!(
                                message_id = %msg.id,
                                from = %msg.from,
                                to = %msg.to,
                                "Queued message delivered to reconnected user"
                            );
                        } else {
                            tracing::debug!(message_id = %msg.id, "Queued message delivered to reconnected user");
                        }
                    }
                    Err(e) => {
                        failed += 1;
                        if ctx.config.logging.enable_message_metadata {
                            tracing::error!(
                                error = %e,
                                message_id = %msg.id,
                                from = %msg.from,
                                to = %msg.to,
                                "Failed to deliver queued message to reconnected user"
                            );
                        } else {
                            tracing::error!(error = %e, message_id = %msg.id, "Failed to deliver queued message to reconnected user");
                        }
                    }
                }
            }

            if ctx.config.logging.enable_user_identifiers {
                tracing::info!(
                    user_id = %uid_str,
                    total = total,
                    delivered = delivered,
                    failed = failed,
                    "Queued messages delivery completed"
                );
            } else {
                tracing::info!(
                    user_hash = %log_safe_id(&uid_str, &ctx.config.logging.hash_salt),
                    total = total,
                    delivered = delivered,
                    failed = failed,
                    "Queued messages delivery completed"
                );
            }
        }
    } // queue_lock is automatically dropped here

    *current_user_id = Some(uid_str.clone());
    ctx.clients.write().await.insert(uid_str, tx.clone());

    Ok(())
}
