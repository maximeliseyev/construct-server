use crate::context::AppContext;
use crate::db::User;
use crate::message::ServerMessage;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};

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

        // Phase 5: Track user online status in Redis for delivery-worker
        // This allows worker to route messages directly to the correct server
        if let Err(e) = queue_lock
            .track_user_online(&uid_str, &ctx.server_instance_id)
            .await
        {
            tracing::error!(
                error = %e,
                user_id = %uid_str,
                "Failed to track user online status"
            );
        }

        // CRITICAL FIX: Process offline messages when user comes online
        // Move messages from delivery_queue:offline:{user_id} to delivery_queue:{server_instance_id}
        // so they can be delivered via the delivery listener
        match queue_lock
            .process_offline_messages_for_user(&uid_str, &ctx.server_instance_id)
            .await
        {
            Ok(count) => {
                if count > 0 {
                    tracing::info!(
                        user_id = %uid_str,
                        server_instance_id = %ctx.server_instance_id,
                        message_count = count,
                        "Processed offline messages for user"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    user_id = %uid_str,
                    "Failed to process offline messages for user"
                );
            }
        }

        // Publish notification that user came online
        // This triggers the Delivery Worker to process offline messages from Kafka
        if let Err(e) = queue_lock
            .publish_user_online(
                &uid_str,
                &ctx.server_instance_id,
                &ctx.config.online_channel,
            )
            .await
        {
            tracing::error!(
                error = %e,
                user_id = %uid_str,
                "Failed to publish user online notification"
            );
        } else {
            tracing::debug!(
                user_id = %uid_str,
                server_instance_id = %ctx.server_instance_id,
                channel = %ctx.config.online_channel,
                "Published user online notification"
            );
        }
    } // queue_lock is automatically dropped here

    *current_user_id = Some(uid_str.clone());
    ctx.clients.write().await.insert(uid_str, tx.clone());

    Ok(())
}
