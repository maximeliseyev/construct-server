use anyhow::{Context, Result};
use construct_server::config::Config;
use futures_util::stream::StreamExt;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Notification that a user has come online
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserOnlineNotification {
    /// User ID that came online
    user_id: String,

    /// Unique ID of the server instance handling this user's connection
    server_instance_id: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Delivery Worker starting...");

    // Load configuration
    let config = Config::from_env()?;

    // Mask credentials in Redis URL for logging
    let redis_url_safe = if let Some(at_pos) = config.redis_url.find('@') {
        let protocol_end = config.redis_url.find("://").map(|p| p + 3).unwrap_or(0);
        format!(
            "{}***{}",
            &config.redis_url[..protocol_end],
            &config.redis_url[at_pos..]
        )
    } else {
        config.redis_url.clone()
    };
    info!("Connecting to Redis at: {}", redis_url_safe);

    // Connect to Redis
    let client =
        redis::Client::open(config.redis_url.as_str()).context("Failed to create Redis client")?;

    let mut pubsub_conn = client
        .get_async_pubsub()
        .await
        .context("Failed to create Redis Pub/Sub connection")?;

    let mut data_conn = client
        .get_multiplexed_async_connection()
        .await
        .context("Failed to create Redis data connection")?;

    info!("Connected to Redis");

    // Subscribe to user online notifications
    const ONLINE_CHANNEL: &str = "user_online_notifications";
    pubsub_conn
        .subscribe(ONLINE_CHANNEL)
        .await
        .context("Failed to subscribe to user_online_notifications channel")?;

    info!("Subscribed to channel: {}", ONLINE_CHANNEL);
    info!("Delivery Worker ready to process offline messages");

    // Main event loop
    loop {
        // Wait for messages on the Pub/Sub channel
        let msg = match pubsub_conn.on_message().next().await {
            Some(msg) => msg,
            None => {
                warn!("Pub/Sub channel closed, reconnecting...");
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        // Get message payload
        let payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to get message payload: {}", e);
                continue;
            }
        };

        // Parse notification
        let notification: UserOnlineNotification = match serde_json::from_str(&payload) {
            Ok(n) => n,
            Err(e) => {
                error!(
                    "Failed to parse notification JSON: {}. Payload: {}",
                    e, payload
                );
                continue;
            }
        };

        info!(
            user_id = %notification.user_id,
            server_instance_id = %notification.server_instance_id,
            "User came online, processing offline messages"
        );

        // Process offline messages for this user
        if let Err(e) = process_offline_messages(
            &mut data_conn,
            &notification.user_id,
            &notification.server_instance_id,
        )
        .await
        {
            error!(
                error = %e,
                user_id = %notification.user_id,
                "Failed to process offline messages"
            );
        }
    }
}

/// Processes offline messages for a user who came online
async fn process_offline_messages(
    conn: &mut redis::aio::MultiplexedConnection,
    user_id: &str,
    server_instance_id: &str,
) -> Result<()> {
    let queue_key = format!("queue:{}", user_id);
    let delivery_key = format!("delivery_queue:{}", server_instance_id);

    // Get all messages from the user's offline queue
    let messages: Vec<Vec<u8>> = conn
        .lrange(&queue_key, 0, -1)
        .await
        .context("Failed to read messages from queue")?;

    let message_count = messages.len();

    if message_count == 0 {
        info!(user_id = %user_id, "No offline messages to deliver");
        return Ok(());
    }

    info!(
        user_id = %user_id,
        count = message_count,
        "Retrieved offline messages"
    );

    // Delete the queue (messages will be moved to delivery queue)
    let _: () = conn
        .del(&queue_key)
        .await
        .context("Failed to delete offline queue")?;

    // Move each message to the server instance's delivery queue
    for (idx, message_bytes) in messages.iter().enumerate() {
        match conn.lpush::<_, _, ()>(&delivery_key, message_bytes).await {
            Ok(_) => {
                info!(
                    user_id = %user_id,
                    message_index = idx + 1,
                    total = message_count,
                    "Message moved to delivery queue"
                );
            }
            Err(e) => {
                error!(
                    error = %e,
                    user_id = %user_id,
                    message_index = idx + 1,
                    "Failed to push message to delivery queue"
                );
            }
        }
    }

    info!(
        user_id = %user_id,
        count = message_count,
        server_instance_id = %server_instance_id,
        "All offline messages queued for delivery"
    );

    Ok(())
}
