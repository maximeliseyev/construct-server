use anyhow::{Context, Result};
use construct_server::config::Config;
use futures_util::stream::StreamExt;
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
    // Load configuration
    let config = Config::from_env()?;

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(config.rust_log.clone()))
        .with(tracing_subscriber::fmt::layer())
        .init();

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
    pubsub_conn
        .subscribe(config.online_channel.as_str())
        .await
        .context("Failed to subscribe to user_online_notifications channel")?;

    info!("Delivery Worker Started");
    info!("Channel: {}", config.online_channel);
    info!("Offline queue prefix: {}", config.offline_queue_prefix);
    info!("Delivery queue prefix: {}", config.delivery_queue_prefix);
    info!("Waiting for user online notifications...");

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
            &config,
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
    config: &Config,
    conn: &mut redis::aio::MultiplexedConnection,
    user_id: &str,
    server_instance_id: &str,
) -> Result<()> {
    let queue_key = format!("{}{}", config.offline_queue_prefix, user_id);
    let delivery_key = format!("{}{}", config.delivery_queue_prefix, server_instance_id);

    // Use Lua script to atomically move all messages from offline queue to delivery queue
    // and publish notification to the server instance
    // This replaces the loop of LMOVE operations with a single atomic operation
    let notification_channel = format!("delivery_notification:{}", server_instance_id);
    let script = redis::Script::new(
        r"
        local queue_key = KEYS[1]
        local delivery_key = KEYS[2]
        local notification_channel = ARGV[1]
        local messages = redis.call('LRANGE', queue_key, 0, -1)
        local count = #messages
        if count > 0 then
            for i = 1, count do
                redis.call('RPUSH', delivery_key, messages[i])
            end
            redis.call('DEL', queue_key)
            redis.call('PUBLISH', notification_channel, tostring(count))
        end
        return count
        "
    );

    let moved_count: i64 = script
        .key(&queue_key)
        .key(&delivery_key)
        .arg(&notification_channel)
        .invoke_async(conn)
        .await?;

    if moved_count > 0 {
        info!(
            user_id = %user_id,
            count = moved_count,
            server_instance_id = %server_instance_id,
            queue_key = %queue_key,
            delivery_key = %delivery_key,
            "Moved offline messages to delivery queue"
        );
    } else {
        info!(
            user_id = %user_id,
            queue_key = %queue_key,
            "No offline messages to deliver"
        );
    }

    Ok(())
}
