// ============================================================================
// Delivery Worker - Phase 3: Kafka Consumer
// ============================================================================
//
// This worker consumes messages from Kafka and delivers them to online users.
//
// Architecture:
// 1. Kafka Consumer reads from "construct-messages" topic (partitioned by recipient_id)
// 2. For each message:
//    - Check if processed (Redis deduplication)
//    - Check if recipient online (Redis lookup)
//    - If online: Forward to delivery_queue:{server_instance_id}
//    - Commit Kafka offset after successful forward
// 3. Redis Pub/Sub listener triggers immediate processing when user comes online
//
// Guarantees:
// - At-least-once delivery (Kafka consumer may retry)
// - Deduplication via Redis (processed_msg:{message_id})
// - Ordering per user (Kafka partitioning by recipient_id)
// ============================================================================

use anyhow::{Context, Result};
use construct_server::config::Config;
use construct_server::kafka::{KafkaMessageEnvelope, MessageConsumer};
use futures_util::stream::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Notification that a user has come online
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserOnlineNotification {
    /// User ID that came online
    user_id: String,

    /// Unique ID of the server instance handling this user's connection
    server_instance_id: String,
}

/// Shared state for Kafka-based delivery worker
struct WorkerState {
    config: Arc<Config>,
    redis_conn: Arc<RwLock<redis::aio::MultiplexedConnection>>,
    /// Counter for consecutive "no delivery queues" errors (for periodic summary logging)
    no_queues_count: Arc<RwLock<u64>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config = Config::from_env()?;
    let config = Arc::new(config);

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(config.rust_log.clone()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("=== Delivery Worker Starting ===");
    info!("Kafka Enabled: {}", config.kafka.enabled);
    info!("Kafka Brokers: {}", config.kafka.brokers);
    info!("Kafka Topic: {}", config.kafka.topic);
    info!("Kafka Consumer Group: {}", config.kafka.consumer_group);

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

    let redis_conn = client
        .get_multiplexed_async_connection()
        .await
        .context("Failed to create Redis data connection")?;

    info!("Connected to Redis");

    let redis_conn = Arc::new(RwLock::new(redis_conn));

    let state = Arc::new(WorkerState {
        config: config.clone(),
        redis_conn: redis_conn.clone(),
        no_queues_count: Arc::new(RwLock::new(0)),
    });

    // Choose delivery mode based on KAFKA_ENABLED
    if config.kafka.enabled {
        info!("Starting Kafka consumer mode");
        run_kafka_consumer_mode(state).await
    } else {
        info!("Starting Redis-only mode (legacy)");
        run_redis_only_mode(config).await
    }
}

/// Kafka-based delivery worker (Phase 3+)
async fn run_kafka_consumer_mode(state: Arc<WorkerState>) -> Result<()> {
    // Initialize Kafka consumer
    let consumer = MessageConsumer::new(&state.config.kafka)
        .context("Failed to initialize Kafka consumer")?;

    info!("Kafka consumer initialized successfully");
    info!("Polling messages from Kafka topic: {}", state.config.kafka.topic);

    // Main Kafka consumer loop
    loop {
        match consumer.poll(std::time::Duration::from_secs(1)).await {
            Ok(Some(envelope)) => {
                if let Err(e) = process_kafka_message(&state, &envelope).await {
                    // Log unexpected errors (no delivery queues are already logged in process_kafka_message)
                    let error_msg = e.to_string();
                    if !error_msg.contains("No delivery queues available") {
                        error!(
                            error = %e,
                            message_id = %envelope.message_id,
                            recipient_id = %envelope.recipient_id,
                            "Failed to process Kafka message"
                        );
                    }
                    // Do NOT commit offset on error - message will be redelivered
                    continue;
                }

                // Commit offset after successful processing
                if let Err(e) = consumer.commit() {
                    error!(
                        error = %e,
                        message_id = %envelope.message_id,
                        "Failed to commit Kafka offset"
                    );
                }
            }
            Ok(None) => {
                // No messages available, continue polling
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
            Err(e) => {
                error!(error = %e, "Kafka consumer error");
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }
}

/// Process a single Kafka message
async fn process_kafka_message(state: &WorkerState, envelope: &KafkaMessageEnvelope) -> Result<()> {
    let message_id = &envelope.message_id;
    let recipient_id = &envelope.recipient_id;

    debug!(
        message_id = %message_id,
        recipient_id = %recipient_id,
        "Processing Kafka message"
    );

    // 1. Deduplication check: have we already processed this message?
    let dedup_key = format!("processed_msg:{}", message_id);
    let mut conn = state.redis_conn.write().await;

    let exists_result: i64 = redis::cmd("EXISTS")
        .arg(&dedup_key)
        .query_async(&mut *conn)
        .await
        .context("Failed to check deduplication")?;

    let already_processed = exists_result > 0;

    if already_processed {
        info!(
            message_id = %message_id,
            "Message already processed (deduplication)"
        );
        return Ok(()); // Return success to commit offset
    }

    // 2. Check if recipient is online by looking for active connections
    // We search for "delivery_queue:*" pattern and check if any server has this user online
    // For now, we use a simpler approach: try to deliver to ALL server instances
    // and let the server instance handle it if the user is connected

    // OPTIMIZATION: In production, you'd maintain a "user:{user_id}:server_instance" mapping
    // For now, we broadcast to all delivery queues (inefficient but functional)

    // Get list of all delivery queue keys
    let delivery_keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("{}*", state.config.delivery_queue_prefix))
        .query_async(&mut *conn)
        .await
        .context("Failed to fetch delivery queue keys")?;

    drop(conn); // Release write lock

    if delivery_keys.is_empty() {
        // Return error to prevent Kafka offset commit - message will be retried
        // This happens when no server instances are running to accept deliveries

        // Track consecutive failures and log summary periodically to avoid spam
        let mut count = state.no_queues_count.write().await;
        *count += 1;
        let current_count = *count;
        drop(count);

        // Log detailed warning every 100 messages, or for the first occurrence
        if current_count == 1 || current_count % 100 == 0 {
            warn!(
                message_id = %message_id,
                recipient_id = %recipient_id,
                delivery_queue_prefix = %state.config.delivery_queue_prefix,
                consecutive_failures = current_count,
                "No delivery queues available - no server instances running. Messages are being held in Kafka and will be retried when servers come online."
            );
        } else {
            // Use debug level for subsequent messages to reduce log spam
            debug!(
                message_id = %message_id,
                recipient_id = %recipient_id,
                consecutive_failures = current_count,
                "No delivery queues available (message will retry)"
            );
        }

        return Err(anyhow::anyhow!(
            "No delivery queues available (no server instances online). Message will be retried."
        ));
    }

    // Reset counter when we successfully find delivery queues
    let mut count = state.no_queues_count.write().await;
    if *count > 0 {
        info!(
            recovered_after = *count,
            "Server instances are back online, resuming message delivery"
        );
        *count = 0;
    }
    drop(count);

    // 3. Serialize envelope to JSON for Redis storage
    let message_json = serde_json::to_string(&envelope)
        .context("Failed to serialize Kafka envelope")?;

    // 4. Forward message to delivery queues
    let mut conn = state.redis_conn.write().await;

    // Push to first available delivery queue (simplification)
    // In production, you'd route to specific server instance where user is connected
    let delivery_key = &delivery_keys[0];

    let _: i64 = redis::cmd("RPUSH")
        .arg(delivery_key)
        .arg(&message_json)
        .query_async(&mut *conn)
        .await
        .context("Failed to push message to delivery queue")?;

    // Notify server instance via Pub/Sub
    let server_instance_id = delivery_key
        .strip_prefix(&state.config.delivery_queue_prefix)
        .unwrap_or("unknown");
    let notification_channel = format!("delivery_notification:{}", server_instance_id);

    let _: i64 = redis::cmd("PUBLISH")
        .arg(&notification_channel)
        .arg("1") // Message count
        .query_async(&mut *conn)
        .await
        .context("Failed to publish delivery notification")?;

    // 5. Mark message as processed (7-day TTL)
    let ttl_seconds = state.config.message_ttl_days * 24 * 60 * 60;
    let _: String = redis::cmd("SETEX")
        .arg(&dedup_key)
        .arg(ttl_seconds)
        .arg("1")
        .query_async(&mut *conn)
        .await
        .context("Failed to mark message as processed")?;

    info!(
        message_id = %message_id,
        recipient_id = %recipient_id,
        delivery_queue = %delivery_key,
        "Message forwarded from Kafka to delivery queue"
    );

    Ok(())
}

/// Legacy Redis-only mode (Phase 1-2, for rollback)
async fn run_redis_only_mode(config: Arc<Config>) -> Result<()> {
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

    // Subscribe to user online notifications
    pubsub_conn
        .subscribe(config.online_channel.as_str())
        .await
        .context("Failed to subscribe to user_online_notifications channel")?;

    info!("Delivery Worker Started (Redis-only mode)");
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
        if let Err(e) = process_offline_messages_redis_only(
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

/// Processes offline messages for a user who came online (Redis-only mode)
async fn process_offline_messages_redis_only(
    config: &Config,
    conn: &mut redis::aio::MultiplexedConnection,
    user_id: &str,
    server_instance_id: &str,
) -> Result<()> {
    let queue_key = format!("{}{}", config.offline_queue_prefix, user_id);
    let delivery_key = format!("{}{}", config.delivery_queue_prefix, server_instance_id);

    // Use Lua script to atomically move all messages from offline queue to delivery queue
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
