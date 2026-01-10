// Delivery Worker - Phase 5: Kafka-only Mode
// ============================================================================
//
// This worker consumes messages from Kafka and delivers them to online users.
//
// Architecture (Phase 5 - Kafka-only):
// 1. Kafka Consumer reads from "construct-messages" topic (partitioned by recipient_id)
// 2. For each message:
//    - Check if processed (Redis deduplication)
//    - Check if recipient online via user:{user_id}:server_instance_id
//    - If online: Publish message directly to delivery_message:{server_instance_id} Pub/Sub channel
//    - If offline: Don't commit offset - leave message in Kafka for retry
//    - Commit Kafka offset only after successful delivery
// 3. Redis Pub/Sub listener triggers immediate processing when user comes online
//
// Key differences from Phase 3:
// - NO Redis delivery_queue - messages delivered directly via Pub/Sub
// - NO Redis offline queues - Kafka is the only storage
// - Direct routing to server instance where user is connected
//
// Guarantees:
// - At-least-once delivery (Kafka consumer may retry)
// - Deduplication via Redis (processed_msg:{message_id})
// - Ordering per user (Kafka partitioning by recipient_id)
// ============================================================================

use anyhow::{Context, Result};
use construct_server::config::Config;
use construct_server::kafka::{KafkaMessageEnvelope, MessageConsumer};
use construct_server::utils::log_safe_id;
use futures_util::stream::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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
    redis_client: Arc<redis::Client>,
    /// Counter for consecutive "no delivery queues" errors (for periodic summary logging)
    #[allow(dead_code)]
    no_queues_count: Arc<RwLock<u64>>,
    /// Phase 4: Shadow-read mode enabled
    /// When true, compares Kafka messages with Redis offline queues for validation
    #[allow(dead_code)]
    shadow_read_enabled: bool,
    /// Track message IDs processed from Kafka (for reverse-check in Phase 4.3)
    #[allow(dead_code)]
    processed_message_ids: Arc<RwLock<HashSet<String>>>,
    /// Users who came online (for logging and monitoring)
    users_online_notifications: Arc<RwLock<HashSet<String>>>,
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

    // Phase 4: Shadow-read mode (compare Kafka vs Redis)
    let shadow_read_enabled = config.worker.shadow_read_enabled;

    if shadow_read_enabled {
        info!("🔍 Shadow-read mode ENABLED - will compare Kafka vs Redis offline queues");
    }

    let state = Arc::new(WorkerState {
        config: config.clone(),
        redis_conn: redis_conn.clone(),
        redis_client: Arc::new(client),
        no_queues_count: Arc::new(RwLock::new(0)),
        shadow_read_enabled,
        processed_message_ids: Arc::new(RwLock::new(HashSet::new())),
        users_online_notifications: Arc::new(RwLock::new(HashSet::new())),
    });

    // Choose delivery mode based on KAFKA_ENABLED
    if config.kafka.enabled {
        info!("Starting Kafka consumer mode");
        run_kafka_consumer_mode(state).await
    } else {
        error!("Redis-only mode is not supported. Please enable KAFKA_ENABLED=true");
        Err(anyhow::anyhow!("Redis-only mode is deprecated. Use Kafka mode instead."))
    }
}

/// Kafka-based delivery worker (Phase 3+)
async fn run_kafka_consumer_mode(state: Arc<WorkerState>) -> Result<()> {
    // Initialize message consumer
    let consumer =
        MessageConsumer::new(&state.config.kafka).context("Failed to initialize Kafka consumer")?;

    info!("Kafka consumer initialized successfully");
    info!(
        "Polling messages from Kafka topic: {}",
        state.config.kafka.topic
    );

    // Spawn ACK consumer in background (Solution 1D)
    // Note: ACK consumer disabled in Phase 5 Kafka-only mode
    // Delivery ACKs are handled directly by the server
    // TODO: Re-enable if ACK processing via Kafka is needed

    // Phase 4.3: Spawn reverse-check scanner (if shadow-read enabled)
    // Note: Shadow-read disabled in Phase 5 Kafka-only mode
    // TODO: Re-enable if shadow-read validation is needed

    // Phase 5: Subscribe to user online notifications
    // This allows worker to know when users come online and can process their messages
    let state_clone = state.clone();
    let _online_notification_handle = tokio::spawn(async move {
        if let Err(e) = run_user_online_notification_listener(state_clone).await {
            error!(error = %e, "User online notification listener failed");
        }
    });
    info!("Started user online notification listener (Phase 5)");
    info!("Subscribed to channel: {}", state.config.online_channel);

    // Main Kafka consumer loop
    let mut offline_message_count: u64 = 0;
    let mut last_offline_log_time = std::time::Instant::now();
    
    loop {
        match consumer.poll(std::time::Duration::from_secs(1)).await {
            Ok(Some(envelope)) => {
                match process_kafka_message(&state, &envelope).await {
                    Ok(()) => {
                        // Message processed successfully - reset offline counter
                        if offline_message_count > 0 {
                            info!(
                                offline_messages_handled = offline_message_count,
                                "Processed offline messages queue, resuming normal operation"
                            );
                            offline_message_count = 0;
                        }
                    }
                    Err(e) => {
                        let error_msg = e.to_string();
                        
                        // Phase 5: User offline is EXPECTED behavior - don't log as ERROR
                        if error_msg.contains("Recipient is offline") {
                            offline_message_count += 1;
                            
                            // Log summary every 10 seconds to avoid log spam
                            // First offline message logs immediately, then every 10 seconds
                            let now = std::time::Instant::now();
                            let should_log = offline_message_count == 1 || 
                                now.duration_since(last_offline_log_time).as_secs() >= 10;
                            
                            if should_log {
                                let salt = &state.config.logging.hash_salt;
                                if offline_message_count == 1 {
                                    debug!(
                                        recipient_hash = %log_safe_id(&envelope.recipient_id, salt),
                                        "Recipient is offline - message will be delivered when user comes online (this is normal)"
                                    );
                                } else {
                                    debug!(
                                        offline_count = offline_message_count,
                                        recipient_hash = %log_safe_id(&envelope.recipient_id, salt),
                                        "Multiple messages waiting for offline recipients (this is normal - messages will be delivered when users come online)"
                                    );
                                }
                                last_offline_log_time = now;
                            }
                        }
                        // Legacy: "No delivery queues available" is also expected
                        else if error_msg.contains("No delivery queues available") {
                            // Already logged in process_kafka_message, skip duplicate error log
                        }
                        // Real errors - log as ERROR
                        else {
                            // SECURITY: Hash recipient_id for privacy
                            let salt = &state.config.logging.hash_salt;
                            error!(
                                error = %e,
                                message_id = %envelope.message_id,
                                recipient_hash = %log_safe_id(&envelope.recipient_id, salt),
                                "Failed to process Kafka message"
                            );
                        }
                        // Do NOT commit offset on error - message will be redelivered
                        continue;
                    }
                }

                // Commit offset after successful processing
                if let Err(e) = consumer.commit() {
                    error!(
                        error = %e,
                        message_id = %envelope.message_id,
                        "Failed to commit Kafka offset after successful delivery"
                    );
                } else {
                    debug!(
                        message_id = %envelope.message_id,
                        "Kafka offset committed successfully"
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

/// Execute a Redis operation with retry logic and auto-reconnection
async fn execute_redis_with_retry<F, T>(
    state: &WorkerState,
    operation_name: &str,
    mut operation: F,
) -> Result<T>
where
    F: FnMut(
        &mut redis::aio::MultiplexedConnection,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<T, redis::RedisError>> + Send + '_>,
    >,
{
    const MAX_RETRIES: u32 = 3;
    const INITIAL_BACKOFF_MS: u64 = 100;

    for attempt in 1..=MAX_RETRIES {
        let mut conn = state.redis_conn.write().await;

        match operation(&mut *conn).await {
            Ok(result) => {
                if attempt > 1 {
                    info!(
                        operation = operation_name,
                        attempt = attempt,
                        "Redis operation succeeded after retry"
                    );
                }
                return Ok(result);
            }
            Err(e) => {
                drop(conn); // Release lock before potentially reconnecting

                warn!(
                    operation = operation_name,
                    attempt = attempt,
                    max_retries = MAX_RETRIES,
                    error = %e,
                    "Redis operation failed, will retry"
                );

                if attempt < MAX_RETRIES {
                    // Exponential backoff
                    let backoff_ms = INITIAL_BACKOFF_MS * 2_u64.pow(attempt - 1);
                    tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;

                    // Try to reconnect on last retry before final attempt
                    if attempt == MAX_RETRIES - 1 {
                        info!("Attempting to reconnect to Redis...");
                        match state.redis_client.get_multiplexed_async_connection().await {
                            Ok(new_conn) => {
                                let mut conn = state.redis_conn.write().await;
                                *conn = new_conn;
                                info!("Successfully reconnected to Redis");
                            }
                            Err(reconnect_err) => {
                                error!(error = %reconnect_err, "Failed to reconnect to Redis");
                            }
                        }
                    }
                } else {
                    return Err(anyhow::anyhow!(
                        "Redis operation '{}' failed after {} retries: {}",
                        operation_name,
                        MAX_RETRIES,
                        e
                    ));
                }
            }
        }
    }

    unreachable!()
}

/// Listen for user online notifications via Redis Pub/Sub (Phase 5)
/// When a user comes online, Kafka consumer will automatically retry their messages
/// because offsets were not committed (messages remained in Kafka)
async fn run_user_online_notification_listener(state: Arc<WorkerState>) -> Result<()> {
    let client = state.redis_client.clone();
    
    loop {
        let mut pubsub_conn = match client.get_async_pubsub().await {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, "Failed to create Redis Pub/Sub connection, retrying in 5s...");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        // Subscribe to user online notifications
        if let Err(e) = pubsub_conn.subscribe(state.config.online_channel.as_str()).await {
            error!(error = %e, channel = %state.config.online_channel, "Failed to subscribe to user online notifications, retrying in 5s...");
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            continue;
        }

        info!(
            channel = %state.config.online_channel,
            "Subscribed to user online notifications (Phase 5)"
        );

        // Listen for notifications
        let mut stream = pubsub_conn.on_message();
        while let Some(msg) = stream.next().await {
            let payload: String = match msg.get_payload() {
                Ok(p) => p,
                Err(e) => {
                    error!(error = %e, "Failed to get Pub/Sub message payload");
                    continue;
                }
            };

            // Parse notification
            let notification: UserOnlineNotification = match serde_json::from_str(&payload) {
                Ok(n) => n,
                Err(e) => {
                    error!(
                        error = %e,
                        payload = %payload,
                        "Failed to parse user online notification JSON"
                    );
                    continue;
                }
            };

            // Track this user as online (for monitoring)
            {
                let mut users = state.users_online_notifications.write().await;
                users.insert(notification.user_id.clone());
                // Keep set size reasonable (cleanup old entries periodically)
                if users.len() > 10000 {
                    // Clear oldest entries (simple cleanup - in production could use LRU)
                    users.clear();
                }
            }

            // SECURITY: Hash user_id for privacy
            let salt = &state.config.logging.hash_salt;
            info!(
                user_hash = %log_safe_id(&notification.user_id, salt),
                server_instance_id = %notification.server_instance_id,
                "User came online - Kafka consumer will retry messages for this user (offsets were not committed for offline messages)"
            );

            // Note: We don't need to explicitly trigger Kafka consumer here
            // Kafka will automatically redeliver messages because offsets were not committed
            // when user was offline. The consumer will process them on next poll().
            // This notification serves for monitoring and logging purposes.
        }

        // Stream ended - reconnect
        warn!("Pub/Sub stream ended, reconnecting...");
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

/// Process a single Kafka message
async fn process_kafka_message(state: &WorkerState, envelope: &KafkaMessageEnvelope) -> Result<()> {
    let message_id = &envelope.message_id;
    let recipient_id = &envelope.recipient_id;

    // SECURITY: Even in debug logs, hash recipient_id for privacy
    let salt = &state.config.logging.hash_salt;
    debug!(
        message_id = %message_id,
        recipient_hash = %log_safe_id(recipient_id, salt),
        "Processing Kafka message"
    );

    // 1. Deduplication check: have we already processed this message?
    let dedup_key = format!("{}{}", state.config.redis_key_prefixes.processed_msg, message_id);

    let exists_result: i64 = execute_redis_with_retry(state, "check_deduplication", |conn| {
        let key = dedup_key.clone();
        Box::pin(async move { redis::cmd("EXISTS").arg(&key).query_async(conn).await })
    })
    .await
    .context("Failed to check deduplication after retries")?;

    let already_processed = exists_result > 0;

    if already_processed {
        info!(
            message_id = %message_id,
            "Message already processed (deduplication)"
        );
        return Ok(()); // Return success to commit offset
    }

    // 2. Phase 5: Check if recipient is online by looking up their server instance
    // Instead of searching delivery_queue keys, we directly check user:{user_id}:server_instance_id
    let user_server_key = format!("{}{}:server_instance_id", state.config.redis_key_prefixes.user, recipient_id);
    
    let server_instance_id: Option<String> = execute_redis_with_retry(state, "check_user_online", |conn| {
        let key = user_server_key.clone();
        Box::pin(async move {
            redis::cmd("GET")
                .arg(&key)
                .query_async(conn)
                .await
        })
    })
    .await
    .context("Failed to check user online status after retries")?;

    if let Some(server_instance_id) = server_instance_id {
        // User is online on this server instance - deliver directly via Pub/Sub
        info!(
            message_id = %message_id,
            recipient_hash = %log_safe_id(recipient_id, &state.config.logging.hash_salt),
            server_instance_id = %server_instance_id,
            "Recipient is online, delivering message directly via Pub/Sub"
        );

        // Serialize envelope to MessagePack
        let message_bytes = rmp_serde::encode::to_vec_named(&envelope)
            .context("Failed to serialize Kafka envelope to MessagePack")?;

        // Phase 5: Publish message directly to delivery_message channel
        // Server will listen to this channel and deliver via WebSocket
        let delivery_channel = format!("{}{}", state.config.redis_channels.delivery_message, server_instance_id);
        
        let _: i64 = execute_redis_with_retry(state, "publish_delivery_message", |conn| {
            let channel = delivery_channel.clone();
            let msg = message_bytes.clone();
            Box::pin(async move {
                redis::cmd("PUBLISH")
                    .arg(&channel)
                    .arg(&msg)
                    .query_async(conn)
                    .await
            })
        })
        .await
        .context("Failed to publish delivery message after retries")?;
        
        info!(
            message_id = %message_id,
            channel = %delivery_channel,
            "Message published to delivery channel (Phase 5 - direct Pub/Sub delivery)"
        );
        
        // 3. Mark message as processed (7-day TTL)
        // Phase 5: After successful Pub/Sub publication, we commit Kafka offset
        use construct_server::config::SECONDS_PER_DAY;
        let ttl_seconds = state.config.message_ttl_days * SECONDS_PER_DAY;
        let _: String = execute_redis_with_retry(state, "mark_message_processed", |conn| {
            let key = dedup_key.clone();
            let ttl = ttl_seconds;
            Box::pin(async move {
                redis::cmd("SETEX")
                    .arg(&key)
                    .arg(ttl)
                    .arg("1")
                    .query_async(conn)
                    .await
            })
        })
        .await
        .context("Failed to mark message as processed after retries")?;
        
        // SECURITY: Hash recipient_id for privacy in production logs
        let salt = &state.config.logging.hash_salt;
        info!(
            message_id = %message_id,
            recipient_hash = %log_safe_id(recipient_id, salt),
            "Message delivered directly via Pub/Sub (Phase 5)"
        );
        
        return Ok(()); // Success - Kafka offset will be committed
    } else {
        // CRITICAL FIX: User is offline - save message to Redis delivery_queue for later delivery
        // Problem: Message was already read from Kafka via recv(), but offset not committed.
        // If we do continue, next poll() will return the NEXT message, and current message is LOST.
        // Solution: Save message to Redis delivery_queue with recipient_id as key, so it can be
        // delivered when user comes online via the delivery listener mechanism.
        
        // Get all active server instances to find where to queue the message
        // We'll queue it to a special key that will be processed when user comes online
        // Format: delivery_queue:offline:{recipient_id} -> list of messages
        let offline_queue_key = format!("{}offline:{}", state.config.delivery_queue_prefix, recipient_id);
        
        // Serialize envelope to MessagePack for Redis storage
        let message_bytes = rmp_serde::encode::to_vec_named(envelope)
            .context("Failed to serialize Kafka envelope to MessagePack for offline queue")?;
        
        // Save to Redis list with TTL (will be cleaned up after delivery or TTL expiry)
        use construct_server::config::SECONDS_PER_DAY;
        let ttl_seconds = state.config.message_ttl_days * SECONDS_PER_DAY;
        
        let _: i64 = execute_redis_with_retry(state, "save_offline_message", |conn| {
            let key = offline_queue_key.clone();
            let msg = message_bytes.clone();
            let ttl = ttl_seconds;
            Box::pin(async move {
                // Use RPUSH to add message to list (FIFO order - oldest first)
                // This maintains order when messages are later moved to delivery_queue
                let _: () = redis::cmd("RPUSH").arg(&key).arg(&msg).query_async(conn).await?;
                // Set TTL on the key (messages will expire if not delivered)
                let _: () = redis::cmd("EXPIRE").arg(&key).arg(ttl).query_async(conn).await?;
                Ok::<i64, redis::RedisError>(1)
            })
        })
        .await
        .context("Failed to save offline message to Redis after retries")?;
        
        // Mark message as processed to prevent duplicate delivery when user comes online
        // (the message is saved in Redis, so it will be delivered via delivery listener)
        let _: String = execute_redis_with_retry(state, "mark_message_processed_for_offline", |conn| {
            let key = dedup_key.clone();
            let ttl = ttl_seconds;
            Box::pin(async move {
                redis::cmd("SETEX")
                    .arg(&key)
                    .arg(ttl)
                    .arg("1")
                    .query_async(conn)
                    .await
            })
        })
        .await
        .context("Failed to mark offline message as processed after retries")?;
        
        info!(
            message_id = %message_id,
            recipient_hash = %log_safe_id(recipient_id, &state.config.logging.hash_salt),
            queue_key = %offline_queue_key,
            "Recipient is offline - message saved to Redis delivery_queue for later delivery"
        );
        
        // Return success to commit offset - message is safely stored in Redis
        // When user comes online, delivery listener will process messages from delivery_queue
        return Ok(());
    }
}
