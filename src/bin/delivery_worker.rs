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
use construct_server::kafka::types::DeliveryAckEvent;
use construct_server::kafka::{KafkaMessageEnvelope, MessageConsumer};
use construct_server::message::ChatMessage;
use construct_server::metrics::{
    SHADOW_READ_DISCREPANCIES, SHADOW_READ_KAFKA_ONLY, SHADOW_READ_MATCHES,
    SHADOW_READ_PROCESSED, SHADOW_READ_REDIS_ONLY,
};
use construct_server::utils::log_safe_id;
use futures_util::stream::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;
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
    no_queues_count: Arc<RwLock<u64>>,
    /// Phase 4: Shadow-read mode enabled
    /// When true, compares Kafka messages with Redis offline queues for validation
    shadow_read_enabled: bool,
    /// Track message IDs processed from Kafka (for reverse-check in Phase 4.3)
    processed_message_ids: Arc<RwLock<HashSet<String>>>,
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
    let shadow_read_enabled = std::env::var("SHADOW_READ_ENABLED")
        .unwrap_or_else(|_| "false".to_string())
        .parse()
        .unwrap_or(false);

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
    // Initialize message consumer
    let consumer =
        MessageConsumer::new(&state.config.kafka).context("Failed to initialize Kafka consumer")?;

    info!("Kafka consumer initialized successfully");
    info!(
        "Polling messages from Kafka topic: {}",
        state.config.kafka.topic
    );

    // Spawn ACK consumer in background (Solution 1D)
    let state_clone = state.clone();
    let _ack_consumer_handle = tokio::spawn(async move {
        if let Err(e) = run_ack_consumer_loop(state_clone).await {
            error!(error = %e, "ACK consumer loop failed");
        }
    });

    // Phase 4.3: Spawn reverse-check scanner (if shadow-read enabled)
    if state.shadow_read_enabled {
        let state_clone = state.clone();
        let _reverse_check_handle = tokio::spawn(async move {
            run_redis_reverse_check_scanner(state_clone).await;
        });
        info!("Started Redis reverse-check scanner (Phase 4.3)");
    }

    // Main Kafka consumer loop
    loop {
        match consumer.poll(std::time::Duration::from_secs(1)).await {
            Ok(Some(envelope)) => {
                if let Err(e) = process_kafka_message(&state, &envelope).await {
                    // Log unexpected errors (no delivery queues are already logged in process_kafka_message)
                    let error_msg = e.to_string();
                    if !error_msg.contains("No delivery queues available") {
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
    let dedup_key = format!("processed_msg:{}", message_id);

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

    // 2. Check if recipient is online by looking for active connections
    // We search for "delivery_queue:*" pattern and check if any server has this user online
    // For now, we use a simpler approach: try to deliver to ALL server instances
    // and let the server instance handle it if the user is connected

    // OPTIMIZATION: In production, you'd maintain a "user:{user_id}:server_instance" mapping
    // For now, we broadcast to all delivery queues (inefficient but functional)

    // Get list of all delivery queue keys using SCAN for production safety
    let delivery_keys: Vec<String> =
        execute_redis_with_retry(state, "fetch_delivery_queues", |conn| {
            let prefix = state.config.delivery_queue_prefix.clone();
            Box::pin(async move {
                let mut keys = Vec::new();
                let mut cursor: u64 = 0;
                let pattern = format!("{}*", prefix);

                loop {
                    let (new_cursor, mut found_keys): (u64, Vec<String>) = redis::cmd("SCAN")
                        .arg(cursor)
                        .arg("MATCH")
                        .arg(&pattern)
                        .arg("COUNT")
                        .arg(100) // Fetch 100 keys per iteration
                        .query_async(conn)
                        .await?;

                    keys.append(&mut found_keys);

                    if new_cursor == 0 {
                        break;
                    }
                    cursor = new_cursor;
                }
                Ok(keys)
            })
        })
        .await
        .context("Failed to fetch delivery queue keys after retries")?;

    debug!(
        "Redis SCAN for '{}*' returned {} keys.",
        state.config.delivery_queue_prefix,
        delivery_keys.len()
    );

    if delivery_keys.is_empty() {
        // Return error to prevent Kafka offset commit - message will be retried
        // This happens when no server instances are running to accept deliveries

        // Track consecutive failures and log summary periodically to avoid spam
        let mut count = state.no_queues_count.write().await;
        *count += 1;
        let current_count = *count;
        drop(count);

        // Log detailed warning every 100 messages, or for the first occurrence
        // SECURITY: Hash recipient_id for privacy
        let salt = &state.config.logging.hash_salt;
        if current_count == 1 || current_count % 100 == 0 {
            warn!(
                message_id = %message_id,
                recipient_hash = %log_safe_id(recipient_id, salt),
                consecutive_failures = current_count,
                "No delivery queues available - messages held in Kafka until servers come online"
            );
        } else {
            // Use debug level for subsequent messages to reduce log spam
            debug!(
                message_id = %message_id,
                recipient_hash = %log_safe_id(recipient_id, salt),
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

    // 3. Serialize envelope to MessagePack for Redis storage
    let message_bytes = rmp_serde::encode::to_vec_named(&envelope)
        .context("Failed to serialize Kafka envelope to MessagePack")?;

    // 4. Forward message to delivery queues
    // Push to first available delivery queue (simplification)
    // In production, you'd route to specific server instance where user is connected
    let delivery_key = delivery_keys[0].clone();

    let _: i64 = execute_redis_with_retry(state, "push_to_delivery_queue", |conn| {
        let key = delivery_key.clone();
        let msg = message_bytes.clone();
        Box::pin(async move {
            redis::cmd("RPUSH")
                .arg(&key)
                .arg(&msg)
                .query_async(conn)
                .await
        })
    })
    .await
    .context("Failed to push message to delivery queue after retries")?;

    // Notify server instance via Pub/Sub
    let server_instance_id = delivery_key
        .strip_prefix(&state.config.delivery_queue_prefix)
        .unwrap_or("unknown");
    let notification_channel = format!("delivery_notification:{}", server_instance_id);

    let _: i64 = execute_redis_with_retry(state, "publish_notification", |conn| {
        let channel = notification_channel.clone();
        Box::pin(async move {
            redis::cmd("PUBLISH")
                .arg(&channel)
                .arg("1")
                .query_async(conn)
                .await
        })
    })
    .await
    .context("Failed to publish delivery notification after retries")?;

    // 5. Mark message as processed (7-day TTL)
    let ttl_seconds = state.config.message_ttl_days * 24 * 60 * 60;
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
        "Message forwarded to delivery queue"
    );

    // Phase 4: Shadow-read comparison (if enabled)
    if state.shadow_read_enabled {
        shadow_read_compare(state, envelope).await;
    }

    Ok(())
}

// ============================================================================
// Phase 4: Shadow-Read Mode (Kafka vs Redis Comparison)
// ============================================================================

/// Compare a Kafka message with Redis offline queue for validation
///
/// This function is called after successfully processing a Kafka message.
/// It reads the Redis offline queue for the same recipient and compares.
///
/// Metrics tracked:
/// - SHADOW_READ_MATCHES: Message found in both Kafka and Redis (fields match)
/// - SHADOW_READ_DISCREPANCIES: Message found in both but fields differ
/// - SHADOW_READ_KAFKA_ONLY: Message in Kafka but not in Redis
async fn shadow_read_compare(state: &WorkerState, envelope: &KafkaMessageEnvelope) {
    let message_id = &envelope.message_id;
    let recipient_id = &envelope.recipient_id;

    SHADOW_READ_PROCESSED.inc();

    // Track this message_id as processed from Kafka (for reverse-check)
    {
        let mut processed = state.processed_message_ids.write().await;
        processed.insert(message_id.clone());
        // Limit memory usage - keep only last 10000 message IDs
        if processed.len() > 10000 {
            // Remove arbitrary element (HashSet doesn't have pop_front)
            if let Some(old_id) = processed.iter().next().cloned() {
                processed.remove(&old_id);
            }
        }
    }

    // Read Redis offline queue for this recipient
    let redis_key = format!("{}{}", state.config.offline_queue_prefix, recipient_id);

    let redis_messages: Vec<Vec<u8>> = match execute_redis_with_retry(
        state,
        "shadow_read_redis_queue",
        |conn| {
            let key = redis_key.clone();
            Box::pin(async move {
                redis::cmd("LRANGE")
                    .arg(&key)
                    .arg(0)
                    .arg(-1)
                    .query_async(conn)
                    .await
            })
        },
    )
    .await
    {
        Ok(msgs) => msgs,
        Err(e) => {
            // SECURITY: Hash recipient_id for privacy
            let salt = &state.config.logging.hash_salt;
            warn!(
                error = %e,
                message_id = %message_id,
                recipient_hash = %log_safe_id(recipient_id, salt),
                "Shadow-read: Failed to fetch Redis offline queue"
            );
            return;
        }
    };

    // Deserialize Redis messages and find matching message_id
    let mut found_match = false;
    for msg_bytes in &redis_messages {
        match rmp_serde::from_slice::<ChatMessage>(msg_bytes) {
            Ok(redis_msg) => {
                if redis_msg.id == *message_id {
                    // Found matching message - compare fields
                    found_match = true;

                    let fields_match = compare_kafka_redis_message(envelope, &redis_msg);
                    if fields_match {
                        SHADOW_READ_MATCHES.inc();
                        debug!(
                            message_id = %message_id,
                            "Shadow-read: MATCH - Kafka and Redis messages are identical"
                        );
                    } else {
                        SHADOW_READ_DISCREPANCIES.inc();
                        // SECURITY: Hash user IDs to prevent PII leakage in logs
                        let salt = &state.config.logging.hash_salt;
                        warn!(
                            message_id = %message_id,
                            kafka_sender_hash = %log_safe_id(&envelope.sender_id, salt),
                            redis_sender_hash = %log_safe_id(&redis_msg.from, salt),
                            kafka_recipient_hash = %log_safe_id(&envelope.recipient_id, salt),
                            redis_recipient_hash = %log_safe_id(&redis_msg.to, salt),
                            kafka_content_len = envelope.encrypted_payload.len(),
                            redis_content_len = redis_msg.content.len(),
                            "Shadow-read: DISCREPANCY - Kafka and Redis messages differ!"
                        );
                    }
                    break;
                }
            }
            Err(e) => {
                // Try JSON deserialization (API v3 format)
                if let Ok(json_msg) = serde_json::from_slice::<serde_json::Value>(msg_bytes) {
                    if let Some(msg_id) = json_msg.get("id").and_then(|v| v.as_str()) {
                        if msg_id == message_id {
                            found_match = true;
                            // For JSON format, just log as match (can't fully compare)
                            SHADOW_READ_MATCHES.inc();
                            debug!(
                                message_id = %message_id,
                                "Shadow-read: MATCH (JSON format) - message found in Redis"
                            );
                            break;
                        }
                    }
                } else {
                    debug!(
                        error = %e,
                        "Shadow-read: Failed to deserialize Redis message (skipping)"
                    );
                }
            }
        }
    }

    if !found_match {
        // Message in Kafka but not in Redis - this is EXPECTED in Phase 4
        // because Kafka messages may arrive faster than Redis writes
        SHADOW_READ_KAFKA_ONLY.inc();
        // SECURITY: Hash recipient_id for privacy
        let salt = &state.config.logging.hash_salt;
        debug!(
            message_id = %message_id,
            recipient_hash = %log_safe_id(recipient_id, salt),
            redis_queue_size = redis_messages.len(),
            "Shadow-read: Message in Kafka but not in Redis offline queue"
        );
    }
}

/// Compare Kafka envelope fields with Redis ChatMessage
fn compare_kafka_redis_message(kafka: &KafkaMessageEnvelope, redis: &ChatMessage) -> bool {
    // Compare core fields
    let id_match = kafka.message_id == redis.id;
    let sender_match = kafka.sender_id == redis.from;
    let recipient_match = kafka.recipient_id == redis.to;
    let content_match = kafka.encrypted_payload == redis.content;

    // Compare message_number (Kafka stores as Option<u32>)
    let msg_num_match = kafka.message_number == Some(redis.message_number);

    // Compare ephemeral_public_key (Kafka stores as base64-encoded Option<String>)
    let epk_match = if let Some(ref kafka_epk_b64) = kafka.ephemeral_public_key {
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, kafka_epk_b64) {
            Ok(kafka_epk_bytes) => kafka_epk_bytes == redis.ephemeral_public_key,
            Err(_) => false,
        }
    } else {
        false
    };

    id_match && sender_match && recipient_match && content_match && msg_num_match && epk_match
}

/// Phase 4.3: Reverse-check scanner
///
/// Periodically scans Redis offline queues and checks if messages
/// were seen in Kafka consumer. This detects messages that exist
/// in Redis but were NOT processed from Kafka (potential data loss).
///
/// Runs every 5 minutes in shadow-read mode.
async fn run_redis_reverse_check_scanner(state: Arc<WorkerState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes

    info!("Redis reverse-check scanner started (interval: 5 minutes)");

    loop {
        interval.tick().await;

        debug!("Running Redis reverse-check scan...");

        // Scan all offline queue keys (pattern: queue:*)
        let queue_keys: Vec<String> = match scan_redis_keys(&state, &state.config.offline_queue_prefix).await {
            Ok(keys) => keys,
            Err(e) => {
                warn!(error = %e, "Reverse-check: Failed to scan Redis keys");
                continue;
            }
        };

        if queue_keys.is_empty() {
            debug!("Reverse-check: No offline queues found");
            continue;
        }

        let processed_ids = state.processed_message_ids.read().await;
        let mut redis_only_count = 0u64;
        let mut total_messages = 0u64;

        for key in &queue_keys {
            // Extract user_id from key
            let _user_id = key.strip_prefix(&state.config.offline_queue_prefix).unwrap_or(key);

            // Read messages from this queue
            let messages: Vec<Vec<u8>> = match execute_redis_with_retry(
                &state,
                "reverse_check_read_queue",
                |conn| {
                    let k = key.clone();
                    Box::pin(async move {
                        redis::cmd("LRANGE")
                            .arg(&k)
                            .arg(0)
                            .arg(-1)
                            .query_async(conn)
                            .await
                    })
                },
            )
            .await
            {
                Ok(msgs) => msgs,
                Err(e) => {
                    warn!(error = %e, key = %key, "Reverse-check: Failed to read queue");
                    continue;
                }
            };

            for msg_bytes in &messages {
                total_messages += 1;

                // Try to extract message_id
                let msg_id = extract_message_id_from_bytes(msg_bytes);

                if let Some(id) = msg_id {
                    if !processed_ids.contains(&id) {
                        // Message in Redis but not processed from Kafka
                        redis_only_count += 1;
                        SHADOW_READ_REDIS_ONLY.inc();

                        // SECURITY: Hash user_id from queue_key to prevent PII leakage
                        let user_id = key.strip_prefix(&state.config.offline_queue_prefix).unwrap_or("unknown");
                        let salt = &state.config.logging.hash_salt;
                        warn!(
                            message_id = %id,
                            user_id_hash = %log_safe_id(user_id, salt),
                            "Reverse-check: Message in Redis but NOT processed from Kafka"
                        );
                    }
                }
            }
        }

        drop(processed_ids);

        info!(
            queues_scanned = queue_keys.len(),
            total_messages = total_messages,
            redis_only = redis_only_count,
            "Reverse-check scan completed"
        );
    }
}

/// Scan Redis keys matching a prefix pattern using SCAN (production-safe)
async fn scan_redis_keys(state: &WorkerState, prefix: &str) -> Result<Vec<String>> {
    execute_redis_with_retry(state, "scan_redis_keys", |conn| {
        let pattern = format!("{}*", prefix);
        Box::pin(async move {
            let mut keys = Vec::new();
            let mut cursor: u64 = 0;

            loop {
                let (new_cursor, mut found_keys): (u64, Vec<String>) = redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(&pattern)
                    .arg("COUNT")
                    .arg(100)
                    .query_async(conn)
                    .await?;

                keys.append(&mut found_keys);

                if new_cursor == 0 {
                    break;
                }
                cursor = new_cursor;
            }

            Ok(keys)
        })
    })
    .await
}

/// Extract message_id from raw message bytes (MessagePack or JSON)
fn extract_message_id_from_bytes(msg_bytes: &[u8]) -> Option<String> {
    // Try MessagePack first
    if let Ok(msg) = rmp_serde::from_slice::<ChatMessage>(msg_bytes) {
        return Some(msg.id);
    }

    // Try JSON
    if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(msg_bytes) {
        if let Some(id) = json_val.get("id").and_then(|v| v.as_str()) {
            return Some(id.to_string());
        }
    }

    None
}

/// Process a delivery ACK event from Kafka (Solution 1D - Privacy-First)
///
/// Flow:
/// 1. Read DeliveryAckEvent from Kafka (contains only hashed IDs)
/// 2. Look up sender_id from Redis using message_hash → ephemeral mapping
/// 3. Forward "delivered" ACK to sender's delivery queue
/// 4. Delete Redis mapping (one-time use)
///
/// **SECURITY**: This function handles NO plaintext IDs in Kafka logs.
/// Only ephemeral Redis mappings can link message_hash to sender_id.
async fn process_delivery_ack_event(state: &WorkerState, event: &DeliveryAckEvent) -> Result<()> {
    let message_hash = &event.message_hash;

    debug!(
        message_hash = %message_hash,
        "Processing delivery ACK event"
    );

    // 1. Validate event structure (security check)
    event.validate().context("Invalid delivery ACK event")?;

    // 2. Deduplication check: have we already processed this ACK?
    let dedup_key = format!("processed_ack:{}", event.message_id);

    let exists_result: i64 = execute_redis_with_retry(state, "check_ack_deduplication", |conn| {
        let key = dedup_key.clone();
        Box::pin(async move { redis::cmd("EXISTS").arg(&key).query_async(conn).await })
    })
    .await
    .context("Failed to check ACK deduplication after retries")?;

    let already_processed = exists_result > 0;

    if already_processed {
        info!(
            message_id = %event.message_id,
            "ACK already processed (deduplication)"
        );
        return Ok(()); // Return success to commit offset
    }

    // 3. Look up sender_id from Redis ephemeral mapping
    let mapping_key = format!("delivery_ack:{}", message_hash);

    let mapping_json: Option<String> =
        execute_redis_with_retry(state, "fetch_ack_mapping", |conn| {
            let key = mapping_key.clone();
            Box::pin(async move { redis::cmd("GET").arg(&key).query_async(conn).await })
        })
        .await
        .context("Failed to fetch ACK mapping after retries")?;

    // Verify mapping exists (we don't need sender_id for broadcast approach)
    if mapping_json.is_none() {
        // Mapping expired or never created - ACK too old or invalid
        debug!(
            message_hash = %message_hash,
            "No ACK mapping found (expired or invalid)"
        );
        return Ok(()); // Return success to commit offset
    }

    // 4. Forward "delivered" ACK to sender's delivery queue
    // We broadcast to all delivery queues (same as message delivery)
    let delivery_keys: Vec<String> =
        execute_redis_with_retry(state, "fetch_delivery_queues_for_ack", |conn| {
            let prefix = state.config.delivery_queue_prefix.clone();
            Box::pin(async move {
                let mut keys = Vec::new();
                let mut cursor: u64 = 0;
                let pattern = format!("{}*", prefix);

                loop {
                    let (new_cursor, mut found_keys): (u64, Vec<String>) = redis::cmd("SCAN")
                        .arg(cursor)
                        .arg("MATCH")
                        .arg(&pattern)
                        .arg("COUNT")
                        .arg(100)
                        .query_async(conn)
                        .await?;

                    keys.append(&mut found_keys);

                    if new_cursor == 0 {
                        break;
                    }
                    cursor = new_cursor;
                }

                Ok::<Vec<String>, redis::RedisError>(keys)
            })
        })
        .await
        .context("Failed to fetch delivery queues after retries")?;

    if delivery_keys.is_empty() {
        debug!("No delivery queues available for ACK delivery");
        return Ok(()); // No servers online, ACK will be lost (acceptable)
    }

    // Construct ACK message
    let ack_message = serde_json::json!({
        "type": "ack",
        "messageId": event.message_id,
        "status": "delivered",
    });
    let ack_json = serde_json::to_string(&ack_message)?;

    // Try to deliver ACK to ALL delivery queues
    // (The server will filter out connections that don't match sender_id)
    for delivery_key in &delivery_keys {
        let result =
            execute_redis_with_retry(state, "forward_ack_to_queue", |conn| {
                let key = delivery_key.clone();
                let json = ack_json.clone();
                Box::pin(async move {
                    let count: i64 = redis::cmd("LPUSH").arg(&key).arg(&json).query_async(conn).await?;
                    Ok::<i64, redis::RedisError>(count)
                })
            })
            .await;

        if let Err(e) = result {
            warn!(
                error = %e,
                delivery_key = %delivery_key,
                "Failed to forward ACK to delivery queue"
            );
        }
    }

    // 5. Delete Redis mapping (one-time use)
    let _: i64 = execute_redis_with_retry(state, "delete_ack_mapping", |conn| {
        let key = mapping_key.clone();
        Box::pin(async move { redis::cmd("DEL").arg(&key).query_async(conn).await })
    })
    .await
    .context("Failed to delete ACK mapping after retries")?;

    // 6. Mark ACK as processed (7-day TTL to prevent reprocessing)
    let ttl_seconds = state.config.message_ttl_days * 24 * 60 * 60;
    let _: String = execute_redis_with_retry(state, "mark_ack_processed", |conn| {
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
    .context("Failed to mark ACK as processed after retries")?;

    // SECURITY: Log ONLY hashes, NEVER plaintext IDs
    info!(
        message_hash = %message_hash,
        sender_id_hash = %event.sender_id_hash,
        "Delivery ACK processed successfully"
    );

    Ok(())
}

/// ACK consumer loop - consumes delivery ACK events from Kafka (Solution 1D)
///
/// This loop runs in a separate task parallel to the main message consumer.
/// It reads from `{topic}-delivery-ack` topic and processes ACK events.
async fn run_ack_consumer_loop(state: Arc<WorkerState>) -> Result<()> {
    info!("Starting ACK consumer loop (Solution 1D - Privacy-First)");

    // Create a custom Kafka config for the ACK topic
    let mut ack_config = state.config.kafka.clone();
    ack_config.topic = format!("{}-delivery-ack", ack_config.topic);
    ack_config.consumer_group = format!("{}-ack", ack_config.consumer_group);

    // Initialize Kafka consumer for ACK events
    let consumer =
        MessageConsumer::new(&ack_config).context("Failed to initialize ACK consumer")?;

    info!("ACK consumer initialized successfully");
    info!("Polling ACK events from Kafka topic: {}", ack_config.topic);

    // Main ACK consumer loop
    loop {
        // Poll for ACK events (timeout: 1 second)
        let raw_message = match consumer.poll_raw(std::time::Duration::from_secs(1)).await {
            Ok(Some(msg)) => msg,
            Ok(None) => {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }
            Err(e) => {
                error!(error = %e, "ACK consumer error");
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        // Deserialize DeliveryAckEvent
        let event: DeliveryAckEvent = match serde_json::from_slice(&raw_message) {
            Ok(e) => e,
            Err(e) => {
                error!(
                    error = %e,
                    "Failed to deserialize DeliveryAckEvent"
                );
                // Commit offset to skip malformed message
                if let Err(commit_err) = consumer.commit() {
                    error!(error = %commit_err, "Failed to commit offset after deserialization error");
                }
                continue;
            }
        };

        // Process ACK event
        if let Err(e) = process_delivery_ack_event(&state, &event).await {
            error!(
                error = %e,
                message_hash = %event.message_hash,
                "Failed to process delivery ACK event"
            );
            // Do NOT commit offset on error - message will be redelivered
            continue;
        }

        // Commit offset after successful processing
        if let Err(e) = consumer.commit() {
            error!(
                error = %e,
                message_hash = %event.message_hash,
                "Failed to commit ACK offset"
            );
        }
    }
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

        // SECURITY: Hash user_id for privacy
        let salt = &config.logging.hash_salt;
        info!(
            user_hash = %log_safe_id(&notification.user_id, salt),
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
                user_hash = %log_safe_id(&notification.user_id, salt),
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
        ",
    );

    let moved_count: i64 = script
        .key(&queue_key)
        .key(&delivery_key)
        .arg(&notification_channel)
        .invoke_async(conn)
        .await?;

    // SECURITY: Hash user_id for privacy
    let salt = &config.logging.hash_salt;
    if moved_count > 0 {
        info!(
            user_hash = %log_safe_id(user_id, salt),
            count = moved_count,
            server_instance_id = %server_instance_id,
            "Moved offline messages to delivery queue"
        );
    } else {
        debug!(
            user_hash = %log_safe_id(user_id, salt),
            "No offline messages to deliver"
        );
    }

    Ok(())
}
