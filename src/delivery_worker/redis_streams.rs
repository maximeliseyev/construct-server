// ============================================================================
// Redis Streams Operations
// ============================================================================
//
// Redis Streams operations for delivery worker.
// Provides optimized message delivery using XADD, XREADGROUP, etc.
//
// Key Benefits over Lists:
// - XADD = 1 command (vs RPUSH + EXPIRE = 2 commands)
// - Blocking read = 0 commands when no messages (vs polling)
// - Automatic trimming via MAXLEN
// - Consumer groups for distribution
//
// ============================================================================

use crate::delivery_worker::retry::execute_redis_with_retry;
use crate::delivery_worker::state::WorkerState;
use anyhow::{Context, Result};
use redis::cmd;
use tracing::debug;

/// Push message to delivery stream using XADD
///
/// Uses XADD with MAXLEN for automatic trimming:
/// XADD stream_key MAXLEN ~ max_len * message_id payload message_bytes
///
/// # Arguments
/// * `state` - Worker state
/// * `stream_key` - Redis stream key (e.g., "delivery_stream:{server_instance_id}")
/// * `message_id` - Unique message ID for deduplication
/// * `message_bytes` - Serialized message payload
/// * `max_len` - Maximum stream length (automatic trim), if None uses config default
///
/// # Returns
/// Stream message ID (e.g., "1234567890-0")
pub async fn push_to_delivery_stream(
    state: &WorkerState,
    stream_key: &str,
    message_id: &str,
    message_bytes: &[u8],
    max_len: Option<usize>,
) -> Result<String> {
    // Use config default if not specified
    // For now, use a reasonable default (10000 messages)
    // TODO: Add delivery_stream_max_len to Config when migrating to Streams
    let max_len = max_len.unwrap_or(10000);

    let stream_id: String = execute_redis_with_retry(state, "push_to_delivery_stream", |conn| {
        let key = stream_key.to_string();
        let msg_id = message_id.to_string();
        let payload = message_bytes.to_vec();
        let max_len = max_len;

        Box::pin(async move {
            // XADD stream_key MAXLEN ~ max_len * message_id payload message_bytes
            // Using ~ for approximate trimming (faster than exact)
            cmd("XADD")
                .arg(&key)
                .arg("MAXLEN")
                .arg("~") // Approximate trimming
                .arg(max_len as i64)
                .arg("*") // Auto-generate message ID (timestamp-sequence)
                .arg("message_id")
                .arg(&msg_id)
                .arg("payload")
                .arg(&payload)
                .query_async(conn)
                .await
        })
    })
    .await
    .context("Failed to push message to delivery stream")?;

    debug!(
        stream_key = %stream_key,
        message_id = %message_id,
        stream_id = %stream_id,
        "Pushed message to delivery stream"
    );

    Ok(stream_id)
}

/// Push message to offline stream
///
/// Similar to push_to_delivery_stream but for offline users.
/// Format: delivery_stream:offline:{user_id}
///
/// # Arguments
/// * `state` - Worker state
/// * `user_id` - Recipient user ID
/// * `message_id` - Unique message ID
/// * `message_bytes` - Serialized message payload
/// * `max_len` - Maximum stream length, if None uses config default
///
/// # Returns
/// Stream message ID
pub async fn push_to_offline_stream(
    state: &WorkerState,
    user_id: &str,
    message_id: &str,
    message_bytes: &[u8],
    max_len: Option<usize>,
) -> Result<String> {
    let stream_key = format!(
        "{}offline:{}",
        state.config.delivery_queue_prefix, // Reuse existing prefix for now
        user_id
    );

    push_to_delivery_stream(state, &stream_key, message_id, message_bytes, max_len).await
}

/// Check if user is online by looking up server instance ID
///
/// Checks Redis key: user:{user_id}:server_instance_id
///
/// # Arguments
/// * `state` - Worker state
/// * `user_id` - User ID to check
///
/// # Returns
/// Server instance ID if user is online, None if offline
pub async fn check_user_online(state: &WorkerState, user_id: &str) -> Result<Option<String>> {
    let user_server_key = format!(
        "{}{}:server_instance_id",
        state.config.redis_key_prefixes.user, user_id
    );

    let server_instance_id: Option<String> =
        execute_redis_with_retry(state, "check_user_online", |conn| {
            let key = user_server_key.clone();
            Box::pin(async move { cmd("GET").arg(&key).query_async(conn).await })
        })
        .await
        .context("Failed to check user online status")?;

    Ok(server_instance_id)
}
