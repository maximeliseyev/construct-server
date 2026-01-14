// ============================================================================
// Message Deduplication
// ============================================================================
//
// Deduplication logic for delivery worker messages.
// Prevents processing the same message multiple times.
//
// Flow:
// 1. Check if message was already processed (processed_msg:{message_id})
// 2. Check if message was delivered directly via tx.send() (delivered_direct:{message_id})
// 3. Mark message as processed after successful handling
//
// ============================================================================

use crate::config::SECONDS_PER_DAY;
use crate::delivery_worker::retry::execute_redis_with_retry;
use crate::delivery_worker::state::WorkerState;
use anyhow::{Context, Result};
use redis::cmd;
use tracing::{debug, info};

/// Check if message was already processed
///
/// Checks Redis key: processed_msg:{message_id}
///
/// # Arguments
/// * `state` - Worker state
/// * `message_id` - Message ID to check
///
/// # Returns
/// `true` if message was already processed, `false` otherwise
pub async fn is_message_processed(state: &WorkerState, message_id: &str) -> Result<bool> {
    let dedup_key = format!(
        "{}{}",
        state.config.redis_key_prefixes.processed_msg, message_id
    );

    let exists_result: i64 = execute_redis_with_retry(state, "check_deduplication", |conn| {
        let key = dedup_key.clone();
        Box::pin(async move { cmd("EXISTS").arg(&key).query_async(conn).await })
    })
    .await
    .context("Failed to check deduplication after retries")?;

    Ok(exists_result > 0)
}

/// Check if message was already delivered directly via tx.send() (fast path)
///
/// УМНАЯ ДЕДУПЛИКАЦИЯ:
/// Если construct-server успешно доставил через tx.send(), он помечает:
/// SET delivered_direct:{message_id} 1 EX 3600
///
/// Мы проверяем этот ключ и пропускаем доставку, чтобы избежать дубликатов.
/// Это снижает нагрузку на сервер и сеть.
///
/// # Arguments
/// * `state` - Worker state
/// * `message_id` - Message ID to check
///
/// # Returns
/// `true` if message was delivered directly, `false` otherwise
pub async fn was_delivered_direct(state: &WorkerState, message_id: &str) -> Result<bool> {
    let delivered_direct_key = format!(
        "{}{}",
        state.config.redis_key_prefixes.delivered_direct, message_id
    );

    let was_delivered: i64 = execute_redis_with_retry(state, "check_delivered_direct", |conn| {
        let key = delivered_direct_key.clone();
        Box::pin(async move { cmd("EXISTS").arg(&key).query_async(conn).await })
    })
    .await
    .context("Failed to check delivered_direct after retries")?;

    Ok(was_delivered > 0)
}

/// Mark message as processed (for deduplication)
///
/// Sets Redis key: processed_msg:{message_id} with TTL
///
/// # Arguments
/// * `state` - Worker state
/// * `message_id` - Message ID to mark as processed
/// * `ttl_seconds` - TTL in seconds (usually message_ttl_days * SECONDS_PER_DAY)
pub async fn mark_message_processed(
    state: &WorkerState,
    message_id: &str,
    ttl_seconds: i64,
) -> Result<()> {
    let dedup_key = format!(
        "{}{}",
        state.config.redis_key_prefixes.processed_msg, message_id
    );

    let _: String = execute_redis_with_retry(state, "mark_message_processed", |conn| {
        let key = dedup_key.clone();
        let ttl = ttl_seconds;
        Box::pin(async move {
            cmd("SETEX")
                .arg(&key)
                .arg(ttl)
                .arg("1")
                .query_async(conn)
                .await
        })
    })
    .await
    .context("Failed to mark message as processed after retries")?;

    Ok(())
}

/// Check if message should be skipped (already processed or delivered directly)
///
/// Convenience function that checks both deduplication paths.
///
/// # Arguments
/// * `state` - Worker state
/// * `message_id` - Message ID to check
///
/// # Returns
/// `Some(reason)` if message should be skipped, `None` if it should be processed
pub async fn should_skip_message(
    state: &WorkerState,
    message_id: &str,
) -> Result<Option<&'static str>> {
    // Check if already processed
    if is_message_processed(state, message_id).await? {
        info!(
            message_id = %message_id,
            "Message already processed (deduplication)"
        );
        return Ok(Some("already_processed"));
    }

    // Check if delivered directly
    if was_delivered_direct(state, message_id).await? {
        debug!(
            message_id = %message_id,
            "Message was already delivered directly via tx.send() - skipping delivery-worker delivery"
        );

        // Mark as processed (deduplication) so we don't check again
        let ttl_seconds = state.config.message_ttl_days * SECONDS_PER_DAY;
        mark_message_processed(state, message_id, ttl_seconds).await?;

        return Ok(Some("delivered_direct"));
    }

    Ok(None)
}
