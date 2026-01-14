// ============================================================================
// Message Processor
// ============================================================================
//
// Main message processing logic for delivery worker.
// Handles Kafka messages and routes them to appropriate Redis streams.
//
// Flow:
// 1. Check deduplication (processed_msg, delivered_direct)
// 2. Check if recipient is online
// 3. Serialize message to MessagePack
// 4. Push to delivery stream (online) or offline stream (offline)
// 5. Mark message as processed
//
// ============================================================================

use crate::config::SECONDS_PER_DAY;
use crate::delivery_worker::deduplication::{mark_message_processed, should_skip_message};
use crate::delivery_worker::redis_streams::{
    check_user_online, push_to_delivery_stream, push_to_offline_stream,
};
use crate::delivery_worker::state::WorkerState;
use crate::kafka::KafkaMessageEnvelope;
use crate::utils::log_safe_id;
use anyhow::{Context, Result};
use tracing::{debug, info};

// Note: This module uses Redis Streams (XADD) instead of Lists (RPUSH).
// The stream keys use the same prefix format as Lists for compatibility:
// - delivery_queue:{server_instance_id} → delivery_stream:{server_instance_id}
// - delivery_queue:offline:{user_id} → delivery_stream:offline:{user_id}
//
// Future migration: Update stream key prefixes when fully migrating to Streams.

/// Process a single Kafka message
///
/// This function handles the complete lifecycle of a message:
/// - Deduplication checks
/// - Online/offline routing
/// - Stream storage (Redis Streams)
/// - Processing confirmation
///
/// # Arguments
/// * `state` - Worker state
/// * `envelope` - Kafka message envelope
///
/// # Returns
/// Result indicating success or failure
pub async fn process_kafka_message(
    state: &WorkerState,
    envelope: &KafkaMessageEnvelope,
) -> Result<()> {
    let message_id = &envelope.message_id;
    let recipient_id = &envelope.recipient_id;

    // SECURITY: Even in debug logs, hash recipient_id for privacy
    let salt = &state.config.logging.hash_salt;
    debug!(
        message_id = %message_id,
        recipient_hash = %log_safe_id(recipient_id, salt),
        "Processing Kafka message"
    );

    // 1. Check if message should be skipped (deduplication)
    if let Some(_skip_reason) = should_skip_message(state, message_id).await? {
        // Message was already processed or delivered directly
        // Return success to commit Kafka offset
        return Ok(());
    }

    // 2. Check if recipient is online
    let server_instance_id = check_user_online(state, recipient_id)
        .await
        .context("Failed to check user online status")?;

    // 3. Serialize envelope to MessagePack for Redis storage
    let message_bytes = rmp_serde::encode::to_vec_named(envelope)
        .context("Failed to serialize Kafka envelope to MessagePack")?;

    let ttl_seconds = state.config.message_ttl_days * SECONDS_PER_DAY;

    // 4. Route message based on online status
    if let Some(server_instance_id) = server_instance_id {
        // User is online - push to delivery stream for this server instance
        let stream_key = format!(
            "{}{}",
            state.config.delivery_queue_prefix, server_instance_id
        );

        push_to_delivery_stream(
            state,
            &stream_key,
            message_id,
            &message_bytes,
            None, // Use default max_len from config
        )
        .await
        .context("Failed to push message to delivery stream")?;

        info!(
            message_id = %message_id,
            recipient_hash = %log_safe_id(recipient_id, salt),
            stream_key = %stream_key,
            "📤 Message pushed to delivery_stream (recipient online) - server will read and deliver"
        );
    } else {
        // User is offline - push to offline stream
        push_to_offline_stream(
            state,
            recipient_id,
            message_id,
            &message_bytes,
            None, // Use default max_len from config
        )
        .await
        .context("Failed to push message to offline stream")?;

        info!(
            message_id = %message_id,
            recipient_hash = %log_safe_id(recipient_id, salt),
            "Recipient is offline - message saved to offline stream for later delivery"
        );
    }

    // 5. Mark message as processed (deduplication)
    mark_message_processed(state, message_id, ttl_seconds)
        .await
        .context("Failed to mark message as processed")?;

    Ok(())
}
