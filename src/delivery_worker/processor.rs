// ============================================================================
// Message Processor
// ============================================================================
//
// Main message processing logic for delivery worker.
// Handles Kafka messages and routes them to appropriate Redis streams.
//
// ARCHITECTURE: Kafka as Single Source of Truth (Hybrid Approach)
// ============================================================================
//
// Key Principle: Kafka offset is committed ONLY when message is successfully
// delivered to an ONLINE user. For offline users, offset is NOT committed,
// so Kafka will redeliver the message when the user comes online.
//
// Flow:
// 1. Check deduplication (processed_msg, delivered_direct)
// 2. Check if recipient is online
// 3. If ONLINE:
//    - Push to delivery_stream:{server_instance_id}
//    - Mark as processed
//    - Return Success -> commit offset
// 4. If OFFLINE:
//    - Optionally cache in Redis for fast delivery (optimization only)
//    - Return UserOffline -> DO NOT commit offset
//    - Message stays in Kafka for redelivery
//
// Guarantees:
// - Kafka remains the single source of truth
// - Messages are never lost (even if Redis fails)
// - At-least-once delivery with deduplication
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

/// Result of processing a Kafka message
///
/// This enum controls whether the Kafka offset should be committed.
/// CRITICAL: Only commit offset for Success and Skipped - never for UserOffline!
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessResult {
    /// Message successfully delivered to online user - COMMIT offset
    Success,
    /// User is offline - DO NOT commit offset, Kafka will redeliver
    UserOffline,
    /// Message was skipped (already processed/delivered) - COMMIT offset
    Skipped,
}

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
/// - Stream storage (Redis Streams) for online users
/// - Optional Redis caching for offline users (optimization only)
///
/// CRITICAL: Returns ProcessResult to control offset commit behavior:
/// - Success/Skipped -> commit offset (message handled)
/// - UserOffline -> DO NOT commit offset (Kafka will redeliver)
///
/// # Arguments
/// * `state` - Worker state
/// * `envelope` - Kafka message envelope
///
/// # Returns
/// ProcessResult indicating how the message was handled
pub async fn process_kafka_message(
    state: &WorkerState,
    envelope: &KafkaMessageEnvelope,
) -> Result<ProcessResult> {
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
    if let Some(skip_reason) = should_skip_message(state, message_id).await? {
        // Message was already processed or delivered directly
        debug!(
            message_id = %message_id,
            reason = skip_reason,
            "Message skipped (deduplication)"
        );
        return Ok(ProcessResult::Skipped);
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
        // ====================================================================
        // USER IS ONLINE - deliver and commit offset
        // ====================================================================
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

        // Mark message as processed (deduplication for online delivery)
        mark_message_processed(state, message_id, ttl_seconds)
            .await
            .context("Failed to mark message as processed")?;

        info!(
            message_id = %message_id,
            recipient_hash = %log_safe_id(recipient_id, salt),
            stream_key = %stream_key,
            "Message pushed to delivery_stream (recipient online) - offset will be committed"
        );

        Ok(ProcessResult::Success)
    } else {
        // ====================================================================
        // USER IS OFFLINE - DO NOT commit offset!
        // ====================================================================
        // Kafka remains the source of truth. When user comes online,
        // Kafka will redeliver this message (offset not committed).
        //
        // OPTIONAL: Cache in Redis for faster delivery when user reconnects.
        // This is purely an optimization - if Redis fails, Kafka has the message.
        // ====================================================================

        // Optional: Save to Redis offline stream as cache (not source of truth)
        // This allows faster delivery when user comes online, but is not required
        if let Err(e) = push_to_offline_stream(
            state,
            recipient_id,
            message_id,
            &message_bytes,
            None,
        )
        .await
        {
            // Log but don't fail - Redis cache is optional, Kafka has the message
            debug!(
                message_id = %message_id,
                recipient_hash = %log_safe_id(recipient_id, salt),
                error = %e,
                "Failed to cache offline message in Redis (not critical - Kafka has the message)"
            );
        }

        // DO NOT mark as processed - message should be redelivered from Kafka
        // DO NOT commit offset - return UserOffline to signal this

        info!(
            message_id = %message_id,
            recipient_hash = %log_safe_id(recipient_id, salt),
            "Recipient is offline - offset NOT committed, Kafka will redeliver when user comes online"
        );

        Ok(ProcessResult::UserOffline)
    }
}
