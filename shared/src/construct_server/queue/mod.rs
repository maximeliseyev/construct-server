// ============================================================================
// Message Queue Module - Phase 2.8 Refactoring
// ============================================================================
//
// Phase 2.8: Split large queue.rs (1203 lines) into logical modules:
// - redis.rs: Redis connection and basic operations
// - sessions.rs: Session management
// - replay.rs: Replay protection
// - rate_limiting.rs: Rate limiting operations
// - cache.rs: Cache operations (key bundles, federation keys)
// - tokens.rs: Token management (refresh tokens, access tokens)
// - delivery.rs: Message delivery operations
//
// ============================================================================

mod cache;
mod connection;
mod delivery;
mod rate_limiting;
mod replay;
mod sessions;
mod tokens;

use crate::config::{Config, SECONDS_PER_DAY};
use construct_types::ChatMessage;
use anyhow::Result;
// Note: redis::aio::ConnectionManager is available via the "connection-manager" feature
// It's used the same way in delivery_ack/storage.rs
use redis::AsyncCommands;

/// Message Queue - Redis-only Storage (No Database Persistence)
///
/// IMPORTANT SECURITY POLICY:
///
/// Messages are NEVER persisted to the database to prevent:
/// 1. Social graph reconstruction (metadata leakage: who talks to whom)
/// 2. Long-term storage of encrypted data (reduces attack surface)
/// 3. Server-side message history (true end-to-end encryption)
///
/// Message Lifecycle:
/// 1. Online recipient  → Direct delivery via WebSocket (no storage)
/// 2. Offline recipient → Temporary storage in Redis with TTL
/// 3. User connects     → Messages delivered from Redis queue
/// 4. After delivery    → Messages DELETED from Redis immediately
/// 5. After TTL expires → Undelivered messages AUTO-DELETED by Redis
pub struct MessageQueue {
    // Note: redis::aio::ConnectionManager is available when "connection-manager" feature is enabled
    // This is the same type used in delivery_ack/storage.rs
    client: redis::aio::ConnectionManager,
    /// TTL for queued messages in seconds (configured via message_ttl_days)
    /// After this period, undelivered messages are automatically deleted by Redis
    message_ttl_seconds: i64,
    offline_queue_prefix: String,
    delivery_queue_prefix: String,
    /// Reference to config for Redis key prefixes (needed for key generation)
    config: Config,
}

impl MessageQueue {
    pub async fn new(config: &Config) -> Result<Self> {
        tracing::debug!("Opening Redis client...");

        // Parse Redis URL to check if TLS is required
        let is_tls = config.redis_url.starts_with("rediss://");
        if is_tls {
            tracing::info!("Redis TLS enabled (rediss://)");
        } else {
            tracing::info!("Redis TLS not enabled (redis://)");
        }

        let client = redis::Client::open(config.redis_url.clone())
            .map_err(|e| anyhow::anyhow!("Failed to parse Redis URL: {}", e))?;

        tracing::debug!("Getting Redis connection manager...");
        let conn = client
            .get_connection_manager()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to Redis: {}", e))?;

        let message_ttl_seconds = config.message_ttl_days * SECONDS_PER_DAY;
        tracing::info!(
            "Message queue TTL: {} days ({} seconds)",
            config.message_ttl_days,
            message_ttl_seconds
        );
        Ok(Self {
            client: conn,
            message_ttl_seconds,
            offline_queue_prefix: config.offline_queue_prefix.clone(),
            delivery_queue_prefix: config.delivery_queue_prefix.clone(),
            config: config.clone(),
        })
    }

    // ============================================================================
    // Deprecated Methods (Phase 5+: Use Kafka instead)
    // ============================================================================

    /// @deprecated Phase 5+: Use Kafka for message persistence instead of Redis queues
    /// This method is kept for backward compatibility with legacy flows
    #[deprecated(since = "0.5.0", note = "Use Kafka for message persistence (Phase 5+)")]
    #[allow(dead_code)]
    pub async fn enqueue_message(&mut self, user_id: &str, message: &ChatMessage) -> Result<()> {
        let key = format!("{}{}", self.offline_queue_prefix, user_id);
        let message_bytes = rmp_serde::encode::to_vec_named(message)?;
        let _: () = self.client.lpush(&key, message_bytes).await?;
        let _: () = self.client.expire(&key, self.message_ttl_seconds).await?;
        tracing::info!(user_id = %user_id, message_id = %message.id, "Queued message (DEPRECATED - use Kafka)");
        Ok(())
    }

    /// @deprecated Phase 5+: Use Kafka for message persistence instead of Redis queues
    /// This method is kept for backward compatibility with legacy flows
    #[deprecated(since = "0.5.0", note = "Use Kafka for message persistence (Phase 5+)")]
    #[allow(dead_code)]
    pub async fn enqueue_message_raw(&mut self, user_id: &str, message_json: &str) -> Result<()> {
        let key = format!("{}{}", self.offline_queue_prefix, user_id);
        let message_bytes = message_json.as_bytes();
        let _: () = self.client.lpush(&key, message_bytes).await?;
        let _: () = self.client.expire(&key, self.message_ttl_seconds).await?;
        tracing::info!(user_id = %user_id, "Queued message v3 (DEPRECATED - use Kafka)");
        Ok(())
    }

    /// @deprecated Phase 5+: Use Kafka consumer for message delivery
    /// This method is kept for backward compatibility with legacy flows
    #[deprecated(
        since = "0.5.0",
        note = "Use Kafka consumer for message delivery (Phase 5+)"
    )]
    #[allow(dead_code)]
    pub async fn dequeue_messages(&mut self, user_id: &str) -> Result<Vec<ChatMessage>> {
        let key = format!("{}{}", self.offline_queue_prefix, user_id);
        let messages: Vec<Vec<u8>> = self.client.lrange(&key, 0, -1).await?;
        let total_messages = messages.len();
        if total_messages == 0 {
            return Ok(Vec::new());
        }
        let _: () = self.client.del(&key).await?;
        let mut result = Vec::new();
        for msg_bytes in messages {
            match rmp_serde::from_slice::<ChatMessage>(&msg_bytes) {
                Ok(msg) => result.push(msg),
                Err(e) => tracing::error!(
                    "Failed to parse message from queue for user {}: {}",
                    user_id,
                    e
                ),
            }
        }
        let parsed_messages = result.len();
        let dropped_messages = total_messages - parsed_messages;
        tracing::info!(
            operation = "dequeue_messages",
            user_id = %user_id,
            total_messages,
            parsed_messages,
            dropped_messages,
            "Dequeued messages (DEPRECATED - use Kafka)"
        );
        Ok(result)
    }

    #[allow(dead_code)]
    pub async fn has_messages(&mut self, user_id: &str) -> Result<bool> {
        let key = format!("{}{}", self.offline_queue_prefix, user_id);
        let count: i32 = self.client.llen(&key).await?;
        Ok(count > 0)
    }

    // ============================================================================
    // Session Management (delegated to sessions module)
    // ============================================================================

    pub async fn create_session(
        &mut self,
        jti: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        sessions::SessionManager::new(&mut self.client)
            .create_session(jti, user_id, ttl_seconds)
            .await
    }

    pub async fn validate_session(&mut self, jti: &str) -> Result<Option<String>> {
        sessions::SessionManager::new(&mut self.client)
            .validate_session(jti)
            .await
    }

    pub async fn revoke_session(&mut self, jti: &str, user_id: &str) -> Result<()> {
        sessions::SessionManager::new(&mut self.client)
            .revoke_session(jti, user_id)
            .await
    }

    #[allow(dead_code)]
    pub async fn revoke_all_sessions(&mut self, user_id: &str) -> Result<()> {
        sessions::SessionManager::new(&mut self.client)
            .revoke_all_sessions(user_id)
            .await
    }

    // ============================================================================
    // Replay Protection (delegated to replay module)
    // ============================================================================

    pub async fn check_message_replay(
        &mut self,
        message_id: &str,
        content: &str,
        nonce: &str,
    ) -> Result<bool> {
        replay::ReplayProtection::new(
            &mut self.client,
            self.config.redis_key_prefixes.msg_hash.clone(),
        )
        .check_message_replay(message_id, content, nonce)
        .await
    }

    pub async fn check_replay_with_timestamp(
        &mut self,
        message_id: &str,
        content: &str,
        nonce: &str,
        timestamp: i64,
        max_age_seconds: i64,
    ) -> Result<bool> {
        replay::ReplayProtection::new(
            &mut self.client,
            self.config.redis_key_prefixes.msg_hash.clone(),
        )
        .check_replay_with_timestamp(message_id, content, nonce, timestamp, max_age_seconds)
        .await
    }

    // ============================================================================
    // Rate Limiting (delegated to rate_limiting module)
    // ============================================================================

    pub async fn increment_message_count(&mut self, user_id: &str) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .increment_message_count(user_id)
            .await
    }

    pub async fn increment_ip_message_count(&mut self, ip: &str) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .increment_ip_message_count(ip)
            .await
    }

    pub async fn increment_combined_rate_limit(
        &mut self,
        user_id: &str,
        ip: &str,
        ttl_seconds: i64,
    ) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .increment_combined_rate_limit(user_id, ip, ttl_seconds)
            .await
    }

    pub async fn increment_key_update_count(&mut self, user_id: &str) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .increment_key_update_count(user_id)
            .await
    }

    pub async fn increment_password_change_count(&mut self, user_id: &str) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .increment_password_change_count(user_id)
            .await
    }

    pub async fn increment_rate_limit(&mut self, key: &str, ttl_seconds: i64) -> Result<i64> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .increment_rate_limit(key, ttl_seconds)
            .await
    }

    pub async fn increment_failed_login_count(&mut self, username: &str) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .increment_failed_login_count(username)
            .await
    }

    pub async fn reset_failed_login_count(&mut self, username: &str) -> Result<()> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .reset_failed_login_count(username)
            .await
    }

    #[allow(dead_code)]
    pub async fn get_message_count_last_hour(&mut self, user_id: &str) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .get_message_count_last_hour(user_id)
            .await
    }

    #[allow(dead_code)]
    pub async fn get_key_update_count_last_day(&mut self, user_id: &str) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .get_key_update_count_last_day(user_id)
            .await
    }

    pub async fn block_user_temporarily(
        &mut self,
        user_id: &str,
        duration_seconds: i64,
        reason: &str,
    ) -> Result<()> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .block_user_temporarily(user_id, duration_seconds, reason)
            .await
    }

    pub async fn is_user_blocked(&mut self, user_id: &str) -> Result<Option<String>> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .is_user_blocked(user_id)
            .await
    }

    // ============================================================================
    // Token Management (delegated to tokens module)
    // ============================================================================

    pub async fn store_refresh_token(
        &mut self,
        jti: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .store_refresh_token(jti, user_id, ttl_seconds)
            .await
    }

    pub async fn check_refresh_token(&mut self, jti: &str) -> Result<Option<String>> {
        tokens::TokenManager::new(&mut self.client)
            .check_refresh_token(jti)
            .await
    }

    pub async fn revoke_refresh_token(&mut self, jti: &str) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .revoke_refresh_token(jti)
            .await
    }

    pub async fn revoke_all_user_tokens(&mut self, user_id: &str) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .revoke_all_user_tokens(user_id)
            .await
    }

    pub async fn invalidate_access_token(&mut self, jti: &str, ttl_seconds: i64) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .invalidate_access_token(jti, ttl_seconds)
            .await
    }

    pub async fn is_token_invalidated(&mut self, jti: &str) -> Result<bool> {
        tokens::TokenManager::new(&mut self.client)
            .is_token_invalidated(jti)
            .await
    }

    // ============================================================================
    // Cache Operations (delegated to cache module)
    // ============================================================================

    pub async fn cache_key_bundle(
        &mut self,
        user_id: &str,
        bundle: &construct_crypto::UploadableKeyBundle,
        ttl_hours: i64,
    ) -> Result<()> {
        cache::CacheManager::new(&mut self.client)
            .cache_key_bundle(user_id, bundle, ttl_hours)
            .await
    }

    pub async fn get_cached_key_bundle(
        &mut self,
        user_id: &str,
    ) -> Result<Option<construct_crypto::UploadableKeyBundle>> {
        cache::CacheManager::new(&mut self.client)
            .get_cached_key_bundle(user_id)
            .await
    }

    pub async fn invalidate_key_bundle_cache(&mut self, user_id: &str) -> Result<()> {
        cache::CacheManager::new(&mut self.client)
            .invalidate_key_bundle_cache(user_id)
            .await
    }

    pub async fn cache_federation_key_bundle(
        &mut self,
        user_id: &str,
        response_json: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        cache::CacheManager::new(&mut self.client)
            .cache_federation_key_bundle(user_id, response_json, ttl_seconds)
            .await
    }

    pub async fn get_cached_federation_key_bundle(
        &mut self,
        user_id: &str,
    ) -> Result<Option<String>> {
        cache::CacheManager::new(&mut self.client)
            .get_cached_federation_key_bundle(user_id)
            .await
    }

    // ============================================================================
    // Connection Tracking
    // ============================================================================

    #[allow(dead_code)]
    pub async fn track_connection(&mut self, user_id: &str, connection_id: &str) -> Result<u32> {
        use crate::config::SECONDS_PER_HOUR;
        let key = format!("connections:{}", user_id);
        let _: () = self.client.sadd(&key, connection_id).await?;
        let _: () = self.client.expire(&key, SECONDS_PER_HOUR).await?;

        let count: u32 = self.client.scard(&key).await?;
        Ok(count)
    }

    #[allow(dead_code)]
    pub async fn untrack_connection(&mut self, user_id: &str, connection_id: &str) -> Result<()> {
        let key = format!("connections:{}", user_id);
        let _: () = self.client.srem(&key, connection_id).await?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn get_active_connections(&mut self, user_id: &str) -> Result<u32> {
        let key = format!("connections:{}", user_id);
        let count: u32 = self.client.scard(&key).await?;
        Ok(count)
    }

    // ============================================================================
    // Basic Operations
    // ============================================================================

    pub async fn ping(&mut self) -> Result<()> {
        let _: () = redis::cmd("PING").query_async(&mut self.client).await?;
        Ok(())
    }

    // ============================================================================
    // Message Delivery (delegated to delivery module)
    // ============================================================================

    pub async fn read_user_messages_from_stream(
        &mut self,
        user_id: &str,
        server_instance_id: Option<&str>,
        since_id: Option<&str>,
        count: usize,
    ) -> Result<Vec<(String, crate::kafka::types::KafkaMessageEnvelope)>> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .read_user_messages_from_stream(user_id, server_instance_id, since_id, count)
        .await
    }

    pub async fn wait_for_message_notification(
        &self,
        _user_id: &str,
        timeout_ms: u64,
    ) -> Result<bool> {
        // Note: This method doesn't need mutable access, but DeliveryManager requires it
        // We'll create a temporary mutable reference
        // Actually, wait_for_message_notification doesn't use client, so we can make it simpler
        use tokio::time::Duration;
        tokio::time::sleep(Duration::from_millis(timeout_ms)).await;
        Ok(false)
    }

    pub async fn track_user_online(
        &mut self,
        user_id: &str,
        server_instance_id: &str,
    ) -> Result<()> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .track_user_online(user_id, server_instance_id)
        .await
    }

    pub async fn untrack_user_online(&mut self, user_id: &str) -> Result<()> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .untrack_user_online(user_id)
        .await
    }

    pub async fn get_user_server_instance(&mut self, user_id: &str) -> Result<Option<String>> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .get_user_server_instance(user_id)
        .await
    }

    pub async fn process_offline_messages_for_user(
        &mut self,
        user_id: &str,
        server_instance_id: &str,
    ) -> Result<usize> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .process_offline_messages_for_user(user_id, server_instance_id)
        .await
    }

    pub async fn publish_user_online(
        &mut self,
        user_id: &str,
        server_instance_id: &str,
        online_channel: &str,
    ) -> Result<()> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .publish_user_online(user_id, server_instance_id, online_channel)
        .await
    }

    pub async fn poll_delivery_queue(&mut self, server_instance_id: &str) -> Result<Vec<Vec<u8>>> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .poll_delivery_queue(server_instance_id)
        .await
    }

    pub async fn register_server_instance(
        &mut self,
        queue_key: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .register_server_instance(queue_key, ttl_seconds)
        .await
    }

    pub async fn mark_delivered_direct(&mut self, message_id: &str) -> Result<()> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .mark_delivered_direct(message_id)
        .await
    }

    pub async fn is_delivered_direct(&mut self, message_id: &str) -> Result<bool> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .is_delivered_direct(message_id)
        .await
    }
}
