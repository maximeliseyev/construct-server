// ============================================================================
// Message Queue - Redis-only Storage (No Database Persistence)
// ============================================================================
//
// IMPORTANT SECURITY POLICY:
//
// Messages are NEVER persisted to the database to prevent:
// 1. Social graph reconstruction (metadata leakage: who talks to whom)
// 2. Long-term storage of encrypted data (reduces attack surface)
// 3. Server-side message history (true end-to-end encryption)
//
// Message Lifecycle:
// 1. Online recipient  → Direct delivery via WebSocket (no storage)
// 2. Offline recipient → Temporary storage in Redis with TTL
// 3. User connects     → Messages delivered from Redis queue
// 4. After delivery    → Messages DELETED from Redis immediately
// 5. After TTL expires → Undelivered messages AUTO-DELETED by Redis
//
// This design ensures:
// - Forward secrecy: Old messages cannot be recovered
// - Metadata privacy: No conversation patterns stored
// - Ephemeral nature: Messages exist only during delivery window
//
// ============================================================================

use crate::e2e::UploadableKeyBundle;
use crate::message::ChatMessage;
use anyhow::{Context, Result};
use futures_util::StreamExt;
use redis::{AsyncCommands, Client, cmd};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::config::{Config, SECONDS_PER_DAY, SECONDS_PER_HOUR};

pub struct MessageQueue {
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

        let client = Client::open(config.redis_url.clone())
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
    pub async fn create_session(
        &mut self,
        jti: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        let session_key = format!("session:{}", jti);
        let _: () = self
            .client
            .set_ex(&session_key, user_id, ttl_seconds as u64)
            .await?;
        let user_sessions_key = format!("user_sessions:{}", user_id);
        let _: () = self.client.sadd(&user_sessions_key, jti).await?;
        let _: () = self.client.expire(&user_sessions_key, ttl_seconds).await?;
        tracing::info!(user_id = %user_id, session_jti = %jti, "Created session");
        Ok(())
    }
    pub async fn validate_session(&mut self, jti: &str) -> Result<Option<String>> {
        let session_key = format!("session:{}", jti);
        let user_id: Option<String> = self.client.get(&session_key).await?;
        Ok(user_id)
    }
    pub async fn revoke_session(&mut self, jti: &str, user_id: &str) -> Result<()> {
        let session_key = format!("session:{}", jti);
        let user_sessions_key = format!("user_sessions:{}", user_id);
        let _: () = self.client.del(&session_key).await?;
        let _: () = self.client.srem(&user_sessions_key, jti).await?;
        tracing::info!(user_id = %user_id, session_jti = %jti, "Revoked session");
        Ok(())
    }
    #[allow(dead_code)]
    pub async fn revoke_all_sessions(&mut self, user_id: &str) -> Result<()> {
        let user_sessions_key = format!("user_sessions:{}", user_id);
        let jtis: Vec<String> = self.client.smembers(&user_sessions_key).await?;
        for jti in &jtis {
            let session_key = format!("session:{}", jti);
            let _: () = self.client.del(&session_key).await?;
        }
        if !jtis.is_empty() {
            let _: () = self.client.del(&user_sessions_key).await?;
        }
        tracing::info!(user_id = %user_id, count = jtis.len(), "Revoked all sessions");
        Ok(())
    }

    pub async fn check_message_replay(
        &mut self,
        message_id: &str,
        content: &str,
        nonce: &str,
    ) -> Result<bool> {
        // Создаем уникальный хэш сообщения
        let mut hasher = Sha256::new();
        hasher.update(message_id.as_bytes());
        hasher.update(content.as_bytes());
        hasher.update(nonce.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        let key = format!("{}{}", self.config.redis_key_prefixes.msg_hash, hash);

        // Проверяем существование
        let exists: bool = self.client.exists(&key).await?;

        if exists {
            tracing::warn!(
                message_id = %message_id,
                hash = %hash,
                "Potential replay attack detected"
            );
            return Ok(false); // Сообщение уже было
        }

        let _: () = self
            .client
            .set_ex(&key, "1", SECONDS_PER_DAY as u64)
            .await?;

        Ok(true) // Сообщение уникальное
    }

    /// Enhanced replay protection with timestamp validation
    ///
    /// Checks for replay attacks using:
    /// - message_id + content + nonce hash (for deduplication)
    /// - timestamp validation (rejects requests older than max_age_seconds)
    ///
    /// # Arguments
    /// * `message_id` - Unique message identifier
    /// * `content` - Message content (for hash)
    /// * `nonce` - Nonce for this request (prevents replay)
    /// * `timestamp` - Request timestamp (Unix epoch seconds)
    /// * `max_age_seconds` - Maximum age of request in seconds (default: 300 = 5 minutes)
    ///
    /// # Returns
    /// * `Ok(true)` - Request is new and valid (not a replay)
    /// * `Ok(false)` - Request is a replay (already seen)
    /// * `Err(_)` - Error checking replay protection
    pub async fn check_replay_with_timestamp(
        &mut self,
        message_id: &str,
        content: &str,
        nonce: &str,
        timestamp: i64,
        max_age_seconds: i64,
    ) -> Result<bool> {
        // 1. Validate timestamp (prevent replay of old requests)
        let now = chrono::Utc::now().timestamp();
        let age = now - timestamp;

        if age > max_age_seconds {
            tracing::warn!(
                message_id = %message_id,
                timestamp = timestamp,
                age_seconds = age,
                max_age = max_age_seconds,
                "Request timestamp too old - possible replay attack"
            );
            return Ok(false); // Timestamp validation failed
        }

        if age < -60 {
            // Allow 60 seconds clock skew for future timestamps
            tracing::warn!(
                message_id = %message_id,
                timestamp = timestamp,
                now = now,
                "Request timestamp too far in future - possible clock skew or attack"
            );
            return Ok(false); // Timestamp too far in future
        }

        // 2. Check replay using hash (same as check_message_replay)
        let mut hasher = Sha256::new();
        hasher.update(message_id.as_bytes());
        hasher.update(content.as_bytes());
        hasher.update(nonce.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        let key = format!("{}{}", self.config.redis_key_prefixes.msg_hash, hash);

        // Check if already exists
        let exists: bool = self.client.exists(&key).await?;

        if exists {
            tracing::warn!(
                message_id = %message_id,
                hash = %hash,
                "Potential replay attack detected (duplicate hash)"
            );
            return Ok(false); // Message already seen
        }

        // Store with TTL = max_age_seconds (cleanup old entries automatically)
        let _: () = self
            .client
            .set_ex(&key, &timestamp.to_string(), max_age_seconds as u64)
            .await?;

        Ok(true) // Request is new and valid
    }

    pub async fn increment_message_count(&mut self, user_id: &str) -> Result<u32> {
        let key = format!("rate:msg:{}", user_id);

        // Инкрементируем счетчик
        let count: u32 = self.client.incr(&key, 1).await?;

        // Устанавливаем TTL только при первом инкременте
        if count == 1 {
            let _: () = self.client.expire(&key, SECONDS_PER_HOUR).await?;
        }

        Ok(count)
    }

    /// Increments message count per IP address for rate limiting
    /// Returns the total count of messages from this IP in the last hour
    /// This provides protection against distributed attacks (multiple users from same IP)
    pub async fn increment_ip_message_count(&mut self, ip: &str) -> Result<u32> {
        // Normalize IP (handle IPv6 brackets if present)
        let normalized_ip = ip.trim_start_matches('[').trim_end_matches(']');
        let key = format!("rate:ip:{}", normalized_ip);

        // Increment counter
        let count: u32 = self.client.incr(&key, 1).await?;

        // Set TTL only on first increment (1 hour window)
        if count == 1 {
            let _: () = self.client.expire(&key, SECONDS_PER_HOUR).await?;
        }

        Ok(count)
    }

    /// Increments combined rate limit counter (user_id + IP)
    /// Returns the total count of operations from this user+IP combination in the last hour
    /// This provides more precise rate limiting for authenticated operations:
    /// - Same user from different IPs: separate limits per IP
    /// - Different users from same IP: separate limits per user
    /// - Protects against both account takeover and distributed attacks
    ///
    /// # Arguments
    /// * `user_id` - User identifier (UUID string)
    /// * `ip` - Client IP address (normalized)
    /// * `ttl_seconds` - Time window in seconds (default: 1 hour)
    ///
    /// # Returns
    /// Current count for this user+IP combination
    pub async fn increment_combined_rate_limit(
        &mut self,
        user_id: &str,
        ip: &str,
        ttl_seconds: i64,
    ) -> Result<u32> {
        // Normalize IP (handle IPv6 brackets if present)
        let normalized_ip = ip.trim_start_matches('[').trim_end_matches(']');

        // Create combined key: "rate:combined:{user_id}:{ip}"
        // This allows separate tracking per user+IP combination
        let key = format!("rate:combined:{}:{}", user_id, normalized_ip);

        // Increment counter
        let count: u32 = self.client.incr(&key, 1).await?;

        // Set TTL only on first increment
        if count == 1 {
            let _: () = self.client.expire(&key, ttl_seconds).await?;
        }

        Ok(count)
    }

    pub async fn increment_key_update_count(&mut self, user_id: &str) -> Result<u32> {
        let key = format!("rate:key:{}", user_id);

        let count: u32 = self.client.incr(&key, 1).await?;

        if count == 1 {
            let _: () = self.client.expire(&key, SECONDS_PER_DAY).await?;
        }

        Ok(count)
    }

    /// Increments password change attempt counter for rate limiting
    /// Returns the total count of password changes in the last 24 hours
    pub async fn increment_password_change_count(&mut self, user_id: &str) -> Result<u32> {
        let key = format!("rate:pwd:{}", user_id);

        let count: u32 = self.client.incr(&key, 1).await?;

        if count == 1 {
            let _: () = self.client.expire(&key, SECONDS_PER_DAY).await?;
        }

        Ok(count)
    }

    /// Generic rate limiter: increments counter for a given key with specified TTL
    /// Returns the current count
    pub async fn increment_rate_limit(&mut self, key: &str, ttl_seconds: i64) -> Result<i64> {
        let full_key = format!("rate:{}", key);

        let count: i64 = self.client.incr(&full_key, 1).await?;

        if count == 1 {
            let _: () = self.client.expire(&full_key, ttl_seconds).await?;
        }

        Ok(count)
    }

    /// Increments failed login attempt counter for rate limiting
    /// Returns the total count of failed login attempts in the last 15 minutes
    pub async fn increment_failed_login_count(&mut self, username: &str) -> Result<u32> {
        let key = format!("rate:login:{}", username);

        let count: u32 = self.client.incr(&key, 1).await?;

        // 15 minutes = 900 seconds
        const FAILED_LOGIN_WINDOW_SECS: i64 = 900;
        if count == 1 {
            let _: () = self.client.expire(&key, FAILED_LOGIN_WINDOW_SECS).await?;
        }

        Ok(count)
    }

    /// Resets failed login counter after successful login
    pub async fn reset_failed_login_count(&mut self, username: &str) -> Result<()> {
        let key = format!("rate:login:{}", username);
        let _: () = self.client.del(&key).await?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn get_message_count_last_hour(&mut self, user_id: &str) -> Result<u32> {
        let key = format!("rate:msg:{}", user_id);
        let count: Option<u32> = self.client.get(&key).await?;
        Ok(count.unwrap_or(0))
    }

    #[allow(dead_code)]
    pub async fn get_key_update_count_last_day(&mut self, user_id: &str) -> Result<u32> {
        let key = format!("rate:key:{}", user_id);
        let count: Option<u32> = self.client.get(&key).await?;
        Ok(count.unwrap_or(0))
    }

    pub async fn block_user_temporarily(
        &mut self,
        user_id: &str,
        duration_seconds: i64,
        reason: &str,
    ) -> Result<()> {
        let key = format!("blocked:{}", user_id);
        let _: () = self
            .client
            .set_ex(&key, reason, duration_seconds as u64)
            .await?;

        tracing::warn!(
            user_id = %user_id,
            duration_seconds = duration_seconds,
            reason = %reason,
            "User temporarily blocked"
        );

        Ok(())
    }

    pub async fn is_user_blocked(&mut self, user_id: &str) -> Result<Option<String>> {
        let key = format!("blocked:{}", user_id);
        let reason: Option<String> = self.client.get(&key).await?;
        Ok(reason)
    }

    /// Store refresh token in Redis for validation and revocation
    ///
    /// # Arguments
    /// * `jti` - JWT ID (unique token identifier)
    /// * `user_id` - User ID this token belongs to
    /// * `ttl_seconds` - Time to live in seconds
    pub async fn store_refresh_token(
        &mut self,
        jti: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        let key = format!("refresh_token:{}", jti);
        // Store user_id with the token for validation
        let _: () = self
            .client
            .set_ex(&key, user_id, ttl_seconds as u64)
            .await?;
        Ok(())
    }

    /// Check if refresh token is valid (exists and not revoked)
    ///
    /// # Returns
    /// * `Ok(Some(user_id))` - Token is valid and belongs to this user
    /// * `Ok(None)` - Token doesn't exist or was revoked
    /// * `Err(_)` - Error checking token
    pub async fn check_refresh_token(&mut self, jti: &str) -> Result<Option<String>> {
        let key = format!("refresh_token:{}", jti);
        let user_id: Option<String> = self.client.get(&key).await?;
        Ok(user_id)
    }

    /// Revoke refresh token (soft logout)
    ///
    /// Removes the token from Redis, making it invalid for future use
    pub async fn revoke_refresh_token(&mut self, jti: &str) -> Result<()> {
        let key = format!("refresh_token:{}", jti);
        let _: () = self.client.del(&key).await?;
        Ok(())
    }

    /// Revoke all refresh tokens for a user (logout from all devices)
    ///
    /// Note: This requires scanning all refresh tokens, which can be expensive.
    /// For better performance, consider maintaining a set of active tokens per user.
    /// This implementation uses a simple approach - in production, you might want to
    /// maintain a set: user_tokens:{user_id} -> Set{jti} for O(1) revocation.
    pub async fn revoke_all_user_tokens(&mut self, user_id: &str) -> Result<()> {
        // Pattern: refresh_token:*
        // Use KEYS for simplicity (in production with many tokens, use SCAN)
        let pattern = "refresh_token:*";

        // Note: KEYS can block Redis, but for token revocation it's acceptable
        // In high-scale production, maintain a reverse index: user_tokens:{user_id} -> Set{jti}
        let keys: Vec<String> = self.client.keys(pattern).await?;

        let mut deleted_count = 0;
        for key in keys {
            // Check if this token belongs to the user
            let stored_user_id: Option<String> = self.client.get(&key).await?;
            if stored_user_id.as_deref() == Some(user_id) {
                let _: () = self.client.del(&key).await?;
                deleted_count += 1;
            }
        }

        tracing::info!(
            user_id = %user_id,
            deleted_count = deleted_count,
            "Revoked all refresh tokens for user"
        );

        Ok(())
    }

    /// Store invalidated access token (for soft logout)
    ///
    /// Stores token JTI with short TTL to prevent reuse after logout
    /// TTL should match access token lifetime
    pub async fn invalidate_access_token(&mut self, jti: &str, ttl_seconds: i64) -> Result<()> {
        let key = format!("invalidated_token:{}", jti);
        let _: () = self.client.set_ex(&key, "1", ttl_seconds as u64).await?;
        Ok(())
    }

    /// Check if access token is invalidated (was revoked)
    ///
    /// # Returns
    /// * `Ok(true)` - Token is invalidated (should be rejected)
    /// * `Ok(false)` - Token is valid (not invalidated)
    pub async fn is_token_invalidated(&mut self, jti: &str) -> Result<bool> {
        let key = format!("invalidated_token:{}", jti);
        let exists: bool = self.client.exists(&key).await?;
        Ok(exists)
    }

    pub async fn cache_key_bundle(
        &mut self,
        user_id: &str,
        bundle: &UploadableKeyBundle,
        ttl_hours: i64,
    ) -> Result<()> {
        let key = format!("key_bundle:{}", user_id);
        let bundle_json = serde_json::to_string(bundle)
            .map_err(|e| anyhow::anyhow!("Failed to serialize bundle: {}", e))?;
        let ttl_seconds = ttl_hours * SECONDS_PER_HOUR;
        let _: () = self
            .client
            .set_ex(&key, bundle_json, ttl_seconds as u64)
            .await?;
        tracing::debug!(user_id = %user_id, ttl_hours = ttl_hours, "Cached key bundle");
        Ok(())
    }

    pub async fn get_cached_key_bundle(
        &mut self,
        user_id: &str,
    ) -> Result<Option<UploadableKeyBundle>> {
        let key = format!("key_bundle:{}", user_id);
        let bundle_json: Option<String> = self.client.get(&key).await?;

        match bundle_json {
            Some(json) => {
                let bundle: UploadableKeyBundle = serde_json::from_str(&json)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize bundle: {}", e))?;
                Ok(Some(bundle))
            }
            None => Ok(None),
        }
    }

    pub async fn invalidate_key_bundle_cache(&mut self, user_id: &str) -> Result<()> {
        let key = format!("key_bundle:{}", user_id);
        let _: () = self.client.del(&key).await?;
        tracing::debug!(user_id = %user_id, "Invalidated key bundle cache");
        Ok(())
    }

    /// Cache federation key bundle response (includes user_id, username, bundle)
    /// Used for federation key exchange endpoint
    ///
    /// # Arguments
    /// * `user_id` - User ID (UUID)
    /// * `response_json` - JSON response string to cache
    /// * `ttl_seconds` - Time to live in seconds (typically 300 = 5 minutes)
    pub async fn cache_federation_key_bundle(
        &mut self,
        user_id: &str,
        response_json: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        let key = format!("federation_key_bundle:{}", user_id);
        let _: () = self
            .client
            .set_ex(&key, response_json, ttl_seconds as u64)
            .await?;
        tracing::debug!(
            user_id = %user_id,
            ttl_seconds = ttl_seconds,
            "Cached federation key bundle"
        );
        Ok(())
    }

    /// Get cached federation key bundle response
    ///
    /// # Returns
    /// * `Ok(Some(json))` - Cached JSON response string
    /// * `Ok(None)` - Not in cache
    pub async fn get_cached_federation_key_bundle(
        &mut self,
        user_id: &str,
    ) -> Result<Option<String>> {
        let key = format!("federation_key_bundle:{}", user_id);
        let cached: Option<String> = self.client.get(&key).await?;
        Ok(cached)
    }

    #[allow(dead_code)]
    pub async fn track_connection(&mut self, user_id: &str, connection_id: &str) -> Result<u32> {
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

    pub async fn ping(&mut self) -> Result<()> {
        let _: () = cmd("PING").query_async(&mut self.client).await?;
        Ok(())
    }

    // ============================================================================
    // Phase 2.5: REST API Message Retrieval (Long Polling)
    // ============================================================================

    /// Read messages from Redis Stream for a user
    ///
    /// Reads from either:
    /// - delivery_stream:offline:{user_id} (if user was offline)
    /// - delivery_stream:{server_instance_id} (if user is online, filters by recipient_id)
    ///
    /// # Arguments
    /// * `user_id` - User ID to get messages for
    /// * `server_instance_id` - Server instance ID (if user is online)
    /// * `since_id` - Stream message ID to read after (optional, for pagination)
    /// * `count` - Maximum number of messages to return
    ///
    /// # Returns
    /// Vector of (stream_message_id, KafkaMessageEnvelope) tuples
    pub async fn read_user_messages_from_stream(
        &mut self,
        user_id: &str,
        server_instance_id: Option<&str>,
        since_id: Option<&str>,
        count: usize,
    ) -> Result<Vec<(String, crate::kafka::types::KafkaMessageEnvelope)>> {
        // Try offline stream first (if user was offline)
        let offline_stream_key = format!("{}offline:{}", self.delivery_queue_prefix, user_id);

        // Check if offline stream exists and has messages
        let offline_messages = self
            .read_stream_messages(&offline_stream_key, since_id, count)
            .await?;

        if !offline_messages.is_empty() {
            // Parse and filter messages for this user
            let mut result = Vec::new();
            for (stream_id, fields) in offline_messages {
                if let Some(envelope) = self.parse_stream_message(fields, user_id)? {
                    result.push((stream_id, envelope));
                }
            }
            return Ok(result);
        }

        // If no offline messages, check delivery stream (if user is online)
        if let Some(server_id) = server_instance_id {
            let delivery_stream_key = format!("{}{}", self.delivery_queue_prefix, server_id);
            let delivery_messages = self
                .read_stream_messages(&delivery_stream_key, since_id, count * 2)
                .await?;

            // Filter messages for this user (delivery stream contains messages for all users on this server)
            let mut result = Vec::new();
            for (stream_id, fields) in delivery_messages {
                if let Some(envelope) = self.parse_stream_message(fields, user_id)? {
                    result.push((stream_id, envelope));
                    if result.len() >= count {
                        break;
                    }
                }
            }
            return Ok(result);
        }

        Ok(vec![])
    }

    /// Read messages from a Redis Stream using XREAD
    ///
    /// # Arguments
    /// * `stream_key` - Redis stream key
    /// * `since_id` - Stream message ID to read after (None = "0" = from beginning)
    /// * `count` - Maximum number of messages
    ///
    /// # Returns
    /// Vector of (stream_message_id, fields_map) tuples
    async fn read_stream_messages(
        &mut self,
        stream_key: &str,
        since_id: Option<&str>,
        count: usize,
    ) -> Result<Vec<(String, HashMap<String, Vec<u8>>)>> {
        let start_id = since_id.unwrap_or("0");

        // XREAD COUNT count STREAMS stream_key start_id
        // Note: Redis returns Vec<(stream_key, Vec<(message_id, Vec<(field, value)>)>)>
        type StreamResult = Vec<(String, Vec<(String, Vec<(String, Vec<u8>)>)>)>;
        let result: redis::RedisResult<StreamResult> = cmd("XREAD")
            .arg("COUNT")
            .arg(count as i64)
            .arg("STREAMS")
            .arg(stream_key)
            .arg(start_id)
            .query_async(&mut self.client)
            .await;

        match result {
            Ok(streams) => {
                if streams.is_empty() {
                    return Ok(vec![]);
                }

                // Parse result: [(stream_key, [(message_id, [(field, value), ...]), ...])]
                let messages: Vec<(String, HashMap<String, Vec<u8>>)> = streams
                    .into_iter()
                    .flat_map(|(_, messages)| {
                        messages.into_iter().map(|(id, fields)| {
                            let field_map: HashMap<String, Vec<u8>> = fields.into_iter().collect();
                            (id, field_map)
                        })
                    })
                    .collect();

                Ok(messages)
            }
            Err(e) => {
                // Check if it's a "stream doesn't exist" error
                let err_str = e.to_string();
                if err_str.contains("no such key") || err_str.contains("WRONGTYPE") {
                    // Stream doesn't exist or is empty
                    Ok(vec![])
                } else {
                    Err(anyhow::anyhow!("Failed to read stream: {}", e))
                }
            }
        }
    }

    /// Parse stream message fields into KafkaMessageEnvelope
    /// Filters by recipient_id to ensure user only gets their messages
    fn parse_stream_message(
        &self,
        fields: HashMap<String, Vec<u8>>,
        user_id: &str,
    ) -> Result<Option<crate::kafka::types::KafkaMessageEnvelope>> {
        // Extract message_id and payload from fields
        let message_id_bytes = fields
            .get("message_id")
            .ok_or_else(|| anyhow::anyhow!("Missing message_id in stream message"))?;
        let _message_id =
            String::from_utf8(message_id_bytes.clone()).context("Invalid UTF-8 in message_id")?;

        let payload = fields
            .get("payload")
            .ok_or_else(|| anyhow::anyhow!("Missing payload in stream message"))?;

        // Deserialize KafkaMessageEnvelope from MessagePack
        let envelope: crate::kafka::types::KafkaMessageEnvelope = rmp_serde::from_slice(payload)
            .context("Failed to deserialize KafkaMessageEnvelope from stream")?;

        // SECURITY: Filter by recipient_id - only return messages for this user
        if envelope.recipient_id != user_id {
            return Ok(None);
        }

        Ok(Some(envelope))
    }

    /// Subscribe to Redis Pub/Sub channel for message notifications
    ///
    /// # Arguments
    /// * `user_id` - User ID to subscribe for
    /// * `timeout_ms` - Timeout in milliseconds
    ///
    /// # Returns
    /// true if notification received, false if timeout
    pub async fn wait_for_message_notification(
        &self,
        user_id: &str,
        timeout_ms: u64,
    ) -> Result<bool> {
        use tokio::time::{Duration, timeout};

        let channel = format!("message_notifications:{}", user_id);

        // Create a new connection for Pub/Sub (can't use same connection for commands and pub/sub)
        let client = Client::open(self.config.redis_url.clone())
            .map_err(|e| anyhow::anyhow!("Failed to create Redis client for Pub/Sub: {}", e))?;

        let mut pubsub_conn = client
            .get_async_pubsub()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get Pub/Sub connection: {}", e))?;

        // Subscribe to channel
        pubsub_conn
            .subscribe(&channel)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to subscribe to channel: {}", e))?;

        // Wait for message or timeout
        let mut stream = pubsub_conn.on_message();
        let result = timeout(Duration::from_millis(timeout_ms), stream.next()).await;

        match result {
            Ok(Some(_)) => Ok(true), // Notification received
            Ok(None) => Ok(false),   // Channel closed
            Err(_) => Ok(false),     // Timeout
        }
    }

    // ============================================================================
    // Delivery Worker Integration
    // ============================================================================

    /// Publishes a notification that a user has come online
    /// This triggers the Delivery Worker to process offline messages
    /// Phase 5: Track which server instance a user is connected to
    /// This allows delivery-worker to route messages directly to the correct server
    pub async fn track_user_online(
        &mut self,
        user_id: &str,
        server_instance_id: &str,
    ) -> Result<()> {
        let key = format!(
            "{}{}:server_instance_id",
            self.config.redis_key_prefixes.user, user_id
        );
        // Set with TTL matching session TTL from config
        let ttl_seconds = self.config.session_ttl_days * SECONDS_PER_DAY;

        let _: () = cmd("SETEX")
            .arg(&key)
            .arg(ttl_seconds)
            .arg(server_instance_id)
            .query_async(&mut self.client)
            .await?;

        tracing::debug!(
            user_id = %user_id,
            server_instance_id = %server_instance_id,
            "Tracked user online status"
        );

        Ok(())
    }

    /// Phase 5: Remove user online tracking when they disconnect
    pub async fn untrack_user_online(&mut self, user_id: &str) -> Result<()> {
        let key = format!(
            "{}{}:server_instance_id",
            self.config.redis_key_prefixes.user, user_id
        );
        let _: () = self.client.del(&key).await?;

        tracing::debug!(
            user_id = %user_id,
            "Removed user online tracking"
        );

        Ok(())
    }

    /// Phase 5: Get server instance ID for an online user
    pub async fn get_user_server_instance(&mut self, user_id: &str) -> Result<Option<String>> {
        let key = format!(
            "{}{}:server_instance_id",
            self.config.redis_key_prefixes.user, user_id
        );
        let result: Option<String> = self.client.get(&key).await?;
        Ok(result)
    }

    /// Process offline messages for a user when they come online
    /// Moves messages from delivery_queue:offline:{user_id} to delivery_queue:{server_instance_id}
    /// so they can be delivered via the delivery listener mechanism
    ///
    /// Messages are moved in FIFO order (oldest first) to maintain message ordering
    pub async fn process_offline_messages_for_user(
        &mut self,
        user_id: &str,
        server_instance_id: &str,
    ) -> Result<usize> {
        let offline_queue_key = format!("{}offline:{}", self.delivery_queue_prefix, user_id);
        let delivery_queue_key = format!("{}{}", self.delivery_queue_prefix, server_instance_id);

        // Use Lua script to atomically get all messages from offline queue and move to delivery queue
        // This ensures atomicity and maintains FIFO order
        let script = redis::Script::new(
            r"
            local offline_key = KEYS[1]
            local delivery_key = KEYS[2]
            local messages = redis.call('LRANGE', offline_key, 0, -1)
            if #messages > 0 then
                -- Move messages to delivery queue (FIFO order - oldest first)
                for i, msg in ipairs(messages) do
                    redis.call('RPUSH', delivery_key, msg)
                end
                -- Delete offline queue after moving
                redis.call('DEL', offline_key)
            end
            return #messages
            ",
        );

        let message_count: usize = script
            .key(&offline_queue_key)
            .key(&delivery_queue_key)
            .invoke_async(&mut self.client)
            .await?;

        if message_count > 0 {
            tracing::info!(
                user_id = %user_id,
                server_instance_id = %server_instance_id,
                message_count = message_count,
                "Processed offline messages for user - moved to delivery queue (FIFO order maintained)"
            );
        }

        Ok(message_count)
    }

    pub async fn publish_user_online(
        &mut self,
        user_id: &str,
        server_instance_id: &str,
        online_channel: &str,
    ) -> Result<()> {
        let notification = serde_json::json!({
            "user_id": user_id,
            "server_instance_id": server_instance_id,
        });

        let notification_str = notification.to_string();

        let _: () = self
            .client
            .publish(online_channel, notification_str)
            .await?;

        tracing::debug!(
            user_id = %user_id,
            server_instance_id = %server_instance_id,
            channel = %online_channel,
            "Published user online notification"
        );

        Ok(())
    }

    /// Polls the delivery queue for this server instance
    /// Returns a list of message payloads (as bytes) that should be delivered
    pub async fn poll_delivery_queue(&mut self, server_instance_id: &str) -> Result<Vec<Vec<u8>>> {
        let key = format!("{}{}", self.delivery_queue_prefix, server_instance_id);

        // Use Lua script to atomically get all messages and delete the queue
        // This replaces the loop of LMOVE operations with a single atomic operation
        let script = redis::Script::new(
            r"
            local messages = redis.call('LRANGE', KEYS[1], 0, -1)
            if #messages > 0 then
                redis.call('LTRIM', KEYS[1], 1, 0)
            end
            return messages
            ",
        );

        let messages: Vec<Vec<u8>> = script.key(&key).invoke_async(&mut self.client).await?;

        // Filter out the empty placeholder message left by `register_server_instance`
        let filtered_messages: Vec<Vec<u8>> =
            messages.into_iter().filter(|msg| !msg.is_empty()).collect();

        if !filtered_messages.is_empty() {
            tracing::debug!(
                server_instance_id = %server_instance_id,
                count = filtered_messages.len(),
                "Polled delivery queue"
            );
        }

        Ok(filtered_messages)
    }

    /// Register this server instance in Redis
    /// Creates a delivery queue key with TTL to signal that this server is active
    /// delivery-worker uses KEYS delivery_queue:* to discover active servers
    pub async fn register_server_instance(
        &mut self,
        queue_key: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        tracing::debug!(queue_key = %queue_key, "Registering server instance");
        // Create an empty list (if doesn't exist) and set TTL
        // The heartbeat task will refresh this periodically

        // Check if key exists and its type
        let key_type: Option<String> = self.client.key_type(queue_key).await?;
        tracing::debug!(queue_key = %queue_key, key_type = ?key_type, "Checked key type");

        match key_type.as_deref() {
            // Key is already a list, do nothing.
            Some("list") => {
                tracing::debug!(queue_key = %queue_key, "Key is a list, doing nothing");
            }
            // Key doesn't exist (redis 'TYPE' returns 'none'), create it with a placeholder.
            Some("none") | None => {
                tracing::debug!(queue_key = %queue_key, "Key does not exist, creating it");
                self.client.rpush::<_, _, ()>(queue_key, b"").await?;
            }
            // Key exists but has the wrong type, so delete and recreate it.
            Some(other_type) => {
                tracing::warn!(
                    queue_key = %queue_key,
                    key_type = %other_type,
                    "Delivery queue key has wrong type, deleting and recreating as list"
                );
                self.client.del::<_, ()>(queue_key).await?;
                self.client.rpush::<_, _, ()>(queue_key, b"").await?;
            }
        }

        // Set/renew TTL
        self.client.expire::<_, ()>(queue_key, ttl_seconds).await?;
        tracing::debug!(queue_key = %queue_key, ttl = ttl_seconds, "Set TTL for key");

        Ok(())
    }

    /// Mark a message as delivered directly via tx.send() (fast path)
    /// ========================================================================
    /// УМНАЯ ДЕДУПЛИКАЦИЯ (Вариант D):
    ///
    /// После успешного tx.send() помечаем сообщение в Redis:
    /// SET delivered_direct:{message_id} 1 EX 3600
    ///
    /// delivery-worker перед доставкой проверяет:
    /// IF EXISTS delivered_direct:{message_id} → SKIP (уже доставлено)
    ///
    /// Это позволяет:
    /// 1. Kafka остаётся source of truth
    /// 2. Быстрая доставка через tx.send()
    /// 3. Нет дублирования - delivery-worker не доставляет повторно
    /// 4. TTL 1 час - ключи автоматически очищаются
    /// ========================================================================
    pub async fn mark_delivered_direct(&mut self, message_id: &str) -> Result<()> {
        let key = format!(
            "{}{}",
            self.config.redis_key_prefixes.delivered_direct, message_id
        );
        const DELIVERED_DIRECT_TTL: i64 = SECONDS_PER_HOUR; // 1 hour TTL

        self.client
            .set_ex::<_, _, ()>(&key, "1", DELIVERED_DIRECT_TTL as u64)
            .await?;

        tracing::debug!(
            message_id = %message_id,
            ttl_seconds = DELIVERED_DIRECT_TTL,
            "Marked message as delivered directly (delivery-worker will skip)"
        );

        Ok(())
    }

    /// Check if a message was already delivered directly via tx.send()
    /// Used by delivery-worker to skip messages already delivered
    pub async fn is_delivered_direct(&mut self, message_id: &str) -> Result<bool> {
        let key = format!(
            "{}{}",
            self.config.redis_key_prefixes.delivered_direct, message_id
        );

        let exists: bool = self.client.exists(&key).await?;

        if exists {
            tracing::debug!(
                message_id = %message_id,
                "Message was already delivered directly - skipping delivery-worker delivery"
            );
        }

        Ok(exists)
    }
}
