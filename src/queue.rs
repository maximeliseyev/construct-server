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
use anyhow::Result;
use redis::{AsyncCommands, Client, cmd};
use sha2::{Digest, Sha256};

use crate::config::Config;

const SECONDS_PER_DAY: i64 = 86400;

pub struct MessageQueue {
    client: redis::aio::ConnectionManager,
    /// TTL for queued messages in seconds (configured via message_ttl_days)
    /// After this period, undelivered messages are automatically deleted by Redis
    message_ttl_seconds: i64,
    offline_queue_prefix: String,
    delivery_queue_prefix: String,
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
    #[deprecated(since = "0.5.0", note = "Use Kafka consumer for message delivery (Phase 5+)")]
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

        let key = format!("msg_hash:{}", hash);

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

        let _: () = self.client.set_ex(&key, "1", 86400).await?;

        Ok(true) // Сообщение уникальное
    }

    pub async fn increment_message_count(&mut self, user_id: &str) -> Result<u32> {
        let key = format!("rate:msg:{}", user_id);

        // Инкрементируем счетчик
        let count: u32 = self.client.incr(&key, 1).await?;

        // Устанавливаем TTL только при первом инкременте
        if count == 1 {
            let _: () = self.client.expire(&key, 3600).await?; // 1 час
        }

        Ok(count)
    }

    pub async fn increment_key_update_count(&mut self, user_id: &str) -> Result<u32> {
        let key = format!("rate:key:{}", user_id);

        let count: u32 = self.client.incr(&key, 1).await?;

        if count == 1 {
            let _: () = self.client.expire(&key, 86400).await?; // 24 часа
        }

        Ok(count)
    }

    /// Increments password change attempt counter for rate limiting
    /// Returns the total count of password changes in the last 24 hours
    pub async fn increment_password_change_count(&mut self, user_id: &str) -> Result<u32> {
        let key = format!("rate:pwd:{}", user_id);

        let count: u32 = self.client.incr(&key, 1).await?;

        if count == 1 {
            let _: () = self.client.expire(&key, 86400).await?; // 24 hours
        }

        Ok(count)
    }

    /// Increments failed login attempt counter for rate limiting
    /// Returns the total count of failed login attempts in the last 15 minutes
    pub async fn increment_failed_login_count(&mut self, username: &str) -> Result<u32> {
        let key = format!("rate:login:{}", username);

        let count: u32 = self.client.incr(&key, 1).await?;

        if count == 1 {
            let _: () = self.client.expire(&key, 900).await?; // 15 minutes
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

    pub async fn cache_key_bundle(
        &mut self,
        user_id: &str,
        bundle: &UploadableKeyBundle,
        ttl_hours: i64,
    ) -> Result<()> {
        let key = format!("key_bundle:{}", user_id);
        let bundle_json = serde_json::to_string(bundle)
            .map_err(|e| anyhow::anyhow!("Failed to serialize bundle: {}", e))?;
        let ttl_seconds = ttl_hours * 3600;
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

    #[allow(dead_code)]
    pub async fn track_connection(&mut self, user_id: &str, connection_id: &str) -> Result<u32> {
        let key = format!("connections:{}", user_id);
        let _: () = self.client.sadd(&key, connection_id).await?;
        let _: () = self.client.expire(&key, 3600).await?; // Обновляем TTL

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
        let key = format!("user:{}:server_instance_id", user_id);
        // Set with TTL matching session TTL (30 days default)
        let ttl_seconds = 30 * 24 * 60 * 60; // 30 days
        
        let _: () = self.client.setex(&key, ttl_seconds, server_instance_id).await?;
        
        tracing::debug!(
            user_id = %user_id,
            server_instance_id = %server_instance_id,
            "Tracked user online status"
        );
        
        Ok(())
    }
    
    /// Phase 5: Remove user online tracking when they disconnect
    pub async fn untrack_user_online(&mut self, user_id: &str) -> Result<()> {
        let key = format!("user:{}:server_instance_id", user_id);
        let _: () = self.client.del(&key).await?;
        
        tracing::debug!(
            user_id = %user_id,
            "Removed user online tracking"
        );
        
        Ok(())
    }
    
    /// Phase 5: Get server instance ID for an online user
    pub async fn get_user_server_instance(&mut self, user_id: &str) -> Result<Option<String>> {
        let key = format!("user:{}:server_instance_id", user_id);
        let result: Option<String> = self.client.get(&key).await?;
        Ok(result)
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
}
