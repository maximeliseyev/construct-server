use crate::message::Message;
use anyhow::Result;
use redis::{AsyncCommands, Client, cmd};
use tracing;

use crate::config::Config;
const SECONDS_PER_DAY: i64 = 86400;
pub struct MessageQueue {
    client: redis::aio::ConnectionManager,
    message_ttl_seconds: i64,
}
impl MessageQueue {
    pub async fn new(config: &Config) -> Result<Self> {
        let client = Client::open(config.redis_url.clone())?;
        let conn = client.get_connection_manager().await?;
        let message_ttl_seconds = config.message_ttl_days * SECONDS_PER_DAY;
        tracing::info!(
            "📦 Message queue TTL: {} days ({} seconds)",
            config.message_ttl_days,
            message_ttl_seconds
        );
        Ok(Self {
            client: conn,
            message_ttl_seconds,
        })
    }
    pub async fn enqueue_message(&mut self, user_id: &str, message: &Message) -> Result<()> {
        let key = format!("queue:{}", user_id);
        let message_bytes = rmp_serde::to_vec(message)?;
        let _: () = self.client.lpush(&key, message_bytes).await?;
        let _: () = self.client.expire(&key, self.message_ttl_seconds).await?;
        tracing::info!(user_id = %user_id, message_id = %message.id, "Queued message");
        Ok(())
    }
    pub async fn dequeue_messages(&mut self, user_id: &str) -> Result<Vec<Message>> {
        let key = format!("queue:{}", user_id);
        let messages: Vec<Vec<u8>> = self.client.lrange(&key, 0, -1).await?;
        let total_messages = messages.len();
        if total_messages == 0 {
            return Ok(Vec::new());
        }
        let _: () = self.client.del(&key).await?;
        let mut result = Vec::new();
        for msg_bytes in messages {
            match rmp_serde::from_slice::<Message>(&msg_bytes) {
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
            "Dequeued messages"
        );
        Ok(result)
    }
    // Проверить есть ли сообщения
    #[allow(dead_code)]
    pub async fn has_messages(&mut self, user_id: &str) -> Result<bool> {
        let key = format!("queue:{}", user_id);
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

    pub async fn ping(&mut self) -> Result<()> {
        let _: () = cmd("PING").query_async(&mut self.client).await?;
        Ok(())
    }
}
