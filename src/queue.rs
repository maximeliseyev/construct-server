use crate::message::Message;
use anyhow::Result;
use redis::{AsyncCommands, Client};

const DEFAULT_MESSAGE_TTL_DAYS: i64 = 7;
const SECONDS_PER_DAY: i64 = 86400;

pub struct MessageQueue {
    client: redis::aio::ConnectionManager,
    message_ttl_seconds: i64,
}

impl MessageQueue {
    pub async fn new(redis_url: &str) -> Result<Self> {
        let client = Client::open(redis_url)?;
        let conn = client.get_connection_manager().await?;

        // Read TTL from environment variable or use default (7 days)
        let ttl_days = std::env::var("MESSAGE_TTL_DAYS")
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(DEFAULT_MESSAGE_TTL_DAYS);

        let message_ttl_seconds = ttl_days * SECONDS_PER_DAY;

        println!(
            "📦 Message queue TTL: {} days ({} seconds)",
            ttl_days, message_ttl_seconds
        );

        Ok(Self {
            client: conn,
            message_ttl_seconds,
        })
    }

    // Сохранить сообщение для офлайн пользователя
    pub async fn enqueue_message(&mut self, user_id: &str, message: &Message) -> Result<()> {
        let key = format!("queue:{}", user_id);
        let message_json = serde_json::to_string(message)?;

        let _: () = self.client.lpush(&key, message_json).await?;

        // Set TTL from configuration
        let _: () = self.client.expire(&key, self.message_ttl_seconds).await?;

        println!("📬 Queued message for user {}", user_id);
        Ok(())
    }

    // Получить все сообщения для пользователя
    pub async fn dequeue_messages(&mut self, user_id: &str) -> Result<Vec<Message>> {
        let key = format!("queue:{}", user_id);

        let messages: Vec<String> = self.client.lrange(&key, 0, -1).await?;

        // Удаляем очередь после получения
        let _: () = self.client.del(&key).await?; // <- исправлено

        let mut result = Vec::new();
        for msg_json in messages {
            if let Ok(msg) = serde_json::from_str::<Message>(&msg_json) {
                result.push(msg);
            }
        }

        println!("📭 Dequeued {} messages for user {}", result.len(), user_id);
        Ok(result)
    }

    // Проверить есть ли сообщения
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

        // Добавляем jti в список сессий пользователя (для force logout всех устройств)
        let user_sessions_key = format!("user_sessions:{}", user_id);
        let _: () = self.client.sadd(&user_sessions_key, jti).await?;
        let _: () = self.client.expire(&user_sessions_key, ttl_seconds).await?;

        println!("Created session {} for user {}", jti, user_id);
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

        println!("Revoked session {} for user {}", jti, user_id);
        Ok(())
    }

    pub async fn revoke_all_sessions(&mut self, user_id: &str) -> Result<()> {
        let user_sessions_key = format!("user_sessions:{}", user_id);

        let jtis: Vec<String> = self.client.smembers(&user_sessions_key).await?;

        for jti in jtis {
            let session_key = format!("session:{}", jti);
            let _: () = self.client.del(&session_key).await?;
        }

        let _: () = self.client.del(&user_sessions_key).await?;

        println!("Revoked ALL sessions for user {}", user_id);
        Ok(())
    }
}
