use crate::message::Message;
use anyhow::Result;
use redis::{AsyncCommands, Client};
use serde_json;

pub struct MessageQueue {
    client: redis::aio::ConnectionManager,
}

impl MessageQueue {
    pub async fn new(redis_url: &str) -> Result<Self> {
        let client = Client::open(redis_url)?;
        let conn = client.get_connection_manager().await?; // <- исправлено
        Ok(Self { client: conn })
    }

    // Сохранить сообщение для офлайн пользователя
    pub async fn enqueue_message(&mut self, user_id: &str, message: &Message) -> Result<()> {
        let key = format!("queue:{}", user_id);
        let message_json = serde_json::to_string(message)?;

        // Указываем тип возвращаемого значения: ()
        let _: () = self.client.lpush(&key, message_json).await?; // <- исправлено

        // TTL 30 дней
        let _: () = self.client.expire(&key, 2592000).await?; // <- исправлено

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
}
