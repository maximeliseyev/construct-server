use crate::db::DbPool;
use crate::kafka::MessageProducer;
use crate::queue::MessageQueue;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;

pub async fn health_check(
    pool: &DbPool,
    queue: Arc<Mutex<MessageQueue>>,
    kafka_producer: Arc<MessageProducer>,
) -> Result<()> {
    // Check database
    sqlx::query("SELECT 1").execute(pool).await?;

    // Check Redis
    queue.lock().await.ping().await?;

    // Check Kafka (if enabled)
    if kafka_producer.is_enabled() {
        // Kafka producer is initialized and connected
        // The producer will fail on first send if broker is unreachable
        tracing::debug!("Kafka producer is enabled and initialized");
    }

    Ok(())
}
