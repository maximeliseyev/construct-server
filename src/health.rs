use crate::db::DbPool;
use crate::queue::MessageQueue;
use anyhow::Result;
use tokio::sync::Mutex;
use std::sync::Arc;

pub async fn health_check(pool: &DbPool, queue: Arc<Mutex<MessageQueue>>) -> Result<()> {
    // Check database
    sqlx::query("SELECT 1").execute(pool).await?;

    // Check Redis
    queue.lock().await.ping().await?;

    Ok(())
}
