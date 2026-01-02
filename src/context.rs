use crate::auth::AuthManager;
use crate::config::Config;
use crate::db::DbPool;
use crate::handlers::session::Clients;
use crate::kafka::MessageProducer;
use crate::queue::MessageQueue;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Application context containing shared dependencies
/// This reduces parameter passing and makes it easier to add new dependencies
#[derive(Clone)]
pub struct AppContext {
    pub db_pool: Arc<DbPool>,
    pub queue: Arc<Mutex<MessageQueue>>,
    pub auth_manager: Arc<AuthManager>,
    pub clients: Clients,
    pub config: Arc<Config>,
    /// Kafka producer for reliable message delivery (Phase 1+)
    pub kafka_producer: Arc<MessageProducer>,
    /// Unique identifier for this server instance (for delivery worker coordination)
    pub server_instance_id: String,
}

impl AppContext {
    /// Creates a new application context
    pub fn new(
        db_pool: Arc<DbPool>,
        queue: Arc<Mutex<MessageQueue>>,
        auth_manager: Arc<AuthManager>,
        clients: Clients,
        config: Arc<Config>,
        kafka_producer: Arc<MessageProducer>,
        server_instance_id: String,
    ) -> Self {
        Self {
            db_pool,
            queue,
            auth_manager,
            clients,
            config,
            kafka_producer,
            server_instance_id,
        }
    }
}
