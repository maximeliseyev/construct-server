// ============================================================================
// Notification Service - Phase 2.6.5
// ============================================================================
//
// Minimal context and utilities for Notification Service microservice.
//
// ============================================================================

pub mod handlers;

use crate::apns::{ApnsClient, DeviceTokenEncryption};
use crate::auth::AuthManager;
use crate::config::Config;
use crate::db::DbPool;
use crate::handlers::session::Clients;
use crate::queue::MessageQueue;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// Notification Service context (minimal dependencies)
#[derive(Clone)]
pub struct NotificationServiceContext {
    pub db_pool: Arc<DbPool>,
    pub queue: Arc<Mutex<MessageQueue>>,
    pub auth_manager: Arc<AuthManager>,
    pub apns_client: Arc<ApnsClient>,
    pub token_encryption: Arc<DeviceTokenEncryption>,
    pub config: Arc<Config>,
}

impl NotificationServiceContext {
    /// Convert to AppContext for use with existing handlers
    /// This is a temporary adapter until handlers are refactored to use traits
    pub fn to_app_context(&self) -> crate::context::AppContext {
        use crate::kafka::MessageProducer;

        // Create minimal/mock dependencies for unused fields
        let clients: Clients = Arc::new(RwLock::new(HashMap::new()));

        // Create minimal Kafka producer (not used by notification handlers)
        let kafka_producer = MessageProducer::new(&self.config.kafka)
            .map(Arc::new)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "Kafka producer creation failed in notification service - notification handlers don't use Kafka, continuing");
                panic!("Kafka producer is required but not available - this should not happen in notification service")
            });

        crate::context::AppContext::new(
            self.db_pool.clone(),
            self.queue.clone(),
            self.auth_manager.clone(),
            clients,
            self.config.clone(),
            kafka_producer,
            self.apns_client.clone(),
            self.token_encryption.clone(),
            uuid::Uuid::new_v4().to_string(),
        )
    }
}
