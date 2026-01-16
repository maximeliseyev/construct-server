// ============================================================================
// Auth Service - Phase 2.6.2
// ============================================================================
//
// Minimal context and utilities for Auth Service microservice.
//
// ============================================================================

pub mod handlers;

use crate::auth::AuthManager;
use crate::config::Config;
use crate::db::DbPool;
use crate::handlers::session::Clients;
use crate::queue::MessageQueue;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// Auth Service context (minimal dependencies)
#[derive(Clone)]
pub struct AuthServiceContext {
    pub db_pool: Arc<DbPool>,
    pub queue: Arc<Mutex<MessageQueue>>,
    pub auth_manager: Arc<AuthManager>,
    pub config: Arc<Config>,
}

impl AuthServiceContext {
    /// Convert to AppContext for use with existing handlers
    /// This is a temporary adapter until handlers are refactored to use traits
    pub fn to_app_context(&self) -> crate::context::AppContext {
        use crate::apns::{ApnsClient, DeviceTokenEncryption};
        use crate::kafka::MessageProducer;

        // Create minimal/mock dependencies for unused fields
        let clients: Clients = Arc::new(RwLock::new(HashMap::new()));

        // Create minimal Kafka producer (not used by auth handlers)
        // Try to create, but if it fails, we'll use a dummy (auth handlers don't use Kafka)
        let kafka_producer = MessageProducer::new(&self.config.kafka)
            .map(Arc::new)
            .unwrap_or_else(|_| {
                // Auth handlers don't use Kafka, so this is safe
                // Create a minimal producer that will fail if used (but auth handlers won't use it)
                tracing::warn!("Kafka producer creation failed in auth service - auth handlers don't use Kafka, continuing");
                // We need to return something, but this should never be used
                // In a real implementation, we'd use Option<Arc<MessageProducer>> in AppContext
                // For now, we'll panic if this is actually used (which shouldn't happen)
                panic!("Kafka producer is required but not available - this should not happen in auth service")
            });

        // Create minimal APNs client (not used by auth handlers)
        let apns_client = ApnsClient::new(self.config.apns.clone())
            .map(Arc::new)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "APNs client creation failed in auth service - auth handlers don't use APNs, continuing");
                panic!("APNs client is required but not available - this should not happen in auth service")
            });

        // Create minimal token encryption (not used by auth handlers)
        // Use from_hex helper (same as in lib.rs)
        let token_encryption = DeviceTokenEncryption::from_hex(&self.config.apns.device_token_encryption_key)
            .map(Arc::new)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "Token encryption creation failed in auth service - auth handlers don't use it, continuing");
                panic!("Token encryption is required but not available - this should not happen in auth service")
            });

        // Create AppContext using builder pattern (Phase 2.8)
        crate::context::AppContext::builder()
            .with_db_pool(self.db_pool.clone())
            .with_queue(self.queue.clone())
            .with_auth_manager(self.auth_manager.clone())
            .with_clients(clients)
            .with_config(self.config.clone())
            .with_kafka_producer(kafka_producer)
            .with_apns_client(apns_client)
            .with_token_encryption(token_encryption)
            .with_server_instance_id(uuid::Uuid::new_v4().to_string())
            .build()
            .expect("Failed to build AppContext for auth service")
    }
}
