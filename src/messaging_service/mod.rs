// ============================================================================
// Messaging Service - Phase 2.6.4
// ============================================================================
//
// Minimal context and utilities for Messaging Service microservice.
//
// ============================================================================

pub mod handlers;

use crate::auth::AuthManager;
use crate::config::Config;
use crate::db::DbPool;
use crate::handlers::session::Clients;
use crate::kafka::MessageProducer;
use crate::queue::MessageQueue;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// Messaging Service context (minimal dependencies)
#[derive(Clone)]
pub struct MessagingServiceContext {
    pub db_pool: Arc<DbPool>,
    pub queue: Arc<Mutex<MessageQueue>>,
    pub auth_manager: Arc<AuthManager>,
    pub kafka_producer: Arc<MessageProducer>,
    pub config: Arc<Config>,
}

impl MessagingServiceContext {
    /// Convert to AppContext for use with existing handlers
    /// This is a temporary adapter until handlers are refactored to use traits
    pub fn to_app_context(&self) -> crate::context::AppContext {
        use crate::apns::{ApnsClient, DeviceTokenEncryption};

        // Create minimal/mock dependencies for unused fields
        let clients: Clients = Arc::new(RwLock::new(HashMap::new()));

        // Create minimal APNs client (not used by messaging handlers)
        let apns_client = ApnsClient::new(self.config.apns.clone())
            .map(Arc::new)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "APNs client creation failed in messaging service - messaging handlers don't use APNs, continuing");
                panic!("APNs client is required but not available - this should not happen in messaging service")
            });

        // Create minimal token encryption (not used by messaging handlers)
        let token_encryption = Arc::new(
            DeviceTokenEncryption::from_hex(&self.config.apns.device_token_encryption_key)
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "Token encryption creation failed in messaging service");
                    panic!("Token encryption is required but not available - this should not happen in messaging service")
                })
        );

        // Create AppContext using builder pattern (Phase 2.8)
        crate::context::AppContext::builder()
            .with_db_pool(self.db_pool.clone())
            .with_queue(self.queue.clone())
            .with_auth_manager(self.auth_manager.clone())
            .with_clients(clients)
            .with_config(self.config.clone())
            .with_kafka_producer(self.kafka_producer.clone())
            .with_apns_client(apns_client)
            .with_token_encryption(token_encryption)
            .with_server_instance_id(uuid::Uuid::new_v4().to_string())
            .build()
            .expect("Failed to build AppContext for messaging service")
    }
}
