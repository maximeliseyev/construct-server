// ============================================================================
// User Service - Phase 2.6.3
// ============================================================================
//
// Minimal context and utilities for User Service microservice.
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

/// User Service context (minimal dependencies)
#[derive(Clone)]
pub struct UserServiceContext {
    pub db_pool: Arc<DbPool>,
    pub queue: Arc<Mutex<MessageQueue>>,
    pub auth_manager: Arc<AuthManager>,
    pub config: Arc<Config>,
}

impl UserServiceContext {
    /// Convert to AppContext for use with existing handlers
    /// This is a temporary adapter until handlers are refactored to use traits
    pub fn to_app_context(&self) -> crate::context::AppContext {
        use crate::apns::{ApnsClient, DeviceTokenEncryption};

        // Create minimal/mock dependencies for unused fields
        let clients: Clients = Arc::new(RwLock::new(HashMap::new()));
        
        // Create minimal Kafka producer (not used by user handlers)
        let kafka_producer = crate::kafka::MessageProducer::new(&self.config.kafka)
            .map(Arc::new)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "Kafka producer creation failed in user service - user handlers don't use Kafka, continuing");
                panic!("Kafka producer is required but not available - this should not happen in user service")
            });

        // Create minimal APNs client (not used by user handlers)
        let apns_client = ApnsClient::new(self.config.apns.clone())
            .map(Arc::new)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "APNs client creation failed in user service - user handlers don't use APNs, continuing");
                panic!("APNs client is required but not available - this should not happen in user service")
            });

        // Create minimal token encryption (not used by user handlers)
        let token_encryption = Arc::new(
            DeviceTokenEncryption::from_hex(&self.config.apns.device_token_encryption_key)
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "Token encryption creation failed in user service");
                    panic!("Token encryption is required but not available - this should not happen in user service")
                })
        );

        crate::context::AppContext::new(
            self.db_pool.clone(),
            self.queue.clone(),
            self.auth_manager.clone(),
            clients,
            self.config.clone(),
            kafka_producer,
            apns_client,
            token_encryption,
            uuid::Uuid::new_v4().to_string(),
        )
    }
}
