// ============================================================================
// AppContext Logical Groups - Phase 2.7
// ============================================================================
//
// Logical grouping of AppContext fields to reduce coupling and improve
// maintainability. Each group represents a cohesive set of related dependencies.
//
// ============================================================================

use crate::apns::{ApnsClient, DeviceTokenEncryption};
use crate::auth::AuthManager;
use crate::config::Config;
use crate::db::DbPool;
use crate::delivery_ack::{DeliveryAckManager, PostgresDeliveryStorage};
use crate::federation::{PublicKeyCache, ServerSigner};
use crate::handlers::session::Clients;
use crate::kafka::MessageProducer;
use crate::message_gateway::MessageGatewayClient;
use crate::queue::MessageQueue;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Database-related dependencies
#[derive(Clone)]
pub struct DatabaseContext {
    pub db_pool: Arc<DbPool>,
}

/// Message-related dependencies (queue, Kafka)
#[derive(Clone)]
pub struct MessageContext {
    pub queue: Arc<Mutex<MessageQueue>>,
    pub kafka_producer: Arc<MessageProducer>,
}

/// Authentication-related dependencies
#[derive(Clone)]
pub struct AuthContext {
    pub auth_manager: Arc<AuthManager>,
    pub clients: Clients,
}

/// Notification-related dependencies (APNs)
#[derive(Clone)]
pub struct NotificationContext {
    pub apns_client: Arc<ApnsClient>,
    pub token_encryption: Arc<DeviceTokenEncryption>,
}

/// Federation-related dependencies
#[derive(Clone)]
pub struct FederationContext {
    pub server_signer: Option<Arc<ServerSigner>>,
    pub public_key_cache: Arc<PublicKeyCache>,
}

/// Gateway-related dependencies
#[derive(Clone)]
pub struct GatewayContext {
    pub gateway_client: Option<Arc<Mutex<MessageGatewayClient>>>,
}

/// Delivery-related dependencies
#[derive(Clone)]
pub struct DeliveryContext {
    pub delivery_ack_manager: Option<Arc<DeliveryAckManager<PostgresDeliveryStorage>>>,
}

/// Configuration and instance metadata
#[derive(Clone)]
pub struct ConfigContext {
    pub config: Arc<Config>,
    pub server_instance_id: String,
}
