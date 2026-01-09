use crate::apns::{ApnsClient, DeviceTokenEncryption};
use crate::auth::AuthManager;
use crate::config::Config;
use crate::db::DbPool;
use crate::delivery_ack::{DeliveryAckManager, PostgresDeliveryStorage};
use crate::handlers::session::Clients;
use crate::kafka::MessageProducer;
use crate::message_gateway::MessageGatewayClient;
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
    /// APNs client for push notifications
    pub apns_client: Arc<ApnsClient>,
    /// Device token encryption for privacy
    pub token_encryption: Arc<DeviceTokenEncryption>,
    /// Unique identifier for this server instance (for delivery worker coordination)
    pub server_instance_id: String,
    /// Message Gateway client for delegating message processing (Phase 2+)
    /// When None: process messages locally (legacy mode)
    /// When Some: forward to Message Gateway service via gRPC
    pub gateway_client: Option<Arc<Mutex<MessageGatewayClient>>>,
    /// Delivery ACK manager for privacy-preserving message delivery confirmations
    /// When None: delivery ACK system is disabled
    /// When Some: track and route delivery acknowledgments
    pub delivery_ack_manager: Option<Arc<DeliveryAckManager<PostgresDeliveryStorage>>>,
}

impl AppContext {
    /// Creates a new application context
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db_pool: Arc<DbPool>,
        queue: Arc<Mutex<MessageQueue>>,
        auth_manager: Arc<AuthManager>,
        clients: Clients,
        config: Arc<Config>,
        kafka_producer: Arc<MessageProducer>,
        apns_client: Arc<ApnsClient>,
        token_encryption: Arc<DeviceTokenEncryption>,
        server_instance_id: String,
    ) -> Self {
        Self {
            db_pool,
            queue,
            auth_manager,
            clients,
            config,
            kafka_producer,
            apns_client,
            token_encryption,
            server_instance_id,
            gateway_client: None, // Legacy mode by default
            delivery_ack_manager: None, // Disabled by default
        }
    }

    /// Creates a new application context with Message Gateway client
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_gateway(
        db_pool: Arc<DbPool>,
        queue: Arc<Mutex<MessageQueue>>,
        auth_manager: Arc<AuthManager>,
        clients: Clients,
        config: Arc<Config>,
        kafka_producer: Arc<MessageProducer>,
        apns_client: Arc<ApnsClient>,
        token_encryption: Arc<DeviceTokenEncryption>,
        server_instance_id: String,
        gateway_client: Arc<Mutex<MessageGatewayClient>>,
    ) -> Self {
        Self {
            db_pool,
            queue,
            auth_manager,
            clients,
            config,
            kafka_producer,
            apns_client,
            token_encryption,
            server_instance_id,
            gateway_client: Some(gateway_client),
            delivery_ack_manager: None, // Disabled by default
        }
    }

    /// Set delivery ACK manager (builder pattern)
    pub fn with_delivery_ack_manager(
        mut self,
        manager: Arc<DeliveryAckManager<PostgresDeliveryStorage>>,
    ) -> Self {
        self.delivery_ack_manager = Some(manager);
        self
    }
}
