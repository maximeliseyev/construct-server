// ============================================================================
// Message Router
// ============================================================================
//
// Routes messages to their destination:
// - Currently: all messages go to local Kafka
// - Future: local vs remote node routing for federation
//
// This is the foundation for federation - when we add S2S support,
// this module will parse recipient domains and route accordingly.
// ============================================================================

use crate::kafka::MessageProducer;
use crate::message::ChatMessage;
use anyhow::Result;

pub struct MessageRouter {
    kafka_producer: MessageProducer,
    // Future: federation_client: FederationClient,
    // Future: local_domain: String,
}

impl MessageRouter {
    /// Create a new message router
    pub fn new(kafka_producer: MessageProducer) -> Self {
        Self { kafka_producer }
    }

    /// Route message to destination
    ///
    /// Currently: all messages go to local Kafka
    /// Future: parse recipient, check if local or remote domain
    pub async fn route_message(&self, msg: &ChatMessage) -> Result<()> {
        // Phase 1: Local-only routing
        // Everything goes to Kafka for local delivery

        // Create Kafka envelope
        let envelope = crate::kafka::KafkaMessageEnvelope::from(msg);

        // Send to Kafka
        self.kafka_producer.send_message(&envelope).await?;

        tracing::debug!(
            message_id = %msg.id,
            recipient = %msg.to,
            "Message routed to local Kafka"
        );

        Ok(())
    }

    // Future: Federation routing
    // pub async fn route_message_federated(&self, msg: &ChatMessage) -> Result<()> {
    //     let recipient = UserId::parse(&msg.to)?;
    //
    //     if recipient.is_local(&self.local_domain) {
    //         // Local delivery via Kafka
    //         self.route_to_local_kafka(msg).await?;
    //     } else {
    //         // Remote delivery via Federation Client
    //         self.federation_client.send_to_node(&recipient.domain, msg).await?;
    //
    //         // Track communication pattern for smart replication
    //         self.track_communication_pattern(&msg.from, &recipient.domain).await?;
    //     }
    //
    //     Ok(())
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KafkaConfig;

    #[tokio::test]
    async fn test_router_creation() {
        let kafka_config = KafkaConfig {
            enabled: false,
            brokers: "localhost:9092".to_string(),
            topic: "test-topic".to_string(),
            consumer_group: "test-group".to_string(),
            ssl_enabled: false,
            sasl_mechanism: None,
            sasl_username: None,
            sasl_password: None,
            producer_compression: "snappy".to_string(),
            producer_acks: "all".to_string(),
            producer_linger_ms: 10,
            producer_batch_size: 16384,
            producer_max_in_flight: 5,
            producer_retries: 2147483647,
            producer_request_timeout_ms: 30000,
            producer_delivery_timeout_ms: 120000,
            producer_enable_idempotence: true,
        };

        let producer = MessageProducer::new(&kafka_config).unwrap();
        let router = MessageRouter::new(producer);

        // Router should be created successfully
        assert!(std::mem::size_of_val(&router) > 0);
    }
}
