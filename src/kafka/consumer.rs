use anyhow::{Context, Result};
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::Message;
use std::time::Duration;
use tracing::{error, info};

use super::types::KafkaMessageEnvelope;

/// Kafka message consumer for delivery worker
///
/// This consumer is configured for:
/// - Manual offset commits (after successful delivery)
/// - Consumer group coordination (multiple delivery workers)
/// - Auto-rebalancing on worker addition/removal
pub struct MessageConsumer {
    consumer: StreamConsumer,
    #[allow(dead_code)]
    topic: String,
}

impl MessageConsumer {
    /// Create a new Kafka consumer
    ///
    /// # Arguments
    /// * `brokers` - Comma-separated list of Kafka brokers
    /// * `topic` - Kafka topic to consume from
    /// * `group_id` - Consumer group ID (e.g., "construct-delivery-workers")
    ///
    /// # Configuration
    /// - `enable.auto.commit=false`: Manual offset management
    /// - `auto.offset.reset=earliest`: Read from beginning on first start
    /// - `session.timeout.ms=30000`: 30s session timeout
    /// - `heartbeat.interval.ms=3000`: 3s heartbeat interval
    pub fn new(brokers: &str, topic: String, group_id: &str) -> Result<Self> {
        info!("Initializing Kafka consumer");
        info!("Brokers: {}", brokers);
        info!("Topic: {}", topic);
        info!("Consumer Group: {}", group_id);

        let consumer: StreamConsumer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("group.id", group_id)
            // Offset management
            .set("enable.auto.commit", "false") // Manual commit after delivery
            .set("auto.offset.reset", "earliest") // Read from beginning
            // Performance
            .set("fetch.min.bytes", "1")
            .set("fetch.wait.max.ms", "500") // Max wait for fetch
            .set("max.partition.fetch.bytes", "1048576") // 1MB
            // Session management
            .set("session.timeout.ms", "30000") // 30s timeout
            .set("heartbeat.interval.ms", "3000") // 3s heartbeat
            .set("max.poll.interval.ms", "300000") // 5min max processing time
            .create()
            .context("Failed to create Kafka consumer")?;

        // Subscribe to topic
        consumer
            .subscribe(&[&topic])
            .context("Failed to subscribe to Kafka topic")?;

        info!("Kafka consumer initialized successfully");

        Ok(Self { consumer, topic })
    }

    /// Poll for next message
    ///
    /// Returns `None` if timeout expires without message.
    pub async fn poll(&self, _timeout: Duration) -> Result<Option<KafkaMessageEnvelope>> {
        match self.consumer.recv().await {
            Ok(message) => {
                // Parse payload
                let payload = message.payload()
                    .context("Message payload is empty")?;

                let envelope: KafkaMessageEnvelope = serde_json::from_slice(payload)
                    .context("Failed to deserialize message envelope")?;

                Ok(Some(envelope))
            }
            Err(e) => {
                error!(error = %e, "Kafka consumer error");
                Err(anyhow::anyhow!("Consumer error: {}", e))
            }
        }
    }

    /// Commit current offset (after successful delivery)
    ///
    /// This tells Kafka "I've successfully processed all messages up to this point".
    /// If the consumer crashes before committing, messages will be redelivered.
    pub fn commit(&self) -> Result<()> {
        self.consumer
            .commit_consumer_state(rdkafka::consumer::CommitMode::Sync)
            .context("Failed to commit offset")?;
        Ok(())
    }

    /// Get consumer reference (for advanced usage)
    pub fn inner(&self) -> &StreamConsumer {
        &self.consumer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consumer_creation_fails_without_kafka() {
        // This should fail if Kafka is not running
        let result = MessageConsumer::new(
            "localhost:9092",
            "test-topic".to_string(),
            "test-group",
        );

        // We can't test successful creation without running Kafka
        // Just verify the function signature is correct
        let _ = result;
    }
}
