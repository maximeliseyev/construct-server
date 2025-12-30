use anyhow::{Context, Result};
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord, Producer};
use rdkafka::util::Timeout;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

use super::metrics;
use super::types::KafkaMessageEnvelope;

/// Kafka message producer for reliable message delivery
///
/// This producer is configured for:
/// - At-least-once delivery guarantees
/// - Idempotent writes (no duplicates within producer session)
/// - Compression (zstd for encrypted payloads)
/// - Low latency (10ms linger)
pub struct MessageProducer {
    producer: Arc<FutureProducer>,
    topic: String,
    enabled: bool,
}

impl MessageProducer {
    /// Create a new Kafka producer
    ///
    /// # Arguments
    /// * `brokers` - Comma-separated list of Kafka brokers (e.g., "kafka1:9092,kafka2:9092")
    /// * `topic` - Kafka topic name (e.g., "construct-messages")
    /// * `enabled` - Whether Kafka is enabled (false = no-op producer for testing)
    ///
    /// # Configuration
    /// - `acks=all`: Wait for all in-sync replicas to acknowledge
    /// - `enable.idempotence=true`: Prevent duplicate writes
    /// - `retries=2147483647`: Retry indefinitely on transient errors
    /// - `compression.type=zstd`: Best compression for encrypted data
    /// - `linger.ms=10`: Small batching window for low latency
    pub fn new(brokers: &str, topic: String, enabled: bool) -> Result<Self> {
        if !enabled {
            info!("Kafka producer disabled (KAFKA_ENABLED=false)");
            // Create a dummy producer (won't be used)
            let producer = ClientConfig::new()
                .set("bootstrap.servers", "localhost:9092")
                .create()
                .context("Failed to create disabled Kafka producer")?;

            return Ok(Self {
                producer: Arc::new(producer),
                topic,
                enabled: false,
            });
        }

        info!("Initializing Kafka producer");
        info!("Brokers: {}", brokers);
        info!("Topic: {}", topic);

        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            // Reliability settings
            .set("acks", "all") // Wait for all in-sync replicas
            .set("enable.idempotence", "true") // Exactly-once semantics within producer
            .set("max.in.flight.requests.per.connection", "5")
            .set("retries", "2147483647") // Retry indefinitely (i32::MAX)
            // Performance settings
            .set("compression.type", "zstd") // Best compression for encrypted data
            .set("linger.ms", "10") // Small batch window for low latency
            .set("batch.size", "16384") // 16KB batches
            // Timeout settings
            .set("request.timeout.ms", "30000") // 30s request timeout
            .set("delivery.timeout.ms", "120000") // 2min overall delivery timeout
            .create()
            .context("Failed to create Kafka producer")?;

        info!("Kafka producer initialized successfully");

        Ok(Self {
            producer: Arc::new(producer),
            topic,
            enabled: true,
        })
    }

    /// Send a message to Kafka
    ///
    /// This is a blocking async operation that waits for Kafka acknowledgment.
    /// In Phase 1 (dual-write), failures are logged but don't fail the request.
    /// In Phase 6 (cutover), failures should fail the request.
    ///
    /// # Arguments
    /// * `envelope` - Message envelope to send
    ///
    /// # Returns
    /// * `Ok((partition, offset))` - Successfully written to Kafka
    /// * `Err(anyhow::Error)` - Failed to write (should be logged/alerted)
    pub async fn send_message(
        &self,
        envelope: &KafkaMessageEnvelope,
    ) -> Result<(i32, i64)> {
        // Skip if Kafka disabled (Phase 1 testing)
        if !self.enabled {
            return Ok((-1, -1)); // Dummy partition/offset
        }

        // Validate envelope before sending
        envelope.validate().context("Invalid message envelope")?;

        // Serialize to JSON
        let payload = serde_json::to_vec(envelope)
            .context("Failed to serialize message envelope")?;

        // Partition key: recipient_id (ensures ordering per user/group)
        let key = envelope.recipient_id.as_bytes();

        // Create Kafka record
        let record = FutureRecord::to(&self.topic)
            .key(key)
            .payload(&payload);

        // Send with timeout (2 seconds for async feedback)
        let start = std::time::Instant::now();

        match self.producer.send(record, Timeout::After(Duration::from_secs(2))).await {
            Ok((partition, offset)) => {
                let latency = start.elapsed();

                // Update metrics
                metrics::KAFKA_PRODUCE_SUCCESS.inc();
                metrics::KAFKA_PRODUCE_LATENCY.observe(latency.as_secs_f64());

                info!(
                    partition = partition,
                    offset = offset,
                    message_id = %envelope.message_id,
                    latency_ms = latency.as_millis(),
                    "Message persisted to Kafka"
                );

                Ok((partition, offset))
            }
            Err((kafka_err, _)) => {
                let latency = start.elapsed();

                // Update metrics
                metrics::KAFKA_PRODUCE_FAILURE.inc();

                error!(
                    error = %kafka_err,
                    message_id = %envelope.message_id,
                    topic = %self.topic,
                    latency_ms = latency.as_millis(),
                    "Failed to send message to Kafka"
                );

                Err(anyhow::anyhow!("Kafka send failed: {}", kafka_err))
            }
        }
    }

    /// Check if Kafka is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get topic name
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// Flush pending messages (for graceful shutdown)
    ///
    /// This waits for all in-flight messages to be acknowledged.
    /// Should be called before application shutdown.
    pub async fn flush(&self, timeout: Duration) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        info!("Flushing Kafka producer (timeout: {:?})", timeout);

        self.producer.flush(Timeout::After(timeout))
            .context("Failed to flush Kafka producer")?;

        info!("Kafka producer flushed successfully");
        Ok(())
    }
}

// Implement Clone manually to avoid cloning the producer (Arc handles it)
impl Clone for MessageProducer {
    fn clone(&self) -> Self {
        Self {
            producer: Arc::clone(&self.producer),
            topic: self.topic.clone(),
            enabled: self.enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_producer_creation() {
        let producer = MessageProducer::new(
            "localhost:9092",
            "test-topic".to_string(),
            false, // disabled
        );

        assert!(producer.is_ok());
        assert!(!producer.unwrap().is_enabled());
    }

    #[tokio::test]
    async fn test_disabled_producer_send() {
        let producer = MessageProducer::new(
            "localhost:9092",
            "test-topic".to_string(),
            false,
        ).unwrap();

        let envelope = KafkaMessageEnvelope::new_direct_message(
            "msg-123".to_string(),
            "user-456".to_string(),
            "user-789".to_string(),
            vec![0u8; 32],
            42,
            "encrypted".to_string(),
            "hash123".to_string(),
        );

        // Should succeed with dummy values
        let result = producer.send_message(&envelope).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (-1, -1));
    }
}
