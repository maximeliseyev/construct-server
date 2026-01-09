use anyhow::Result;
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, Histogram, IntCounter, TextEncoder, opts, register_histogram, register_int_counter,
};

pub static CONNECTIONS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "construct_connections_total",
        "Total number of client connections"
    ))
    .unwrap()
});

pub static MESSAGES_SENT_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "construct_messages_sent_total",
        "Total number of messages sent"
    ))
    .unwrap()
});

#[allow(dead_code)]
pub static MESSAGE_DELIVERY_TIME: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "construct_message_delivery_time_seconds",
        "Histogram of message delivery times"
    )
    .unwrap()
});

// ============================================================================
// Phase 4: Shadow-Read Metrics (Kafka vs Redis Comparison)
// ============================================================================

/// Messages that matched between Kafka and Redis
pub static SHADOW_READ_MATCHES: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "shadow_read_matches_total",
        "Messages that matched between Kafka and Redis offline queue"
    ))
    .unwrap()
});

/// Messages that differed between Kafka and Redis
pub static SHADOW_READ_DISCREPANCIES: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "shadow_read_discrepancies_total",
        "Messages that differed between Kafka and Redis offline queue"
    ))
    .unwrap()
});

/// Messages found in Kafka but not in Redis
pub static SHADOW_READ_KAFKA_ONLY: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "shadow_read_kafka_only_total",
        "Messages present in Kafka but not in Redis offline queue"
    ))
    .unwrap()
});

/// Messages found in Redis but not in Kafka (reverse-check)
pub static SHADOW_READ_REDIS_ONLY: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "shadow_read_redis_only_total",
        "Messages present in Redis offline queue but not seen in Kafka"
    ))
    .unwrap()
});

/// Total messages processed in shadow-read mode
pub static SHADOW_READ_PROCESSED: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "shadow_read_processed_total",
        "Total messages processed in shadow-read mode"
    ))
    .unwrap()
});

pub fn gather_metrics() -> Result<String> {
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    encoder.encode(&metric_families, &mut buffer)?;

    Ok(String::from_utf8(buffer)?)
}
