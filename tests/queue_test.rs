use construct_server::config::Config;
use construct_server::queue::MessageQueue;
use redis::Commands;
use serial_test::serial;
use std::env;
use uuid::Uuid;

async fn setup_queue() -> (MessageQueue, redis::Connection) {
    // Manually construct a config for testing
    // This avoids needing a full .env file for this specific test
    let mut config = Config {
        database_url: "".to_string(), // Not needed for this test
        redis_url: env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
        // SECURITY: Use a strong test secret that passes entropy validation
        // This must be at least 32 chars with good entropy (not all same char, no simple patterns, >= 8 unique chars)
        jwt_secret: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0".to_string(),
        port: 8080,
        health_port: 8081,
        heartbeat_interval_secs: 60 as i64,
        server_registry_ttl_secs: 120 as i64,
        message_ttl_days: 7,
        session_ttl_days: 30,
        refresh_token_ttl_days: 90,
        jwt_issuer: "construct-test".to_string(),
        online_channel: "test-online-channel".to_string(),
        offline_queue_prefix: "test_queue:".to_string(),
        delivery_queue_prefix: "test_delivery_queue:".to_string(),
        delivery_poll_interval_ms: 1000,
        rust_log: "info".to_string(),
        // These nested configs are not used by MessageQueue but are required by the Config struct
        logging: construct_server::config::LoggingConfig {
            enable_message_metadata: false,
            enable_user_identifiers: false,
            hash_salt: "test-salt-that-is-super-secret".to_string(),
        },
        security: construct_server::config::SecurityConfig {
            prekey_ttl_days: 30,
            prekey_min_ttl_days: 7,
            prekey_max_ttl_days: 90,
            max_messages_per_hour: 1000,
            max_key_rotations_per_day: 10,
            max_password_changes_per_day: 5,
            max_failed_login_attempts: 5,
            max_connections_per_user: 5,
            key_bundle_cache_hours: 1,
            rate_limit_block_duration_seconds: 3600,
        },
        kafka: construct_server::config::KafkaConfig {
            enabled: false,
            brokers: "".to_string(),
            topic: "".to_string(),
            consumer_group: "".to_string(),
            ssl_enabled: false,
            sasl_mechanism: None,
            sasl_username: None,
            sasl_password: None,
            producer_compression: "none".to_string(),
            producer_acks: "1".to_string(),
            producer_linger_ms: 0,
            producer_batch_size: 0,
            producer_max_in_flight: 0,
            producer_retries: 0,
            producer_request_timeout_ms: 0,
            producer_delivery_timeout_ms: 0,
            producer_enable_idempotence: false,
        },
        apns: construct_server::config::ApnsConfig {
            enabled: false,
            environment: construct_server::config::ApnsEnvironment::Development,
            key_path: "".to_string(),
            key_id: "".to_string(),
            team_id: "".to_string(),
            bundle_id: "".to_string(),
            topic: "".to_string(),
            device_token_encryption_key:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        },
        federation: construct_server::config::FederationConfig {
            enabled: false,
            instance_domain: "test.local".to_string(),
            base_domain: "test.local".to_string(),
            signing_key_seed: None,
        },
        db: construct_server::config::DbConfig {
            max_connections: 10,
            acquire_timeout_secs: 30,
            idle_timeout_secs: 600,
        },
        deeplinks: construct_server::config::DeepLinksConfig {
            apple_team_id: "".to_string(),
            android_package_name: "".to_string(),
            android_cert_fingerprint: "".to_string(),
        },
        worker: construct_server::config::WorkerConfig {
            shadow_read_enabled: false,
        },
        redis_key_prefixes: construct_server::config::RedisKeyPrefixes {
            processed_msg: "processed_msg:".to_string(),
            user: "user:".to_string(),
            session: "session:".to_string(),
            user_sessions: "user_sessions:".to_string(),
            msg_hash: "msg_hash:".to_string(),
            rate: "rate:".to_string(),
            blocked: "blocked:".to_string(),
            key_bundle: "key_bundle:".to_string(),
            connections: "connections:".to_string(),
        },
        redis_channels: construct_server::config::RedisChannels {
            dead_letter_queue: "dead_letter_queue".to_string(),
            delivery_message: "delivery_message:{}".to_string(),
            delivery_notification: "delivery_notification:{}".to_string(),
        },
        // Legacy aliases
        instance_domain: "test.local".to_string(),
        federation_base_domain: "test.local".to_string(),
        federation_enabled: false,
        deep_link_base_url: "".to_string(),
    };

    // Allow overriding redis_url from environment for CI/different setups
    if let Ok(redis_url) = env::var("REDIS_URL") {
        config.redis_url = redis_url;
    }

    let message_queue = MessageQueue::new(&config)
        .await
        .expect("Failed to create MessageQueue");

    let redis_client =
        redis::Client::open(config.redis_url.as_str()).expect("Failed to create Redis client");
    let redis_conn = redis_client
        .get_connection()
        .expect("Failed to get Redis connection");

    (message_queue, redis_conn)
}

#[tokio::test]
#[serial]
async fn test_register_server_instance_logic() {
    let (mut message_queue, mut redis_conn) = setup_queue().await;
    let queue_key = format!("test-delivery-queue:{}", Uuid::new_v4());

    // 1. Test creation of a new, non-existent key
    message_queue
        .register_server_instance(&queue_key, 60 as i64)
        .await
        .expect("register_server_instance failed on creation");

    let key_type: String = redis_conn
        .key_type(&queue_key)
        .expect("Redis TYPE command failed");
    assert_eq!(key_type, "list", "The key should be created as a list");

    let llen: i64 = redis_conn
        .llen(&queue_key)
        .expect("Redis LLEN command failed");
    assert_eq!(llen, 1, "The list should contain one placeholder element");

    let ttl: i64 = redis_conn
        .ttl(&queue_key)
        .expect("Redis TTL command failed");
    assert!(
        ttl > 0 && ttl <= 60,
        "The key should have a TTL set within the expected range"
    );

    // 2. Test correction of a key with the wrong type
    let _: () = redis_conn
        .set(&queue_key, "this is not a list")
        .expect("Redis SET command failed");

    let key_type_before: String = redis_conn
        .key_type(&queue_key)
        .expect("Redis TYPE command failed");
    assert_eq!(
        key_type_before, "string",
        "The key should be a string before correction"
    );

    message_queue
        .register_server_instance(&queue_key, 60 as i64)
        .await
        .expect("register_server_instance failed on correction");

    let key_type_after: String = redis_conn
        .key_type(&queue_key)
        .expect("Redis TYPE command failed");
    assert_eq!(
        key_type_after, "list",
        "The key should be corrected to a list"
    );

    // 3. Clean up the key from Redis
    let _: () = redis_conn
        .del(&queue_key)
        .expect("Redis DEL command failed");
}
