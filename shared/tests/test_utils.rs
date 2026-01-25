// ============================================================================
// Test Utilities for Microservices
// ============================================================================
//
// Provides test infrastructure for REST API integration tests.
// Spawns individual microservices (auth, user, messaging, notification)
// with isolated test databases.
//
// ============================================================================

use axum::Router;
use axum::routing::{delete, get, post, put};
use construct_server_shared::{
    apns::{ApnsClient, DeviceTokenEncryption},
    auth::AuthManager,
    auth_service::{AuthServiceContext, handlers as auth_handlers},
    config::Config,
    db::DbPool,
    kafka::MessageProducer,
    messaging_service::{MessagingServiceContext, handlers as messaging_handlers},
    notification_service::{NotificationServiceContext, handlers as notification_handlers},
    queue::MessageQueue,
    user_service::{UserServiceContext, handlers as user_handlers},
};
use sqlx::{Connection, Executor, PgConnection, PgPool};
use std::sync::Arc;
use tokio::{net::TcpListener, sync::Mutex};
use uuid::Uuid;

/// Test application with all microservices
pub struct TestApp {
    /// Legacy: points to auth service for backward compatibility
    pub address: String,
    pub auth_address: String,
    pub user_address: String,
    pub messaging_address: String,
    pub notification_address: String,
    pub db_pool: PgPool,
    pub config: Arc<Config>,
}

/// Single service test app (for focused tests)
pub struct SingleServiceApp {
    pub address: String,
    pub db_pool: PgPool,
    pub config: Arc<Config>,
}

/// Create test config from .env.test
async fn create_test_config(db_name: &str) -> Config {
    // Load .env.test with override - this replaces any existing env vars
    // Try multiple paths since tests may run from different directories
    let _ = dotenvy::from_filename_override(".env.test")
        .or_else(|_| dotenvy::from_filename_override("../.env.test"))
        .or_else(|_| dotenvy::from_filename_override("../../.env.test"));

    // Read JWT keys directly from files - try multiple paths for workspace compatibility
    let private_key = try_read_key_file(&["prkeys/jwt_private_key.pem", "../prkeys/jwt_private_key.pem"])
        .expect("Failed to read JWT private key file");
    let public_key = try_read_key_file(&["prkeys/jwt_public_key.pem", "../prkeys/jwt_public_key.pem"])
        .expect("Failed to read JWT public key file");

    // Set env vars before Config::from_env() reads them
    // SAFETY: Tests run single-threaded (--test-threads=1) so this is safe
    unsafe {
        std::env::set_var("JWT_PRIVATE_KEY", &private_key);
        std::env::set_var("JWT_PUBLIC_KEY", &public_key);
    }

    let mut config = Config::from_env().expect("Failed to read base config from .env.test");

    // Override database for test isolation (unique DB per test)
    config.database_url = format!(
        "postgres://construct:construct_dev_password@localhost:5432/{}",
        db_name
    );

    config
}

/// Try to read a key file from multiple possible paths
fn try_read_key_file(paths: &[&str]) -> Result<String, std::io::Error> {
    for path in paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            return Ok(content);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("Key file not found in any of: {:?}", paths),
    ))
}

/// Create test database
async fn setup_test_database(db_name: &str) -> PgPool {
    let mut connection = PgConnection::connect(
        "postgres://construct:construct_dev_password@localhost:5432/postgres",
    )
    .await
    .expect("Failed to connect to Postgres");

    // Drop if exists and create fresh
    let _ = connection
        .execute(format!(r#"DROP DATABASE IF EXISTS "{}";"#, db_name).as_str())
        .await;

    connection
        .execute(format!(r#"CREATE DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to create database");

    let db_url = format!(
        "postgres://construct:construct_dev_password@localhost:5432/{}",
        db_name
    );

    let db_pool = PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to test database");

    sqlx::migrate!("./migrations")
        .run(&db_pool)
        .await
        .expect("Failed to run migrations");

    db_pool
}

/// Cleanup rate limiting keys from Redis
pub async fn cleanup_rate_limits(redis_url: &str) {
    use redis::AsyncCommands;

    let client = redis::Client::open(redis_url).ok();
    if let Some(client) = client {
        if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
            let patterns = vec![
                "rate:*",
                "rate:login:*",
                "rate:register:*",
                "rate:combined:*",
            ];

            for pattern in patterns {
                let keys: Vec<String> = conn.keys(pattern).await.unwrap_or_default();
                if !keys.is_empty() {
                    let _: Result<(), _> = conn.del(&keys).await;
                }
            }
        }
    }
}

/// Spawn auth service
async fn spawn_auth_service(config: Arc<Config>, db_pool: Arc<PgPool>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let address = format!("127.0.0.1:{}", port);

    let queue = Arc::new(Mutex::new(
        MessageQueue::new(&config)
            .await
            .expect("Failed to create queue"),
    ));
    let auth_manager = Arc::new(AuthManager::new(&config).expect("Failed to create auth manager"));

    let context = Arc::new(AuthServiceContext {
        db_pool,
        queue,
        auth_manager,
        config: config.clone(),
        key_management: None,
    });

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/api/v1/auth/register", post(auth_handlers::register))
        .route("/api/v1/auth/login", post(auth_handlers::login))
        .route("/api/v1/auth/refresh", post(auth_handlers::refresh_token))
        .route("/api/v1/auth/logout", post(auth_handlers::logout))
        .with_state(context);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    address
}

/// Spawn user service
async fn spawn_user_service(config: Arc<Config>, db_pool: Arc<PgPool>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let address = format!("127.0.0.1:{}", port);

    let queue = Arc::new(Mutex::new(
        MessageQueue::new(&config)
            .await
            .expect("Failed to create queue"),
    ));
    let auth_manager = Arc::new(AuthManager::new(&config).expect("Failed to create auth manager"));

    let context = Arc::new(UserServiceContext {
        db_pool,
        queue,
        auth_manager,
        config: config.clone(),
    });

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/api/v1/account", get(user_handlers::get_account))
        .route("/api/v1/account", put(user_handlers::update_account))
        .route("/api/v1/account", delete(user_handlers::delete_account))
        .route("/api/v1/keys/upload", post(user_handlers::upload_keys))
        .route(
            "/api/v1/users/:user_id/public-key",
            get(user_handlers::get_keys_v1),
        )
        .with_state(context);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    address
}

/// Spawn messaging service
async fn spawn_messaging_service(config: Arc<Config>, db_pool: Arc<PgPool>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let address = format!("127.0.0.1:{}", port);

    let queue = Arc::new(Mutex::new(
        MessageQueue::new(&config)
            .await
            .expect("Failed to create queue"),
    ));
    let auth_manager = Arc::new(AuthManager::new(&config).expect("Failed to create auth manager"));
    let kafka_producer =
        Arc::new(MessageProducer::new(&config.kafka).expect("Failed to create kafka producer"));
    let apns_client =
        Arc::new(ApnsClient::new(config.apns.clone()).expect("Failed to create APNs client"));

    let context = Arc::new(MessagingServiceContext {
        db_pool,
        queue,
        auth_manager,
        kafka_producer,
        apns_client,
        config: config.clone(),
        key_management: None,
    });

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/api/v1/messages", post(messaging_handlers::send_message))
        .route("/api/v1/messages", get(messaging_handlers::get_messages))
        .with_state(context);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    address
}

/// Spawn notification service
async fn spawn_notification_service(config: Arc<Config>, db_pool: Arc<PgPool>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let address = format!("127.0.0.1:{}", port);

    let queue = Arc::new(Mutex::new(
        MessageQueue::new(&config)
            .await
            .expect("Failed to create queue"),
    ));
    let auth_manager = Arc::new(AuthManager::new(&config).expect("Failed to create auth manager"));
    let apns_client =
        Arc::new(ApnsClient::new(config.apns.clone()).expect("Failed to create APNs client"));
    let token_encryption = Arc::new(
        DeviceTokenEncryption::from_hex(&config.apns.device_token_encryption_key)
            .expect("Failed to create token encryption"),
    );

    let context = Arc::new(NotificationServiceContext {
        db_pool,
        queue,
        auth_manager,
        apns_client,
        token_encryption,
        config: config.clone(),
        key_management: None,
    });

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/api/v1/notifications/register-device",
            post(notification_handlers::register_device),
        )
        .route(
            "/api/v1/notifications/unregister-device",
            post(notification_handlers::unregister_device),
        )
        .route(
            "/api/v1/notifications/preferences",
            put(notification_handlers::update_preferences),
        )
        .with_state(context);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    address
}

/// Spawn all microservices for full integration tests
pub async fn spawn_app() -> TestApp {
    let db_name = format!(
        "construct_test_{}",
        Uuid::new_v4().to_string().replace("-", "_")
    );
    let db_pool = setup_test_database(&db_name).await;
    let config = Arc::new(create_test_config(&db_name).await);
    let db_pool_arc = Arc::new(db_pool.clone());

    let auth_address = spawn_auth_service(config.clone(), db_pool_arc.clone()).await;
    let user_address = spawn_user_service(config.clone(), db_pool_arc.clone()).await;
    let messaging_address = spawn_messaging_service(config.clone(), db_pool_arc.clone()).await;
    let notification_address =
        spawn_notification_service(config.clone(), db_pool_arc.clone()).await;

    // Give services time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    TestApp {
        address: auth_address.clone(), // Legacy compatibility
        auth_address,
        user_address,
        messaging_address,
        notification_address,
        db_pool,
        config,
    }
}

/// Spawn only auth service (for auth-focused tests)
pub async fn spawn_auth_app() -> SingleServiceApp {
    let db_name = format!(
        "construct_test_{}",
        Uuid::new_v4().to_string().replace("-", "_")
    );
    let db_pool = setup_test_database(&db_name).await;
    let config = Arc::new(create_test_config(&db_name).await);
    let db_pool_arc = Arc::new(db_pool.clone());

    let address = spawn_auth_service(config.clone(), db_pool_arc).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    SingleServiceApp {
        address,
        db_pool,
        config,
    }
}

/// Spawn only user service (for user-focused tests)
pub async fn spawn_user_app() -> SingleServiceApp {
    let db_name = format!(
        "construct_test_{}",
        Uuid::new_v4().to_string().replace("-", "_")
    );
    let db_pool = setup_test_database(&db_name).await;
    let config = Arc::new(create_test_config(&db_name).await);
    let db_pool_arc = Arc::new(db_pool.clone());

    let address = spawn_user_service(config.clone(), db_pool_arc).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    SingleServiceApp {
        address,
        db_pool,
        config,
    }
}

impl TestApp {
    /// Get base URL for auth service
    pub fn auth_url(&self) -> String {
        format!("http://{}", self.auth_address)
    }

    /// Get base URL for user service
    pub fn user_url(&self) -> String {
        format!("http://{}", self.user_address)
    }

    /// Get base URL for messaging service
    pub fn messaging_url(&self) -> String {
        format!("http://{}", self.messaging_address)
    }

    /// Get base URL for notification service
    pub fn notification_url(&self) -> String {
        format!("http://{}", self.notification_address)
    }
}

impl SingleServiceApp {
    /// Get base URL
    pub fn url(&self) -> String {
        format!("http://{}", self.address)
    }
}
