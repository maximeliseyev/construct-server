// ============================================================================
// Messaging Service - Phase 2.6.4
// ============================================================================
//
// Messaging service for microservices architecture.
// Handles:
// - Sending messages (POST /api/v1/messages)
// - Getting messages (GET /api/v1/messages?since=<id>)
// - Long polling for new messages
// - Replay protection
// - Message validation
//
// Architecture:
// - Stateless processing
// - Kafka for message queue (source of truth)
// - Redis for replay protection, rate limiting, long polling
//
// ============================================================================

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use construct_config::Config;
use construct_server_shared::auth::AuthManager;
use construct_server_shared::db::DbPool;
use construct_server_shared::kafka::MessageProducer;
use construct_server_shared::apns::DeviceTokenEncryption;
use construct_server_shared::messaging_service::MessagingServiceContext;
use construct_server_shared::queue::MessageQueue;
use serde_json::json;

use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status": "ok"})))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config = Config::from_env()?;
    let config = Arc::new(config);

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(config.rust_log.clone()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("=== Messaging Service Starting ===");
    info!("Port: {}", config.port);

    // Initialize database
    info!("Connecting to database...");
    let db_pool = Arc::new(
        DbPool::connect(&config.database_url)
            .await
            .context("Failed to connect to database")?,
    );
    info!("Connected to database");

    // Apply database migrations
    info!("Applying database migrations...");
    sqlx::migrate!("../shared/migrations")
        .run(&*db_pool)
        .await
        .context("Failed to apply database migrations")?;
    info!("Database migrations applied successfully");

    // Initialize Redis
    info!("Connecting to Redis...");
    let queue = Arc::new(Mutex::new(
        MessageQueue::new(&config)
            .await
            .context("Failed to create message queue")?,
    ));
    info!("Connected to Redis");

    // Initialize Kafka Producer
    info!("Connecting to Kafka...");
    let kafka_producer =
        Arc::new(MessageProducer::new(&config.kafka).context("Failed to create Kafka producer")?);
    info!("Connected to Kafka");

    // Initialize Auth Manager
    let auth_manager =
        Arc::new(AuthManager::new(&config).context("Failed to initialize auth manager")?);

    // ✅ NEW: Initialize APNs Client for push notifications
    info!("Initializing APNs client...");
    let apns_client = Arc::new(
        construct_server_shared::apns::ApnsClient::new(config.apns.clone())
            .context("Failed to initialize APNs client")?,
    );
    let token_encryption = Arc::new(
        DeviceTokenEncryption::from_hex(&config.apns.device_token_encryption_key)
            .context("Failed to initialize device token encryption")?,
    );
    if config.apns.enabled {
        info!("APNs client initialized and ENABLED");
    } else {
        info!("APNs client initialized but DISABLED (APNS_ENABLED=false)");
    }

    // Initialize Key Management System (optional, requires VAULT_ADDR)
    let key_management =
        match construct_server_shared::key_management::KeyManagementConfig::from_env() {
            Ok(kms_config) => {
                info!("Initializing Key Management System...");
                match construct_server_shared::key_management::KeyManagementSystem::new(
                    db_pool.clone(),
                    kms_config,
                )
                .await
                {
                    Ok(kms) => {
                        // Start background tasks (key refresh, rotation)
                        if let Err(e) = kms.start().await {
                            tracing::error!(error = %e, "Failed to start key management background tasks");
                            return Err(e).context("Failed to start key management system");
                        }
                        info!("Key Management System initialized and started");
                        Some(Arc::new(kms))
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "Failed to initialize Key Management System - continuing without automatic key rotation"
                        );
                        None
                    }
                }
            }
            Err(e) => {
                tracing::info!(
                    error = %e,
                    "Key Management System disabled (VAULT_ADDR not configured or invalid config)"
                );
                None
            }
        };

    // Create service context
    let context = Arc::new(MessagingServiceContext {
        db_pool,
        queue,
        auth_manager,
        kafka_producer,
        apns_client,
        token_encryption,
        config: config.clone(),
        key_management,
    });

    // Import messaging service handlers
    use construct_server_shared::messaging_service::handlers;

    // Import media routes
    use construct_server_shared::routes::media;

    // Create router
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        .route("/health/ready", get(health_check))
        .route("/health/live", get(health_check))
        // Messaging endpoints
        .route("/api/v1/messages", post(handlers::send_message))
        .route("/api/v1/messages", get(handlers::get_messages))
        // Phase 4.5: Control messages endpoint
        .route("/api/v1/control", post(handlers::send_control_message))
        // Media upload token endpoint
        .route("/api/v1/media/token", post(media::generate_media_token))
        // Legacy endpoints (for backward compatibility)
        .route("/messages/send", post(handlers::send_message))
        // Apply middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .with_state(context);

    // Start server
    info!("Messaging Service listening on {}", config.bind_address);

    let listener = tokio::net::TcpListener::bind(&config.bind_address)
        .await
        .context("Failed to bind to address")?;

    axum::serve(listener, app)
        .await
        .context("Failed to start server")?;

    Ok(())
}
