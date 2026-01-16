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
    routing::{get, post},
    http::StatusCode,
    response::IntoResponse,
    Json, Router,
};
use construct_server::auth::AuthManager;
use construct_server::config::Config;
use construct_server::db::DbPool;
use construct_server::kafka::MessageProducer;
use construct_server::messaging_service::MessagingServiceContext;
use construct_server::queue::MessageQueue;
use serde_json::json;
use std::net::SocketAddr;
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

    // Initialize Redis
    info!("Connecting to Redis...");
    let queue = Arc::new(
        Mutex::new(
            MessageQueue::new(&config)
                .await
                .context("Failed to create message queue")?,
        ),
    );
    info!("Connected to Redis");

    // Initialize Kafka Producer
    info!("Connecting to Kafka...");
    let kafka_producer = Arc::new(
        MessageProducer::new(&config.kafka)
            .context("Failed to create Kafka producer")?,
    );
    info!("Connected to Kafka");

    // Initialize Auth Manager
    let auth_manager = Arc::new(
        AuthManager::new(&config)
            .context("Failed to initialize auth manager")?,
    );

    // Create service context
    let context = Arc::new(MessagingServiceContext {
        db_pool,
        queue,
        auth_manager,
        kafka_producer,
        config: config.clone(),
    });

    // Import messaging service handlers
    use construct_server::messaging_service::handlers;

    // Create router
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        .route("/health/ready", get(health_check))
        .route("/health/live", get(health_check))
        // Messaging endpoints
        .route("/api/v1/messages", post(handlers::send_message))
        .route("/api/v1/messages", get(handlers::get_messages))
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
    let addr: SocketAddr = format!("0.0.0.0:{}", config.port)
        .parse()
        .context("Failed to parse bind address")?;

    info!("Messaging Service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context("Failed to bind to address")?;

    axum::serve(listener, app)
        .await
        .context("Failed to start server")?;

    Ok(())
}
