// ============================================================================
// User Service - Phase 2.6.3
// ============================================================================
//
// User management service for microservices architecture.
// Handles:
// - User profiles management
// - Public keys (key bundles)
// - Account management (get, update, delete)
//
// Architecture:
// - Stateless
// - Horizontally scalable
// - Redis caching for key bundles
//
// ============================================================================

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use construct_server::auth::AuthManager;
use construct_server::config::Config;
use construct_server::db::DbPool;
use construct_server::queue::MessageQueue;
use construct_server::user_service::UserServiceContext;
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

    info!("=== User Service Starting ===");
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
    sqlx::migrate!()
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

    // Initialize Auth Manager
    let auth_manager =
        Arc::new(AuthManager::new(&config).context("Failed to initialize auth manager")?);

    // Create service context
    let context = Arc::new(UserServiceContext {
        db_pool,
        queue,
        auth_manager,
        config: config.clone(),
    });

    // Import user service handlers
    use construct_server::user_service::handlers;

    // Create router
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        .route("/health/ready", get(health_check))
        .route("/health/live", get(health_check))
        // Account management endpoints
        .route("/api/v1/account", get(handlers::get_account))
        .route("/api/v1/account", put(handlers::update_account))
        .route("/api/v1/account", delete(handlers::delete_account))
        // Keys management endpoints
        .route("/api/v1/users/:id/public-key", get(handlers::get_public_key_bundle))
        .route("/api/v1/keys/upload", post(handlers::upload_keys))
        // Legacy endpoints (for backward compatibility)
        .route("/keys/:user_id", get(handlers::get_keys_legacy))
        .route("/keys/upload", post(handlers::upload_keys)) // Legacy
        // Apply middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .with_state(context);

    // Start server
    let addr: SocketAddr = config
        .bind_address
        .parse()
        .context("Failed to parse bind address")?;

    info!("User Service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context("Failed to bind to address")?;

    axum::serve(listener, app)
        .await
        .context("Failed to start server")?;

    Ok(())
}
