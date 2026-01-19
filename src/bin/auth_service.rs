// ============================================================================
// Auth Service - Phase 2.6.2
// ============================================================================
//
// Authentication and authorization service for microservices architecture.
// Handles:
// - User registration
// - User login
// - JWT token management (access tokens, refresh tokens)
// - Token refresh
// - Logout (token invalidation)
// - Password management (future)
//
// Architecture:
// - Stateless (JWT tokens)
// - Horizontally scalable
// - No sticky sessions required
//
// ============================================================================

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use construct_server::auth_service::AuthServiceContext;
use construct_server::config::Config;
use construct_server::db::DbPool;
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

    info!("=== Auth Service Starting ===");
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
    let queue = Arc::new(Mutex::new(
        MessageQueue::new(&config)
            .await
            .context("Failed to create message queue")?,
    ));
    info!("Connected to Redis");

    // Initialize Auth Manager
    let auth_manager = Arc::new(
        construct_server::auth::AuthManager::new(&config)
            .context("Failed to initialize auth manager")?,
    );

    // Initialize Key Management System (optional, requires VAULT_ADDR)
    let key_management = match construct_server::key_management::KeyManagementConfig::from_env() {
        Ok(kms_config) => {
            info!("Initializing Key Management System...");
            match construct_server::key_management::KeyManagementSystem::new(
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
    let context = Arc::new(AuthServiceContext {
        db_pool,
        queue,
        auth_manager,
        config: config.clone(),
        key_management,
    });

    // Import auth service handlers
    use construct_server::auth_service::handlers;

    // Create router
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        .route("/health/ready", get(health_check))
        .route("/health/live", get(health_check))
        // Auth endpoints
        .route("/api/v1/auth/register", post(handlers::register))
        .route("/api/v1/auth/login", post(handlers::login))
        .route("/api/v1/auth/refresh", post(handlers::refresh_token))
        .route("/api/v1/auth/logout", post(handlers::logout))
        // Legacy endpoints (for backward compatibility)
        .route("/auth/refresh", post(handlers::refresh_token))
        .route("/auth/logout", post(handlers::logout))
        // Apply middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .with_state(context);

    // Start server
    let addr: SocketAddr = format!("[::]:{}", config.port)
        .parse()
        .context("Failed to parse bind address")?;

    info!("Auth Service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context("Failed to bind to address")?;

    axum::serve(listener, app)
        .await
        .context("Failed to start server")?;

    Ok(())
}
