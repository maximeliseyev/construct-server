// ============================================================================
// Notification Service - Phase 2.6.5
// ============================================================================
//
// Notification service for microservices architecture.
// Handles:
// - Device token registration (POST /api/v1/notifications/register-device)
// - Device token unregistration (POST /api/v1/notifications/unregister-device)
// - Notification preferences (PUT /api/v1/notifications/preferences)
// - Push notifications (APNs for iOS, FCM for Android - future)
//
// Architecture:
// - Stateless sending
// - Can scale independently
// - Rate limiting for APNs/FCM
//
// ============================================================================

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, put},
};
use construct_server::apns::{ApnsClient, DeviceTokenEncryption};
use construct_server::auth::AuthManager;
use construct_server::config::Config;
use construct_server::db::DbPool;
use construct_server::notification_service::NotificationServiceContext;
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

    info!("=== Notification Service Starting ===");
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
    sqlx::migrate!().run(&*db_pool).await
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

    // Initialize APNs Client
    info!("Initializing APNs client...");
    let apns_client =
        Arc::new(ApnsClient::new(config.apns.clone()).context("Failed to initialize APNs client")?);
    info!("APNs client initialized");

    // Initialize Device Token Encryption
    let token_encryption = Arc::new(
        DeviceTokenEncryption::from_hex(&config.apns.device_token_encryption_key)
            .context("Failed to initialize device token encryption")?,
    );

    // Initialize Auth Manager
    let auth_manager =
        Arc::new(AuthManager::new(&config).context("Failed to initialize auth manager")?);

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
    let context = Arc::new(NotificationServiceContext {
        db_pool,
        queue,
        auth_manager,
        apns_client,
        token_encryption,
        config: config.clone(),
        key_management,
    });

    // Import notification service handlers
    use construct_server::notification_service::handlers;

    // Create router
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        .route("/health/ready", get(health_check))
        .route("/health/live", get(health_check))
        // Notification endpoints
        .route(
            "/api/v1/notifications/register-device",
            post(handlers::register_device),
        )
        .route(
            "/api/v1/notifications/unregister-device",
            post(handlers::unregister_device),
        )
        .route(
            "/api/v1/notifications/preferences",
            put(handlers::update_preferences),
        )
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

    info!("Notification Service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context("Failed to bind to address")?;

    axum::serve(listener, app)
        .await
        .context("Failed to start server")?;

    Ok(())
}
