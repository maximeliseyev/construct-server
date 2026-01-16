// ============================================================================
// API Gateway Service - Phase 2.6.1
// ============================================================================
//
// API Gateway acts as a single entry point for all client requests.
// It handles:
// - JWT authentication verification
// - Rate limiting (IP-based, user-based)
// - CSRF protection
// - Request routing to appropriate microservices
// - Load balancing between service instances
//
// Architecture:
// - Stateless (can scale horizontally)
// - Routes requests to microservices based on path
// - Falls back to monolithic mode if microservices are disabled
//
// ============================================================================

use anyhow::{Context, Result};
use axum::{
    middleware,
    routing::any,
    Router,
};
use construct_server::auth::AuthManager;
use construct_server::config::Config;
use construct_server::gateway::middleware::{csrf_protection, jwt_verification, rate_limiting, GatewayMiddlewareState};
use construct_server::gateway::router::{route_request, GatewayRouter};
use construct_server::queue::MessageQueue;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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

    info!("=== API Gateway Service Starting ===");
    info!("Port: {}", config.port);
    info!("Microservices Enabled: {}", config.microservices.enabled);

    if !config.microservices.enabled {
        warn!("Microservices mode is DISABLED. Gateway will return 503 for all requests.");
        warn!("Set MICROSERVICES_ENABLED=true to enable microservices mode.");
    }

    // Initialize dependencies
    let auth_manager = Arc::new(AuthManager::new(&config)?);
    let queue = Arc::new(Mutex::new(MessageQueue::new(&config).await?));

    // Create gateway state
    let gateway_state = GatewayRouter::create_state(config.clone(), auth_manager.clone(), queue.clone());
    
    // Create middleware state (for middleware layers)
    let middleware_state = Arc::new(GatewayMiddlewareState {
        config: config.clone(),
        auth_manager: auth_manager.clone(),
        queue: queue.clone(),
    });

    // Create router
    let app = Router::new()
        // Health check endpoints (bypass gateway and middleware)
        .route("/health", axum::routing::get(health_check))
        .route("/health/ready", axum::routing::get(health_check))
        .route("/health/live", axum::routing::get(health_check))
        // Route all /api/v1/* requests through gateway with middleware
        .route("/api/v1/*", any(route_request))
        // Apply middleware (order matters - last added runs first)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(middleware::from_fn_with_state(
                    middleware_state.clone(),
                    csrf_protection,
                ))
                .layer(middleware::from_fn_with_state(
                    middleware_state.clone(),
                    rate_limiting,
                ))
                .layer(middleware::from_fn_with_state(
                    middleware_state,
                    jwt_verification,
                ))
                .into_inner(),
        )
        .with_state(gateway_state);

    // Start server
    let addr: SocketAddr = format!("0.0.0.0:{}", config.port)
        .parse()
        .context("Failed to parse bind address")?;

    info!("API Gateway listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context("Failed to bind to address")?;

    axum::serve(listener, app)
        .await
        .context("Failed to start server")?;

    Ok(())
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "ok"
}
