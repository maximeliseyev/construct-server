// ============================================================================
// Axum Routes Module
// ============================================================================
//
// This module contains all HTTP routes migrated from the manual HTTP handler
// to Axum framework for better type safety, middleware support, and maintainability.
//
// Structure:
// - mod.rs: Main router assembly and middleware
// - health.rs: Health check and metrics endpoints
// - keys.rs: Key management endpoints
// - messages.rs: Message sending endpoints
// - federation.rs: Federation endpoints
// - csrf.rs: CSRF token generation and validation
// - extractors.rs: Custom Axum extractors (JWT, AppContext, etc.)
// - middleware.rs: Request logging, CSRF protection, security headers
//
// ============================================================================

mod auth;
mod csrf;
mod extractors;
mod federation;
mod health;
mod keys;
mod messages;
mod middleware;
mod request_signing;

use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

use crate::context::AppContext;

/// Create the main application router with all routes
pub fn create_router(app_context: Arc<AppContext>) -> Router {
    Router::new()
        // Health and monitoring (no CSRF needed)
        .route("/health", get(health::health_check))
        .route("/metrics", get(health::metrics))
        // CSRF token endpoint (GET - no CSRF needed)
        .route("/api/csrf-token", get(csrf::get_csrf_token))
        // Authentication endpoints
        .route("/auth/refresh", post(auth::refresh_token))
        .route("/auth/logout", post(auth::logout))
        // Keys management (CSRF protected)
        .route("/keys/upload", post(keys::upload_keys))
        .route("/keys/:user_id", get(keys::get_keys))
        // Messages (CSRF protected)
        .route("/messages/send", post(messages::send_message))
        // Federation (no CSRF - uses server signatures)
        .route(
            "/.well-known/konstruct",
            get(federation::well_known_konstruct),
        )
        .route("/federation/health", get(federation::federation_health))
        .route(
            "/federation/v1/messages",
            post(federation::receive_federated_message),
        )
        // Apply middleware (order matters - last added runs first)
        .layer(
            ServiceBuilder::new()
                // Tracing layer (outermost - runs first)
                .layer(TraceLayer::new_for_http())
                // Request logging
                .layer(axum::middleware::from_fn(
                    crate::routes::middleware::request_logging,
                ))
                // Security headers
                .layer(axum::middleware::from_fn(
                    crate::routes::middleware::add_security_headers,
                ))
                .into_inner(),
        )
        // CSRF protection middleware (needs state, applied separately)
        .layer(axum::middleware::from_fn_with_state(
            app_context.clone(),
            crate::routes::middleware::csrf_protection,
        ))
        .with_state(app_context)
}
