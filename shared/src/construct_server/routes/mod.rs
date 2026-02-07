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

pub mod account; // Made public for user-service
pub mod auth; // Made public for auth-service
mod capabilities; // Phase 5: Crypto-agility capabilities endpoint
pub mod csrf; // Made public for gateway middleware
pub mod devices; // Device-based passwordless authentication
pub mod extractors; // Made public for auth-service, user-service, messaging-service, and notification-service
mod federation;
mod health;
mod invites; // Phase 5: Dynamic invite tokens (one-time QR codes)
pub mod keys; // Made public for user-service
pub mod media; // Made public for messaging-service
pub mod messages; // Made public for messaging-service
mod middleware;
pub mod notifications; // Made public for notification-service
pub mod request_signing; // Made public for user-service (account deletion uses request signing)

use axum::{
    Router,
    routing::{delete, get, patch, post, put},
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
        .route("/health/ready", get(health::readiness_check))
        .route("/health/live", get(health::liveness_check))
        .route("/metrics", get(health::metrics))
        // CSRF token endpoint (GET - no CSRF needed)
        .route("/api/csrf-token", get(csrf::get_csrf_token))
        // Authentication endpoints
        .route("/auth/refresh", post(auth::refresh_token))
        .route("/auth/logout", post(auth::logout))
        // Phase 2.5: REST API authentication endpoints
        .route("/api/v1/auth/register", post(auth::register))
        .route("/api/v1/auth/login", post(auth::login))
        // Account management (CSRF protected, authenticated)
        .route("/api/v1/account", get(account::get_account))
        .route("/api/v1/account", put(account::update_account))
        .route("/api/v1/account", delete(account::delete_account))
        // Keys management (CSRF protected)
        .route("/keys/upload", post(keys::upload_keys)) // Legacy
        .route("/keys/:user_id", get(keys::get_keys)) // Legacy
        // Phase 2.5.4: Migrated endpoints under /api/v1/
        .route("/api/v1/keys/upload", post(keys::upload_keys))
        .route(
            "/api/v1/users/:id/public-key",
            get(keys::get_public_key_bundle),
        )
        // PATCH endpoint for updating verifying key (per INVITE_LINKS_QR_API_SPEC.md)
        .route(
            "/api/v1/users/me/public-key",
            patch(keys::update_verifying_key),
        )
        // Phase 5: Crypto-agility capabilities
        .route(
            "/api/v1/users/:id/capabilities",
            get(capabilities::get_user_capabilities),
        )
        // Phase 5: Dynamic invites (one-time contact sharing)
        .route("/api/v1/invites/generate", post(invites::generate_invite))
        .route("/api/v1/invites/accept", post(invites::accept_invite))
        // Messages (CSRF protected)
        .route("/messages/send", post(messages::send_message)) // Legacy
        // Phase 2.5: REST API for messages
        .route("/api/v1/messages", post(messages::send_message)) // Phase 2.5.4: Migrated
        .route("/api/v1/messages", get(messages::get_messages)) // Phase 2.5.1: Long polling
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
        .route(
            "/federation/v1/keys/:user_id",
            get(federation::get_federation_keys),
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
        // Metrics authentication (needs state, applied before CSRF)
        .layer(axum::middleware::from_fn_with_state(
            app_context.clone(),
            crate::routes::middleware::metrics_auth,
        ))
        // CSRF protection middleware (needs state, applied separately)
        .layer(axum::middleware::from_fn_with_state(
            app_context.clone(),
            crate::routes::middleware::csrf_protection,
        ))
        .with_state(app_context)
}
