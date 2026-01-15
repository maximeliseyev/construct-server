// ============================================================================
// Health and Metrics Routes
// ============================================================================
//
// Endpoints:
// - GET /health - Health check (database, Redis, Kafka)
// - GET /metrics - Prometheus metrics
//
// ============================================================================

use axum::{extract::State, http::StatusCode, response::IntoResponse};
use std::sync::Arc;

use crate::context::AppContext;
use crate::error::AppError;
use crate::health;
use crate::metrics;

/// GET /health
/// Health check endpoint
pub async fn health_check(
    State(app_context): State<Arc<AppContext>>,
) -> Result<impl IntoResponse, AppError> {
    match health::health_check(
        &app_context.db_pool,
        app_context.queue.clone(),
        app_context.kafka_producer.clone(),
    )
    .await
    {
        Ok(_) => Ok((StatusCode::OK, "OK")),
        Err(e) => {
            tracing::error!("Health check failed: {}", e);
            Ok((StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable"))
        }
    }
}

/// GET /metrics
/// Prometheus metrics endpoint
pub async fn metrics() -> Result<impl IntoResponse, AppError> {
    match metrics::gather_metrics() {
        Ok(metrics_data) => Ok((
            StatusCode::OK,
            [("Content-Type", "text/plain; version=0.0.4")],
            metrics_data,
        )),
        Err(e) => {
            tracing::error!("Failed to gather metrics: {}", e);
            Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                [("Content-Type", "text/plain")],
                "Internal Server Error".to_string(),
            ))
        }
    }
}
