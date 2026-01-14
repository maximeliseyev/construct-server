use axum::{http::StatusCode, response::IntoResponse};
use bytes::Bytes;
use http_body_util::Full;
use hyper::Response;
use serde_json::json;
use thiserror::Error;

pub type AppResult<T> = Result<T, AppError>;

/// Application error type with comprehensive error handling
///
/// This enum covers all error types that can occur in the application,
/// providing structured error information for logging and user-facing responses.
#[derive(Error, Debug)]
pub enum AppError {
    // ===== HTTP & Network Errors =====
    #[error("HTTP header error: {0}")]
    HttpHeader(#[from] hyper::header::InvalidHeaderValue),

    #[error("Hyper HTTP error: {0}")]
    Hyper(String),

    #[error("HTTP client error: {0}")]
    Reqwest(#[from] reqwest::Error),

    // ===== Serialization Errors =====
    #[error("Serialization error: {0}")]
    Serialization(#[from] rmp_serde::encode::Error),

    #[error("Deserialization error: {0}")]
    Deserialization(#[from] rmp_serde::decode::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    // ===== Database & Storage Errors =====
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    // ===== Message Queue & Kafka Errors =====
    #[error("Kafka error: {0}")]
    Kafka(String),

    #[error("Message queue error: {0}")]
    MessageQueue(String),

    // ===== WebSocket Errors =====
    #[error("WebSocket error: {0}")]
    WebSocket(String),

    // ===== Authentication & Authorization Errors =====
    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    // ===== Validation Errors =====
    #[error("Validation error: {0}")]
    Validation(String),

    #[error("UUID parse error: {0}")]
    Uuid(#[from] uuid::Error),

    // ===== Federation Errors =====
    #[error("Federation error: {0}")]
    Federation(String),

    // ===== Message Processing Errors =====
    #[error("Message processing error: {0}")]
    Message(String),

    // ===== Configuration Errors =====
    #[error("Configuration error: {0}")]
    Config(String),

    // ===== Internal Server Errors =====
    #[error("Internal server error: {0}")]
    Internal(String),

    // ===== Unknown/Generic Errors =====
    #[error("Unknown error: {0}")]
    Unknown(#[from] anyhow::Error),
}

impl AppError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            AppError::Auth(_) | AppError::Jwt(_) => StatusCode::UNAUTHORIZED,
            AppError::Validation(_) | AppError::Uuid(_) => StatusCode::BAD_REQUEST,
            AppError::Reqwest(_) | AppError::Federation(_) => StatusCode::BAD_GATEWAY,
            AppError::Database(_)
            | AppError::Redis(_)
            | AppError::Kafka(_)
            | AppError::MessageQueue(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::WebSocket(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get a user-friendly error message (without sensitive details)
    pub fn user_message(&self) -> String {
        match self {
            AppError::Auth(msg) => format!("Authentication failed: {}", msg),
            AppError::Jwt(_) => "Invalid or expired token".to_string(),
            AppError::Validation(msg) => format!("Validation error: {}", msg),
            AppError::Database(_) => "Database error".to_string(),
            AppError::Redis(_) => "Cache error".to_string(),
            AppError::Kafka(_) => "Message queue error".to_string(),
            AppError::MessageQueue(_) => "Message queue error".to_string(),
            AppError::Reqwest(_) => "External service error".to_string(),
            AppError::Federation(_) => "Federation error".to_string(),
            AppError::WebSocket(_) => "WebSocket connection error".to_string(),
            AppError::Config(msg) => format!("Configuration error: {}", msg),
            AppError::Internal(msg) => format!("Internal error: {}", msg),
            _ => "Internal server error".to_string(),
        }
    }

    /// Get error code for programmatic error handling
    pub fn error_code(&self) -> &'static str {
        match self {
            AppError::Auth(_) => "AUTH_ERROR",
            AppError::Jwt(_) => "JWT_ERROR",
            AppError::Validation(_) => "VALIDATION_ERROR",
            AppError::Database(_) => "DATABASE_ERROR",
            AppError::Redis(_) => "REDIS_ERROR",
            AppError::Kafka(_) => "KAFKA_ERROR",
            AppError::MessageQueue(_) => "MESSAGE_QUEUE_ERROR",
            AppError::Reqwest(_) => "EXTERNAL_SERVICE_ERROR",
            AppError::Federation(_) => "FEDERATION_ERROR",
            AppError::WebSocket(_) => "WEBSOCKET_ERROR",
            AppError::Config(_) => "CONFIG_ERROR",
            AppError::Internal(_) => "INTERNAL_ERROR",
            _ => "UNKNOWN_ERROR",
        }
    }

    /// Log this error with appropriate level and context
    pub fn log(&self) {
        let status = self.status_code();
        let code = self.error_code();

        if status.is_server_error() {
            tracing::error!(
                error = %self,
                error_code = %code,
                status = %status.as_u16(),
                "Server error occurred"
            );
        } else if status == StatusCode::UNAUTHORIZED {
            tracing::warn!(
                error = %self,
                error_code = %code,
                "Authentication failed"
            );
        } else {
            tracing::debug!(
                error = %self,
                error_code = %code,
                "Client error occurred"
            );
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        // Log the error with appropriate level
        self.log();

        let status = self.status_code();
        let error_code = self.error_code();
        let user_message = self.user_message();

        // Create structured error response
        let error_response = json!({
            "error": user_message,
            "error_code": error_code,
            "status": status.as_u16(),
        });

        // For server errors, don't expose internal details to client
        let response_body = if status.is_server_error() {
            json!({
                "error": "Internal server error",
                "error_code": error_code,
                "status": status.as_u16(),
            })
        } else {
            error_response
        };

        (status, axum::Json(response_body)).into_response()
    }
}

// ============================================================================
// Conversion from common error types
// ============================================================================

impl From<rdkafka::error::KafkaError> for AppError {
    fn from(err: rdkafka::error::KafkaError) -> Self {
        tracing::error!(error = %err, "Kafka error occurred");
        AppError::Kafka(err.to_string())
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for AppError {
    fn from(err: tokio_tungstenite::tungstenite::Error) -> Self {
        tracing::warn!(error = %err, "WebSocket error occurred");
        AppError::WebSocket(err.to_string())
    }
}

// ============================================================================
// Helper functions for creating common errors
// ============================================================================

impl AppError {
    /// Create an authentication error
    pub fn auth(msg: impl Into<String>) -> Self {
        AppError::Auth(msg.into())
    }

    /// Create a validation error
    pub fn validation(msg: impl Into<String>) -> Self {
        AppError::Validation(msg.into())
    }

    /// Create an internal server error
    pub fn internal(msg: impl Into<String>) -> Self {
        AppError::Internal(msg.into())
    }

    /// Create a federation error
    pub fn federation(msg: impl Into<String>) -> Self {
        AppError::Federation(msg.into())
    }

    /// Create a message processing error
    pub fn message(msg: impl Into<String>) -> Self {
        AppError::Message(msg.into())
    }

    /// Create a configuration error
    pub fn config(msg: impl Into<String>) -> Self {
        AppError::Config(msg.into())
    }

    /// Create a Kafka error
    pub fn kafka(msg: impl Into<String>) -> Self {
        AppError::Kafka(msg.into())
    }

    /// Create a WebSocket error
    pub fn websocket(msg: impl Into<String>) -> Self {
        AppError::WebSocket(msg.into())
    }

    /// Create a message queue error
    pub fn message_queue(msg: impl Into<String>) -> Self {
        AppError::MessageQueue(msg.into())
    }

    /// Convert AppError to hyper::Response for use in non-Axum handlers
    /// This is used in lib.rs where we use hyper directly instead of Axum
    pub fn to_hyper_response(self) -> Response<Full<Bytes>> {
        // Log the error with appropriate level
        self.log();

        let status = self.status_code();
        let error_code = self.error_code();
        let user_message = self.user_message();

        // Create structured error response
        let error_response = json!({
            "error": user_message,
            "error_code": error_code,
            "status": status.as_u16(),
        });

        // For server errors, don't expose internal details to client
        let response_body = if status.is_server_error() {
            json!({
                "error": "Internal server error",
                "error_code": error_code,
                "status": status.as_u16(),
            })
        } else {
            error_response
        };

        let json_bytes = serde_json::to_vec(&response_body).unwrap_or_else(|_| {
            // Fallback if JSON serialization fails
            b"{\"error\":\"Internal server error\"}".to_vec()
        });

        let mut response = Response::new(Full::new(Bytes::from(json_bytes)));
        *response.status_mut() = status;

        // Set Content-Type header
        if let Ok(content_type) = "application/json".parse() {
            response.headers_mut().insert("content-type", content_type);
        }

        response
    }
}
