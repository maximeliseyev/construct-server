// ============================================================================
// Message Gateway Service - Main Binary
// ============================================================================
//
// Central message processing service that handles:
// - Message validation and rate limiting
// - Kafka message production
// - Future: Federation routing
//
// Architecture:
// - gRPC server for message submission from construct-server
// - Stateless processing (horizontally scalable)
// - Redis for rate limiting and deduplication
// - Kafka for reliable message delivery
//
// Deployment:
// - Fly.io as separate app (message-gateway)
// - Auto-scaling based on gRPC request rate
// - Health check endpoint for service discovery
//
// ============================================================================

use anyhow::{Context, Result};
use construct_server::config::Config;
use construct_server::kafka::MessageProducer;
use construct_server::message::ChatMessage;
use construct_server::message_gateway::{
    grpc::*,
    rate_limiter::RateLimiter,
    router::MessageRouter,
    validator::MessageValidator,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Message Gateway gRPC service implementation
pub struct MessageGatewayServiceImpl {
    validator: MessageValidator,
    rate_limiter: Arc<RwLock<RateLimiter>>,
    router: MessageRouter,
    config: Arc<Config>,
}

impl MessageGatewayServiceImpl {
    pub fn new(
        redis_conn: redis::aio::MultiplexedConnection,
        kafka_producer: MessageProducer,
        config: Arc<Config>,
    ) -> Self {
        Self {
            validator: MessageValidator::new(),
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new(redis_conn))),
            router: MessageRouter::new(kafka_producer),
            config,
        }
    }
}

#[tonic::async_trait]
impl MessageGatewayService for MessageGatewayServiceImpl {
    async fn submit_message(
        &self,
        request: Request<SubmitMessageRequest>,
    ) -> Result<Response<SubmitMessageResponse>, Status> {
        let req = request.into_inner();

        // Convert gRPC request to ChatMessage
        // Note: ciphertext arrives as Vec<u8> via gRPC, but ChatMessage expects base64 String
        let content_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &req.ciphertext);

        let msg = ChatMessage {
            id: req.message_id.clone(),
            from: req.from.clone(),
            to: req.to.clone(),
            ephemeral_public_key: req.ephemeral_public_key.clone(),
            content: content_base64,
            message_number: req.message_number,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        info!(
            message_id = %msg.id,
            from = %msg.from,
            to = %msg.to,
            "Processing message submission"
        );

        // Step 1: Validate message structure
        if let Err(e) = self.validator.validate_structure(&msg) {
            warn!(
                message_id = %msg.id,
                error = %e,
                "Message validation failed"
            );
            return Ok(Response::new(SubmitMessageResponse {
                status: SubmissionStatus::ValidationError.into(),
                error: Some(ErrorDetails {
                    error_code: "INVALID_MESSAGE_FORMAT".to_string(),
                    error_message: e.to_string(),
                }),
            }));
        }

        // Step 2: Verify sender (anti-spoofing)
        if let Err(e) = self.validator.verify_sender(&msg, &req.authenticated_user_id) {
            warn!(
                message_id = %msg.id,
                authenticated_user = %req.authenticated_user_id,
                message_from = %msg.from,
                error = %e,
                "Sender spoofing attempt detected"
            );
            return Ok(Response::new(SubmitMessageResponse {
                status: SubmissionStatus::ValidationError.into(),
                error: Some(ErrorDetails {
                    error_code: "FORBIDDEN".to_string(),
                    error_message: "Sender mismatch".to_string(),
                }),
            }));
        }

        // Step 3: Check user blocking
        let mut rate_limiter = self.rate_limiter.write().await;
        match rate_limiter.check_user_blocked(&msg.from).await {
            Ok(Some(reason)) => {
                warn!(
                    message_id = %msg.id,
                    user_id = %msg.from,
                    reason = %reason,
                    "Blocked user attempted to send message"
                );
                return Ok(Response::new(SubmitMessageResponse {
                    status: SubmissionStatus::UserBlocked.into(),
                    error: Some(ErrorDetails {
                        error_code: "USER_BLOCKED".to_string(),
                        error_message: format!("User is blocked: {}", reason),
                    }),
                }));
            }
            Ok(None) => {} // Not blocked, continue
            Err(e) => {
                error!(
                    message_id = %msg.id,
                    error = %e,
                    "Failed to check user blocking status"
                );
                // Continue processing (fail open)
            }
        }

        // Step 4: Replay protection
        let dedup_key = self.validator.create_dedup_key(&msg);
        match rate_limiter.check_message_replay(&dedup_key).await {
            Ok(true) => {} // New message, continue
            Ok(false) => {
                warn!(
                    message_id = %msg.id,
                    "Duplicate message detected"
                );
                return Ok(Response::new(SubmitMessageResponse {
                    status: SubmissionStatus::Duplicate.into(),
                    error: Some(ErrorDetails {
                        error_code: "DUPLICATE_MESSAGE".to_string(),
                        error_message: "Message already processed".to_string(),
                    }),
                }));
            }
            Err(e) => {
                error!(
                    message_id = %msg.id,
                    error = %e,
                    "Failed to check message replay"
                );
                // Continue processing (fail open)
            }
        }

        // Step 5: Rate limiting
        match rate_limiter.increment_message_count(&msg.from).await {
            Ok(count) => {
                let max_messages = self.config.security.max_messages_per_hour;
                let block_threshold = max_messages + (max_messages / 2);

                if count > block_threshold as u64 {
                    // Block user
                    let block_duration = self.config.security.rate_limit_block_duration_seconds;
                    if let Err(e) = rate_limiter
                        .block_user(&msg.from, block_duration, "Rate limit exceeded")
                        .await
                    {
                        error!(error = %e, "Failed to block user for rate limiting");
                    }

                    warn!(
                        message_id = %msg.id,
                        user_id = %msg.from,
                        count = count,
                        "User rate limit exceeded, blocked"
                    );

                    return Ok(Response::new(SubmitMessageResponse {
                        status: SubmissionStatus::RateLimited.into(),
                        error: Some(ErrorDetails {
                            error_code: "RATE_LIMIT_BLOCKED".to_string(),
                            error_message: format!(
                                "Too many messages. Blocked for {} seconds.",
                                block_duration
                            ),
                        }),
                    }));
                } else if count > max_messages as u64 {
                    warn!(
                        message_id = %msg.id,
                        user_id = %msg.from,
                        count = count,
                        max = max_messages,
                        "User approaching rate limit"
                    );

                    return Ok(Response::new(SubmitMessageResponse {
                        status: SubmissionStatus::RateLimited.into(),
                        error: Some(ErrorDetails {
                            error_code: "RATE_LIMIT_WARNING".to_string(),
                            error_message: format!("Slow down! ({}/{})", count, max_messages),
                        }),
                    }));
                }
            }
            Err(e) => {
                error!(
                    message_id = %msg.id,
                    error = %e,
                    "Failed to check rate limit"
                );
                // Continue processing (fail open)
            }
        }

        // Step 6: Mark message as processed (for replay protection)
        if let Err(e) = rate_limiter
            .mark_message_processed(&dedup_key, self.config.message_ttl_days)
            .await
        {
            error!(
                message_id = %msg.id,
                error = %e,
                "Failed to mark message as processed"
            );
            // Continue (non-fatal)
        }

        drop(rate_limiter); // Release lock

        // Step 7: Route message (to Kafka for now, federation later)
        if let Err(e) = self.router.route_message(&msg).await {
            error!(
                message_id = %msg.id,
                error = %e,
                "Failed to route message to Kafka"
            );

            return Ok(Response::new(SubmitMessageResponse {
                status: SubmissionStatus::InternalError.into(),
                error: Some(ErrorDetails {
                    error_code: "KAFKA_ERROR".to_string(),
                    error_message: "Failed to queue message for delivery".to_string(),
                }),
            }));
        }

        info!(
            message_id = %msg.id,
            from = %msg.from,
            to = %msg.to,
            "Message successfully processed and queued"
        );

        Ok(Response::new(SubmitMessageResponse {
            status: SubmissionStatus::Success.into(),
            error: None,
        }))
    }

    async fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        // TODO: Actually check Redis and Kafka health
        Ok(Response::new(HealthCheckResponse {
            status: HealthStatus::Serving.into(),
            message: Some("Message Gateway is healthy".to_string()),
        }))
    }
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

    info!("=== Message Gateway Service Starting ===");
    info!("gRPC Port: {}", config.port);
    info!("Kafka Enabled: {}", config.kafka.enabled);
    info!("Kafka Brokers: {}", config.kafka.brokers);
    info!("Kafka Topic: {}", config.kafka.topic);

    // Connect to Redis
    let redis_url_safe = if let Some(at_pos) = config.redis_url.find('@') {
        let protocol_end = config.redis_url.find("://").map(|p| p + 3).unwrap_or(0);
        format!(
            "{}***{}",
            &config.redis_url[..protocol_end],
            &config.redis_url[at_pos..]
        )
    } else {
        config.redis_url.clone()
    };
    info!("Connecting to Redis at: {}", redis_url_safe);

    let client =
        redis::Client::open(config.redis_url.as_str()).context("Failed to create Redis client")?;

    let redis_conn = client
        .get_multiplexed_async_connection()
        .await
        .context("Failed to connect to Redis")?;

    info!("Connected to Redis");

    // Initialize Kafka producer
    info!("Initializing Kafka producer...");
    let kafka_producer = MessageProducer::new(&config.kafka)
        .context("Failed to initialize Kafka producer")?;
    info!("Kafka producer initialized");

    // Create gRPC service
    let service = MessageGatewayServiceImpl::new(redis_conn, kafka_producer, config.clone());

    // Start gRPC server
    let addr: SocketAddr = format!("0.0.0.0:{}", config.port)
        .parse()
        .context("Failed to parse bind address")?;

    info!("Message Gateway gRPC server listening on {}", addr);

    Server::builder()
        .add_service(MessageGatewayServer::new(service))
        .serve(addr)
        .await
        .context("gRPC server failed")?;

    Ok(())
}
