use anyhow::Result;
use bytes::Bytes;
use futures_util::stream::StreamExt;
use http_body_util::Full;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::{Mutex, RwLock};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite;
use tracing;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, body::Incoming as IncomingBody};
use hyper_util::rt::TokioIo;

pub mod apns;
pub mod auth;
pub mod config;
pub mod context;
pub mod db;
pub mod e2e;
pub mod federation;
pub mod handlers;
pub mod health;
pub mod kafka;
pub mod message;
pub mod message_gateway;
pub mod metrics;
pub mod queue;
pub mod server_registry;
pub mod user_id;
pub mod utils;

// Re-export delivery_worker modules for use in bin/delivery_worker.rs
pub mod delivery_worker;

use auth::AuthManager;
use config::Config;
use context::AppContext;
use db::DbPool;
use handlers::{handle_websocket, session::Clients};
use kafka::MessageProducer;
use queue::MessageQueue;

type HttpResult = Result<Response<Full<Bytes>>, Infallible>;

async fn http_handler(
    req: Request<IncomingBody>,
    db_pool: Arc<DbPool>,
    queue: Arc<Mutex<MessageQueue>>,
    auth_manager: Arc<AuthManager>,
    clients: Clients,
    config: Arc<Config>,
    kafka_producer: Arc<MessageProducer>,
    apns_client: Arc<apns::ApnsClient>,
    token_encryption: Arc<apns::DeviceTokenEncryption>,
    server_instance_id: String,
) -> HttpResult {
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    let response = match (method.as_str(), path.as_str()) {
        ("GET", "/health") => match health::health_check(&db_pool, queue, kafka_producer).await {
            Ok(_) => Response::new(Full::new(Bytes::from("OK"))),
            Err(e) => {
                tracing::error!("Health check failed: {}", e);
                let mut res = Response::new(Full::new(Bytes::from("Service Unavailable")));
                *res.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                res
            }
        },
        ("GET", "/metrics") => match metrics::gather_metrics() {
            Ok(metrics_data) => {
                let mut res = Response::new(Full::new(Bytes::from(metrics_data)));
                res.headers_mut()
                    .insert("Content-Type", "text/plain; version=0.0.4".parse().unwrap());
                res
            }
            Err(e) => {
                tracing::error!("Failed to gather metrics: {}", e);
                let mut res = Response::new(Full::new(Bytes::from("Internal Server Error")));
                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                res
            }
        },

        // API routes
        ("POST", "/keys/upload") => {
            let ctx = AppContext::new(
                db_pool,
                queue,
                auth_manager,
                clients,
                config,
                kafka_producer,
                apns_client,
                token_encryption,
                server_instance_id,
            );
            let (parts, body) = req.into_parts();
            handlers::keys::handle_upload_keys(&ctx, &parts.headers, body).await
        }
        ("GET", p) if p.starts_with("/keys/") => {
            let user_id = p.trim_start_matches("/keys/");
            let ctx = AppContext::new(
                db_pool,
                queue,
                auth_manager,
                clients,
                config,
                kafka_producer,
                apns_client,
                token_encryption,
                server_instance_id,
            );
            let (parts, _) = req.into_parts();
            handlers::keys::handle_get_keys(&ctx, &parts.headers, user_id).await
        }
        ("POST", "/messages/send") => {
            let ctx = AppContext::new(
                db_pool,
                queue,
                auth_manager,
                clients,
                config,
                kafka_producer,
                apns_client,
                token_encryption,
                server_instance_id,
            );
            let (parts, body) = req.into_parts();
            handlers::messages::handle_send_message(&ctx, &parts.headers, body).await
        }

        // Federation routes
        ("GET", "/.well-known/konstruct") => {
            let ctx = AppContext::new(
                db_pool,
                queue,
                auth_manager,
                clients,
                config,
                kafka_producer,
                apns_client,
                token_encryption,
                server_instance_id,
            );
            handlers::federation::well_known_konstruct(ctx).await
        }
        ("GET", "/federation/health") => {
            let ctx = AppContext::new(
                db_pool,
                queue,
                auth_manager,
                clients,
                config,
                kafka_producer,
                apns_client,
                token_encryption,
                server_instance_id,
            );
            handlers::federation::federation_health(ctx).await
        }
        ("POST", "/federation/v1/messages") => {
            let ctx = AppContext::new(
                db_pool,
                queue,
                auth_manager,
                clients,
                config,
                kafka_producer,
                apns_client,
                token_encryption,
                server_instance_id,
            );
            let (_parts, body) = req.into_parts();
            handlers::federation::receive_federated_message_http(&ctx, body).await
        }

        _ => {
            let mut not_found = Response::new(Full::new(Bytes::from("Not Found")));
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            not_found
        }
    };
    Ok(response)
}

pub async fn run_unified_server(app_context: AppContext, listener: TcpListener) {
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to accept socket: {}", e);
                continue;
            }
        };

        let ctx = app_context.clone();

        tokio::spawn(async move {
            let io = TokioIo::new(stream);

            let service = service_fn(move |mut req: Request<IncomingBody>| {
                let ctx = ctx.clone();
                async move {
                    if req
                        .headers()
                        .get("upgrade")
                        .and_then(|v| v.to_str().ok())
                        .map(|v| v.eq_ignore_ascii_case("websocket"))
                        .unwrap_or(false)
                    {
                        // Manually implement the handshake response to avoid moving `req`.
                        // Extract the key, build the response, and then move `req` into the upgrade task.
                        let key = match req.headers().get(hyper::header::SEC_WEBSOCKET_KEY) {
                            Some(key) => key.clone(),
                            None => {
                                let mut res = Response::new(Full::new(Bytes::from(
                                    "Bad Request: Missing Sec-WebSocket-Key",
                                )));
                                *res.status_mut() = StatusCode::BAD_REQUEST;
                                return Ok(res);
                            }
                        };

                        let ctx_clone = ctx.clone();
                        tokio::spawn(async move {
                            match hyper::upgrade::on(&mut req).await {
                                Ok(upgraded) => {
                                    let io = TokioIo::new(upgraded);
                                    let ws_stream = WebSocketStream::from_raw_socket(
                                        io,
                                        tungstenite::protocol::Role::Server,
                                        None,
                                    )
                                    .await;
                                    use handlers::WebSocketStreamType;
                                    handle_websocket(
                                        WebSocketStreamType::Upgraded(ws_stream),
                                        addr,
                                        ctx_clone,
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    tracing::error!("WebSocket upgrade error: {}", e);
                                }
                            }
                        });

                        // Build the response with the derived key.
                        let derived_key = tungstenite::handshake::derive_accept_key(key.as_bytes());
                        let mut res = Response::new(Full::new(Bytes::new()));
                        *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                        res.headers_mut()
                            .insert(hyper::header::UPGRADE, "websocket".parse().unwrap());
                        res.headers_mut()
                            .insert(hyper::header::CONNECTION, "Upgrade".parse().unwrap());
                        res.headers_mut().insert(
                            hyper::header::SEC_WEBSOCKET_ACCEPT,
                            derived_key.parse().unwrap(),
                        );
                        Ok(res)
                    } else {
                        // Handle regular HTTP
                        http_handler(
                            req,
                            ctx.db_pool.clone(),
                            ctx.queue.clone(),
                            ctx.auth_manager.clone(),
                            ctx.clients.clone(),
                            ctx.config.clone(),
                            ctx.kafka_producer.clone(),
                            ctx.apns_client.clone(),
                            ctx.token_encryption.clone(),
                            ctx.server_instance_id.clone(),
                        )
                        .await
                    }
                }
            });

            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                tracing::error!("Connection error: {:?}", err);
            }
        });
    }
}

/// Spawns a background task that listens for messages from the delivery worker
/// and forwards them to connected clients
fn spawn_delivery_listener(
    queue: Arc<Mutex<MessageQueue>>,
    clients: Clients,
    server_instance_id: String,
    config: Arc<Config>,
) {
    let redis_url = config.redis_url.clone();
    let poll_interval = config.delivery_poll_interval_ms;

    tokio::spawn(async move {
        tracing::info!(
            "📬 Delivery listener started for instance: {}",
            server_instance_id
        );

        // Create a separate Redis client for Pub/Sub
        let redis_client = match redis::Client::open(redis_url.as_str()) {
            Ok(client) => client,
            Err(e) => {
                tracing::error!(error = %e, "Failed to create Redis client for Pub/Sub");
                return;
            }
        };

        let mut pubsub_conn = match redis_client.get_async_pubsub().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!(error = %e, "Failed to connect to Redis Pub/Sub");
                return;
            }
        };

        let notification_channel = format!("delivery_notification:{}", server_instance_id);
        if let Err(e) = pubsub_conn.subscribe(&notification_channel).await {
            tracing::error!(error = %e, channel = %notification_channel, "Failed to subscribe to notification channel");
            return;
        }

        tracing::info!(channel = %notification_channel, "Subscribed to Redis Pub/Sub notifications");

        // Use a notify to trigger immediate polling from pub/sub
        let notify = Arc::new(tokio::sync::Notify::new());
        let notify_clone = notify.clone();

        // Spawn a task to listen for pub/sub notifications
        let _pubsub_listener = tokio::spawn(async move {
            let mut stream = pubsub_conn.on_message();
            while let Some(_msg) = stream.next().await {
                tracing::debug!("Received delivery notification via Pub/Sub");
                notify_clone.notify_one();
            }
            tracing::warn!("Pub/Sub stream ended unexpectedly");
        });

        loop {
            // Wait for either pub/sub notification or periodic polling interval
            tokio::select! {
                _ = notify.notified() => {
                    tracing::debug!("Triggered poll by Pub/Sub notification");
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval)) => {
                    tracing::trace!("Triggered poll by periodic interval");
                }
            }

            // Poll the delivery queue
            let messages = {
                let mut queue_guard = queue.lock().await;
                match queue_guard.poll_delivery_queue(&server_instance_id).await {
                    Ok(msgs) => msgs,
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to poll delivery queue");
                        continue;
                    }
                }
            };

            if messages.is_empty() {
                continue;
            }

            tracing::debug!(
                count = messages.len(),
                "Received messages from delivery queue"
            );

            // Forward messages to clients
            for message_bytes in messages {
                // Try to parse as ChatMessage (old format) or as JSON (v3 format)

                // First, try to deserialize as MessagePack (old format)
                if let Ok(chat_msg) = rmp_serde::from_slice::<message::ChatMessage>(&message_bytes)
                {
                    // Old format: send to the recipient via WebSocket
                    let clients_guard = clients.read().await;
                    if let Some(tx) = clients_guard.get(&chat_msg.to) {
                        let server_msg = message::ServerMessage::Message(chat_msg.clone());
                        if tx.send(server_msg).is_err() {
                            tracing::warn!(
                                recipient_id = %chat_msg.to,
                                "Failed to send message to client (channel closed)"
                            );
                        } else {
                            tracing::info!(
                                recipient_id = %chat_msg.to,
                                message_id = %chat_msg.id,
                                "Delivered offline message to online client"
                            );
                        }
                    } else {
                        tracing::warn!(
                            recipient_id = %chat_msg.to,
                            "Client not found for message delivery"
                        );
                    }
                }
                // Try to parse as JSON (v3 format)
                else if let Ok(json_str) = std::str::from_utf8(&message_bytes) {
                    if let Ok(v3_msg) = serde_json::from_str::<e2e::EncryptedMessageV3>(json_str) {
                        // V3 format: send to the recipient via WebSocket
                        let clients_guard = clients.read().await;
                        if let Some(tx) = clients_guard.get(&v3_msg.recipient_id) {
                            let server_msg = message::ServerMessage::EncryptedV3(v3_msg.clone());
                            if tx.send(server_msg).is_err() {
                                tracing::warn!(
                                    recipient_id = %v3_msg.recipient_id,
                                    "Failed to send V3 message to client (channel closed)"
                                );
                            } else {
                                tracing::info!(
                                    recipient_id = %v3_msg.recipient_id,
                                    "Delivered offline V3 message to online client"
                                );
                            }
                        } else {
                            tracing::warn!(
                                recipient_id = %v3_msg.recipient_id,
                                "Client not found for V3 message delivery"
                            );
                        }
                    } else {
                        tracing::error!(
                            "Failed to parse message as ChatMessage or EncryptedMessageV3"
                        );
                    }
                } else {
                    tracing::error!("Invalid message encoding (not UTF-8)");
                }
            }
        }
    });
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env()?;
    let app_config = Arc::new(config);

    let bind_address = format!("0.0.0.0:{}", app_config.port);

    // Connect to database
    let db_pool = Arc::new(db::create_pool(&app_config.database_url).await?);
    tracing::info!("Connected to database");

    // Apply database migrations
    tracing::info!("Applying database migrations...");
    sqlx::migrate!().run(&*db_pool).await?;
    tracing::info!("Database migrations applied successfully.");

    // Connect to Redis
    let redis_url_safe = if let Some(at_pos) = app_config.redis_url.find('@') {
        let protocol_end = app_config.redis_url.find("://").map(|p| p + 3).unwrap_or(0);
        format!(
            "{}***{}",
            &app_config.redis_url[..protocol_end],
            &app_config.redis_url[at_pos..]
        )
    } else {
        app_config.redis_url.clone()
    };
    tracing::info!("Connecting to Redis at: {}", redis_url_safe);

    let message_queue = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        MessageQueue::new(&app_config),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Redis connection timed out after 10 seconds"))??;

    tracing::info!("Connected to Redis");

    let queue = Arc::new(Mutex::new(message_queue));

    // Initialize Kafka producer (Phase 1: Foundation)
    tracing::info!("Initializing Kafka producer...");
    let kafka_producer = MessageProducer::new(&app_config.kafka)?;
    tracing::info!(
        enabled = app_config.kafka.enabled,
        brokers = %app_config.kafka.brokers,
        topic = %app_config.kafka.topic,
        "Kafka producer initialized"
    );
    let kafka_producer = Arc::new(kafka_producer);

    // Initialize APNs client
    tracing::info!("Initializing APNs client...");
    let apns_client = apns::ApnsClient::new(app_config.apns.clone())?;
    if app_config.apns.enabled {
        apns_client.initialize().await?;
        tracing::info!(
            environment = ?app_config.apns.environment,
            key_id = %app_config.apns.key_id,
            "APNs client initialized successfully"
        );
    } else {
        tracing::info!("APNs is disabled");
    }
    let apns_client = Arc::new(apns_client);

    // Initialize device token encryption
    tracing::info!("Initializing device token encryption...");
    let token_encryption =
        apns::DeviceTokenEncryption::from_hex(&app_config.apns.device_token_encryption_key)?;
    let token_encryption = Arc::new(token_encryption);
    tracing::info!("Device token encryption initialized");

    // Create auth manager
    let auth_manager = Arc::new(AuthManager::new(&app_config));

    // WebSocket listener
    let listener = TcpListener::bind(&bind_address).await?;
    tracing::info!("Construct server listening on {} (WebSocket)", bind_address);

    let clients: Clients = Arc::new(RwLock::new(HashMap::new()));

    // Generate unique server instance ID for delivery worker coordination
    let server_instance_id = uuid::Uuid::new_v4().to_string();
    tracing::info!("Server instance ID: {}", server_instance_id);

    // Create application context
    let app_context = AppContext::new(
        db_pool.clone(),
        queue.clone(),
        auth_manager.clone(),
        clients.clone(),
        app_config.clone(),
        kafka_producer.clone(),
        apns_client.clone(),
        token_encryption.clone(),
        server_instance_id.clone(),
    );

    // Spawn background task to listen for messages from delivery worker
    spawn_delivery_listener(
        queue.clone(),
        clients.clone(),
        server_instance_id.clone(),
        app_config.clone(),
    );

    // Spawn heartbeat task to register this server in Redis
    server_registry::spawn_server_heartbeat(
        queue.clone(),
        server_instance_id.clone(),
        app_config.delivery_queue_prefix.clone(),
    );

    let unified_server = run_unified_server(app_context, listener);

    tokio::select! {
        _ = unified_server => {
            tracing::info!("Server shut down.");
        },
        _ = signal::ctrl_c() => {
            tracing::info!("Shutdown signal received. Shutting down...");
        }
    }

    Ok(())
}
