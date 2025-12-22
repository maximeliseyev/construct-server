use anyhow::Result;
use bytes::Bytes;
use http_body_util::Full;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::{Mutex, RwLock};
use tokio_tungstenite::accept_async;
use tracing;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming as IncomingBody, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;

pub mod auth;
pub mod config;
pub mod context;
pub mod e2e;
pub mod db;
pub mod handlers;
pub mod health;
pub mod message;
pub mod metrics;
pub mod queue;
pub mod utils;

use auth::AuthManager;
use config::Config;
use context::AppContext;
use db::DbPool;
use handlers::{handle_websocket, session::Clients};
use queue::MessageQueue;

type HttpResult = Result<Response<Full<Bytes>>, Infallible>;

async fn http_handler(
    req: Request<IncomingBody>,
    db_pool: Arc<DbPool>,
    queue: Arc<Mutex<MessageQueue>>,
) -> HttpResult {
    let response = match req.uri().path() {
        "/health" => match health::health_check(&db_pool, queue).await {
            Ok(_) => Response::new(Full::new(Bytes::from("OK"))),
            Err(e) => {
                tracing::error!("Health check failed: {}", e);
                let mut res = Response::new(Full::new(Bytes::from("Service Unavailable")));
                *res.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                res
            }
        },
        "/metrics" => match metrics::gather_metrics() {
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
        _ => {
            let mut not_found = Response::new(Full::new(Bytes::from("Not Found")));
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            not_found
        }
    };
    Ok(response)
}

pub async fn run_http_server(
    config: Config,
    db_pool: Arc<DbPool>,
    queue: Arc<Mutex<MessageQueue>>,
) -> Result<()> {
    let http_addr = format!("0.0.0.0:{}", config.health_port);
    let listener = TcpListener::bind(&http_addr).await?;
    tracing::info!("HTTP server listening on http://{}", http_addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        let db_pool_clone = db_pool.clone();
        let queue_clone = queue.clone();

        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                http_handler(req, db_pool_clone.clone(), queue_clone.clone())
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                tracing::error!("Error serving HTTP connection: {:?}", err);
            }
        });
    }
}

pub async fn run_websocket_server(app_context: AppContext, listener: TcpListener) {
    loop {
        let (socket, addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to accept socket: {}", e);
                continue;
            }
        };

        let ctx = app_context.clone();

        tokio::spawn(async move {
            if let Ok(ws_stream) = accept_async(socket).await {
                handle_websocket(ws_stream, addr, ctx).await;
            }
        });
    }
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
        format!("{}***{}", &app_config.redis_url[..protocol_end], &app_config.redis_url[at_pos..])
    } else {
        app_config.redis_url.clone()
    };
    tracing::info!("Connecting to Redis at: {}", redis_url_safe);

    let message_queue = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        MessageQueue::new(&app_config)
    ).await.map_err(|_| anyhow::anyhow!("Redis connection timed out after 10 seconds"))??;

    tracing::info!("Connected to Redis");

    let queue = Arc::new(Mutex::new(message_queue));

    // Create auth manager
    let auth_manager = Arc::new(AuthManager::new(&app_config));

    // WebSocket listener
    let listener = TcpListener::bind(&bind_address).await?;
    tracing::info!("Construct server listening on {} (WebSocket)", bind_address);

    let clients: Clients = Arc::new(RwLock::new(HashMap::new()));

    // Create application context
    let app_context = AppContext::new(
        db_pool.clone(),
        queue.clone(),
        auth_manager,
        clients,
        app_config.clone(),
    );

    let http_server_config = app_config.as_ref().clone();
    let websocket_server = run_websocket_server(app_context, listener);
    let http_server = run_http_server(http_server_config, db_pool.clone(), queue.clone());

    tokio::select! {
        _ = websocket_server => {
            tracing::info!("WebSocket server shut down.");
        },
        res = http_server => {
            if let Err(e) = res {
                tracing::error!("HTTP server failed: {}", e);
            }
        },
        _ = signal::ctrl_c() => {
            tracing::info!("Shutdown signal received. Shutting down...");
        }
    }

    Ok(())
}
