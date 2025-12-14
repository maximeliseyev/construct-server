use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};
use tokio_tungstenite::accept_async;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod context;
mod crypto;
mod db;
mod handlers;
mod message;
mod queue;

use auth::AuthManager;
use context::AppContext;
use handlers::{handle_websocket, session::Clients};
use queue::MessageQueue;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Environment variables
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "change-this-secret-in-production".to_string());

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);

    let bind_address = format!("0.0.0.0:{}", port);

    // Connect to database
    let db_pool = db::create_pool(&database_url).await?;
    tracing::info!("Connected to database");

    // Connect to Redis
    let message_queue = MessageQueue::new(&redis_url).await?;
    tracing::info!("Connected to Redis");

    let queue = Arc::new(Mutex::new(message_queue));

    // Create auth manager
    let auth_manager = Arc::new(AuthManager::new(&jwt_secret));

    // WebSocket listener
    let listener = TcpListener::bind(&bind_address).await?;
    tracing::info!(
        "Construct server listening on {} (WebSocket)",
        bind_address
    );

    let clients: Clients = Arc::new(RwLock::new(HashMap::new()));

    // Create application context
    let app_context = AppContext::new(db_pool, queue, auth_manager, clients);

    loop {
        let (socket, addr) = listener.accept().await?;

        let ctx = app_context.clone();

        tokio::spawn(async move {
            if let Ok(ws_stream) = accept_async(socket).await {
                handle_websocket(ws_stream, addr, ctx).await;
            }
        });
    }
}
