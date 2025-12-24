use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use construct_server::{
    auth::AuthManager,
    config::Config,
    context::AppContext,
    message::{ClientMessage, ServerMessage},
    queue::MessageQueue,
};
use futures_util::{SinkExt, StreamExt};
use sqlx::{Connection, Executor, PgConnection, PgPool};
use std::{collections::HashMap, sync::Arc};
use tokio::{net::TcpListener, sync::Mutex, sync::RwLock};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage, WebSocketStream};
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub db_pool: PgPool,
}

pub struct TestClient {
    pub ws: WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub session_token: Option<String>,
}

pub async fn spawn_app() -> TestApp {
    // This requires a running Postgres database.
    // You can start one with `docker-compose up -d postgres`
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let address = format!("127.0.0.1:{}", port);

    let mut config = Config::from_env().expect("Failed to read config");
    config.database_url = format!(
        "postgres://construct:construct_dev_password@localhost:5432/construct_test_{}",
        Uuid::new_v4().to_string()
    );
    config.redis_url = "redis://127.0.0.1:6379".to_string(); // Point to local Redis

    let mut connection = PgConnection::connect("postgres://construct:construct_dev_password@localhost:5432/postgres")
        .await
        .expect("Failed to connect to Postgres");
    connection
        .execute(format!(r#"CREATE DATABASE "{}";"#, config.database_url.split('/').last().unwrap()).as_str())
        .await
        .expect("Failed to create database.");

    let db_pool = PgPool::connect(&config.database_url)
        .await
        .expect("Failed to connect to the database");
    sqlx::migrate!("./migrations")
        .run(&db_pool)
        .await
        .expect("Failed to migrate the database");

    let app_config = Arc::new(config);
    let db_pool_arc = Arc::new(db_pool.clone());
    let message_queue = MessageQueue::new(&app_config).await.unwrap();
    let queue = Arc::new(Mutex::new(message_queue));
    let auth_manager = Arc::new(AuthManager::new(&app_config));
    let clients = Arc::new(RwLock::new(HashMap::new()));
    let server_instance_id = Uuid::new_v4().to_string();
    let app_context = AppContext::new(
        db_pool_arc.clone(),
        queue.clone(),
        auth_manager,
        clients,
        app_config.clone(),
        server_instance_id,
    );

    tokio::spawn(construct_server::run_websocket_server(
        app_context,
        listener,
    ));

    TestApp {
        address,
        db_pool,
    }
}

impl TestClient {
    pub async fn connect(server_addr: &str) -> Result<Self> {
        let url = format!("ws://{}", server_addr);
        let (ws, _) = connect_async(&url).await?;
        Ok(Self {
            ws,
            user_id: None,
            username: None,
            session_token: None,
        })
    }

    pub async fn send(&mut self, message: &ClientMessage) -> Result<()> {
        let msg = rmp_serde::to_vec_named(message)?;
        self.ws.send(WsMessage::Binary(msg)).await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Option<ServerMessage>> {
        match self.ws.next().await {
            Some(Ok(WsMessage::Binary(bin))) => {
                let msg = rmp_serde::from_slice(&bin)?;
                Ok(Some(msg))
            }
            Some(Ok(WsMessage::Close(_))) => Ok(None),
            Some(Err(e)) => Err(anyhow::anyhow!(e)),
            _ => Ok(None),
        }
    }

    pub async fn register(&mut self, username: &str, password: &str) -> Result<()> {
        // Create a valid UploadableKeyBundle for testing
        use construct_server::e2e::{BundleData, SuiteKeyMaterial, UploadableKeyBundle};

        // Create dummy key material for suite 1 (CLASSIC_X25519)
        let suite_material = SuiteKeyMaterial {
            suite_id: 1,
            identity_key: BASE64.encode(vec![0u8; 32]),      // 32 bytes for X25519
            signed_prekey: BASE64.encode(vec![1u8; 32]),     // 32 bytes for X25519
            one_time_prekeys: vec![],
        };

        // Create BundleData
        let bundle_data = BundleData {
            user_id: "temp-user-id".to_string(), // Will be replaced after registration
            timestamp: chrono::Utc::now().to_rfc3339(),
            supported_suites: vec![suite_material],
        };

        // Serialize BundleData to JSON
        let bundle_data_json = serde_json::to_string(&bundle_data).unwrap();
        let bundle_data_base64 = BASE64.encode(bundle_data_json.as_bytes());

        // Create UploadableKeyBundle
        let uploadable_bundle = UploadableKeyBundle {
            master_identity_key: BASE64.encode(vec![2u8; 32]),  // 32 bytes for Ed25519
            bundle_data: bundle_data_base64,
            signature: BASE64.encode(vec![3u8; 64]),             // 64 bytes for Ed25519 signature
        };

        // Serialize UploadableKeyBundle to JSON
        let bundle_json = serde_json::to_string(&uploadable_bundle).unwrap();
        let public_key = BASE64.encode(bundle_json.as_bytes());

        let msg = ClientMessage::Register(construct_server::message::RegisterData {
            username: username.to_string(),
            password: password.to_string(),
            public_key,
        });
        self.send(&msg).await?;
        match self.recv().await? {
            Some(ServerMessage::RegisterSuccess(data)) => {
                self.user_id = Some(data.user_id);
                self.username = Some(data.username);
                self.session_token = Some(data.session_token);
                Ok(())
            }
            Some(ServerMessage::Error(e)) => Err(anyhow::anyhow!("Registration failed: {}", e.message)),
            _ => Err(anyhow::anyhow!("Unexpected response")),
        }
    }
}
