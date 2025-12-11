use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{accept_async, tungstenite::Message as WsMessage};

mod crypto;
mod db;
mod message;
mod queue;

use base64::{engine::general_purpose, Engine as _};
use db::DbPool;
use message::{ClientMessage, ServerMessage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    let db_pool = db::create_pool(&database_url).await?;
    println!("Connected to database");

    let message_queue = queue::MessageQueue::new(&redis_url).await?;
    println!("Connected to Redis");

    let queue = Arc::new(tokio::sync::Mutex::new(message_queue));

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Construct server listening on 127.0.0.1:8080 (WebSocket)");

    let clients: Clients = Arc::new(RwLock::new(HashMap::new()));

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("New connection from: {}", addr);

        let clients = clients.clone();
        let db_pool = db_pool.clone();
        let queue = queue.clone();

        tokio::spawn(async move {
            // Пытаемся upgrade TCP -> WebSocket
            match accept_async(socket).await {
                Ok(ws_stream) => {
                    println!("WebSocket connection established: {}", addr);
                    handle_websocket(ws_stream, addr, clients, db_pool, queue).await;
                }
                Err(e) => {
                    println!("WebSocket upgrade failed for {}: {}", addr, e);
                }
            }
        });
    }
}

type WebSocketStream = tokio_tungstenite::WebSocketStream<TcpStream>;

async fn handle_websocket(
    ws_stream: WebSocketStream,
    addr: SocketAddr,
    clients: Clients,
    db_pool: DbPool,
    queue: Arc<tokio::sync::Mutex<queue::MessageQueue>>,
) {
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();
    let mut user_id: Option<String> = None;

    loop {
        tokio::select! {
            Some(msg) = ws_receiver.next() => {
                match msg {
                    Ok(WsMessage::Text(text)) => {
                        println!("Received from {}: {}", addr, text);

                        match serde_json::from_str::<ClientMessage>(&text) {
                            Ok(ClientMessage::Register { username, password, public_key }) => {
                                println!("Registration attempt for username: {}", username);

                                let identity_key = match general_purpose::STANDARD.decode(&public_key) {
                                    Ok(key) => key,
                                    Err(e) => {
                                        println!("Invalid public key format: {}", e);
                                        let error = ServerMessage::Error {
                                            reason: "Invalid public key format".to_string()
                                        };
                                        if let Ok(json) = serde_json::to_string(&error) {
                                            let _ = ws_sender.send(WsMessage::Text(json)).await;
                                        }
                                        continue;
                                    }
                                };

                                match db::create_user(&db_pool, &username, &password, &identity_key).await {
                                    Ok(user) => {
                                        println!("User {} registered successfully", username);
                                        let response = ServerMessage::RegisterSuccess {
                                            user_id: user.id.to_string()
                                        };
                                        if let Ok(json) = serde_json::to_string(&response) {
                                            let _ = ws_sender.send(WsMessage::Text(json)).await;
                                        }
                                    }
                                    Err(e) => {
                                        println!("Registration failed: {}", e);
                                        let error = ServerMessage::Error {
                                            reason: "Registration failed. Username may already exist.".to_string()
                                        };
                                        if let Ok(json) = serde_json::to_string(&error) {
                                            let _ = ws_sender.send(WsMessage::Text(json)).await;
                                        }
                                    }
                                }
                            }

                            Ok(ClientMessage::Login { username, password }) => {
                                println!("Login attempt for username: {}", username);

                                match db::get_user_by_username(&db_pool, &username).await {
                                    Ok(Some(user)) => {
                                        if db::verify_password(&user, &password).await.unwrap_or(false) {
                                            println!("User {} logged in successfully", username);
                                            user_id = Some(user.id.to_string());

                                            clients.write().await.insert(user.id.to_string(), tx.clone());
                                            let mut queue_lock = queue.lock().await;
                                            match queue_lock.dequeue_messages(&user.id.to_string()).await {
                                                Ok(messages) => {
                                                    println!("📭 Sending {} queued messages to {}", messages.len(), username);
                                                    for msg in messages {
                                                        let _ = tx.send(ServerMessage::Message(msg));
                                                    }
                                                }
                                                Err(e) => {
                                                    println!("Error dequeuing messages: {}", e);
                                                }
                                            }
                                            drop(queue_lock);

                                            let response = ServerMessage::LoginSuccess {
                                                user_id: user.id.to_string()
                                            };
                                            if let Ok(json) = serde_json::to_string(&response) {
                                                let _ = ws_sender.send(WsMessage::Text(json)).await;
                                            }
                                        } else {
                                            println!("Invalid password for user: {}", username);
                                            let error = ServerMessage::Error {
                                                reason: "Invalid credentials".to_string()
                                            };
                                            if let Ok(json) = serde_json::to_string(&error) {
                                                let _ = ws_sender.send(WsMessage::Text(json)).await;
                                            }
                                        }
                                    }
                                    Ok(None) => {
                                        println!("User not found: {}", username);
                                        let error = ServerMessage::Error {
                                            reason: "Invalid credentials".to_string()
                                        };
                                        if let Ok(json) = serde_json::to_string(&error) {
                                            let _ = ws_sender.send(WsMessage::Text(json)).await;
                                        }
                                    }
                                    Err(e) => {
                                        println!("Database error during login: {}", e);
                                        let error = ServerMessage::Error {
                                            reason: "Server error".to_string()
                                        };
                                        if let Ok(json) = serde_json::to_string(&error) {
                                            let _ = ws_sender.send(WsMessage::Text(json)).await;
                                        }
                                    }
                                }
                            }

                            Ok(ClientMessage::GetPublicKey { username }) => {
                                println!("Public key request for: {}", username);

                                match db::get_user_by_username(&db_pool, &username).await {
                                    Ok(Some(user)) => {
                                        let public_key_b64 = general_purpose::STANDARD.encode(&user.identity_key);

                                        let response = ServerMessage::PublicKey {
                                            user_id: user.id.to_string(),
                                            username: username.clone(),
                                            public_key: public_key_b64,
                                        };
                                        if let Ok(json) = serde_json::to_string(&response) {
                                            let _ = ws_sender.send(WsMessage::Text(json)).await;
                                        }
                                    }
                                    Ok(None) => {
                                        let error = ServerMessage::Error {
                                            reason: format!("User {} not found", username),
                                        };
                                        if let Ok(json) = serde_json::to_string(&error) {
                                            let _ = ws_sender.send(WsMessage::Text(json)).await;
                                        }
                                    }
                                    Err(e) => {
                                        println!("Database error: {}", e);
                                        let error = ServerMessage::Error {
                                            reason: "Server error".to_string(),
                                        };
                                        if let Ok(json) = serde_json::to_string(&error) {
                                            let _ = ws_sender.send(WsMessage::Text(json)).await;
                                        }
                                    }
                                }
                            }

                            Ok(ClientMessage::SendMessage(msg)) => {
                                println!("Routing message from {} to {}", msg.from, msg.to);

                                let clients_read = clients.read().await;
                                if let Some(recipient_tx) = clients_read.get(&msg.to) {
                                    let _ = recipient_tx.send(ServerMessage::Message(msg.clone()));

                                    let ack = ServerMessage::Ack {
                                        id: format!("{}-delivered", addr)
                                    };
                                    if let Ok(json) = serde_json::to_string(&ack) {
                                        let _ = ws_sender.send(WsMessage::Text(json)).await;
                                    }
                                } else {
                                    drop(clients_read);
                                    let mut queue_lock = queue.lock().await;
                                    match queue_lock.enqueue_message(&msg.to, &msg).await {
                                        Ok(_) => {
                                            let ack = ServerMessage::Ack {
                                                id: format!("{}-queued", addr)
                                            };
                                            if let Ok(json) = serde_json::to_string(&ack) {
                                                let _ = ws_sender.send(WsMessage::Text(json)).await;
                                            }
                                        }
                                        Err(e) => {
                                            println!("Error queuing message: {}", e);
                                            let error = ServerMessage::Error {
                                                reason: "Failed to queue message".to_string()
                                            };
                                            if let Ok(json) = serde_json::to_string(&error) {
                                                let _ = ws_sender.send(WsMessage::Text(json)).await;
                                            }
                                        }
                                    }
                                }
                            }

                            Ok(ClientMessage::Logout) => {
                                println!("User logout: {:?}", user_id);
                                break;
                            }

                            Err(e) => {
                                println!("Failed to parse message from {}: {}", addr, e);
                            }
                        }
                    }
                    Ok(WsMessage::Close(_)) => {
                        println!("Connection closed by client: {}", addr);
                        break;
                    }
                    Ok(WsMessage::Ping(data)) => {
                        let _ = ws_sender.send(WsMessage::Pong(data)).await;
                    }
                    Err(e) => {
                        println!("WebSocket error from {}: {}", addr, e);
                        break;
                    }
                    _ => {}
                }
            }

            Some(server_msg) = rx.recv() => {
                if let Ok(json) = serde_json::to_string(&server_msg) {
                    if let Err(e) = ws_sender.send(WsMessage::Text(json)).await {
                        println!("Failed to send to {}: {}", addr, e);
                        break;
                    }
                }
            }
        }
    }

    // Cleanup
    if let Some(uid) = user_id {
        clients.write().await.remove(&uid);
        println!("User {} disconnected", uid);
    }
    println!("Connection closed: {}", addr);
}

type Clients = Arc<RwLock<HashMap<String, mpsc::UnboundedSender<ServerMessage>>>>;
