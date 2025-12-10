mod crypto;
mod db;
mod message;
mod queue;

use base64::{engine::general_purpose, Engine as _};
use db::DbPool;
use message::{ClientMessage, ServerMessage};
use queue::MessageQueue;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};

type Clients = Arc<RwLock<HashMap<String, mpsc::UnboundedSender<ServerMessage>>>>;

#[tokio::main]

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let db_pool = db::create_pool(&database_url).await?;
    println!("Connected to database!");

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    let message_queue = MessageQueue::new(&redis_url).await?;
    println!("Connected to Redis");

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Construct server listening on 127.0.0.1:8080");

    let clients: Clients = Arc::new(RwLock::new(HashMap::new()));
    let queue = Arc::new(tokio::sync::Mutex::new(message_queue));

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("New connection from: {}", addr);

        let clients = clients.clone();
        let db_pool = db_pool.clone();
        let queue = queue.clone();

        tokio::spawn(async move {
            handle_client(socket, addr, clients, db_pool, queue).await;
        });
    }
}

async fn handle_client(
    mut socket: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    clients: Clients,
    db_pool: DbPool,
    queue: Arc<tokio::sync::Mutex<MessageQueue>>,
) {
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();
    let mut user_id: Option<String> = None;
    let mut buf = vec![0; 4096];

    loop {
        tokio::select! {
            resut = socket.read(&mut buf) => {
                match resut {
                    Ok(0) => {
                        println!("Connection from {} closed", addr);
                        break;
                    }
                    Ok(n) => {
                        match serde_json::from_slice::<ClientMessage>(&buf[..n]) {
                            Ok(ClientMessage::Register { username, password, public_key }) => {
                                println!("Registration attempt for username: {}", username);

                                let identity_key = match general_purpose::STANDARD.decode(&public_key) {
                                    Ok(key) => key,
                                    Err(e) => {
                                        println!("Invalid public key format: {}", e);
                                        let error = ServerMessage::Error {
                                            reason: "Invalid public key format".to_string()
                                        };
                                        if let Ok(json) = serde_json::to_vec(&error) {
                                            let _ = socket.write_all(&json).await;
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
                                            if let Ok(json) = serde_json::to_vec(&response) {
                                                let _ = socket.write_all(&json).await;
                                            }
                                    }
                                    Err(e) => {
                                        println!("Registration failed: {}", e);
                                        let error = ServerMessage::Error {
                                            reason: "Registration failed. Username may already exist.".to_string()
                                        };
                                        if let Ok(json) = serde_json::to_vec(&error) {
                                            let _ = socket.write_all(&json).await;
                                        }
                                    }
                                }
                            }
                            Ok(ClientMessage::GetPublicKey { username }) => {
                                println!("Public key request for: {}", username);

                                match db::get_user_by_username(&db_pool, &username).await {
                                    Ok(Some(user)) => {
                                        use base64::{engine::general_purpose, Engine as _};
                                        let public_key_b64 = general_purpose::STANDARD.encode(&user.identity_key);

                                        let response = ServerMessage::PublicKey {
                                            user_id: user.id.to_string(),
                                            username: username.clone(),
                                            public_key: public_key_b64,
                                        };
                                        if let Ok(json) = serde_json::to_vec(&response) {
                                            let _ = socket.write_all(&json).await;
                                        }
                                    }
                                    Ok(None) => {
                                        let error = ServerMessage::Error {
                                            reason: format!("User {} not found", username),
                                        };
                                        if let Ok(json) = serde_json::to_vec(&error) {
                                            let _ = socket.write_all(&json).await;
                                        }
                                    }
                                    Err(e) => {
                                        println!("Database error: {}", e);
                                        let error = ServerMessage::Error {
                                            reason: "Server error".to_string(),
                                        };
                                        if let Ok(json) = serde_json::to_vec(&error) {
                                            let _ = socket.write_all(&json).await;
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
                                            if let Ok(json) = serde_json::to_vec(&response) {
                                                let _ = socket.write_all(&json).await;
                                            }
                                        } else {
                                            println!("Invalid password for user {}", username);
                                            let error = ServerMessage::Error {
                                                reason: "Invalid username or password".to_string()
                                            };
                                            if let Ok(json) = serde_json::to_vec(&error) {
                                                let _ = socket.write_all(&json).await;
                                            }
                                        }
                                    }
                                    Ok(None) => {
                                        println!("User {} not found", username);
                                        let error = ServerMessage::Error {
                                            reason: "Invalid username or password".to_string()
                                        };
                                        if let Ok(json) = serde_json::to_vec(&error) {
                                            let _ = socket.write_all(&json).await;
                                        }
                                    }
                                    Err(e) => {
                                        println!("Database error: {}", e);
                                        let error = ServerMessage::Error {
                                            reason: "Server error".to_string()
                                        };
                                        if let Ok(json) = serde_json::to_vec(&error) {
                                            let _ = socket.write_all(&json).await;
                                        }
                                    }
                                }
                            }
                            Ok(ClientMessage::SendMessage(msg)) => {
                                println!("Routing message from {} to {}", msg.from, msg.to);

                                let clients_read = clients.read().await;
                                if let Some(recipient_tx) = clients_read.get(&msg.to) {

                                    let _ = recipient_tx.send(ServerMessage::Message(msg.clone()));


                                    let ack = ServerMessage::Ack { id: format!("{}-delivered", addr) };
                                    if let Ok(json) = serde_json::to_vec(&ack) {
                                        let _ = socket.write_all(&json).await;
                                    }
                                } else {

                                    let mut queue_lock = queue.lock().await;
                                    match queue_lock.enqueue_message(&msg.to, &msg).await {
                                        Ok(_) => {
                                            let ack = ServerMessage::Ack {
                                                id: format!("{}-queued", addr)
                                            };
                                            if let Ok(json) = serde_json::to_vec(&ack) {
                                                let _ = socket.write_all(&json).await;
                                            }
                                        }
                                        Err(e) => {
                                            println!("Error queuing message: {}", e);
                                            let error = ServerMessage::Error {
                                                reason: "Failed to queue message".to_string()
                                            };
                                            if let Ok(json) = serde_json::to_vec(&error) {
                                                let _ = socket.write_all(&json).await;
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(ClientMessage::Logout) => {
                                println!("User {:?} logging out", user_id);
                                break;
                            }
                            Err(e) => {
                                println!("Failed to parse message from {}: {}", addr, e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("Error reading from {}: {}", addr, e);
                        break;
                    }
                }
            }
            Some(msg) = rx.recv() => {
                if let Ok(json) = serde_json::to_vec(&msg) && socket.write_all(&json).await.is_err() {
                } else {
                    break;
                }
            }
        }
    }

    if let Some(uid) = user_id {
        clients.write().await.remove(&uid);
        println!("User {} removed from clients", uid);
    }
}
