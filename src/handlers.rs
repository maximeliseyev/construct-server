use crate::auth::AuthManager;
use crate::db::{self, DbPool};
use crate::message::{ClientMessage, Message, ServerMessage};
use crate::queue::MessageQueue;
use base64::{engine::general_purpose, Engine as _};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::{Mutex, RwLock};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::WebSocketStream;
use uuid::Uuid;

const TOKEN_ALIVE_TIME: i64 = 2592000;

pub type Clients = Arc<RwLock<HashMap<String, mpsc::UnboundedSender<ServerMessage>>>>;
type WebSocketStreamType = WebSocketStream<TcpStream>;

pub async fn handle_websocket(
    ws_stream: WebSocketStreamType,
    addr: SocketAddr,
    clients: Clients,
    db_pool: DbPool,
    queue: Arc<Mutex<MessageQueue>>,
    auth_manager: Arc<AuthManager>,
) {
    println!("New connection from: {}", addr);

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
                            // REGISTER - создаём пользователя + JWT
                            Ok(ClientMessage::Register { username, display_name, password, public_key }) => {
                                handle_register(
                                    &db_pool,
                                    &queue,
                                    &auth_manager,
                                    &mut ws_sender,
                                    &tx,
                                    &clients,
                                    &mut user_id,
                                    username,
                                    display_name,
                                    password,
                                    public_key,
                                ).await;
                            }

                            // LOGIN - проверяем пароль + создаём JWT
                            Ok(ClientMessage::Login { username, password }) => {
                                handle_login(
                                    &db_pool,
                                    &queue,
                                    &auth_manager,
                                    &mut ws_sender,
                                    &tx,
                                    &clients,
                                    &mut user_id,
                                    username,
                                    password,
                                ).await;
                            }

                            // CONNECT - проверяем JWT + Redis session
                            Ok(ClientMessage::Connect { session_token }) => {
                                handle_connect(
                                    &db_pool,
                                    &queue,
                                    &auth_manager,
                                    &mut ws_sender,
                                    &tx,
                                    &clients,
                                    &mut user_id,
                                    session_token,
                                ).await;
                            }

                            // LOGOUT - удаляем session из Redis
                            Ok(ClientMessage::Logout { session_token }) => {
                                handle_logout(
                                    &queue,
                                    &auth_manager,
                                    &mut ws_sender,
                                    session_token,
                                ).await;
                            }

                            // SEARCH USERS
                            Ok(ClientMessage::SearchUsers { query }) => {
                                handle_search_users(&db_pool, &mut ws_sender, query).await;
                            }

                            // GET PUBLIC KEY
                            Ok(ClientMessage::GetPublicKey { user_id: target_user_id }) => {
                                handle_get_public_key(&db_pool, &mut ws_sender, target_user_id).await;
                            }

                            // SEND MESSAGE
                            Ok(ClientMessage::SendMessage(msg)) => {
                                handle_send_message(&clients, &queue, &mut ws_sender, addr, msg).await;
                            }

                            Err(e) => {
                                println!("Failed to parse message from {}: {}", addr, e);
                                send_error(&mut ws_sender, "Invalid message format").await;
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
                    if ws_sender.send(WsMessage::Text(json)).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    // Cleanup
    if let Some(uid) = user_id {
        clients.write().await.remove(&uid);
    }
    println!("Connection closed: {}", addr);
}

// === HANDLER FUNCTIONS ===

async fn handle_register(
    db_pool: &DbPool,
    queue: &Arc<Mutex<MessageQueue>>,
    auth_manager: &AuthManager,
    ws_sender: &mut futures_util::stream::SplitSink<WebSocketStreamType, WsMessage>,
    tx: &mpsc::UnboundedSender<ServerMessage>,
    clients: &Clients,
    user_id: &mut Option<String>,
    username: String,
    display_name: Option<String>,
    password: String,
    public_key: String,
) {
    println!(
        "Registration: username={}, display_name={:?}",
        username, display_name
    );

    let identity_key = match general_purpose::STANDARD.decode(&public_key) {
        Ok(key) => key,
        Err(e) => {
            println!("Invalid public key format: {}", e);
            send_error(ws_sender, "Invalid public key format").await;
            return;
        }
    };

    let display_name_final = display_name.as_deref().unwrap_or(&username);

    match db::create_user(
        db_pool,
        &username,
        display_name_final,
        &password,
        &identity_key,
    )
    .await
    {
        Ok(user) => {
            println!(
                "User registered: {} (@{})",
                user.display_name, user.username
            );

            // Создаём JWT токен
            match auth_manager.create_token(&user.id) {
                Ok((token, jti, expires_at)) => {
                    let mut queue_lock = queue.lock().await;
                    if let Err(e) = queue_lock
                        .create_session(&jti, &user.id.to_string(), TOKEN_ALIVE_TIME)
                        .await
                    {
                        println!("Failed to create session: {}", e);
                        send_error(ws_sender, "Failed to create session").await;
                        return;
                    }
                    drop(queue_lock);

                    *user_id = Some(user.id.to_string());
                    clients
                        .write()
                        .await
                        .insert(user.id.to_string(), tx.clone());

                    let response = ServerMessage::RegisterSuccess {
                        user_id: user.id.to_string(),
                        username: user.username.clone(),
                        display_name: user.display_name.clone(),
                        session_token: token,
                        expires_at,
                    };
                    send_json(ws_sender, &response).await;
                }
                Err(e) => {
                    println!("Failed to create token: {}", e);
                    send_error(ws_sender, "Failed to create session token").await;
                }
            }
        }
        Err(e) => {
            println!("Registration failed: {}", e);
            let reason = if e.to_string().contains("users_username_key") {
                format!("Username '{}' is already taken", username)
            } else {
                "Registration failed".to_string()
            };
            send_error(ws_sender, &reason).await;
        }
    }
}

async fn handle_login(
    db_pool: &DbPool,
    queue: &Arc<Mutex<MessageQueue>>,
    auth_manager: &AuthManager,
    ws_sender: &mut futures_util::stream::SplitSink<WebSocketStreamType, WsMessage>,
    tx: &mpsc::UnboundedSender<ServerMessage>,
    clients: &Clients,
    user_id: &mut Option<String>,
    username: String,
    password: String,
) {
    println!("Login attempt: {}", username);

    match db::get_user_by_username(db_pool, &username).await {
        Ok(Some(user)) => {
            if db::verify_password(&user, &password).await.unwrap_or(false) {
                println!("User logged in: {} (@{})", user.display_name, user.username);

                match auth_manager.create_token(&user.id) {
                    Ok((token, jti, expires_at)) => {
                        let mut queue_lock = queue.lock().await;
                        if let Err(e) = queue_lock
                            .create_session(&jti, &user.id.to_string(), TOKEN_ALIVE_TIME)
                            .await
                        {
                            println!("Failed to create session: {}", e);
                            send_error(ws_sender, "Failed to create session").await;
                            return;
                        }

                        match queue_lock.dequeue_messages(&user.id.to_string()).await {
                            Ok(messages) => {
                                println!("Sending {} queued messages", messages.len());
                                for msg in messages {
                                    let _ = tx.send(ServerMessage::Message(msg));
                                }
                            }
                            Err(e) => {
                                println!("Error dequeuing messages: {}", e);
                            }
                        }
                        drop(queue_lock);

                        *user_id = Some(user.id.to_string());
                        clients
                            .write()
                            .await
                            .insert(user.id.to_string(), tx.clone());

                        let response = ServerMessage::LoginSuccess {
                            user_id: user.id.to_string(),
                            username: user.username.clone(),
                            display_name: user.display_name.clone(),
                            session_token: token,
                            expires_at,
                        };
                        send_json(ws_sender, &response).await;
                    }
                    Err(e) => {
                        println!("Failed to create token: {}", e);
                        send_error(ws_sender, "Failed to create session token").await;
                    }
                }
            } else {
                println!("Invalid password for: {}", username);
                send_error(ws_sender, "Invalid credentials").await;
            }
        }
        Ok(None) => {
            println!("User not found: {}", username);
            send_error(ws_sender, "Invalid credentials").await;
        }
        Err(e) => {
            println!("Database error: {}", e);
            send_error(ws_sender, "Server error").await;
        }
    }
}

async fn handle_connect(
    db_pool: &DbPool,
    queue: &Arc<Mutex<MessageQueue>>,
    auth_manager: &AuthManager,
    ws_sender: &mut futures_util::stream::SplitSink<WebSocketStreamType, WsMessage>,
    tx: &mpsc::UnboundedSender<ServerMessage>,
    clients: &Clients,
    user_id: &mut Option<String>,
    session_token: String,
) {
    println!("Connect attempt with token");

    match auth_manager.verify_token(&session_token) {
        Ok(claims) => {
            // 2. Проверяем в Redis whitelist
            let mut queue_lock = queue.lock().await;
            match queue_lock.validate_session(&claims.jti).await {
                Ok(Some(uid)) if uid == claims.sub => {
                    // Session valid!
                    let uuid = match Uuid::parse_str(&uid) {
                        Ok(u) => u,
                        Err(_) => {
                            send_error(ws_sender, "Invalid user ID").await;
                            return;
                        }
                    };

                    match db::get_user_by_id(db_pool, &uuid).await {
                        Ok(Some(user)) => {
                            *user_id = Some(user.id.to_string());
                            clients
                                .write()
                                .await
                                .insert(user.id.to_string(), tx.clone());

                            // Отправляем offline messages
                            match queue_lock.dequeue_messages(&user.id.to_string()).await {
                                Ok(messages) => {
                                    println!("📭 Sending {} queued messages", messages.len());
                                    for msg in messages {
                                        let _ = tx.send(ServerMessage::Message(msg));
                                    }
                                }
                                Err(e) => println!("Error dequeuing: {}", e),
                            }
                            drop(queue_lock);

                            let response = ServerMessage::ConnectSuccess {
                                user_id: user.id.to_string(),
                                display_name: user.display_name.clone(),
                            };
                            send_json(ws_sender, &response).await;
                        }
                        _ => {
                            send_json(ws_sender, &ServerMessage::SessionExpired).await;
                        }
                    }
                }
                _ => {
                    send_json(ws_sender, &ServerMessage::SessionExpired).await;
                }
            }
        }
        Err(_) => {
            send_error(ws_sender, "Invalid token").await;
        }
    }
}

async fn handle_logout(
    queue: &Arc<Mutex<MessageQueue>>,
    auth_manager: &AuthManager,
    ws_sender: &mut futures_util::stream::SplitSink<WebSocketStreamType, WsMessage>,
    session_token: String,
) {
    if let Ok(claims) = auth_manager.verify_token(&session_token) {
        let mut queue_lock = queue.lock().await;
        let _ = queue_lock.revoke_session(&claims.jti, &claims.sub).await;
    }

    let response = ServerMessage::Ack {
        id: "logged_out".to_string(),
    };
    send_json(ws_sender, &response).await;
}

async fn handle_search_users(
    db_pool: &DbPool,
    ws_sender: &mut futures_util::stream::SplitSink<WebSocketStreamType, WsMessage>,
    query: String,
) {
    println!("Search users: '{}'", query);

    match db::search_users_by_display_name(db_pool, &query).await {
        Ok(users) => {
            println!("Found {} users", users.len());
            let response = ServerMessage::SearchResults { users };
            send_json(ws_sender, &response).await;
        }
        Err(e) => {
            println!("Search error: {}", e);
            send_error(ws_sender, "Search failed").await;
        }
    }
}

async fn handle_get_public_key(
    db_pool: &DbPool,
    ws_sender: &mut futures_util::stream::SplitSink<WebSocketStreamType, WsMessage>,
    user_id: String,
) {
    println!("Public key request for user_id: {}", user_id);

    match Uuid::parse_str(&user_id) {
        Ok(uuid) => match db::get_user_by_id(db_pool, &uuid).await {
            Ok(Some(user)) => {
                let public_key_b64 = general_purpose::STANDARD.encode(&user.identity_key);

                let response = ServerMessage::PublicKey {
                    user_id: user.id.to_string(),
                    username: user.username.clone(),
                    display_name: user.display_name.clone(),
                    public_key: public_key_b64,
                };
                send_json(ws_sender, &response).await;
            }
            Ok(None) => {
                send_error(ws_sender, &format!("User {} not found", user_id)).await;
            }
            Err(e) => {
                println!("Database error: {}", e);
                send_error(ws_sender, "Server error").await;
            }
        },
        Err(_) => {
            send_error(ws_sender, "Invalid user_id format").await;
        }
    }
}

async fn handle_send_message(
    clients: &Clients,
    queue: &Arc<Mutex<MessageQueue>>,
    ws_sender: &mut futures_util::stream::SplitSink<WebSocketStreamType, WsMessage>,
    addr: SocketAddr,
    msg: Message,
) {
    println!("Routing message from {} to {}", msg.from, msg.to);

    let clients_read = clients.read().await;
    if let Some(recipient_tx) = clients_read.get(&msg.to) {
        // Online - deliver immediately
        let _ = recipient_tx.send(ServerMessage::Message(msg.clone()));

        let ack = ServerMessage::Ack {
            id: format!("{}-delivered", addr),
        };
        send_json(ws_sender, &ack).await;
    } else {
        // Offline - queue in Redis
        drop(clients_read);
        let mut queue_lock = queue.lock().await;
        match queue_lock.enqueue_message(&msg.to, &msg).await {
            Ok(_) => {
                let ack = ServerMessage::Ack {
                    id: format!("{}-queued", addr),
                };
                send_json(ws_sender, &ack).await;
            }
            Err(e) => {
                println!("Error queuing message: {}", e);
                send_error(ws_sender, "Failed to queue message").await;
            }
        }
    }
}

// === HELPER FUNCTIONS ===

 async fn send_json(
    ws_sender: &mut futures_util::stream::SplitSink<WebSocketStreamType, WsMessage>,
    msg: &ServerMessage,
) {
    if let Ok(json) = serde_json::to_string(msg) {
        let _ = ws_sender.send(WsMessage::Text(json)).await;
    }
}

async fn send_error(
    ws_sender: &mut futures_util::stream::SplitSink<WebSocketStreamType, WsMessage>,
    reason: &str,
) {
    let error = ServerMessage::Error {
        reason: reason.to_string(),
    };
    send_json(ws_sender, &error).await;
}
