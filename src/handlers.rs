use crate::auth::AuthManager;
use crate::db::{self, DbPool, User};
use crate::message::{ClientMessage, Message, ServerMessage};
use crate::queue::MessageQueue;
use crate::crypto::{decode_base64, encode_base64};
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
    _addr: SocketAddr, // Marked as _addr because it's only used for logging currently
    clients: Clients,
    db_pool: DbPool,
    queue: Arc<Mutex<MessageQueue>>,
    auth_manager: Arc<AuthManager>,
) {
    println!("New connection from: {}", _addr);

    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();
    let mut user_id: Option<String> = None;

    loop {
        tokio::select! {
            Some(msg) = ws_receiver.next() => {
                match msg {
                    Ok(WsMessage::Text(text)) => {
                        println!("Received from {}: {}", _addr, text);

                        match serde_json::from_str::<ClientMessage>(&text) {
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

                            Ok(ClientMessage::Logout { session_token }) => {
                                handle_logout(
                                    &queue,
                                    &auth_manager,
                                    &mut ws_sender,
                                    &clients, // Added clients here
                                    &user_id, // Added user_id here
                                    session_token,
                                ).await;
                            }

                            Ok(ClientMessage::SearchUsers { query }) => {
                                handle_search_users(&db_pool, &mut ws_sender, query).await;
                            }

                            Ok(ClientMessage::GetPublicKey { user_id: target_user_id }) => {
                                handle_get_public_key(&db_pool, &mut ws_sender, target_user_id).await;
                            }

                            Ok(ClientMessage::SendMessage(mut msg)) => {
                                // Assign a new UUID to the message ID
                                msg.id = Uuid::new_v4().to_string();
                                handle_send_message(&clients, &queue, &mut ws_sender, msg).await;
                            }

                            Err(e) => {
                                println!("Failed to parse message from {}: {}", _addr, e);
                                send_error(&mut ws_sender, "INVALID_FORMAT", "Invalid message format").await;
                            }
                        }
                    }
                    Ok(WsMessage::Close(_)) => {
                        println!("Connection closed by client: {}", _addr);
                        break;
                    }
                    Ok(WsMessage::Ping(data)) => {
                        let _ = ws_sender.send(WsMessage::Pong(data)).await;
                    }
                    Err(e) => {
                        println!("WebSocket error from {}: {}", _addr, e);
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

    if let Some(uid) = user_id {
        clients.write().await.remove(&uid);
    }
    println!("Connection closed: {}", _addr);
}

// === HANDLER FUNCTIONS ===

async fn establish_session(
    clients: &Clients,
    tx: &mpsc::UnboundedSender<ServerMessage>,
    current_user_id: &mut Option<String>,
    user: &db::User,
    queue: &Arc<Mutex<MessageQueue>>,
    jti: &str,
) -> Result<(), String> {
    let uid_str = user.id.to_string();

    let mut queue_lock = queue.lock().await;
    if let Err(e) = queue_lock
        .create_session(jti, &uid_str, TOKEN_ALIVE_TIME)
        .await
    {
        return Err(format!("Failed to create session: {}", e));
    }

    if let Ok(messages) = queue_lock.dequeue_messages(&uid_str).await {
        for msg in messages {
            let _ = tx.send(ServerMessage::Message(msg));
        }
    }
    drop(queue_lock); // Explicitly drop to release the lock early

    *current_user_id = Some(uid_str.clone());
    clients
        .write()
        .await
        .insert(uid_str, tx.clone());
    Ok(())
}

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
    let identity_key = match decode_base64(&public_key) {
        Ok(key) => key,
        Err(_) => {
            send_error(
                ws_sender,
                "INVALID_PUBLIC_KEY",
                "Public key is not valid base64",
            )
            .await;
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

            match auth_manager.create_token(&user.id) {
                Ok((token, jti, expires)) => {
                    if let Err(e_msg) = establish_session(clients, tx, user_id, &user, queue, &jti).await {
                        println!("Failed to establish session: {}", e_msg);
                        send_error(ws_sender, "SESSION_CREATION_FAILED", "Could not create session")
                            .await;
                        return;
                    }

                    let response = ServerMessage::RegisterSuccess {
                        user_id: user.id.to_string(),
                        username: user.username.clone(),
                        display_name: user.display_name.clone(),
                        session_token: token,
                        expires,
                    };
                    send_json(ws_sender, &response).await;
                }
                Err(e) => {
                    println!("Failed to create token: {}", e);
                    send_error(ws_sender, "TOKEN_CREATION_FAILED", "Could not create session token")
                        .await;
                }
            }
        }
        Err(e) => {
            println!("Registration failed: {}", e);
            let (code, message) = if e.to_string().contains("users_username_key") {
                (
                    "USERNAME_TAKEN",
                    format!("Username '{}' is already taken", username),
                )
            } else {
                ("REGISTRATION_FAILED", "Registration failed".to_string())
            };
            send_error(ws_sender, code, &message).await;
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
    match db::get_user_by_username(db_pool, &username).await {
        Ok(Some(user)) => {
            if db::verify_password(&user, &password).await.unwrap_or(false) {
                println!("User logged in: {} (@{})", user.display_name, user.username);

                match auth_manager.create_token(&user.id) {
                    Ok((token, jti, expires)) => {
                        if let Err(e_msg) = establish_session(clients, tx, user_id, &user, queue, &jti).await {
                            println!("Failed to establish session: {}", e_msg);
                            send_error(ws_sender, "SESSION_CREATION_FAILED", "Could not create session")
                                .await;
                            return;
                        }

                        let response = ServerMessage::LoginSuccess {
                            user_id: user.id.to_string(),
                            username: user.username.clone(),
                            display_name: user.display_name.clone(),
                            session_token: token,
                            expires,
                        };
                        send_json(ws_sender, &response).await;
                    }
                    Err(e) => {
                        println!("Failed to create token: {}", e);
                        send_error(
                            ws_sender,
                            "TOKEN_CREATION_FAILED",
                            "Could not create session token",
                        )
                        .await;
                    }
                }
            } else {
                println!("Invalid password for: {}", username);
                send_error(ws_sender, "INVALID_CREDENTIALS", "Invalid credentials").await;
            }
        }
        Ok(None) => {
            println!("User not found: {}", username);
            send_error(ws_sender, "INVALID_CREDENTIALS", "Invalid credentials").await;
        }
        Err(e) => {
            println!("Database error: {}", e);
            send_error(ws_sender, "SERVER_ERROR", "A server error occurred").await;
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
    match auth_manager.verify_token(&session_token) {
        Ok(claims) => {
            let mut queue_lock = queue.lock().await;
            match queue_lock.validate_session(&claims.jti).await {
                Ok(Some(uid)) if uid == claims.sub => {
                    let uuid = match Uuid::parse_str(&uid) {
                        Ok(u) => u,
                        Err(_) => {
                            send_error(ws_sender, "INVALID_USER_ID", "Invalid user ID in token")
                                .await;
                            return;
                        }
                    };

                    match db::get_user_by_id(db_pool, &uuid).await {
                        Ok(Some(user)) => {
                            if let Err(e_msg) = establish_session(clients, tx, user_id, &user, queue, &claims.jti).await {
                                println!("Failed to establish session: {}", e_msg);
                                send_error(ws_sender, "SESSION_CREATION_FAILED", "Could not create session")
                                    .await;
                                return;
                            }

                            let response = ServerMessage::ConnectSuccess {
                                user_id: user.id.to_string(),
                                username: user.username.clone(),
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
            send_error(ws_sender, "INVALID_TOKEN", "Session token is invalid or expired").await;
        }
    }
}

async fn handle_logout(
    queue: &Arc<Mutex<MessageQueue>>,
    auth_manager: &AuthManager,
    ws_sender: &mut futures_util::stream::SplitSink<WebSocketStreamType, WsMessage>,
    clients: &Clients,
    current_user_id: &Option<String>,
    session_token: String,
) {
    if let Ok(claims) = auth_manager.verify_token(&session_token) {
        let mut queue_lock = queue.lock().await;
        let _ = queue_lock.revoke_session(&claims.jti, &claims.sub).await;
        
        if let Some(uid) = current_user_id {
            clients.write().await.remove(uid);
        }
    }
    send_json(ws_sender, &ServerMessage::LogoutSuccess).await;
}

async fn handle_search_users(
    db_pool: &DbPool,
    ws_sender: &mut futures_util::stream::SplitSink<WebSocketStreamType, WsMessage>,
    query: String,
) {
    match db::search_users_by_display_name(db_pool, &query).await {
        Ok(users) => {
            let response = ServerMessage::SearchResults { users };
            send_json(ws_sender, &response).await;
        }
        Err(e) => {
            println!("Search error: {}", e);
            send_error(ws_sender, "SEARCH_FAILED", "Failed to search for users").await;
        }
    }
}

async fn handle_get_public_key(
    db_pool: &DbPool,
    ws_sender: &mut futures_util::stream::SplitSink<WebSocketStreamType, WsMessage>,
    user_id: String,
) {
    match Uuid::parse_str(&user_id) {
        Ok(uuid) => match db::get_user_by_id(db_pool, &uuid).await {
            Ok(Some(user)) => {
                let public_key_b64 = encode_base64(&user.identity_key);
                let response = ServerMessage::PublicKey {
                    user_id: user.id.to_string(),
                    username: user.username.clone(),
                    display_name: user.display_name.clone(),
                    public_key: public_key_b64,
                };
                send_json(ws_sender, &response).await;
            }
            Ok(None) => {
                send_error(
                    ws_sender,
                    "USER_NOT_FOUND",
                    &format!("User {} not found", user_id),
                )
                .await;
            }
            Err(e) => {
                println!("Database error: {}", e);
                send_error(ws_sender, "SERVER_ERROR", "A server error occurred").await;
            }
        },
        Err(_) => {
            send_error(ws_sender, "INVALID_USER_ID", "Invalid user ID format").await;
        }
    }
}

async fn handle_send_message(
    clients: &Clients,
    queue: &Arc<Mutex<MessageQueue>>,
    ws_sender: &mut futures_util::stream::SplitSink<WebSocketStreamType, WsMessage>,
    msg: Message,
) {
    let clients_read = clients.read().await;
    if let Some(recipient_tx) = clients_read.get(&msg.to) {
        let _ = recipient_tx.send(ServerMessage::Message(msg.clone()));
        let ack = ServerMessage::Ack {
            message_id: msg.id,
            status: "delivered".to_string(),
        };
        send_json(ws_sender, &ack).await;
    } else {
        drop(clients_read);
        let mut queue_lock = queue.lock().await;
        match queue_lock.enqueue_message(&msg.to, &msg).await {
            Ok(_) => {
                let ack = ServerMessage::Ack {
                    message_id: msg.id,
                    status: "queued".to_string(),
                };
                send_json(ws_sender, &ack).await;
            }
            Err(e) => {
                println!("Error queuing message: {}", e);
                send_error(ws_sender, "QUEUE_FAILED", "Failed to queue message").await;
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
    code: &str,
    message: &str,
) {
    let error = ServerMessage::Error {
        code: code.to_string(),
        message: message.to_string(),
    };
    send_json(ws_sender, &error).await;
}
