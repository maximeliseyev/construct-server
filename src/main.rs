mod message;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{RwLock, mpsc};
use std::collections::HashMap;
use std::sync::Arc;
use message::{ClientMessage, ServerMessage};

type Clients = Arc<RwLock<HashMap<String, mpsc::UnboundedSender<ServerMessage>>>>;


#[tokio::main]

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Construct server listening on 127.0.0.1:8080");

    let clients: Clients = Arc::new(RwLock::new(HashMap::new()));

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("New connection from: {}", addr);

        let clients = clients.clone();

        tokio::spawn(async move {
            handle_client(socket, addr, clients).await;
        });
    }
}

async fn handle_client(
    mut socket: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    clients: Clients,
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
                            Ok(ClientMessage::Login { user_id: uid }) => {
                                println!("User {} logged in from {}", uid, addr);
                                user_id = Some(uid.clone());
                                
                                clients.write().await.insert(uid.clone(), tx.clone());
                                
                                let response = ServerMessage::LoginSuccess { user_id: uid };
                                if let Ok(json) = serde_json::to_vec(&response) {
                                    let _ = socket.write_all(&json).await;
                                }
                            }
                            Ok(ClientMessage::SendMessage(msg)) => {
                                println!("Routing message from {} to {}", msg.from, msg.to);
                                
                                let clients_read = clients.read().await;
                                if let Some(recipient_tx) = clients_read.get(&msg.to) {
                                    // Отправляем через channel
                                    let _ = recipient_tx.send(ServerMessage::Message(msg.clone()));
                                    
                                    // Подтверждение отправителю
                                    let ack = ServerMessage::Ack { id: format!("{}-delivered", addr) };
                                    if let Ok(json) = serde_json::to_vec(&ack) {
                                        let _ = socket.write_all(&json).await;
                                    }
                                } else {
                                    // Пользователь офлайн
                                    let error = ServerMessage::Error { 
                                        reason: format!("User {} is offline", msg.to) 
                                    };
                                    if let Ok(json) = serde_json::to_vec(&error) {
                                        let _ = socket.write_all(&json).await;
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
                if let Ok(json) = serde_json::to_vec(&msg) {
                    if socket.write_all(&json).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    if let Some(uid) = user_id {
        clients.write().await.remove(&uid);
        println!("User {} removed from clients", uid);
    }

}



