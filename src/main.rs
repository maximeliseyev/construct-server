mod message;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use message::{Message, ServerMessage};

#[tokio::main]

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Construct server listening on 127.0.0.1:8080");

    loop {
        let (mut socket, addr) = listener.accept().await?;
        println!("New connection from: {}", addr);

        tokio::spawn(async move {
            let mut buf = vec![0; 1024];

            loop {
                match socket.read(&mut buf).await {
                    Ok(0) => {
                        println!("Connection from {} closed", addr);
                        break;
                    }
                    Ok(n) => {
                        let recieved = String::from_utf8_lossy(&buf[..n]);
                        println!("Recieved from {}: {}", addr, recieved.trim());

                        if socket.write_all(&buf[..n]).await.is_err() {
                            println!("Failed to write to {}", addr);
                            break;
                        }
                    }
                    Err(e) => {
                        println!("Error reading from {}: {}", addr, e);
                        break;
                    }
                }
            }
        });
    }
} 
