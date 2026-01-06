// tests/handshake_test.rs

use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http1::handshake;
use hyper::{header, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serial_test::serial;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;

mod test_utils;
use test_utils::spawn_app;

#[tokio::test]
#[serial]
async fn test_websocket_handshake_is_correct() {
    // 1. Arrange
    let app = spawn_app().await;
    let addr: SocketAddr = app.address.parse().unwrap();

    // The key we'll send to the server
    let client_key = generate_key();

    // Manually build an HTTP GET request with WebSocket upgrade headers
    let request = Request::builder()
        .uri(format!("ws://{}/", app.address))
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "websocket")
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .header(header::SEC_WEBSOCKET_KEY, &client_key)
        .body(Full::<Bytes>::new(Bytes::new()))
        .unwrap();

    // 2. Act
    // Manually open a TCP stream and send the request
    let stream = TcpStream::connect(addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = handshake(io).await.unwrap();
    tokio::spawn(conn);
    let response = sender.send_request(request).await.unwrap();

    // 3. Assert
    // Check that the server returned "101 Switching Protocols"
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

    // Check that the server sent back the correct 'Sec-WebSocket-Accept' header
    let headers = response.headers();
    let accept_header = headers
        .get(header::SEC_WEBSOCKET_ACCEPT)
        .unwrap()
        .to_str()
        .unwrap();

    // This is how the server should calculate the accept key
    let expected_key =
        tokio_tungstenite::tungstenite::handshake::derive_accept_key(client_key.as_bytes());

    assert_eq!(accept_header, expected_key);
}

#[tokio::test]
#[serial]
async fn test_websocket_handshake_fails_without_key() {
    // 1. Arrange
    let app = spawn_app().await;
    let addr: SocketAddr = app.address.parse().unwrap();

    // Build a request *without* the Sec-WebSocket-Key
    let request = Request::builder()
        .uri(format!("http://{}/", app.address))
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "websocket")
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .body(Full::<Bytes>::new(Bytes::new()))
        .unwrap();

    // 2. Act
    let stream = TcpStream::connect(addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = handshake(io).await.unwrap();
    tokio::spawn(conn);
    let response = sender.send_request(request).await.unwrap();

    // 3. Assert
    // Check that the server correctly rejects the request
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
