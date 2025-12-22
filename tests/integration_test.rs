use construct_server::message::{ChatMessage, ClientMessage, ServerMessage};
use serial_test::serial;
use uuid::Uuid;

mod test_utils;
use test_utils::{spawn_app, TestClient};

#[tokio::test]
#[serial]
async fn test_message_flow_success() {
    let app = spawn_app().await;
    let mut alice = TestClient::connect(&app.address).await.unwrap();
    let mut bob = TestClient::connect(&app.address).await.unwrap();

    // Register users
    alice.register("alice", "password").await.unwrap();
    bob.register("bob", "password").await.unwrap();

    let bob_id = bob.user_id.clone().unwrap();

    // Alice sends a message to Bob
    let msg = ChatMessage {
        id: Uuid::new_v4().to_string(),
        from: alice.user_id.clone().unwrap(),
        to: bob_id,
        content: "Hello, Bob!".to_string(),
        ephemeral_public_key: vec![0; 32],
        message_number: 0,
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    alice
        .send(&ClientMessage::SendMessage(msg.clone()))
        .await
        .unwrap();

    // Bob should receive the message
    let received = bob.recv().await.unwrap();
    match received {
        Some(ServerMessage::Message(received_msg)) => {
            assert_eq!(received_msg.content, "Hello, Bob!");
        }
        _ => panic!("Expected to receive a message"),
    }
}

#[tokio::test]
#[serial]
async fn test_message_spoofing_is_prevented() {
    let app = spawn_app().await;
    let mut alice = TestClient::connect(&app.address).await.unwrap();
    let mut eve = TestClient::connect(&app.address).await.unwrap();

    // Register users
    alice.register("alice", "password").await.unwrap();
    eve.register("eve", "password").await.unwrap();

    let alice_id = alice.user_id.clone().unwrap();

    // Eve tries to send a message *from* Alice
    let spoofed_msg = ChatMessage {
        id: Uuid::new_v4().to_string(),
        from: alice_id, // Eve is trying to impersonate Alice
        to: eve.user_id.clone().unwrap(),
        content: "I am Alice".to_string(),
        ephemeral_public_key: vec![0; 32],
        message_number: 0,
        timestamp: chrono::Utc::now().timestamp() as u64,
    };

    eve.send(&ClientMessage::SendMessage(spoofed_msg))
        .await
        .unwrap();

    // Eve should receive a FORBIDDEN error
    let received = eve.recv().await.unwrap();
    match received {
        Some(ServerMessage::Error(e)) => {
            assert_eq!(e.code, "FORBIDDEN");
        }
        _ => panic!("Expected to receive a FORBIDDEN error"),
    }
}