// ============================================================================
// Offline Message Delivery Tests
// ============================================================================
//
// Tests for the critical offline message delivery mechanism:
// 1. Messages sent to offline users are queued in Redis
// 2. When user comes online, offline messages are delivered
// 3. Messages are delivered in FIFO order
// 4. Messages expire after TTL
//
// ============================================================================

use construct_server::message::{ChatMessage, ClientMessage, ServerMessage};
use serial_test::serial;
use uuid::Uuid;

mod test_utils;
use test_utils::{TestClient, spawn_app};

#[tokio::test]
#[serial]
async fn test_offline_message_delivery() {
    let app = spawn_app().await;

    // 1. Register Alice and Bob
    let mut alice = TestClient::connect(&app.address).await.unwrap();
    let mut bob = TestClient::connect(&app.address).await.unwrap();

    alice.register("alice", "password").await.unwrap();
    bob.register("bob", "password").await.unwrap();

    let alice_id = alice.user_id.clone().unwrap();
    let bob_id = bob.user_id.clone().unwrap();

    // 2. Bob disconnects (goes offline)
    drop(bob);

    // 3. Alice sends messages to offline Bob
    let msg1 = ChatMessage {
        id: Uuid::new_v4().to_string(),
        from: alice_id.clone(),
        to: bob_id.clone(),
        content: "Message 1".to_string(),
        ephemeral_public_key: vec![0; 32],
        message_number: 0,
        timestamp: chrono::Utc::now().timestamp() as u64,
    };

    let msg2 = ChatMessage {
        id: Uuid::new_v4().to_string(),
        from: alice_id.clone(),
        to: bob_id.clone(),
        content: "Message 2".to_string(),
        ephemeral_public_key: vec![1; 32],
        message_number: 1,
        timestamp: chrono::Utc::now().timestamp() as u64,
    };

    // Send messages while Bob is offline
    alice
        .send(&ClientMessage::SendMessage(msg1.clone()))
        .await
        .unwrap();
    alice
        .send(&ClientMessage::SendMessage(msg2.clone()))
        .await
        .unwrap();

    // Wait a bit for messages to be queued
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // 4. Bob reconnects
    let mut bob = TestClient::connect(&app.address).await.unwrap();
    bob.register("bob", "password").await.unwrap();

    // 5. Bob should receive both messages in order
    let received1 = bob.recv().await.unwrap();
    match received1 {
        Some(ServerMessage::Message(msg)) => {
            assert_eq!(msg.content, "Message 1");
            assert_eq!(msg.from, alice_id);
        }
        _ => panic!("Expected Message 1, got: {:?}", received1),
    }

    let received2 = bob.recv().await.unwrap();
    match received2 {
        Some(ServerMessage::Message(msg)) => {
            assert_eq!(msg.content, "Message 2");
            assert_eq!(msg.from, alice_id);
        }
        _ => panic!("Expected Message 2, got: {:?}", received2),
    }
}

#[tokio::test]
#[serial]
async fn test_offline_message_fifo_order() {
    let app = spawn_app().await;

    let mut alice = TestClient::connect(&app.address).await.unwrap();
    let mut bob = TestClient::connect(&app.address).await.unwrap();

    alice.register("alice", "password").await.unwrap();
    bob.register("bob", "password").await.unwrap();

    let alice_id = alice.user_id.clone().unwrap();
    let bob_id = bob.user_id.clone().unwrap();

    // Bob goes offline
    drop(bob);

    // Send multiple messages
    let messages: Vec<String> = (1..=5).map(|i| format!("Message {}", i)).collect();

    for (i, content) in messages.iter().enumerate() {
        let msg = ChatMessage {
            id: Uuid::new_v4().to_string(),
            from: alice_id.clone(),
            to: bob_id.clone(),
            content: content.clone(),
            ephemeral_public_key: vec![i as u8; 32],
            message_number: i as u32,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        alice.send(&ClientMessage::SendMessage(msg)).await.unwrap();
    }

    // Wait for messages to be queued
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Bob reconnects
    let mut bob = TestClient::connect(&app.address).await.unwrap();
    bob.register("bob", "password").await.unwrap();

    // Verify messages are received in FIFO order
    for (i, expected_content) in messages.iter().enumerate() {
        let received = bob.recv().await.unwrap();
        match received {
            Some(ServerMessage::Message(msg)) => {
                assert_eq!(
                    msg.content,
                    *expected_content,
                    "Message {} should be received in order",
                    i + 1
                );
            }
            _ => panic!("Expected message {}, got: {:?}", i + 1, received),
        }
    }
}

#[tokio::test]
#[serial]
async fn test_offline_message_ack_queued() {
    let app = spawn_app().await;

    let mut alice = TestClient::connect(&app.address).await.unwrap();
    let mut bob = TestClient::connect(&app.address).await.unwrap();

    alice.register("alice", "password").await.unwrap();
    bob.register("bob", "password").await.unwrap();

    let alice_id = alice.user_id.clone().unwrap();
    let bob_id = bob.user_id.clone().unwrap();

    // Bob goes offline
    drop(bob);

    // Alice sends a message
    let msg = ChatMessage {
        id: Uuid::new_v4().to_string(),
        from: alice_id.clone(),
        to: bob_id.clone(),
        content: "Offline message".to_string(),
        ephemeral_public_key: vec![0; 32],
        message_number: 0,
        timestamp: chrono::Utc::now().timestamp() as u64,
    };

    alice
        .send(&ClientMessage::SendMessage(msg.clone()))
        .await
        .unwrap();

    // Alice should receive ACK with "queued" status
    let ack = alice.recv().await.unwrap();
    match ack {
        Some(ServerMessage::Ack(ack_data)) => {
            assert_eq!(ack_data.message_id, msg.id);
            assert_eq!(ack_data.status, "queued");
        }
        _ => panic!("Expected ACK with queued status, got: {:?}", ack),
    }
}
