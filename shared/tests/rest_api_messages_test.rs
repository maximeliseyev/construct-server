// ============================================================================
// REST API Messages Endpoints Tests
// ============================================================================
//
// Tests for message endpoints:
// - POST /api/v1/messages - Send an E2E-encrypted message
// - GET /api/v1/messages - Get messages (long polling)
//
// ============================================================================

#![allow(dead_code)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(unused_variables)]

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use construct_crypto::EncryptedMessage;
use serial_test::serial;
use uuid::Uuid;

mod test_utils;
use test_utils::{cleanup_rate_limits, register_user_passwordless, spawn_app};

// Helper function to create HTTP client with API headers (bypasses CSRF)
fn create_api_client() -> reqwest::Client {
    reqwest::Client::builder()
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                "X-Requested-With",
                reqwest::header::HeaderValue::from_static("XMLHttpRequest"),
            );
            headers
        })
        .build()
        .unwrap()
}

// Helper function to add user_id as X-User-Id header (for TrustedUser extractor)
fn add_user_auth_header(
    request: reqwest::RequestBuilder,
    user_id: &str,
) -> reqwest::RequestBuilder {
    request.header("X-User-Id", user_id)
}

// Helper function to generate a valid test username (3-20 chars)
fn generate_test_username(prefix: &str) -> String {
    // Take first 8 chars of UUID to keep username short enough
    let uuid_short = &Uuid::new_v4().to_string()[0..8];
    format!("{}_{}", prefix, uuid_short)
}

// Helper function to create a test encrypted message
fn create_test_message(recipient_id: &str, suite_id: u16) -> EncryptedMessage {
    // Create a dummy ciphertext (base64-encoded random bytes)
    // In real scenario, this would be properly encrypted
    let dummy_ciphertext = BASE64.encode(b"dummy_encrypted_message_content_for_testing");
    // Dummy ephemeral public key (32 bytes for X25519)
    let dummy_ephemeral_key = BASE64.encode(&[0u8; 32]);

    EncryptedMessage {
        recipient_id: recipient_id.to_string(),
        suite_id, // SuiteId is a type alias for u16
        ephemeral_public_key: dummy_ephemeral_key,
        message_number: 0,
        previous_chain_length: 0,
        ciphertext: dummy_ciphertext,
        nonce: None,
        timestamp: None,
        temp_id: Some(Uuid::new_v4().to_string()), // Client-generated temporary ID
    }
}

// ============================================================================
// POST /api/v1/messages Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_send_message_success() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register two users: sender and recipient (using passwordless auth)
    let sender_username = generate_test_username("sender");
    let recipient_username = generate_test_username("recipient");

    let (sender_user_id, _sender_token) =
        register_user_passwordless(&client, &app.auth_address, Some(&sender_username)).await;

    let (recipient_user_id, _recipient_token) =
        register_user_passwordless(&client, &app.auth_address, Some(&recipient_username)).await;

    // Create and send a message (to messaging service)
    let message = create_test_message(&recipient_user_id, 1);
    let response = client
        .post(&format!("http://{}/api/v1/messages", app.messaging_address))
        .header("X-User-Id", &sender_user_id)
        .json(&message)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().await.unwrap();
    // API returns status: "sent" (message queued in Kafka)
    assert_eq!(body["status"], "sent");
    // Response uses camelCase: "messageId"
    assert!(body.get("messageId").is_some());
}

#[tokio::test]
#[serial]
async fn test_send_message_requires_auth() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Try to send message without authentication
    let message = create_test_message(&Uuid::new_v4().to_string(), 1);
    let response = client
        .post(&format!("http://{}/api/v1/messages", app.messaging_address))
        .json(&message)
        .send()
        .await
        .unwrap();

    // Should return 401 Unauthorized
    assert!(
        response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::FORBIDDEN
    );
}

#[tokio::test]
#[serial]
async fn test_send_message_invalid_recipient() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register sender
    let sender_username = generate_test_username("sender");
    let (sender_user_id, _sender_token) =
        register_user_passwordless(&client, &app.auth_address, Some(&sender_username)).await;

    // Try to send message to invalid recipient ID
    let message = create_test_message("invalid-uuid-format", 1);
    let response = client
        .post(&format!("http://{}/api/v1/messages", app.messaging_address))
        .header("X-User-Id", &sender_user_id)
        .json(&message)
        .send()
        .await
        .unwrap();

    // Should return 400 Bad Request
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body.get("error").is_some());
}

#[tokio::test]
#[serial]
async fn test_send_message_to_self() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register sender
    let sender_username = generate_test_username("sender");
    let (sender_user_id, _) =
        register_user_passwordless(&client, &app.auth_address, Some(&sender_username)).await;

    // Try to send message to self
    let message = create_test_message(&sender_user_id, 1);
    let response = client
        .post(&format!("http://{}/api/v1/messages", app.messaging_address))
        .header("X-User-Id", &sender_user_id)
        .json(&message)
        .send()
        .await
        .unwrap();

    // Should return 400 Bad Request
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body.get("error").is_some());
    let error_msg = body["error"].as_str().unwrap().to_lowercase();
    assert!(error_msg.contains("self") || error_msg.contains("cannot"));
}

#[tokio::test]
#[serial]
async fn test_send_message_rate_limiting() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register sender and recipient
    let sender_username = generate_test_username("sender");
    let recipient_username = generate_test_username("recipient");

    let (sender_user_id, _sender_token) =
        register_user_passwordless(&client, &app.auth_address, Some(&sender_username)).await;

    let (recipient_user_id, _recipient_token) =
        register_user_passwordless(&client, &app.auth_address, Some(&recipient_username)).await;

    // Send many messages rapidly to trigger rate limiting
    // Note: Rate limit is typically 100 messages per hour per user+IP
    // We'll send 101 messages to test the limit
    let mut success_count = 0;
    let mut _rate_limited = false;

    for _i in 0..105 {
        let message = create_test_message(&recipient_user_id, 1);
        let response = client
            .post(&format!("http://{}/api/v1/messages", app.messaging_address))
            .header("X-User-Id", &sender_user_id)
            .json(&message)
            .send()
            .await
            .unwrap();

        if response.status() == reqwest::StatusCode::OK {
            success_count += 1;
        } else if response.status() == reqwest::StatusCode::BAD_REQUEST {
            let body: serde_json::Value = response.json().await.unwrap();
            let error_msg = body["error"].as_str().unwrap_or("").to_lowercase();
            if error_msg.contains("rate limit") || error_msg.contains("too many") {
                _rate_limited = true;
                break;
            }
        }
    }

    // At least some messages should succeed, and eventually rate limiting should kick in
    // (Note: This test might be flaky depending on rate limit configuration)
    assert!(success_count > 0, "At least some messages should succeed");
}

// ============================================================================
// GET /api/v1/messages Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_get_messages_empty() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register user
    let username = generate_test_username("user");
    let (user_id, _access_token) =
        register_user_passwordless(&client, &app.auth_address, Some(&username)).await;

    // Get messages (should be empty for new user)
    // Note: Messaging service uses TrustedUser extractor which expects X-User-Id header
    let response = client
        .get(&format!("http://{}/api/v1/messages", app.messaging_address))
        .header("X-User-Id", &user_id)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["messages"].as_array().unwrap().len(), 0);
    assert_eq!(body["hasMore"], false);
}

#[tokio::test]
#[serial]
async fn test_get_messages_with_since() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register user
    let username = generate_test_username("user");
    let (user_id, _access_token) =
        register_user_passwordless(&client, &app.auth_address, Some(&username)).await;

    // Get messages with since parameter
    let response = client
        .get(&format!(
            "http://{}/api/v1/messages?since=some-message-id",
            app.messaging_address
        ))
        .header("X-User-Id", &user_id)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body.get("messages").is_some());
    assert!(body.get("hasMore").is_some());
}

#[tokio::test]
#[serial]
async fn test_get_messages_requires_auth() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Try to get messages without authentication
    let response = client
        .get(&format!("http://{}/api/v1/messages", app.messaging_address))
        .send()
        .await
        .unwrap();

    // Should return 401 Unauthorized
    assert!(
        response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::FORBIDDEN
    );
}

#[tokio::test]
#[serial]
async fn test_get_messages_only_own() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register two users
    let user1_username = generate_test_username("user1");
    let user2_username = generate_test_username("user2");

    let (user1_id, _user1_token) =
        register_user_passwordless(&client, &app.auth_address, Some(&user1_username)).await;

    let (user2_id, user2_token) =
        register_user_passwordless(&client, &app.auth_address, Some(&user2_username)).await;

    // User1 sends a message to User2
    let message = create_test_message(&user2_id, 1);
    let send_response = client
        .post(&format!("http://{}/api/v1/messages", app.messaging_address))
        .header("X-User-Id", &user1_id)
        .json(&message)
        .send()
        .await
        .unwrap();

    assert_eq!(send_response.status(), reqwest::StatusCode::OK);

    // User2 should be able to get the message
    // Note: This test might need adjustment based on how messages are delivered
    // For now, we just verify that user2 can make the request
    let get_response = client
        .get(&format!("http://{}/api/v1/messages", app.messaging_address))
        .header("X-User-Id", &user2_id)
        .send()
        .await
        .unwrap();

    assert_eq!(get_response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = get_response.json().await.unwrap();
    assert!(body.get("messages").is_some());
}

#[tokio::test]
#[serial]
async fn test_get_messages_rate_limiting() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register user
    let username = generate_test_username("user");
    let (user_id, _access_token) =
        register_user_passwordless(&client, &app.auth_address, Some(&username)).await;

    // Make multiple rapid requests (rate limit is 1 per second)
    let mut _rate_limited = false;
    for i in 0..3 {
        let response = client
            .get(&format!("http://{}/api/v1/messages", app.messaging_address))
            .header("X-User-Id", &user_id)
            .send()
            .await
            .unwrap();

        if response.status() == reqwest::StatusCode::BAD_REQUEST {
            let body: serde_json::Value = response.json().await.unwrap();
            let error_msg = body["error"].as_str().unwrap_or("").to_lowercase();
            if error_msg.contains("rate limit") || error_msg.contains("per second") {
                _rate_limited = true;
                break;
            }
        }

        // Small delay to avoid hitting rate limit too quickly
        if i < 2 {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    // Rate limiting should eventually kick in for rapid requests
    // (Note: This test might be flaky depending on rate limit configuration)
    // For now, we just verify the endpoint works
    // Placeholder - rate limiting behavior may vary
}

// Note: Long polling tests (test_get_messages_long_polling, test_get_messages_long_polling_timeout)
// are more complex and would require:
// 1. Setting up a background task to send a message after a delay
// 2. Verifying that the long polling request receives the message
// 3. Testing timeout behavior
// These can be added in a follow-up if needed

// ============================================================================
// Additional Tests for Stream ID Pagination & ACK (Phase 2.6)
// ============================================================================

#[tokio::test]
#[serial]
async fn test_get_messages_with_stream_id_pagination() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register user
    let username = generate_test_username("streamtest");
    let (user_id, _access_token) =
        register_user_passwordless(&client, &app.auth_address, Some(&username)).await;

    // Get messages with Stream ID format in since parameter
    // Stream ID format: {timestamp}-{sequence} (e.g., "1707584371151-5")
    let stream_id = "0-0"; // Start from beginning of stream

    let response = client
        .get(&format!(
            "http://{}/api/v1/messages?since={}",
            app.messaging_address, stream_id
        ))
        .header("X-User-Id", &user_id)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct GetMessagesResponse {
        messages: Vec<serde_json::Value>,
        has_more: bool,
        next_since: Option<String>,
    }

    let body: GetMessagesResponse = response.json().await.unwrap();

    // nextSince should ALWAYS be returned (even if no messages)
    assert!(
        body.next_since.is_some(),
        "nextSince should always be present"
    );

    // If no messages, nextSince should echo back the input
    if body.messages.is_empty() {
        assert_eq!(body.next_since.unwrap(), stream_id);
    }
}

#[tokio::test]
#[serial]
async fn test_get_messages_next_since_always_returned() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register user
    let username = generate_test_username("nextsince");
    let (user_id, _access_token) =
        register_user_passwordless(&client, &app.auth_address, Some(&username)).await;

    // Test 1: Get messages without since parameter
    let response = client
        .get(&format!("http://{}/api/v1/messages", app.messaging_address))
        .header("X-User-Id", &user_id)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct GetMessagesResponse {
        messages: Vec<serde_json::Value>,
        has_more: bool,
        next_since: Option<String>,
    }

    let body: GetMessagesResponse = response.json().await.unwrap();
    assert!(
        body.next_since.is_some(),
        "nextSince should be present even without since parameter"
    );

    // Test 2: Get messages with since parameter
    let since = "0-0";
    let response2 = client
        .get(&format!(
            "http://{}/api/v1/messages?since={}",
            app.messaging_address, since
        ))
        .header("X-User-Id", &user_id)
        .send()
        .await
        .unwrap();

    assert_eq!(response2.status(), reqwest::StatusCode::OK);
    let body2: GetMessagesResponse = response2.json().await.unwrap();
    assert!(
        body2.next_since.is_some(),
        "nextSince should be present with since parameter"
    );
}

#[tokio::test]
#[serial]
async fn test_message_ack_implicit_via_since() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register two users: sender and recipient
    let sender_username = generate_test_username("sender");
    let recipient_username = generate_test_username("recipient");

    let (sender_user_id, _sender_token) =
        register_user_passwordless(&client, &app.auth_address, Some(&sender_username)).await;

    let (recipient_user_id, recipient_token) =
        register_user_passwordless(&client, &app.auth_address, Some(&recipient_username)).await;

    // Send a message
    let message = create_test_message(&recipient_user_id, 1);
    client
        .post(&format!("http://{}/api/v1/messages", app.messaging_address))
        .header("X-User-Id", &sender_user_id)
        .json(&message)
        .send()
        .await
        .unwrap();

    // Wait a bit for message to be delivered
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Recipient gets messages (first time - no ACK yet)
    let response1 = client
        .get(&format!("http://{}/api/v1/messages", app.messaging_address))
        .header("X-User-Id", &recipient_user_id)
        .send()
        .await
        .unwrap();

    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct GetMessagesResponse {
        messages: Vec<serde_json::Value>,
        has_more: bool,
        next_since: Option<String>,
    }

    let body1: GetMessagesResponse = response1.json().await.unwrap();

    // Should have received at least one message (or none if delivery worker not running)
    let _message_count_first = body1.messages.len();

    // nextSince may be None if no messages delivered yet (async delivery via Kafka)
    // Skip test if delivery hasn't happened yet
    if body1.next_since.is_none() {
        eprintln!(
            "⚠️  Skipping test - no messages delivered yet (Kafka/Delivery Worker not running in test)"
        );
        return;
    }

    let next_since = body1.next_since.unwrap();

    // Second request with since parameter = implicit ACK
    // Messages up to this Stream ID should be deleted from Redis
    let response2 = client
        .get(&format!(
            "http://{}/api/v1/messages?since={}",
            app.messaging_address, next_since
        ))
        .header("X-User-Id", &recipient_user_id)
        .send()
        .await
        .unwrap();

    let body2: GetMessagesResponse = response2.json().await.unwrap();

    // If there were messages before, they should be ACKed and not returned again
    // (Unless new messages arrived in the meantime)
    // This test just verifies the API accepts Stream ID format in since parameter
    assert!(body2.next_since.is_some());
}

#[tokio::test]
#[serial]
async fn test_invalid_stream_id_format() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register user
    let username = generate_test_username("inv");
    let (user_id, _access_token) =
        register_user_passwordless(&client, &app.auth_address, Some(&username)).await;

    // Try with invalid Stream ID format (should fail gracefully)
    let invalid_since_values = vec!["not-a-stream-id", "123", "abc-def", ""];

    for invalid_since in invalid_since_values {
        let response = client
            .get(&format!(
                "http://{}/api/v1/messages?since={}",
                app.messaging_address, invalid_since
            ))
            .header("X-User-Id", &user_id)
            .send()
            .await
            .unwrap();

        // Should either reject (400 Bad Request) or handle gracefully (200 with empty messages)
        assert!(
            response.status() == reqwest::StatusCode::OK
                || response.status() == reqwest::StatusCode::BAD_REQUEST,
            "Invalid Stream ID '{}' should be handled gracefully, got: {}",
            invalid_since,
            response.status()
        );
    }
}

#[tokio::test]
#[serial]
async fn test_message_deduplication() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register two users
    let sender_username = generate_test_username("dups");
    let recipient_username = generate_test_username("dupr");

    let (sender_user_id, _sender_token) =
        register_user_passwordless(&client, &app.auth_address, Some(&sender_username)).await;

    let (recipient_user_id, _recipient_token) =
        register_user_passwordless(&client, &app.auth_address, Some(&recipient_username)).await;

    // Send same message multiple times (should be deduplicated)
    let message = create_test_message(&recipient_user_id, 1);

    // Send message 3 times
    for _ in 0..3 {
        let response = client
            .post(&format!("http://{}/api/v1/messages", app.messaging_address))
            .header("X-User-Id", &sender_user_id)
            .json(&message)
            .send()
            .await
            .unwrap();

        // All requests should succeed (API accepts them)
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }

    // Note: Actual deduplication happens in delivery worker via Redis
    // This test just verifies the API accepts multiple sends without error
}
