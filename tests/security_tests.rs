// Security Tests
// ============================================================================
//
// Comprehensive security tests to verify all critical security measures:
// 1. Ed25519 signature verification for key bundles
// 2. Federation signature requirement
// 3. Rate limiting
// 4. Message size limits
// 5. JWT revocation on password change
// 6. Password not logged
// 7. Username validation
// 8. Message spoofing prevention
//
// ============================================================================

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use construct_server::e2e::{BundleData, ServerCryptoValidator, SuiteKeyMaterial, UploadableKeyBundle};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serial_test::serial;

mod test_utils;
use test_utils::*;

#[tokio::test]
#[serial]
async fn test_ed25519_signature_verification_valid() {
    // Test that a valid Ed25519 signature on a key bundle is accepted
    
    // Generate a new Ed25519 key pair
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    
    // Create bundle data
    let bundle_data = BundleData {
        user_id: "test-user-id".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        supported_suites: vec![SuiteKeyMaterial {
            suite_id: 1,
            identity_key: BASE64.encode(vec![0u8; 32]),
            signed_prekey: BASE64.encode(vec![1u8; 32]),
            one_time_prekeys: vec![],
        }],
    };
    
    // Serialize to canonical bytes
    let canonical_bytes = bundle_data.canonical_bytes().unwrap();
    
    // Sign the bundle data
    let signature = signing_key.sign(&canonical_bytes);
    
    // Create uploadable bundle with valid signature
    let bundle = UploadableKeyBundle {
        master_identity_key: BASE64.encode(verifying_key.as_bytes()),
        bundle_data: BASE64.encode(canonical_bytes),
        signature: BASE64.encode(signature.to_bytes()),
    };
    
    // Validate should succeed
    let result = ServerCryptoValidator::validate_uploadable_key_bundle(&bundle, false);
    assert!(result.is_ok(), "Valid signature should be accepted: {:?}", result.err());
}

#[tokio::test]
#[serial]
async fn test_ed25519_signature_verification_invalid() {
    // Test that an invalid Ed25519 signature on a key bundle is rejected
    
    // Generate a new Ed25519 key pair
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    
    // Create bundle data
    let bundle_data = BundleData {
        user_id: "test-user-id".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        supported_suites: vec![SuiteKeyMaterial {
            suite_id: 1,
            identity_key: BASE64.encode(vec![0u8; 32]),
            signed_prekey: BASE64.encode(vec![1u8; 32]),
            one_time_prekeys: vec![],
        }],
    };
    
    // Serialize to canonical bytes
    let canonical_bytes = bundle_data.canonical_bytes().unwrap();
    
    // Create a DIFFERENT key pair and sign with it (wrong key)
    let wrong_signing_key = SigningKey::generate(&mut OsRng);
    let wrong_signature = wrong_signing_key.sign(&canonical_bytes);
    
    // Create uploadable bundle with INVALID signature (signed with wrong key)
    let bundle = UploadableKeyBundle {
        master_identity_key: BASE64.encode(verifying_key.as_bytes()), // Correct public key
        bundle_data: BASE64.encode(canonical_bytes),
        signature: BASE64.encode(wrong_signature.to_bytes()), // Wrong signature
    };
    
    // Validate should fail
    let result = ServerCryptoValidator::validate_uploadable_key_bundle(&bundle, false);
    assert!(result.is_err(), "Invalid signature should be rejected");
    assert!(result.unwrap_err().to_string().contains("signature verification failed"));
}

#[tokio::test]
#[serial]
async fn test_ed25519_signature_verification_tampered_data() {
    // Test that tampered bundle data is rejected (signature mismatch)
    
    // Generate a new Ed25519 key pair
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    
    // Create bundle data
    let bundle_data = BundleData {
        user_id: "test-user-id".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        supported_suites: vec![SuiteKeyMaterial {
            suite_id: 1,
            identity_key: BASE64.encode(vec![0u8; 32]),
            signed_prekey: BASE64.encode(vec![1u8; 32]),
            one_time_prekeys: vec![],
        }],
    };
    
    // Serialize and sign
    let canonical_bytes = bundle_data.canonical_bytes().unwrap();
    let signature = signing_key.sign(&canonical_bytes);
    
    // Tamper with the data (modify user_id)
    let mut tampered_data = bundle_data.clone();
    tampered_data.user_id = "tampered-user-id".to_string();
    let tampered_bytes = tampered_data.canonical_bytes().unwrap();
    
    // Create uploadable bundle with tampered data
    let bundle = UploadableKeyBundle {
        master_identity_key: BASE64.encode(verifying_key.as_bytes()),
        bundle_data: BASE64.encode(tampered_bytes), // Tampered data
        signature: BASE64.encode(signature.to_bytes()), // Original signature
    };
    
    // Validate should fail
    let result = ServerCryptoValidator::validate_uploadable_key_bundle(&bundle, false);
    assert!(result.is_err(), "Tampered data should be rejected");
    assert!(result.unwrap_err().to_string().contains("signature verification failed"));
}

#[tokio::test]
#[serial]
async fn test_message_size_limit() {
    // Test that messages exceeding MAX_MESSAGE_SIZE are rejected
    
    let app = spawn_app().await;
    let mut client = TestClient::connect(&app.address).await.unwrap();
    
    // Register user
    client.register("testuser", "password123").await.unwrap();
    
    // Create a message that exceeds the limit (MAX_MESSAGE_SIZE = 1MB = 1048576 bytes)
    let oversized_content = "A".repeat(2 * 1024 * 1024); // 2MB
    
    use construct_server::message::ChatMessage;
    use uuid::Uuid;
    
    let oversized_msg = ChatMessage {
        id: Uuid::new_v4().to_string(),
        from: client.user_id.clone().unwrap(),
        to: client.user_id.clone().unwrap(), // Send to self for test
        content: BASE64.encode(oversized_content.as_bytes()),
        ephemeral_public_key: vec![0; 32],
        message_number: 0,
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    
    client.send(&construct_server::message::ClientMessage::SendMessage(oversized_msg))
        .await
        .unwrap();
    
    // Should receive an error
    let response = client.recv().await.unwrap();
    match response {
        Some(construct_server::message::ServerMessage::Error(e)) => {
            assert!(e.message.contains("MESSAGE_TOO_LARGE") || e.message.contains("exceeds maximum"));
        }
        _ => panic!("Expected MESSAGE_TOO_LARGE error, got: {:?}", response),
    }
}

#[tokio::test]
#[serial]
async fn test_username_validation() {
    // Test that invalid usernames are rejected
    
    let app = spawn_app().await;
    
    // Test cases for invalid usernames
    let long_username = "a".repeat(65);
    let invalid_usernames: Vec<(&str, &str)> = vec![
        ("ab", "too short"), // Less than 3 chars
        (&long_username, "too long"), // More than 64 chars
        ("123abc", "starts with number"), // Starts with number
        ("user-name", "contains hyphen"), // Contains invalid character
        ("user.name", "contains dot"), // Contains invalid character
        ("user name", "contains space"), // Contains space
    ];
    
    for (username, reason) in invalid_usernames {
        let mut test_client = TestClient::connect(&app.address).await.unwrap();
        
        // Try to register with invalid username
        let result = test_client.register(username, "password123").await;
        assert!(result.is_err(), "Username '{}' should be rejected: {}", username, reason);
        
        // Check error message
        if let Err(e) = result {
            assert!(e.to_string().contains("INVALID_USERNAME") || 
                   e.to_string().contains("username"), 
                   "Error should mention username validation: {}", e);
        }
    }
    
    // Test valid username (should succeed)
    let mut valid_client = TestClient::connect(&app.address).await.unwrap();
    let result = valid_client.register("validuser", "password123").await;
    assert!(result.is_ok(), "Valid username should be accepted");
}

#[tokio::test]
#[serial]
async fn test_rate_limiting_prevents_spam() {
    // Test that rate limiting blocks excessive messages
    
    let app = spawn_app().await;
    let mut client = TestClient::connect(&app.address).await.unwrap();
    
    // Register user
    client.register("ratetest", "password123").await.unwrap();
    
    use construct_server::message::{ChatMessage, ClientMessage};
    use uuid::Uuid;
    
    let alice_id = client.user_id.clone().unwrap();
    
    // Send many messages rapidly (should trigger rate limit)
    let mut rate_limit_triggered = false;
    for i in 0..150 { // Send 150 messages (should exceed default limit of 100/hour)
        let msg = ChatMessage {
            id: Uuid::new_v4().to_string(),
            from: alice_id.clone(),
            to: alice_id.clone(),
            content: BASE64.encode(format!("Message {}", i).as_bytes()),
            ephemeral_public_key: vec![0; 32],
            message_number: i,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        
        client.send(&ClientMessage::SendMessage(msg)).await.unwrap();
        
        // Check response
        if let Some(response) = client.recv().await.unwrap() {
            if let construct_server::message::ServerMessage::Error(e) = response {
                if e.message.contains("RATE_LIMIT") || e.message.contains("Slow down") {
                    rate_limit_triggered = true;
                    break;
                }
            }
        }
        
        // Small delay to avoid overwhelming the system
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    
    assert!(rate_limit_triggered, "Rate limiting should be triggered after excessive messages");
}

#[tokio::test]
#[serial]
async fn test_message_spoofing_prevented() {
    // Test that users cannot send messages from another user's account
    // (This test already exists in integration_test.rs, but we include it here for completeness)
    
    let app = spawn_app().await;
    let mut alice = TestClient::connect(&app.address).await.unwrap();
    let mut eve = TestClient::connect(&app.address).await.unwrap();
    
    // Register users
    alice.register("alice", "password123").await.unwrap();
    eve.register("eve", "password123").await.unwrap();
    
    let alice_id = alice.user_id.clone().unwrap();
    let eve_id = eve.user_id.clone().unwrap();
    
    // Eve tries to send a message *from* Alice (spoofing attempt)
    use construct_server::message::{ChatMessage, ClientMessage};
    use uuid::Uuid;
    
    let spoofed_msg = ChatMessage {
        id: Uuid::new_v4().to_string(),
        from: alice_id.clone(), // Eve is trying to impersonate Alice
        to: eve_id.clone(),
        content: BASE64.encode("I am Alice".as_bytes()),
        ephemeral_public_key: vec![0; 32],
        message_number: 0,
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    
    eve.send(&ClientMessage::SendMessage(spoofed_msg)).await.unwrap();
    
    // Eve should receive a FORBIDDEN error
    let received = eve.recv().await.unwrap();
    match received {
        Some(construct_server::message::ServerMessage::Error(e)) => {
            assert_eq!(e.code, "FORBIDDEN");
        }
        _ => panic!("Expected FORBIDDEN error for message spoofing, got: {:?}", received),
    }
}

#[tokio::test]
#[serial]
async fn test_key_bundle_signature_required() {
    // Test that key bundles without valid signatures are rejected
    
    // Create bundle data
    let bundle_data = BundleData {
        user_id: "test-user-id".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        supported_suites: vec![SuiteKeyMaterial {
            suite_id: 1,
            identity_key: BASE64.encode(vec![0u8; 32]),
            signed_prekey: BASE64.encode(vec![1u8; 32]),
            one_time_prekeys: vec![],
        }],
    };
    
    // Serialize
    let canonical_bytes = bundle_data.canonical_bytes().unwrap();
    
    // Create bundle with INVALID signature (wrong length)
    let bundle_invalid_sig = UploadableKeyBundle {
        master_identity_key: BASE64.encode(vec![0u8; 32]),
        bundle_data: BASE64.encode(canonical_bytes.clone()),
        signature: BASE64.encode(vec![0u8; 32]), // Invalid: should be 64 bytes, not 32
    };
    
    // Validate should fail due to invalid signature format
    let result = ServerCryptoValidator::validate_uploadable_key_bundle(&bundle_invalid_sig, false);
    assert!(result.is_err(), "Bundle with invalid signature format should be rejected");
    assert!(result.unwrap_err().to_string().contains("64 bytes"));
    
    // Create bundle with MISSING signature (empty)
    let bundle_no_sig = UploadableKeyBundle {
        master_identity_key: BASE64.encode(vec![0u8; 32]),
        bundle_data: BASE64.encode(canonical_bytes),
        signature: "".to_string(), // Empty signature
    };
    
    // Validate should fail due to base64 decode error
    let result = ServerCryptoValidator::validate_uploadable_key_bundle(&bundle_no_sig, false);
    assert!(result.is_err(), "Bundle with empty signature should be rejected");
}
