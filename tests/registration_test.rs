use construct_server::e2e::{BundleData, SuiteKeyMaterial, UploadableKeyBundle};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

mod test_utils;
use test_utils::{spawn_app, TestClient};
use construct_server::message::ClientMessage;
use serial_test::serial;

/// Helper function to create a valid test UploadableKeyBundle
fn create_test_bundle(user_id: &str) -> UploadableKeyBundle {
    // Create key material for suite 1 (CLASSIC_X25519)
    let suite_material = SuiteKeyMaterial {
        suite_id: 1,
        identity_key: BASE64.encode(vec![0u8; 32]),      // 32 bytes for X25519
        signed_prekey: BASE64.encode(vec![1u8; 32]),     // 32 bytes for X25519
        one_time_prekeys: vec![],
    };

    // Create BundleData
    let bundle_data = BundleData {
        user_id: user_id.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        supported_suites: vec![suite_material],
    };

    // Serialize BundleData to JSON and encode as Base64
    let bundle_data_json = serde_json::to_string(&bundle_data).unwrap();
    let bundle_data_base64 = BASE64.encode(bundle_data_json.as_bytes());

    // Create and return UploadableKeyBundle directly
    // No need for additional JSON/Base64 encoding - MessagePack handles serialization
    UploadableKeyBundle {
        master_identity_key: BASE64.encode(vec![2u8; 32]),  // 32 bytes for Ed25519
        bundle_data: bundle_data_base64,
        signature: BASE64.encode(vec![3u8; 64]),             // 64 bytes for Ed25519 signature
    }
}

#[tokio::test]
#[serial]
async fn test_user_registration_success() {
    let app = spawn_app().await;
    let mut client = TestClient::connect(&app.address).await.unwrap();

    // Use a placeholder user_id - server will update it automatically during registration
    let public_key = create_test_bundle("placeholder-user-id");

    let msg = ClientMessage::Register(construct_server::message::RegisterData {
        username: "testuser".to_string(),
        password: "securepassword123".to_string(),
        public_key,
    });

    client.send(&msg).await.unwrap();

    // Wait for response
    let response = client.recv().await.unwrap();
    println!("Registration response: {:?}", response);

    // Check if registration succeeded
    match response {
        Some(construct_server::message::ServerMessage::RegisterSuccess(data)) => {
            println!("✅ Registration successful!");
            println!("   User ID: {}", data.user_id);
            println!("   Username: {}", data.username);
            println!("   Session token: {}...", &data.session_token[..20]);
            assert_eq!(data.username, "testuser");
        }
        Some(construct_server::message::ServerMessage::Error(err)) => {
            panic!("❌ Registration failed: {} - {}", err.code, err.message);
        }
        other => {
            panic!("Unexpected response: {:?}", other);
        }
    }
}

#[tokio::test]
#[serial]
async fn test_duplicate_username_rejected() {
    let app = spawn_app().await;

    // Register first user
    let mut client1 = TestClient::connect(&app.address).await.unwrap();
    let public_key1 = create_test_bundle("00000000-0000-0000-0000-000000000000");

    let msg1 = ClientMessage::Register(construct_server::message::RegisterData {
        username: "duplicate_test".to_string(),
        password: "password1".to_string(),
        public_key: public_key1,
    });
    client1.send(&msg1).await.unwrap();
    let _ = client1.recv().await.unwrap();

    // Try to register second user with same username
    let mut client2 = TestClient::connect(&app.address).await.unwrap();
    let public_key2 = create_test_bundle("11111111-1111-1111-1111-111111111111");

    let msg2 = ClientMessage::Register(construct_server::message::RegisterData {
        username: "duplicate_test".to_string(),
        password: "password2".to_string(),
        public_key: public_key2,
    });
    client2.send(&msg2).await.unwrap();

    let response = client2.recv().await.unwrap();
    match response {
        Some(construct_server::message::ServerMessage::Error(err)) => {
            println!("✅ Duplicate username correctly rejected: {}", err.message);
            assert!(err.message.contains("already exists") || err.message.contains("duplicate"));
        }
        other => {
            panic!("Expected error for duplicate username, got: {:?}", other);
        }
    }
}
