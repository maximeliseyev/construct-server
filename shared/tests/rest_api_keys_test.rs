// ============================================================================
// REST API Keys Endpoints Tests
// ============================================================================
//
// Tests for key management endpoints:
// - POST /api/v1/keys/upload - Upload or update user's key bundle
// - GET /api/v1/users/:id/public-key - Retrieve user's public key bundle
//
// ============================================================================

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use construct_crypto::{BundleData, SuiteKeyMaterial, UploadableKeyBundle};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;

mod test_utils;
use test_utils::{cleanup_rate_limits, spawn_app};

// Helper function to generate a valid test username
fn generate_test_username(prefix: &str) -> String {
    format!(
        "{}_{}",
        prefix,
        Uuid::new_v4().to_string().replace('-', "_")
    )
}

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

// Helper function to create a valid test key bundle with real Ed25519 keys and signatures
fn create_test_bundle(user_id: Option<String>) -> UploadableKeyBundle {
    // Generate a real Ed25519 key pair for signing
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Create key material for suite 1 (CLASSIC_X25519)
    let suite_material = SuiteKeyMaterial {
        suite_id: 1,
        identity_key: BASE64.encode(vec![0u8; 32]), // 32 bytes for X25519
        signed_prekey: BASE64.encode(vec![1u8; 32]), // 32 bytes for X25519
        signed_prekey_signature: BASE64.encode(vec![2u8; 64]), // 64 bytes for Ed25519 signature
        one_time_prekeys: vec![],
    };

    // Create BundleData
    let bundle_data = BundleData {
        user_id: user_id.unwrap_or_else(|| "temp-user-id".to_string()),
        timestamp: chrono::Utc::now().to_rfc3339(),
        supported_suites: vec![suite_material],
    };

    // Serialize to canonical bytes for signing
    let canonical_bytes = bundle_data.canonical_bytes().unwrap();

    // Sign the bundle data with the real Ed25519 key
    let signature = signing_key.sign(&canonical_bytes);

    // Create and return UploadableKeyBundle with valid signature
    UploadableKeyBundle {
        master_identity_key: BASE64.encode(verifying_key.as_bytes()), // Real Ed25519 public key (32 bytes)
        bundle_data: BASE64.encode(canonical_bytes),
        signature: BASE64.encode(signature.to_bytes()), // Real Ed25519 signature (64 bytes)
        nonce: None,
        timestamp: None,
    }
}

// Helper function to register a user and get auth tokens
async fn register_user(
    client: &reqwest::Client,
    app_address: &str,
    username: &str,
    password: &str,
) -> (String, String) {
    let bundle = create_test_bundle(None);

    let request = json!({
        "username": username,
        "password": password,
        "keyBundle": bundle
    });

    let response = client
        .post(&format!("http://{}/api/v1/auth/register", app_address))
        .json(&request)
        .send()
        .await
        .unwrap();

    let status = response.status();
    if status != reqwest::StatusCode::CREATED {
        let error_text = response.text().await.unwrap();
        panic!("Registration failed (status {}): {}", status, error_text);
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AuthResponse {
        user_id: String,
        access_token: String,
        #[allow(dead_code)]
        refresh_token: String,
        #[allow(dead_code)]
        expires_at: i64,
    }

    let auth_response: AuthResponse = response.json().await.unwrap();
    (auth_response.user_id, auth_response.access_token)
}

// ============================================================================
// POST /api/v1/keys/upload Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_upload_keys_success() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // Create a new key bundle for the user
    let bundle = create_test_bundle(Some(user_id.clone()));

    // Upload key bundle
    let response = client
        .post(&format!("http://{}/api/v1/keys/upload", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&bundle)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
#[serial]
async fn test_upload_keys_requires_auth() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Try to upload keys without authentication
    let bundle = create_test_bundle(Some("test-user-id".to_string()));

    let response = client
        .post(&format!("http://{}/api/v1/keys/upload", app.address))
        .json(&bundle)
        .send()
        .await
        .unwrap();

    // Should return 401 Unauthorized or 403 Forbidden
    assert!(
        response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::FORBIDDEN
    );
}

#[tokio::test]
#[serial]
async fn test_upload_keys_user_id_mismatch() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // Create a key bundle with different user_id
    let bundle = create_test_bundle(Some("different-user-id".to_string()));

    // Try to upload key bundle with mismatched user_id
    let _user_id = user_id; // Suppress unused variable warning
    let response = client
        .post(&format!("http://{}/api/v1/keys/upload", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&bundle)
        .send()
        .await
        .unwrap();

    // Should return 401 Unauthorized (user_id mismatch)
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body.get("error").is_some());
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("user_id in bundle does not match")
    );
}

#[tokio::test]
#[serial]
async fn test_upload_keys_invalid_bundle() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // Create an invalid bundle (empty bundle_data)
    let invalid_bundle = json!({
        "masterIdentityKey": BASE64.encode(vec![0u8; 32]),
        "bundleData": "",
        "signature": BASE64.encode(vec![0u8; 64])
    });

    // Try to upload invalid bundle
    let response = client
        .post(&format!("http://{}/api/v1/keys/upload", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&invalid_bundle)
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
async fn test_upload_keys_update_existing() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user (this already uploads a key bundle)
    let username = generate_test_username("testuser");
    let (user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // Create a new key bundle (key rotation)
    let new_bundle = create_test_bundle(Some(user_id.clone()));

    // Upload updated key bundle
    let response = client
        .post(&format!("http://{}/api/v1/keys/upload", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&new_bundle)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["status"], "ok");
}

// ============================================================================
// GET /api/v1/users/:id/public-key Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_get_public_key_success() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // Get public key bundle
    let response = client
        .get(&format!(
            "http://{}/api/v1/users/{}/public-key",
            app.address, user_id
        ))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct PublicKeyBundle {
        master_identity_key: String,
        #[allow(dead_code)]
        bundle_data: String,
        #[allow(dead_code)]
        signature: String,
    }

    let bundle: PublicKeyBundle = response.json().await.unwrap();
    assert!(!bundle.master_identity_key.is_empty());
}

#[tokio::test]
#[serial]
async fn test_get_public_key_requires_auth() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (user_id, _access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // Try to get public key without authentication
    let response = client
        .get(&format!(
            "http://{}/api/v1/users/{}/public-key",
            app.address, user_id
        ))
        .send()
        .await
        .unwrap();

    // Should return 401 Unauthorized or 403 Forbidden
    assert!(
        response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::FORBIDDEN
    );
}

#[tokio::test]
#[serial]
async fn test_get_public_key_nonexistent_user() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user to get a valid token
    let username = generate_test_username("testuser");
    let (_user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // Try to get public key for nonexistent user
    let nonexistent_user_id = Uuid::new_v4().to_string();
    let response = client
        .get(&format!(
            "http://{}/api/v1/users/{}/public-key",
            app.address, nonexistent_user_id
        ))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .unwrap();

    // Should return 404 Not Found
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body.get("error").is_some());
}

#[tokio::test]
#[serial]
async fn test_get_public_key_invalid_user_id() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user to get a valid token
    let username = generate_test_username("testuser");
    let (_user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // Try to get public key with invalid user_id format
    let response = client
        .get(&format!(
            "http://{}/api/v1/users/{}/public-key",
            app.address, "invalid-uuid-format"
        ))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .unwrap();

    // Should return 400 Bad Request or 404 Not Found
    assert!(
        response.status() == reqwest::StatusCode::BAD_REQUEST
            || response.status() == reqwest::StatusCode::NOT_FOUND
    );
}

#[tokio::test]
#[serial]
async fn test_get_public_key_after_upload() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // Upload a new key bundle
    let new_bundle = create_test_bundle(Some(user_id.clone()));
    let upload_response = client
        .post(&format!("http://{}/api/v1/keys/upload", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&new_bundle)
        .send()
        .await
        .unwrap();

    assert_eq!(upload_response.status(), reqwest::StatusCode::OK);

    // Get public key bundle (should return the updated bundle)
    let response = client
        .get(&format!(
            "http://{}/api/v1/users/{}/public-key",
            app.address, user_id
        ))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct PublicKeyBundle {
        master_identity_key: String,
        #[allow(dead_code)]
        bundle_data: String,
        #[allow(dead_code)]
        signature: String,
    }

    let bundle: PublicKeyBundle = response.json().await.unwrap();
    // Verify that the master_identity_key matches the uploaded bundle
    assert_eq!(bundle.master_identity_key, new_bundle.master_identity_key);
}
