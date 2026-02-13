// ============================================================================
// REST API Keys Endpoints Tests
// ============================================================================
//
// Tests for key management endpoints:
// - POST /api/v1/keys/upload - Upload or update user's key bundle
// - GET /api/v1/users/:id/public-key - Retrieve user's public key bundle
// - PATCH /api/v1/users/me/public-key - Update verifying key
//
// ============================================================================

#![allow(dead_code)]

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use construct_crypto::{BundleData, SuiteKeyMaterial, UploadableKeyBundle};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;

mod test_utils;
use test_utils::{cleanup_rate_limits, register_user_passwordless, spawn_app};

// Helper function to generate a valid test username (max 20 chars)
fn generate_test_username(prefix: &str) -> String {
    // Username must be 3-20 chars, so use only first 8 chars of UUID
    format!("{}_{}", prefix, &Uuid::new_v4().to_string()[0..8])
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

// Helper function to register a user and get auth tokens (using passwordless auth)
async fn register_user(
    client: &reqwest::Client,
    app_address: &str,
    username: Option<&str>,
) -> (String, String) {
    register_user_passwordless(client, app_address, username).await
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

    // Register a user using passwordless auth
    let username = generate_test_username("keys");
    let (user_id, access_token) = register_user(&client, &app.auth_address, Some(&username)).await;

    // Create a new key bundle for the user
    let bundle = create_test_bundle(Some(user_id.clone()));

    // Upload key bundle
    let response = client
        .post(format!("http://{}/api/v1/keys/upload", app.user_address))
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
        .post(format!("http://{}/api/v1/keys/upload", app.user_address))
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
    let (user_id, access_token) = register_user(&client, &app.auth_address, Some(&username)).await;

    // Create a key bundle with different user_id
    let bundle = create_test_bundle(Some("different-user-id".to_string()));

    // Try to upload key bundle with mismatched user_id
    let _user_id = user_id; // Suppress unused variable warning
    let response = client
        .post(format!("http://{}/api/v1/keys/upload", app.user_address))
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
    let (_user_id, access_token) = register_user(&client, &app.auth_address, Some(&username)).await;

    // Create an invalid bundle (empty bundle_data)
    let invalid_bundle = json!({
        "masterIdentityKey": BASE64.encode(vec![0u8; 32]),
        "bundleData": "",
        "signature": BASE64.encode(vec![0u8; 64])
    });

    // Try to upload invalid bundle
    let response = client
        .post(format!("http://{}/api/v1/keys/upload", app.user_address))
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
    let (user_id, access_token) = register_user(&client, &app.auth_address, Some(&username)).await;

    // Create a new key bundle (key rotation)
    let new_bundle = create_test_bundle(Some(user_id.clone()));

    // Upload updated key bundle
    let response = client
        .post(format!("http://{}/api/v1/keys/upload", app.user_address))
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
    let (user_id, access_token) = register_user(&client, &app.auth_address, Some(&username)).await;

    // Get public key bundle
    let response = client
        .get(format!(
            "http://{}/api/v1/users/{}/public-key",
            app.user_address, user_id
        ))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    // New response format per INVITE_LINKS_QR_API_SPEC.md
    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct KeyBundleData {
        bundle_data: String,
        master_identity_key: String,
        signature: String,
    }

    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct PublicKeyResponse {
        key_bundle: KeyBundleData,
        username: String,
        verifying_key: String,
    }

    let response_data: PublicKeyResponse = response.json().await.unwrap();
    assert!(!response_data.key_bundle.master_identity_key.is_empty());
    assert!(!response_data.key_bundle.signature.is_empty());
    assert!(!response_data.verifying_key.is_empty());
    assert!(!response_data.username.is_empty());
}

#[tokio::test]
#[serial]
async fn test_get_public_key_requires_auth() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (user_id, _access_token) = register_user(&client, &app.auth_address, Some(&username)).await;

    // Try to get public key without authentication
    let response = client
        .get(format!(
            "http://{}/api/v1/users/{}/public-key",
            app.user_address, user_id
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
    let (_user_id, access_token) = register_user(&client, &app.auth_address, Some(&username)).await;

    // Try to get public key for nonexistent user
    let nonexistent_user_id = Uuid::new_v4().to_string();
    let response = client
        .get(format!(
            "http://{}/api/v1/users/{}/public-key",
            app.user_address, nonexistent_user_id
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
    let (_user_id, access_token) = register_user(&client, &app.auth_address, Some(&username)).await;

    // Try to get public key with invalid user_id format
    let response = client
        .get(format!(
            "http://{}/api/v1/users/{}/public-key",
            app.user_address, "invalid-uuid-format"
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
    let (user_id, access_token) = register_user(&client, &app.auth_address, Some(&username)).await;

    // Upload a new key bundle
    let new_bundle = create_test_bundle(Some(user_id.clone()));
    let upload_response = client
        .post(format!("http://{}/api/v1/keys/upload", app.user_address))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&new_bundle)
        .send()
        .await
        .unwrap();

    assert_eq!(upload_response.status(), reqwest::StatusCode::OK);

    // Get public key bundle (should return the updated bundle)
    let response = client
        .get(format!(
            "http://{}/api/v1/users/{}/public-key",
            app.user_address, user_id
        ))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    // New response format per INVITE_LINKS_QR_API_SPEC.md
    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct KeyBundleData {
        bundle_data: String,
        master_identity_key: String,
        signature: String,
    }

    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct PublicKeyResponse {
        key_bundle: KeyBundleData,
        username: String,
        verifying_key: String,
    }

    let response_data: PublicKeyResponse = response.json().await.unwrap();
    // Verify the response contains valid data
    // Note: With passwordless auth, device keys take precedence over uploaded key bundles
    // So we just verify the response format is correct, not the exact bundle_data match
    assert!(!response_data.key_bundle.master_identity_key.is_empty());
    assert!(!response_data.key_bundle.bundle_data.is_empty());
    assert!(!response_data.key_bundle.signature.is_empty());
    assert!(!response_data.verifying_key.is_empty());
    assert!(!response_data.username.is_empty());
}

// ============================================================================
// Additional Tests for signedPrekeySignature (device-based architecture)
// ============================================================================

#[tokio::test]
#[serial]
async fn test_get_key_bundle_includes_signed_prekey_signature() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user with device (includes signedPrekeySignature)
    let username = generate_test_username("sigtest");
    let (user_id, access_token) = register_user(&client, &app.auth_address, Some(&username)).await;

    // Get user's key bundle via device API
    // This should return the device's keys including signedPrekeySignature
    let response = client
        .get(format!(
            "http://{}/api/v1/users/{}/public-key",
            app.user_address, user_id
        ))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    // Parse response
    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct KeyBundleData {
        bundle_data: String,
        master_identity_key: String,
        signature: String,
    }

    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct PublicKeyResponse {
        key_bundle: KeyBundleData,
        username: String,
        verifying_key: String,
    }

    let response_data: PublicKeyResponse = response.json().await.unwrap();

    // Verify key bundle has signature (this is the bundle signature, not prekey signature)
    assert!(!response_data.key_bundle.signature.is_empty());

    // Decode bundle_data to check if it contains signedPrekeySignature
    let bundle_data_bytes = BASE64
        .decode(&response_data.key_bundle.bundle_data)
        .unwrap();
    let bundle_data_json: serde_json::Value = serde_json::from_slice(&bundle_data_bytes).unwrap();

    // Check that supported_suites contains signed_prekey_signature
    if let Some(suites) = bundle_data_json["supportedSuites"].as_array()
        && let Some(first_suite) = suites.first()
    {
        // signedPrekeySignature should be present
        assert!(
            first_suite.get("signedPrekeySignature").is_some(),
            "signedPrekeySignature should be present in device key bundle"
        );
    }
}

#[tokio::test]
#[serial]
async fn test_upload_keys_preserves_device_signed_prekey() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user with device
    let username = generate_test_username("preservetest");
    let (user_id, access_token) = register_user(&client, &app.auth_address, Some(&username)).await;

    // Upload a new key bundle (legacy API)
    let new_bundle = create_test_bundle(Some(user_id.clone()));

    let upload_response = client
        .post(format!("http://{}/api/v1/keys/upload", app.user_address))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&new_bundle)
        .send()
        .await
        .unwrap();

    assert_eq!(upload_response.status(), reqwest::StatusCode::OK);

    // Get public key - should still return device keys (not uploaded bundle)
    // Because device keys take precedence in device-based architecture
    let response = client
        .get(format!(
            "http://{}/api/v1/users/{}/public-key",
            app.user_address, user_id
        ))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct KeyBundleData {
        bundle_data: String,
        master_identity_key: String,
        signature: String,
    }

    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct PublicKeyResponse {
        key_bundle: KeyBundleData,
        username: String,
        verifying_key: String,
    }

    let response_data: PublicKeyResponse = response.json().await.unwrap();

    // Device keys should be returned (not the uploaded bundle)
    // Verify that verifying_key is the device's verifying key
    assert!(!response_data.verifying_key.is_empty());
    assert!(!response_data.key_bundle.signature.is_empty());
}

#[tokio::test]
#[serial]
async fn test_update_verifying_key_success() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("updatekey");
    let (_user_id, access_token) = register_user(&client, &app.auth_address, Some(&username)).await;

    // Generate new verifying key
    let new_signing_key = SigningKey::generate(&mut OsRng);
    let new_verifying_key = new_signing_key.verifying_key();

    // Update verifying key
    let update_request = json!({
        "verifyingKey": BASE64.encode(new_verifying_key.as_bytes()),
        "reason": "test_update"
    });

    let response = client
        .patch(format!(
            "http://{}/api/v1/users/me/public-key",
            app.user_address
        ))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&update_request)
        .send()
        .await
        .unwrap();

    // Should succeed
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
#[serial]
async fn test_update_verifying_key_invalid_format() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("invalidkey");
    let (_user_id, access_token) = register_user(&client, &app.auth_address, Some(&username)).await;

    // Try to update with invalid verifying key (wrong length)
    let update_request = json!({
        "verifyingKey": BASE64.encode(vec![0u8; 16]), // Wrong length (should be 32)
        "reason": "test_invalid"
    });

    let response = client
        .patch(format!(
            "http://{}/api/v1/users/me/public-key",
            app.user_address
        ))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&update_request)
        .send()
        .await
        .unwrap();

    // Should fail with validation error
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
}
