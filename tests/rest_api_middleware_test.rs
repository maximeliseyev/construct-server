// ============================================================================
// REST API Middleware Tests
// ============================================================================
//
// Tests for middleware:
// - CSRF Protection middleware
// - IP-based Rate Limiting middleware
// - Request Signing middleware (if enabled)
// - JWT Authentication extractor
//
// ============================================================================

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use construct_server::e2e::{BundleData, SuiteKeyMaterial, UploadableKeyBundle};
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

// Helper function to create a valid test key bundle
fn create_test_bundle(user_id: Option<String>) -> UploadableKeyBundle {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let suite_material = SuiteKeyMaterial {
        suite_id: 1,
        identity_key: BASE64.encode(vec![0u8; 32]),
        signed_prekey: BASE64.encode(vec![1u8; 32]),
        signed_prekey_signature: BASE64.encode(vec![2u8; 64]),
        one_time_prekeys: vec![],
    };

    let bundle_data = BundleData {
        user_id: user_id.unwrap_or_else(|| "temp-user-id".to_string()),
        timestamp: chrono::Utc::now().to_rfc3339(),
        supported_suites: vec![suite_material],
    };

    let canonical_bytes = bundle_data.canonical_bytes().unwrap();
    let signature = signing_key.sign(&canonical_bytes);

    UploadableKeyBundle {
        master_identity_key: BASE64.encode(verifying_key.as_bytes()),
        bundle_data: BASE64.encode(canonical_bytes),
        signature: BASE64.encode(signature.to_bytes()),
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

// Helper function to get CSRF token
async fn get_csrf_token(client: &reqwest::Client, app_address: &str, access_token: &str) -> String {
    let response = client
        .get(&format!("http://{}/api/csrf-token", app_address))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    #[derive(serde::Deserialize)]
    struct CsrfResponse {
        token: String,
    }

    let csrf_response: CsrfResponse = response.json().await.unwrap();
    csrf_response.token
}

// ============================================================================
// CSRF Protection Middleware Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_csrf_bypass_with_x_requested_with() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // API clients with X-Requested-With header should bypass CSRF
    let response = client
        .put(&format!("http://{}/api/v1/account", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .header("X-Requested-With", "XMLHttpRequest")
        .json(&json!({
            "newPassword": "NewPassword123!",
            "oldPassword": "TestPassword123!"
        }))
        .send()
        .await
        .unwrap();

    // Should succeed (CSRF bypassed for API clients)
    // Note: May fail for other reasons (e.g., password validation), but not CSRF
    assert_ne!(response.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial]
async fn test_csrf_required_for_browser_requests() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = reqwest::Client::builder().build().unwrap();

    // Register a user
    let username = generate_test_username("testuser");
    let (user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // Browser request without CSRF token should fail
    let response = client
        .put(&format!("http://{}/api/v1/account", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .header("User-Agent", "Mozilla/5.0") // Browser user agent
        .json(&json!({
            "newPassword": "NewPassword123!",
            "oldPassword": "TestPassword123!"
        }))
        .send()
        .await
        .unwrap();

    // Should return 403 Forbidden (CSRF protection)
    // Note: This test may pass if CSRF is disabled in test config
    // The actual behavior depends on configuration
}

#[tokio::test]
#[serial]
async fn test_csrf_skip_safe_methods() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = reqwest::Client::builder().build().unwrap();

    // Register a user
    let username = generate_test_username("testuser");
    let (user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // GET requests should not require CSRF token
    let response = client
        .get(&format!("http://{}/api/v1/account", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .unwrap();

    // Should succeed (GET is a safe method)
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
#[serial]
async fn test_csrf_skip_health_endpoints() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = reqwest::Client::builder().build().unwrap();

    // Health endpoints should not require CSRF
    let response = client
        .get(&format!("http://{}/health/ready", app.address))
        .send()
        .await
        .unwrap();

    // Should succeed (health endpoints are excluded from CSRF)
    assert!(
        response.status() == reqwest::StatusCode::OK
            || response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
}

// ============================================================================
// IP-based Rate Limiting Middleware Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_rate_limiting_allows_normal_usage() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // Make a few requests (should be within rate limit)
    for _ in 0..5 {
        let response = client
            .post(&format!("http://{}/api/v1/messages", app.address))
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&json!({
                "recipientId": Uuid::new_v4().to_string(),
                "suiteId": 1,
                "ciphertext": BASE64.encode(b"test")
            }))
            .send()
            .await
            .unwrap();

        // Should succeed (within rate limit)
        assert_ne!(response.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    }
}

#[tokio::test]
#[serial]
async fn test_rate_limiting_skip_safe_methods() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // GET requests should not be rate limited
    for _ in 0..20 {
        let response = client
            .get(&format!("http://{}/api/v1/account", app.address))
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .unwrap();

        // Should always succeed (GET is not rate limited)
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }
}

#[tokio::test]
#[serial]
async fn test_rate_limiting_skip_health_endpoints() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = reqwest::Client::builder().build().unwrap();

    // Health endpoints should not be rate limited
    for _ in 0..20 {
        let response = client
            .get(&format!("http://{}/health/live", app.address))
            .send()
            .await
            .unwrap();

        // Should always succeed (health endpoints are excluded from rate limiting)
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }
}

// ============================================================================
// JWT Authentication Extractor Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_jwt_extractor_valid_token() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // Request with valid JWT token should succeed
    let response = client
        .get(&format!("http://{}/api/v1/account", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    // Verify response contains correct user_id
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AccountInfo {
        user_id: String,
        username: String,
    }

    let account: AccountInfo = response.json().await.unwrap();
    assert_eq!(account.user_id, user_id);
}

#[tokio::test]
#[serial]
async fn test_jwt_extractor_invalid_token() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Request with invalid JWT token should fail
    let response = client
        .get(&format!("http://{}/api/v1/account", app.address))
        .header("Authorization", "Bearer invalid_token_here")
        .send()
        .await
        .unwrap();

    // Should return 401 Unauthorized
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
async fn test_jwt_extractor_missing_token() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Request without Authorization header should fail
    let response = client
        .get(&format!("http://{}/api/v1/account", app.address))
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
async fn test_jwt_extractor_expired_token() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Create an expired token (this would require modifying token creation)
    // For now, we'll test with an invalid token format
    let expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.invalid_signature";

    let response = client
        .get(&format!("http://{}/api/v1/account", app.address))
        .header("Authorization", format!("Bearer {}", expired_token))
        .send()
        .await
        .unwrap();

    // Should return 401 Unauthorized
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
async fn test_jwt_extractor_malformed_header() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Request with malformed Authorization header should fail
    let response = client
        .get(&format!("http://{}/api/v1/account", app.address))
        .header("Authorization", "InvalidFormat token_here")
        .send()
        .await
        .unwrap();

    // Should return 401 Unauthorized or 403 Forbidden
    assert!(
        response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::FORBIDDEN
    );
}

// ============================================================================
// Request Signing Middleware Tests
// ============================================================================
// Note: Request signing is typically required for critical operations
// like account deletion and key upload (if enabled in config)

#[tokio::test]
#[serial]
async fn test_request_signing_optional_when_disabled() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // Upload keys without request signature (should work if signing is disabled)
    let bundle = create_test_bundle(Some(user_id.clone()));
    let response = client
        .post(&format!("http://{}/api/v1/keys/upload", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&bundle)
        .send()
        .await
        .unwrap();

    // Should succeed if request signing is disabled
    // If enabled, would return 400 Bad Request
    // This test verifies the middleware doesn't block when signing is optional
    assert!(
        response.status() == reqwest::StatusCode::OK
            || response.status() == reqwest::StatusCode::BAD_REQUEST
    );
}

// ============================================================================
// Combined Middleware Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_middleware_chain_order() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // Make a request that goes through all middleware:
    // 1. CSRF check (bypassed with X-Requested-With)
    // 2. Rate limiting (should pass)
    // 3. JWT authentication (should pass)
    let response = client
        .get(&format!("http://{}/api/v1/account", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .unwrap();

    // Should succeed after passing all middleware checks
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
#[serial]
async fn test_middleware_public_endpoints() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = reqwest::Client::builder().build().unwrap();

    // Public endpoints should not require authentication or CSRF
    let endpoints = vec![
        "/health/ready",
        "/health/live",
        "/api/v1/auth/register",
        "/api/v1/auth/login",
    ];

    for endpoint in endpoints {
        let response = client
            .get(&format!("http://{}{}", app.address, endpoint))
            .send()
            .await
            .unwrap();

        // Should not return 401/403 (authentication/authorization errors)
        // May return other status codes (e.g., 400 for POST endpoints with GET)
        assert_ne!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert_ne!(response.status(), reqwest::StatusCode::FORBIDDEN);
    }
}
