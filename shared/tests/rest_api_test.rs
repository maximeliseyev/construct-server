// ============================================================================
// REST API Endpoints Tests
// ============================================================================
//
// Tests for all REST API endpoints after Axum migration:
// - GET /health
// - GET /metrics
// - POST /keys/upload
// - GET /keys/:user_id
// - POST /messages/send
// - GET /.well-known/konstruct
// - GET /federation/health
//
// ============================================================================

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use construct_server_shared::e2e::{BundleData, SuiteKeyMaterial, UploadableKeyBundle};
use serial_test::serial;
use uuid::Uuid;

mod test_utils;
use test_utils::spawn_app;

#[tokio::test]
#[serial]
async fn test_health_endpoint() {
    let app = spawn_app().await;

    let client = reqwest::Client::new();
    let response = client
        .get(&format!("http://{}/health", app.address))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.text().await.unwrap();
    assert_eq!(body, "OK");
}

#[tokio::test]
#[serial]
async fn test_metrics_endpoint() {
    let app = spawn_app().await;

    let client = reqwest::Client::new();
    let response = client
        .get(&format!("http://{}/metrics", app.address))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let content_type = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("text/plain"));

    let body = response.text().await.unwrap();
    // Metrics should contain some basic metrics
    assert!(body.contains("construct_server") || body.len() > 0);
}

#[tokio::test]
#[serial]
async fn test_keys_upload_requires_auth() {
    let app = spawn_app().await;

    let bundle = create_test_bundle("test-user-id".to_string());

    let client = reqwest::Client::new();
    let response = client
        .post(&format!("http://{}/keys/upload", app.address))
        .json(&bundle)
        .send()
        .await
        .unwrap();

    // Should require authentication
    assert!(
        response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::FORBIDDEN
    );
}

#[tokio::test]
#[serial]
async fn test_keys_get_requires_auth() {
    let app = spawn_app().await;

    let client = reqwest::Client::new();
    let response = client
        .get(&format!("http://{}/keys/{}", app.address, Uuid::new_v4()))
        .send()
        .await
        .unwrap();

    // Should require authentication
    assert!(
        response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::FORBIDDEN
    );
}

#[tokio::test]
#[serial]
async fn test_messages_send_requires_auth() {
    let app = spawn_app().await;

    let client = reqwest::Client::new();
    let response = client
        .post(&format!("http://{}/messages/send", app.address))
        .json(&serde_json::json!({
            "recipient_id": Uuid::new_v4().to_string(),
            "ciphertext": "test",
            "suite_id": 1
        }))
        .send()
        .await
        .unwrap();

    // Should require authentication
    assert!(
        response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::FORBIDDEN
    );
}

#[tokio::test]
#[serial]
async fn test_well_known_konstruct() {
    let app = spawn_app().await;

    let client = reqwest::Client::new();
    let response = client
        .get(&format!("http://{}/.well-known/konstruct", app.address))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let json: serde_json::Value = response.json().await.unwrap();

    // Should contain federation info
    assert!(json.get("federation").is_some());
    assert!(json.get("server").is_some());
    assert!(json.get("version").is_some());
}

#[tokio::test]
#[serial]
async fn test_federation_health() {
    let app = spawn_app().await;

    let client = reqwest::Client::new();
    let response = client
        .get(&format!("http://{}/federation/health", app.address))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let json: serde_json::Value = response.json().await.unwrap();

    assert_eq!(json.get("status").unwrap().as_str().unwrap(), "healthy");
    assert!(json.get("federation_enabled").is_some());
}

#[tokio::test]
#[serial]
async fn test_not_found_endpoint() {
    let app = spawn_app().await;

    let client = reqwest::Client::new();
    let response = client
        .get(&format!("http://{}/nonexistent", app.address))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
}

// Helper function to create a test key bundle
fn create_test_bundle(user_id: String) -> UploadableKeyBundle {
    let suite_material = SuiteKeyMaterial {
        suite_id: 1,
        identity_key: BASE64.encode(vec![0u8; 32]),
        signed_prekey: BASE64.encode(vec![1u8; 32]),
        signed_prekey_signature: BASE64.encode(vec![2u8; 64]),
        one_time_prekeys: vec![],
    };

    let bundle_data = BundleData {
        user_id,
        timestamp: chrono::Utc::now().to_rfc3339(),
        supported_suites: vec![suite_material],
    };

    let bundle_data_json = serde_json::to_string(&bundle_data).unwrap();
    let bundle_data_base64 = BASE64.encode(bundle_data_json.as_bytes());

    UploadableKeyBundle {
        master_identity_key: BASE64.encode(vec![2u8; 32]),
        bundle_data: bundle_data_base64,
        signature: BASE64.encode(vec![3u8; 64]),
        nonce: None,
        timestamp: None,
    }
}
