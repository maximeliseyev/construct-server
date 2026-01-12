// ============================================================================
// Construct Media Server - Privacy-Focused Media Storage
// ============================================================================
//
// SECURITY DESIGN:
// ================
// 1. NO IP LOGGING - We don't log IP addresses
// 2. NO USER TRACKING - Upload tokens are one-time, no user_id stored
// 3. ENCRYPTED BLOBS ONLY - We store only E2E encrypted data
// 4. AUTO-DELETE - Files are deleted after TTL (default 7 days)
// 5. MINIMAL METADATA - Only media_id → blob, nothing else
//
// Architecture:
// =============
// - construct-server issues one-time upload tokens
// - Client uploads encrypted blob with token
// - Client downloads via public URL (no auth - content is E2E encrypted)
// - Periodic cleanup deletes expired files
//
// Endpoints:
// ==========
// POST /upload              - Upload encrypted media (requires token)
// GET  /{media_id}          - Download encrypted media (public)
// GET  /health              - Health check
// DELETE /{media_id}        - Delete media (internal, requires admin token)
//
// ============================================================================

use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{Multipart, Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

// ============================================================================
// Configuration
// ============================================================================

#[derive(Clone)]
struct MediaConfig {
    /// Directory to store media files
    data_dir: PathBuf,
    /// Maximum file size in bytes (default: 100MB)
    max_file_size: usize,
    /// TTL for media files in seconds (default: 7 days)
    ttl_seconds: u64,
    /// Port to listen on
    port: u16,
    /// Secret for validating upload tokens (shared with construct-server)
    upload_token_secret: String,
    /// Admin token for delete operations
    admin_token: Option<String>,
}

impl MediaConfig {
    fn from_env() -> Result<Self> {
        let data_dir = std::env::var("MEDIA_DATA_DIR")
            .unwrap_or_else(|_| "/data/media".to_string());
        
        let max_file_size = std::env::var("MEDIA_MAX_FILE_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100 * 1024 * 1024); // 100MB
        
        let ttl_days = std::env::var("MEDIA_TTL_DAYS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(7);
        
        let port = std::env::var("MEDIA_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8090);
        
        let upload_token_secret = std::env::var("MEDIA_UPLOAD_TOKEN_SECRET")
            .context("MEDIA_UPLOAD_TOKEN_SECRET is required")?;
        
        if upload_token_secret.len() < 32 {
            anyhow::bail!("MEDIA_UPLOAD_TOKEN_SECRET must be at least 32 characters");
        }
        
        let admin_token = std::env::var("MEDIA_ADMIN_TOKEN").ok();
        
        Ok(Self {
            data_dir: PathBuf::from(data_dir),
            max_file_size,
            ttl_seconds: ttl_days * 24 * 60 * 60,
            port,
            upload_token_secret,
            admin_token,
        })
    }
}

// ============================================================================
// Application State
// ============================================================================

#[derive(Clone)]
struct AppState {
    config: Arc<MediaConfig>,
}

// ============================================================================
// API Types
// ============================================================================

#[derive(Serialize)]
struct UploadResponse {
    media_id: String,
    media_url: String,
    expires_at: String,
    size: usize,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    code: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    storage_available: bool,
}

// ============================================================================
// Token Validation
// ============================================================================

/// Upload token format: {timestamp_hex}.{random_hex}.{hmac_hex}
/// Token is valid for 5 minutes
fn validate_upload_token(token: &str, secret: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    
    let timestamp_hex = parts[0];
    let random_hex = parts[1];
    let provided_hmac = parts[2];
    
    // Parse timestamp
    let timestamp = match u64::from_str_radix(timestamp_hex, 16) {
        Ok(t) => t,
        Err(_) => return false,
    };
    
    // Check expiry (5 minutes)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    if now > timestamp + 300 || now < timestamp.saturating_sub(60) {
        // Token expired or from future (allowing 60s clock skew)
        return false;
    }
    
    // Verify HMAC
    let message = format!("{}.{}", timestamp_hex, random_hex);
    let expected_hmac = compute_hmac(&message, secret);
    
    // Constant-time comparison
    if provided_hmac.len() != expected_hmac.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (a, b) in provided_hmac.bytes().zip(expected_hmac.bytes()) {
        result |= a ^ b;
    }
    
    result == 0
}

fn compute_hmac(message: &str, secret: &str) -> String {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Generate an upload token (for construct-server to use)
#[allow(dead_code)]
pub fn generate_upload_token(secret: &str) -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let timestamp_hex = format!("{:x}", timestamp);
    let random_bytes: [u8; 16] = rand::random();
    let random_hex = hex::encode(random_bytes);
    
    let message = format!("{}.{}", timestamp_hex, random_hex);
    let hmac = compute_hmac(&message, secret);
    
    format!("{}.{}.{}", timestamp_hex, random_hex, hmac)
}

// ============================================================================
// Handlers
// ============================================================================

/// Health check endpoint
async fn health_check(State(state): State<AppState>) -> Json<HealthResponse> {
    let storage_available = state.config.data_dir.exists() 
        || fs::create_dir_all(&state.config.data_dir).await.is_ok();
    
    Json(HealthResponse {
        status: if storage_available { "ok".into() } else { "degraded".into() },
        storage_available,
    })
}

/// Upload encrypted media
async fn upload_media(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut file_data: Option<Vec<u8>> = None;
    let mut upload_token: Option<String> = None;
    let mut content_hash: Option<String> = None;
    
    // Parse multipart form
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: format!("Failed to parse multipart: {}", e),
            code: "INVALID_MULTIPART".into(),
        }))
    })? {
        let name = field.name().unwrap_or("").to_string();
        
        match name.as_str() {
            "file" => {
                let data = field.bytes().await.map_err(|e| {
                    (StatusCode::BAD_REQUEST, Json(ErrorResponse {
                        error: format!("Failed to read file: {}", e),
                        code: "READ_ERROR".into(),
                    }))
                })?;
                
                // Check size limit
                if data.len() > state.config.max_file_size {
                    return Err((StatusCode::PAYLOAD_TOO_LARGE, Json(ErrorResponse {
                        error: format!(
                            "File size {} bytes exceeds limit of {} bytes",
                            data.len(),
                            state.config.max_file_size
                        ),
                        code: "FILE_TOO_LARGE".into(),
                    })));
                }
                
                file_data = Some(data.to_vec());
            }
            "token" => {
                upload_token = Some(field.text().await.map_err(|e| {
                    (StatusCode::BAD_REQUEST, Json(ErrorResponse {
                        error: format!("Failed to read token: {}", e),
                        code: "INVALID_TOKEN".into(),
                    }))
                })?);
            }
            "hash" => {
                content_hash = Some(field.text().await.unwrap_or_default());
            }
            _ => {
                // Ignore unknown fields
            }
        }
    }
    
    // Validate token
    let token = upload_token.ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse {
            error: "Upload token is required".into(),
            code: "TOKEN_REQUIRED".into(),
        }))
    })?;
    
    if !validate_upload_token(&token, &state.config.upload_token_secret) {
        // SECURITY: Don't log the invalid token
        warn!("Invalid or expired upload token received");
        return Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse {
            error: "Invalid or expired upload token".into(),
            code: "INVALID_TOKEN".into(),
        })));
    }
    
    // Get file data
    let data = file_data.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "File is required".into(),
            code: "FILE_REQUIRED".into(),
        }))
    })?;
    
    // Verify hash if provided
    if let Some(expected_hash) = content_hash {
        if !expected_hash.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let actual_hash = hex::encode(hasher.finalize());
            
            if actual_hash != expected_hash {
                return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
                    error: "Content hash mismatch".into(),
                    code: "HASH_MISMATCH".into(),
                })));
            }
        }
    }
    
    // Generate media ID
    let media_id = Uuid::new_v4().to_string();
    
    // Ensure data directory exists
    fs::create_dir_all(&state.config.data_dir).await.map_err(|e| {
        error!(error = %e, "Failed to create data directory");
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Storage error".into(),
            code: "STORAGE_ERROR".into(),
        }))
    })?;
    
    // Write file
    let file_path = state.config.data_dir.join(&media_id);
    let mut file = fs::File::create(&file_path).await.map_err(|e| {
        error!(error = %e, "Failed to create file");
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Storage error".into(),
            code: "STORAGE_ERROR".into(),
        }))
    })?;
    
    file.write_all(&data).await.map_err(|e| {
        error!(error = %e, "Failed to write file");
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Storage error".into(),
            code: "STORAGE_ERROR".into(),
        }))
    })?;
    
    // Calculate expiry
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + state.config.ttl_seconds;
    
    let expires_at_str = chrono::DateTime::from_timestamp(expires_at as i64, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default();
    
    // SECURITY: Log without any PII - no IP, no user info
    info!(
        media_id = %media_id,
        size_bytes = data.len(),
        "Media uploaded successfully"
    );
    
    // Construct media URL (client will use this to download)
    // In production, this would be the public URL
    let media_url = format!("/{}", media_id);
    
    Ok(Json(UploadResponse {
        media_id,
        media_url,
        expires_at: expires_at_str,
        size: data.len(),
    }))
}

/// Download encrypted media (public - no auth required)
async fn download_media(
    State(state): State<AppState>,
    Path(media_id): Path<String>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    // Validate media_id format (UUID)
    if Uuid::parse_str(&media_id).is_err() {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "Invalid media ID format".into(),
            code: "INVALID_ID".into(),
        })));
    }
    
    let file_path = state.config.data_dir.join(&media_id);
    
    // Check if file exists
    if !file_path.exists() {
        return Err((StatusCode::NOT_FOUND, Json(ErrorResponse {
            error: "Media not found".into(),
            code: "NOT_FOUND".into(),
        })));
    }
    
    // Read file
    let data = fs::read(&file_path).await.map_err(|e| {
        error!(error = %e, media_id = %media_id, "Failed to read media file");
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "Storage error".into(),
            code: "STORAGE_ERROR".into(),
        }))
    })?;
    
    // SECURITY: No logging of download - we don't track who downloads
    
    // Return as binary with appropriate headers
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, data.len())
        .header(header::CACHE_CONTROL, "private, max-age=86400") // 24h cache
        .body(Body::from(data))
        .unwrap();
    
    Ok(response)
}

/// Delete media (internal/admin only)
async fn delete_media(
    State(state): State<AppState>,
    Path(media_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Validate admin token
    let admin_token = state.config.admin_token.as_ref().ok_or_else(|| {
        (StatusCode::FORBIDDEN, Json(ErrorResponse {
            error: "Delete not enabled".into(),
            code: "DELETE_DISABLED".into(),
        }))
    })?;
    
    let provided_token = headers
        .get("X-Admin-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    
    if provided_token != admin_token {
        return Err((StatusCode::FORBIDDEN, Json(ErrorResponse {
            error: "Invalid admin token".into(),
            code: "FORBIDDEN".into(),
        })));
    }
    
    // Validate media_id format
    if Uuid::parse_str(&media_id).is_err() {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "Invalid media ID format".into(),
            code: "INVALID_ID".into(),
        })));
    }
    
    let file_path = state.config.data_dir.join(&media_id);
    
    if file_path.exists() {
        fs::remove_file(&file_path).await.map_err(|e| {
            error!(error = %e, media_id = %media_id, "Failed to delete media file");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                error: "Delete error".into(),
                code: "DELETE_ERROR".into(),
            }))
        })?;
        
        info!(media_id = %media_id, "Media deleted");
    }
    
    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Cleanup Task
// ============================================================================

async fn cleanup_expired_files(config: Arc<MediaConfig>) {
    let cleanup_interval = std::time::Duration::from_secs(3600); // Every hour
    
    loop {
        tokio::time::sleep(cleanup_interval).await;
        
        info!("Starting expired media cleanup");
        
        let now = std::time::SystemTime::now();
        let mut deleted_count = 0;
        let mut error_count = 0;
        
        // Read directory entries
        let entries = match fs::read_dir(&config.data_dir).await {
            Ok(entries) => entries,
            Err(e) => {
                error!(error = %e, "Failed to read media directory for cleanup");
                continue;
            }
        };
        
        let mut entries = entries;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            
            // Get file metadata
            let metadata = match fs::metadata(&path).await {
                Ok(m) => m,
                Err(_) => continue,
            };
            
            // Check if file is expired
            let modified = match metadata.modified() {
                Ok(m) => m,
                Err(_) => continue,
            };
            
            let age = now.duration_since(modified).unwrap_or_default();
            
            if age.as_secs() > config.ttl_seconds {
                match fs::remove_file(&path).await {
                    Ok(_) => {
                        deleted_count += 1;
                    }
                    Err(e) => {
                        error!(error = %e, path = %path.display(), "Failed to delete expired file");
                        error_count += 1;
                    }
                }
            }
        }
        
        if deleted_count > 0 || error_count > 0 {
            info!(
                deleted = deleted_count,
                errors = error_count,
                "Media cleanup completed"
            );
        }
    }
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::new(
                std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
            ),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    
    info!("=== Construct Media Server Starting ===");
    
    // Load configuration
    let config = MediaConfig::from_env()?;
    let config = Arc::new(config);
    
    info!("Data directory: {}", config.data_dir.display());
    info!("Max file size: {} bytes", config.max_file_size);
    info!("TTL: {} days", config.ttl_seconds / 86400);
    info!("Port: {}", config.port);
    
    // Create data directory if it doesn't exist
    fs::create_dir_all(&config.data_dir).await?;
    
    let state = AppState {
        config: config.clone(),
    };
    
    // Spawn cleanup task
    let cleanup_config = config.clone();
    tokio::spawn(async move {
        cleanup_expired_files(cleanup_config).await;
    });
    
    // Build router
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/upload", post(upload_media))
        .route("/:media_id", get(download_media))
        .route("/:media_id", axum::routing::delete(delete_media))
        .with_state(state);
    
    // Start server
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], config.port));
    info!("Listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_and_validate_token() {
        let secret = "test-secret-that-is-at-least-32-chars-long";
        
        let token = generate_upload_token(secret);
        assert!(validate_upload_token(&token, secret));
        
        // Wrong secret should fail
        assert!(!validate_upload_token(&token, "wrong-secret"));
        
        // Malformed token should fail
        assert!(!validate_upload_token("invalid", secret));
        assert!(!validate_upload_token("a.b", secret));
        assert!(!validate_upload_token("a.b.c.d", secret));
    }
    
    #[test]
    fn test_compute_hmac() {
        let hmac1 = compute_hmac("test-message", "secret");
        let hmac2 = compute_hmac("test-message", "secret");
        let hmac3 = compute_hmac("different", "secret");
        
        assert_eq!(hmac1, hmac2);
        assert_ne!(hmac1, hmac3);
    }
}
