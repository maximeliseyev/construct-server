// ============================================================================
// Media Service Utilities
// ============================================================================

use sha2::{Digest, Sha256};

/// Validate upload token using HMAC
pub fn validate_upload_token(token: &str, secret: &str) -> bool {
    if token.len() < 65 {
        // 64 chars HMAC + 1 char separator
        return false;
    }

    let parts: Vec<&str> = token.split(':').collect();
    if parts.len() != 2 {
        return false;
    }

    let expected_hmac = parts[0];
    let message = parts[1];

    let computed_hmac = compute_hmac(message, secret);
    expected_hmac == computed_hmac
}

/// Compute HMAC-SHA256
pub fn compute_hmac(message: &str, secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update(message.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}
