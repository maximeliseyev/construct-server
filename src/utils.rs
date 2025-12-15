use sha2::{Digest, Sha256};

/// Creates a truncated, salted hash of an identifier for safe logging.
///
/// # Arguments
/// * `id` - The identifier to hash (e.g., username, user_id).
/// * `salt` - A salt value from the application's configuration.
///
/// # Returns
/// A short, hexadecimal string representing the salted hash.
pub fn log_safe_id(id: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(id.as_bytes());
    let hash = hasher.finalize();

    // Take first 4 bytes and format each as hex
    hash[..4]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}
