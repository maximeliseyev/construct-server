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

/// Validates password complexity requirements.
///
/// # Password Requirements
/// - Minimum length: 10 characters
/// - At least one uppercase letter (A-Z)
/// - At least one lowercase letter (a-z)
/// - At least one digit (0-9)
///
/// # Returns
/// - `Ok(())` if password meets all requirements
/// - `Err(String)` with user-friendly error message if validation fails
///
/// # Security Note
/// We intentionally do NOT check for special characters to avoid forcing
/// users into specific password managers or causing UX friction.
/// Length + mixed case + digits provides sufficient entropy.
pub fn validate_password_strength(password: &str) -> Result<(), String> {
    // 1. Check minimum length (10 characters for good entropy)
    if password.len() < 10 {
        return Err("Password must be at least 10 characters long".to_string());
    }

    // 2. Check for at least one uppercase letter
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err("Password must contain at least one uppercase letter".to_string());
    }

    // 3. Check for at least one lowercase letter
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err("Password must contain at least one lowercase letter".to_string());
    }

    // 4. Check for at least one digit
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("Password must contain at least one digit".to_string());
    }

    // 5. Optional: Check maximum length to prevent DoS via bcrypt
    // bcrypt has max input of 72 bytes, but we limit earlier for performance
    if password.len() > 128 {
        return Err("Password must not exceed 128 characters".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_too_short() {
        assert!(validate_password_strength("Short1").is_err());
    }

    #[test]
    fn test_password_no_uppercase() {
        assert!(validate_password_strength("lowercase123").is_err());
    }

    #[test]
    fn test_password_no_lowercase() {
        assert!(validate_password_strength("UPPERCASE123").is_err());
    }

    #[test]
    fn test_password_no_digit() {
        assert!(validate_password_strength("NoDigitsHere").is_err());
    }

    #[test]
    fn test_password_valid() {
        assert!(validate_password_strength("ValidPass123").is_ok());
        assert!(validate_password_strength("AnotherGood1").is_ok());
        assert!(validate_password_strength("MySecurePassword2024").is_ok());
    }

    #[test]
    fn test_password_too_long() {
        let long_password = "A".repeat(129) + "a1";
        assert!(validate_password_strength(&long_password).is_err());
    }
}
