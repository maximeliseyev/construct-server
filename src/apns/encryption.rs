use anyhow::{Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Encryption for device tokens using ChaCha20-Poly1305
/// Provides authenticated encryption to protect device tokens in database
pub struct DeviceTokenEncryption {
    cipher: ChaCha20Poly1305,
}

impl DeviceTokenEncryption {
    /// Create new encryption instance from key
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        let cipher = ChaCha20Poly1305::new(key.into());
        Ok(Self { cipher })
    }

    /// Create from hex-encoded key string
    pub fn from_hex(hex_key: &str) -> Result<Self> {
        if hex_key.len() != 64 {
            anyhow::bail!("Device token encryption key must be 64 hex characters (32 bytes)");
        }

        let key_bytes = hex::decode(hex_key)
            .context("Invalid hex in device token encryption key")?;

        let key: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Key must be exactly 32 bytes"))?;

        Self::new(&key)
    }

    /// Encrypt device token
    /// Returns: nonce (12 bytes) || ciphertext (variable) || tag (16 bytes)
    pub fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Prepend nonce to ciphertext (nonce is public, doesn't need encryption)
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt device token
    /// Input: nonce (12 bytes) || ciphertext (variable) || tag (16 bytes)
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<String> {
        if encrypted.len() < 12 {
            anyhow::bail!("Encrypted data too short");
        }

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        String::from_utf8(plaintext).context("Decrypted data is not valid UTF-8")
    }

    /// Hash device token for deduplication (SHA256)
    /// This is safe to store in DB - cannot be reversed
    pub fn hash_token(token: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0u8; 32]; // Test key
        let encryption = DeviceTokenEncryption::new(&key).unwrap();

        let original = "test_device_token_12345";
        let encrypted = encryption.encrypt(original).unwrap();
        let decrypted = encryption.decrypt(&encrypted).unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_hash_token_deterministic() {
        let token = "test_token";
        let hash1 = DeviceTokenEncryption::hash_token(token);
        let hash2 = DeviceTokenEncryption::hash_token(token);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // SHA256 produces 32 bytes
    }

    #[test]
    fn test_hash_token_different_for_different_inputs() {
        let hash1 = DeviceTokenEncryption::hash_token("token1");
        let hash2 = DeviceTokenEncryption::hash_token("token2");

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_from_hex() {
        let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let encryption = DeviceTokenEncryption::from_hex(hex_key).unwrap();

        let original = "test";
        let encrypted = encryption.encrypt(original).unwrap();
        let decrypted = encryption.decrypt(&encrypted).unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_from_hex_invalid_length() {
        let result = DeviceTokenEncryption::from_hex("too_short");
        assert!(result.is_err());
    }
}
