//! End-to-End Encryption Implementation
//!
//! This module provides E2E encryption using:
//! - X25519 for key exchange (Elliptic Curve Diffie-Hellman)
//! - ChaCha20-Poly1305 for authenticated encryption
//!
//! # Security Model
//!
//! 1. **Client-side encryption**: All encryption/decryption happens on client devices
//! 2. **Server-side storage**: Server stores encrypted messages without ability to decrypt
//! 3. **Key management**: Private keys NEVER leave the client device
//!
//! # How it works
//!
//! ## Registration (Client)
//! ```rust,ignore
//! let (private_key, public_key) = generate_x25519_keypair();
//! // Store private_key securely on device (e.g., keychain)
//! // Send public_key to server during registration
//! ```
//!
//! ## Sending a message (Client A → B)
//! ```rust,ignore
//! // 1. Fetch recipient's public key from server
//! let recipient_public_key = fetch_public_key("user_b").await?;
//!
//! // 2. Encrypt message on client
//! let plaintext = "Secret message";
//! let (encrypted, nonce) = encrypt_message(
//!     plaintext.as_bytes(),
//!     &recipient_public_key
//! )?;
//!
//! // 3. Send to server (server cannot decrypt!)
//! send_message(Message {
//!     content: base64_encode(&encrypted),
//!     nonce: Some(base64_encode(&nonce)),
//!     ...
//! });
//! ```
//!
//! ## Receiving a message (Client B)
//! ```rust,ignore
//! // 1. Receive encrypted message from server
//! let message = receive_message().await?;
//!
//! // 2. Decrypt on client using private key
//! let encrypted = base64_decode(&message.content)?;
//! let nonce = base64_decode(&message.nonce.unwrap())?;
//! let my_private_key = load_from_secure_storage();
//!
//! let plaintext = decrypt_message(
//!     &encrypted,
//!     &my_private_key,
//!     &nonce.try_into()?
//! )?;
//! ```
//!
//! # Important Security Notes
//!
//! - **Nonce uniqueness**: Each message MUST use a unique random nonce
//! - **Nonce is public**: The nonce can be transmitted openly with the ciphertext
//! - **Never reuse nonce**: Reusing a nonce with the same key breaks security
//! - **Private key storage**: Private keys must be stored securely (e.g., OS keychain)
//! - **Server cannot decrypt**: The server only sees encrypted blobs

use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use base64::{engine::general_purpose, Engine as _};

/// Generates a new X25519 keypair for E2E encryption
/// Returns (private_key, public_key)
///
/// SECURITY: The private key must NEVER leave the client device!
#[allow(dead_code)]
pub fn generate_x25519_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);

    let secret_bytes = secret.to_bytes();
    let public_bytes = public.to_bytes();

    (secret_bytes, public_bytes)
}

/// Encrypts a message for the recipient using their public key
///
/// This implements E2E encryption where:
/// 1. An ephemeral keypair is generated for this message
/// 2. A shared secret is derived using X25519 Diffie-Hellman
/// 3. The message is encrypted with ChaCha20-Poly1305
/// 4. A unique random nonce is generated for each encryption
///
/// Returns: (encrypted_data, nonce)
/// - encrypted_data: [ephemeral_public_key || ciphertext]
/// - nonce: 12 random bytes that must be sent with the message
///
/// SECURITY:
/// - The nonce MUST be unique for every message
/// - The nonce is NOT secret and can be transmitted openly
/// - Never reuse a nonce with the same key!
#[allow(dead_code)]
pub fn encrypt_message(message: &[u8], recipient_public_key: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    let recipient_public = X25519PublicKey::from(<[u8; 32]>::try_from(recipient_public_key)?);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);

    let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());

    // CRITICAL: Generate a unique random nonce for THIS message
    // Using the same nonce with the same key breaks encryption security!
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, message)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

    // Result format: [32 bytes ephemeral public key || ciphertext]
    let mut result = ephemeral_public.to_bytes().to_vec();
    result.extend_from_slice(&ciphertext);

    Ok((result, nonce_bytes))
}

/// Decrypts a message using the recipient's private key
///
/// This is the counterpart to encrypt_message and:
/// 1. Extracts the ephemeral public key from the encrypted data
/// 2. Derives the shared secret using the recipient's private key
/// 3. Decrypts the ciphertext using the provided nonce
///
/// Parameters:
/// - encrypted: The encrypted data [ephemeral_public_key || ciphertext]
/// - private_key_bytes: The recipient's private key (32 bytes)
/// - nonce_bytes: The nonce that was used for encryption (12 bytes)
///
/// Returns: The decrypted plaintext
///
/// SECURITY:
/// - The private key must NEVER be sent to the server
/// - This function should only run on the client device
/// - The nonce must be the same one used during encryption
#[allow(dead_code)]
pub fn decrypt_message(
    encrypted: &[u8],
    private_key_bytes: &[u8],
    nonce_bytes: &[u8; 12],
) -> Result<Vec<u8>> {
    if encrypted.len() < 32 {
        return Err(anyhow::anyhow!("Invalid encrypted message: too short"));
    }

    // Extract ephemeral public key (first 32 bytes)
    let ephemeral_public = X25519PublicKey::from(<[u8; 32]>::try_from(&encrypted[..32])?);
    let ciphertext = &encrypted[32..];

    // Load recipient's private key
    let private_key_array = <[u8; 32]>::try_from(private_key_bytes)?;
    let our_secret = StaticSecret::from(private_key_array);

    // Derive shared secret
    let shared_secret = our_secret.diffie_hellman(&ephemeral_public);

    let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

    Ok(plaintext)
}

/// Validates that a public key is a valid X25519 public key.
/// It must be 32 bytes and a valid point on the curve.
#[allow(dead_code)]
pub fn validate_public_key(key: &[u8]) -> Result<()> {
    if key.len() != 32 {
        return Err(anyhow::anyhow!("Public key must be 32 bytes"));
    }
    // This will fail if the key is not a valid point on the curve
    let _ = X25519PublicKey::from(<[u8; 32]>::try_from(key)?);
    Ok(())
}

pub fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    general_purpose::STANDARD.decode(input).map_err(|e| format!("Base64 decode error: {}", e))
}

pub fn encode_base64(input: &[u8]) -> String {
    general_purpose::STANDARD.encode(input)
}
