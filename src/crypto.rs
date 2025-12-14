use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use base64::{engine::general_purpose, Engine as _};


pub fn generate_x25519_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);

    let secret_bytes = secret.to_bytes();
    let public_bytes = public.to_bytes();

    (secret_bytes, public_bytes)
}

pub fn encrypt_message(message: &[u8], recipient_public_key: &[u8]) -> Result<Vec<u8>> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    let recipient_public = X25519PublicKey::from(<[u8; 32]>::try_from(recipient_public_key)?);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);

    let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());
    let nonce = Nonce::from_slice(b"unique nonce");
    let ciphertext = cipher
        .encrypt(nonce, message)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

    let mut result = ephemeral_public.to_bytes().to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

pub fn decrypt_message(encrypted: &[u8], private_key_bytes: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < 32 {
        return Err(anyhow::anyhow!("Invalid encrypted message"));
    }

    let ephemeral_public = X25519PublicKey::from(<[u8; 32]>::try_from(&encrypted[..32])?);
    let ciphertext = &encrypted[32..];

    let private_key_array = <[u8; 32]>::try_from(private_key_bytes)?;
    let our_secret = StaticSecret::from(private_key_array);

    let shared_secret = our_secret.diffie_hellman(&ephemeral_public);

    let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());
    let nonce = Nonce::from_slice(b"unique nonce");
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

    Ok(plaintext)
}

pub fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    general_purpose::STANDARD.decode(input).map_err(|e| format!("Base64 decode error: {}", e))
}

pub fn encode_base64(input: &[u8]) -> String {
    general_purpose::STANDARD.encode(input)
}
