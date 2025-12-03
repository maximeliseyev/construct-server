use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use anyhow::Result;

// Генерация ключевой пары для нового пользователя
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

// Шифрование сообщения (упрощённая версия)
pub fn encrypt_message(message: &[u8], recipient_public_key: &[u8]) -> Result<Vec<u8>> {
    // Генерируем временный ключ отправителя
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    
    // Создаём общий секрет
    let recipient_public = X25519PublicKey::from(<[u8; 32]>::try_from(recipient_public_key)?);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);
    
    // Шифруем сообщение
    let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());
    let nonce = Nonce::from_slice(b"unique nonce"); // В продакшене использовать random nonce
    let ciphertext = cipher.encrypt(nonce, message)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;
    // Возвращаем: [ephemeral_public_key (32 bytes) | ciphertext]
    let mut result = ephemeral_public.as_bytes().to_vec();
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

// Расшифровка сообщения (упрощённая версия)
pub fn decrypt_message(encrypted: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < 32 {
        return Err(anyhow::anyhow!("Invalid encrypted message"));
    }
    
    // Извлекаём ephemeral public key отправителя
    let ephemeral_public = X25519PublicKey::from(<[u8; 32]>::try_from(&encrypted[..32])?);
    let ciphertext = &encrypted[32..];
    
    // Создаём общий секрет используя наш приватный ключ
    let private_key_bytes = <[u8; 32]>::try_from(private_key)?;
    let our_private = x25519_dalek::StaticSecret::from(private_key_bytes);
    let shared_secret = our_private.diffie_hellman(&ephemeral_public);
    
    // Расшифровываем
    let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());
    let nonce = Nonce::from_slice(b"unique nonce");
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;
    Ok(plaintext)
}
