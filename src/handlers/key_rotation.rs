use crate::context::AppContext;
use crate::handlers::connection::ConnectionHandler;
use crate::message::ServerMessage;
use crate::crypto::{ServerCryptoValidator, SignedPrekeyUpdate};
use uuid::Uuid;

/// Handles signed prekey rotation request
/// 
/// This allows users to periodically rotate their signed prekeys for forward secrecy.
/// The server validates format and rate limits, but cannot verify cryptographic correctness.
pub async fn handle_rotate_prekey(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    user_id: String,
    update_base64: String,
) {
    // 1. Валидация user_id
    let uuid = match Uuid::parse_str(&user_id) {
        Ok(u) => u,
        Err(_) => {
            tracing::warn!(user_id = %user_id, "Invalid user ID format for key rotation");
            handler.send_error("INVALID_USER_ID", "Invalid user ID format").await;
            return;
        }
    };

    // 2. Декодируем update из base64 JSON
    let update_json = match crate::crypto::decode_base64(&update_base64) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(json) => json,
            Err(e) => {
                tracing::warn!(error = %e, "Invalid UTF-8 in prekey update");
                handler.send_error("INVALID_UPDATE", "Invalid encoding").await;
                return;
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "Invalid base64 in prekey update");
            handler.send_error("INVALID_UPDATE", "Invalid base64").await;
            return;
        }
    };

    let update: SignedPrekeyUpdate = match serde_json::from_str(&update_json) {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, "Invalid prekey update JSON");
            handler.send_error("INVALID_UPDATE", "Invalid update format").await;
            return;
        }
    };

    // 4. Rate limiting для ротации ключей
    let mut queue = ctx.queue.lock().await;
    let key_rotation_count = match queue.increment_key_update_count(&user_id).await {
        Ok(count) => count,
        Err(e) => {
            tracing::error!(error = %e, "Failed to check key rotation rate limit");
            0
        }
    };

    let max_rotations = ctx.config.security.max_key_rotations_per_day;
    if key_rotation_count > max_rotations {
        tracing::warn!(
            user_id = %user_id,
            count = key_rotation_count,
            limit = max_rotations,
            "Key rotation rate limit exceeded"
        );
        drop(queue);
        handler.send_error(
            "RATE_LIMIT_EXCEEDED",
            &format!("Too many key rotations. Limit: {}/day", max_rotations),
        ).await;
        return;
    }
    drop(queue);

    // 5. Получаем текущий bundle из базы данных
    let mut bundle = match crate::db::get_user_key_bundle(&ctx.db_pool, &uuid).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            tracing::warn!(user_id = %user_id, "Key bundle not found for rotation");
            handler.send_error("USER_NOT_FOUND", "Key bundle not found").await;
            return;
        }
        Err(e) => {
            tracing::error!(error = %e, user_id = %user_id, "Database error during key rotation");
            handler.send_error("SERVER_ERROR", "Database error").await;
            return;
        }
    };

    // 6. Обновляем prekey с использованием конфига
    bundle.signed_prekey_public = crate::crypto::encode_base64(&update.new_prekey_public);
    bundle.signature = crate::crypto::encode_base64(&update.signature);
    bundle.registered_at = chrono::Utc::now();
    bundle.prekey_expires_at = chrono::Utc::now() 
        + chrono::Duration::days(ctx.config.security.prekey_ttl_days);

    // 7. Валидация обновленного bundle
    if let Err(e) = ServerCryptoValidator::validate_key_bundle(&bundle) {
        tracing::warn!(
            error = %e,
            user_id = %user_id,
            "Invalid key bundle after rotation"
        );
        handler.send_error("INVALID_KEY_BUNDLE", &e.to_string()).await;
        return;
    }

    // 8. Сохранение в БД
    if let Err(e) = crate::db::store_key_bundle(&ctx.db_pool, &uuid, &bundle).await {
        tracing::error!(
            error = %e,
            user_id = %user_id,
            "Failed to store rotated key bundle"
        );
        handler.send_error("SERVER_ERROR", "Failed to update key").await;
        return;
    }

    let mut queue = ctx.queue.lock().await;
    if let Err(e) = queue.invalidate_key_bundle_cache(&user_id).await {
        tracing::warn!(error = %e, "Failed to invalidate key bundle cache");
    }
    drop(queue);

    // 10. Успешный ответ
    let _ = handler.send_msgpack(&ServerMessage::KeyRotationSuccess).await;
    
    tracing::info!(
        user_id = %user_id,
        expires_at = %bundle.prekey_expires_at,
        "Prekey rotated successfully"
    );
}