use crate::context::AppContext;
use crate::handlers::connection::ConnectionHandler;
use crate::message::ServerMessage;
use sqlx::Row;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Handle device token registration (APNs)
pub async fn handle_register_device_token(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    device_token: String,
    device_name: Option<String>,
    notification_filter: Option<String>,
) {
    // Get authenticated user ID
    let user_id = match handler.user_id() {
        Some(id) => id,
        None => {
            handler
                .send_error("UNAUTHORIZED", "You must be authenticated to register device token")
                .await;
            return;
        }
    };

    // Validate device token format (APNs tokens are typically 64 hex characters)
    if device_token.is_empty() || device_token.len() > 128 {
        handler
            .send_error("INVALID_DEVICE_TOKEN", "Device token format is invalid")
            .await;
        return;
    }

    // Validate notification filter
    let filter = notification_filter.unwrap_or_else(|| "silent".to_string());
    let valid_filters = ["silent", "visible_all", "visible_dm", "visible_mentions", "visible_contacts"];
    if !valid_filters.contains(&filter.as_str()) {
        handler
            .send_error(
                "INVALID_FILTER",
                &format!("Invalid notification filter. Must be one of: {:?}", valid_filters),
            )
            .await;
        return;
    }

    debug!(
        "Registering device token for user_id={}, filter={}",
        user_id, filter
    );

    // Insert or update device token in database
    let query_result = sqlx::query(
        r#"
        INSERT INTO device_tokens (user_id, device_token, device_name, notification_filter, enabled)
        VALUES ($1, $2, $3, $4, TRUE)
        ON CONFLICT (user_id, device_token)
        DO UPDATE SET
            device_name = EXCLUDED.device_name,
            notification_filter = EXCLUDED.notification_filter,
            enabled = TRUE,
            last_used_at = NOW(),
            updated_at = NOW()
        "#,
    )
    .bind(Uuid::parse_str(&user_id).unwrap())
    .bind(&device_token)
    .bind(&device_name)
    .bind(&filter)
    .execute(&*ctx.db_pool)
    .await;

    match query_result {
        Ok(_) => {
            info!(
                "Device token registered successfully for user_id={}, filter={}",
                user_id, filter
            );
            let _ = handler.send_msgpack(&ServerMessage::DeviceTokenRegistered).await;
        }
        Err(e) => {
            error!("Failed to register device token: {:?}", e);
            handler
                .send_error("SERVER_ERROR", "Failed to register device token")
                .await;
        }
    }
}

/// Handle device token unregistration
pub async fn handle_unregister_device_token(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    device_token: String,
) {
    // Get authenticated user ID
    let user_id = match handler.user_id() {
        Some(id) => id,
        None => {
            handler
                .send_error("UNAUTHORIZED", "You must be authenticated")
                .await;
            return;
        }
    };

    debug!(
        "Unregistering device token for user_id={}",
        user_id
    );

    // Delete device token from database
    let query_result = sqlx::query(
        r#"
        DELETE FROM device_tokens
        WHERE user_id = $1 AND device_token = $2
        "#,
    )
    .bind(Uuid::parse_str(&user_id).unwrap())
    .bind(&device_token)
    .execute(&*ctx.db_pool)
    .await;

    match query_result {
        Ok(result) => {
            if result.rows_affected() > 0 {
                info!("Device token unregistered successfully for user_id={}", user_id);
                let _ = handler.send_msgpack(&ServerMessage::DeviceTokenUnregistered).await;
            } else {
                warn!("Device token not found for user_id={}", user_id);
                handler
                    .send_error("DEVICE_TOKEN_NOT_FOUND", "Device token not found")
                    .await;
            }
        }
        Err(e) => {
            error!("Failed to unregister device token: {:?}", e);
            handler
                .send_error("SERVER_ERROR", "Failed to unregister device token")
                .await;
        }
    }
}

/// Handle device token preferences update
pub async fn handle_update_device_token_preferences(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    device_token: String,
    notification_filter: String,
    enabled: bool,
) {
    // Get authenticated user ID
    let user_id = match handler.user_id() {
        Some(id) => id,
        None => {
            handler
                .send_error("UNAUTHORIZED", "You must be authenticated")
                .await;
            return;
        }
    };

    // Validate notification filter
    let valid_filters = ["silent", "visible_all", "visible_dm", "visible_mentions", "visible_contacts"];
    if !valid_filters.contains(&notification_filter.as_str()) {
        handler
            .send_error(
                "INVALID_FILTER",
                &format!("Invalid notification filter. Must be one of: {:?}", valid_filters),
            )
            .await;
        return;
    }

    debug!(
        "Updating device token preferences for user_id={}, filter={}, enabled={}",
        user_id, notification_filter, enabled
    );

    // Update device token preferences
    let query_result = sqlx::query(
        r#"
        UPDATE device_tokens
        SET notification_filter = $3, enabled = $4, updated_at = NOW()
        WHERE user_id = $1 AND device_token = $2
        "#,
    )
    .bind(Uuid::parse_str(&user_id).unwrap())
    .bind(&device_token)
    .bind(&notification_filter)
    .bind(enabled)
    .execute(&*ctx.db_pool)
    .await;

    match query_result {
        Ok(result) => {
            if result.rows_affected() > 0 {
                info!(
                    "Device token preferences updated successfully for user_id={}",
                    user_id
                );
                let _ = handler.send_msgpack(&ServerMessage::DeviceTokenPreferencesUpdated).await;
            } else {
                warn!("Device token not found for user_id={}", user_id);
                handler
                    .send_error("DEVICE_TOKEN_NOT_FOUND", "Device token not found")
                    .await;
            }
        }
        Err(e) => {
            error!("Failed to update device token preferences: {:?}", e);
            handler
                .send_error("SERVER_ERROR", "Failed to update device token preferences")
                .await;
        }
    }
}

/// Get active device tokens for a user (for sending push notifications)
pub async fn get_user_device_tokens(
    ctx: &AppContext,
    user_id: &str,
) -> Result<Vec<DeviceToken>, sqlx::Error> {
    let user_uuid = Uuid::parse_str(user_id).map_err(|_| {
        sqlx::Error::Decode(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid user_id UUID",
        )))
    })?;

    let rows = sqlx::query(
        r#"
        SELECT device_token, notification_filter
        FROM device_tokens
        WHERE user_id = $1 AND enabled = TRUE
        ORDER BY last_used_at DESC
        "#,
    )
    .bind(user_uuid)
    .fetch_all(&*ctx.db_pool)
    .await?;

    let tokens = rows
        .into_iter()
        .map(|row| DeviceToken {
            device_token: row.get("device_token"),
            notification_filter: row.get("notification_filter"),
        })
        .collect();

    Ok(tokens)
}

/// Device token data structure
#[derive(Debug, Clone)]
pub struct DeviceToken {
    pub device_token: String,
    pub notification_filter: String,
}
