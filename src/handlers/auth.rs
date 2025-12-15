use crate::context::AppContext;
use crate::crypto::decode_base64;
use crate::db::{self, User};
use crate::handlers::connection::ConnectionHandler;
use crate::handlers::session::establish_session;
use crate::message::ServerMessage;
use crate::utils::log_safe_id;
use uuid::Uuid;

/// Helper function to establish session and update handler with user ID
async fn establish_session_and_set_user(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    user: &User,
    jti: &str,
) -> Result<(), String> {
    let mut user_id_temp = None;
    establish_session(&ctx, handler.tx(), &mut user_id_temp, user, jti).await?;

    if let Some(uid) = user_id_temp {
        handler.set_user_id(uid);
    }
    Ok(())
}

/// Handles user registration
/// Creates new user account, generates session token, and establishes connection
pub async fn handle_register(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    username: String,
    display_name: Option<String>,
    password: String,
    public_key: String,
) {
    let identity_key = match decode_base64(&public_key) {
        Ok(key) => key,
        Err(_) => {
            handler
                .send_error("INVALID_PUBLIC_KEY", "Public key is not valid base64")
                .await;
            return;
        }
    };

    let display_name_final = display_name.as_deref().unwrap_or(&username);

    match db::create_user(
        &ctx.db_pool,
        &username,
        display_name_final,
        &password,
        &identity_key,
    )
    .await
    {
        Ok(user) => {
            if ctx.config.logging.enable_user_identifiers {
                tracing::info!(
                    username = %user.username,
                    display_name = %user.display_name,
                    "User registered"
                );
            } else {
                tracing::info!(
                    user_hash = %log_safe_id(&user.id.to_string(), &ctx.config.logging.hash_salt),
                    "User registered"
                );
            }

            match ctx.auth_manager.create_token(&user.id) {
                Ok((token, jti, expires)) => {
                    if let Err(e_msg) =
                        establish_session_and_set_user(handler, ctx, &user, &jti).await
                    {
                        tracing::error!(error = %e_msg, "Failed to establish session");
                        handler
                            .send_error("SESSION_CREATION_FAILED", "Could not create session")
                            .await;
                        return;
                    }

                    let response = ServerMessage::RegisterSuccess {
                        user_id: user.id.to_string(),
                        username: user.username.clone(),
                        display_name: user.display_name.clone(),
                        session_token: token,
                        expires,
                    };
                    let _ = handler.send_msgpack(&response).await;
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to create token");
                    handler
                        .send_error("TOKEN_CREATION_FAILED", "Could not create session token")
                        .await;
                }
            }
        }
        Err(e) => {
            if ctx.config.logging.enable_user_identifiers {
                tracing::error!(error = %e, username = %username, "Registration failed");
            } else {
                tracing::error!(error = %e, "Registration failed");
            }
            let (code, message) = if e.to_string().contains("users_username_key") {
                (
                    "USERNAME_TAKEN",
                    format!("Username '{}' is already taken", username),
                )
            } else {
                ("REGISTRATION_FAILED", "Registration failed".to_string())
            };
            handler.send_error(code, &message).await;
        }
    }
}

/// Handles user login
/// Verifies credentials, generates session token, and establishes connection
pub async fn handle_login(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    username: String,
    password: String,
) {
    match db::get_user_by_username(&ctx.db_pool, &username).await {
        Ok(Some(user)) => {
            if db::verify_password(&user, &password).await.unwrap_or(false) {
                if ctx.config.logging.enable_user_identifiers {
                    tracing::info!(
                        username = %user.username,
                        display_name = %user.display_name,
                        "User logged in"
                    );
                } else {
                    tracing::info!(
                        user_hash = %log_safe_id(&user.id.to_string(), &ctx.config.logging.hash_salt),
                        "User logged in"
                    );
                }

                match ctx.auth_manager.create_token(&user.id) {
                    Ok((token, jti, expires)) => {
                        if let Err(e_msg) =
                            establish_session_and_set_user(handler, ctx, &user, &jti).await
                        {
                            tracing::error!(error = %e_msg, "Failed to establish session");
                            handler
                                .send_error("SESSION_CREATION_FAILED", "Could not create session")
                                .await;
                            return;
                        }

                        let response = ServerMessage::LoginSuccess {
                            user_id: user.id.to_string(),
                            username: user.username.clone(),
                            display_name: user.display_name.clone(),
                            session_token: token,
                            expires,
                        };
                        let _ = handler.send_msgpack(&response).await;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to create token");
                        handler
                            .send_error("TOKEN_CREATION_FAILED", "Could not create session token")
                            .await;
                    }
                }
            } else {
                if ctx.config.logging.enable_user_identifiers {
                    tracing::warn!(username = %username, "Invalid password");
                } else {
                    tracing::warn!("Invalid password attempt");
                }
                handler
                    .send_error("INVALID_CREDENTIALS", "Invalid credentials")
                    .await;
            }
        }
        Ok(None) => {
            if ctx.config.logging.enable_user_identifiers {
                tracing::warn!(username = %username, "User not found");
            } else {
                tracing::warn!("User not found attempt");
            }
            handler
                .send_error("INVALID_CREDENTIALS", "Invalid credentials")
                .await;
        }
        Err(e) => {
            tracing::error!(error = %e, "Database error");
            handler
                .send_error("SERVER_ERROR", "A server error occurred")
                .await;
        }
    }
}

/// Handles reconnection with existing session token
/// Validates token, restores session, and delivers queued messages
pub async fn handle_connect(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    session_token: String,
) {
    match ctx.auth_manager.verify_token(&session_token) {
        Ok(claims) => {
            let session_valid = ctx
                .queue
                .lock()
                .await
                .validate_session(&claims.jti)
                .await
                .ok()
                .flatten()
                .map(|uid| uid == claims.sub)
                .unwrap_or(false);

            if !session_valid {
                let _ = handler.send_msgpack(&ServerMessage::SessionExpired).await;
                return;
            }

            let uuid = match Uuid::parse_str(&claims.sub) {
                Ok(u) => u,
                Err(_) => {
                    handler
                        .send_error("INVALID_USER_ID", "Invalid user ID in token")
                        .await;
                    return;
                }
            };

            match db::get_user_by_id(&ctx.db_pool, &uuid).await {
                Ok(Some(user)) => {
                    if let Err(e_msg) =
                        establish_session_and_set_user(handler, ctx, &user, &claims.jti).await
                    {
                        tracing::error!(error = %e_msg, "Failed to establish session");
                        handler
                            .send_error("SESSION_CREATION_FAILED", "Could not create session")
                            .await;
                        return;
                    }

                    let response = ServerMessage::ConnectSuccess {
                        user_id: user.id.to_string(),
                        username: user.username.clone(),
                        display_name: user.display_name.clone(),
                    };
                    let _ = handler.send_msgpack(&response).await;
                }
                _ => {
                    let _ = handler.send_msgpack(&ServerMessage::SessionExpired).await;
                }
            }
        }
        Err(_) => {
            handler
                .send_error("INVALID_TOKEN", "Session token is invalid or expired")
                .await;
        }
    }
}

/// Handles user logout
/// Revokes session token and removes user from online clients
pub async fn handle_logout(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    session_token: String,
) {
    if let Ok(claims) = ctx.auth_manager.verify_token(&session_token) {
        let mut queue_lock = ctx.queue.lock().await;
        let _ = queue_lock.revoke_session(&claims.jti, &claims.sub).await;
        drop(queue_lock);

        handler.disconnect(&ctx.clients).await;
    }
    let _ = handler.send_msgpack(&ServerMessage::LogoutSuccess).await;
}
