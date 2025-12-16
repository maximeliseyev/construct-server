use crate::context::AppContext;
use crate::crypto::{ServerCryptoValidator, StoredKeyBundle, RegistrationBundle};
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
    let bundle_json = match crate::crypto::decode_base64(&public_key) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(json) => json,
            Err(_e) => {
                handler
                    .send_error("INVALID_KEY", "Invalid key encoding")
                    .await;
                return;
            }
        },
        Err(_e) => {
            handler.send_error("INVALID_KEY", "Invalid base64").await;
            return;
        }
    };

    let registration_bundle: RegistrationBundle =
        match serde_json::from_str(&bundle_json) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("Invalid registration bundle: {}", e);
                handler
                    .send_error("INVALID_KEY_BUNDLE", "Invalid key format")
                    .await;
                return;
            }
        };

    let stored_bundle = StoredKeyBundle {
        user_id: String::new(),
        identity_public: crate::crypto::encode_base64(&registration_bundle.identity_public),
        signed_prekey_public: crate::crypto::encode_base64(&registration_bundle.signed_prekey_public),
        signature: crate::crypto::encode_base64(&registration_bundle.signature),
        verifying_key: crate::crypto::encode_base64(&registration_bundle.verifying_key),
        registered_at: chrono::Utc::now(),
        prekey_expires_at: chrono::Utc::now() 
            + chrono::Duration::days(ctx.config.security.prekey_ttl_days),
    };

    if let Err(e) = ServerCryptoValidator::validate_key_bundle(&stored_bundle) {
        tracing::warn!("Key bundle validation failed: {}", e);
        handler
            .send_error("INVALID_KEY_BUNDLE", &e.to_string())
            .await;
        return;
    }

    let display_name_final = display_name.as_deref().unwrap_or(&username);

    match db::create_user(
        &ctx.db_pool,
        &username,
        display_name_final,
        &password,
        &stored_bundle.identity_public,
    )
    .await
    {
        Ok(user) => {
            let mut final_bundle = stored_bundle.clone();
            final_bundle.user_id = user.id.to_string();
        
            if let Err(e) = crate::db::store_key_bundle(&ctx.db_pool, &user.id, &final_bundle).await {
                tracing::error!(error = %e, "Failed to store key bundle during registration");
                handler.send_error("SERVER_ERROR", "Failed to store encryption keys").await;
                return;
            }

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
                                                if handler.send_msgpack(&response).await.is_err() {
                                                    return;
                                                }                }
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
                                                    if handler.send_msgpack(&response).await.is_err() {
                                                        return;
                                                    }                    }
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
            let session_check_result = ctx.queue.lock().await.validate_session(&claims.jti).await;

            match session_check_result {
                Ok(Some(uid)) if uid == claims.sub => {
                    // Session is valid and belongs to this user, proceed.
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
                            if handler.send_msgpack(&response).await.is_err() {
                                // Client disconnected, just return.
                                return;
                            }
                        }
                        _ => {
                            // User not found in DB, treat as expired session
                            if handler.send_msgpack(&ServerMessage::SessionExpired).await.is_err() {
                                return;
                            }
                        }
                    }
                }
                Ok(_) => {
                    // Session not found or doesn't match the token's user (e.g., uid != claims.sub)
                    if handler.send_msgpack(&ServerMessage::SessionExpired).await.is_err() {
                        return;
                    }
                }
                Err(e) => {
                    // An actual error occurred during validation
                    tracing::error!(error = %e, "Failed to validate session");
                    handler.send_error("SERVER_ERROR", "Failed to validate session").await;
                    return; // Return on server error
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
        if let Err(e) = queue_lock.revoke_session(&claims.jti, &claims.sub).await {
            tracing::warn!(error = %e, "Failed to revoke session on logout");
        }
        drop(queue_lock);

        handler.disconnect(&ctx.clients).await;
    }
    if handler.send_msgpack(&ServerMessage::LogoutSuccess).await.is_err() {
        return;
    }
}
