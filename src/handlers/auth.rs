use crate::context::AppContext;

use crate::db::{self, User};
use crate::e2e::BundleData;
use crate::handlers::connection::ConnectionHandler;
use crate::handlers::session::establish_session;
use crate::message::ServerMessage;
use crate::utils::{log_safe_id, validate_password_strength};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
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
use crate::e2e::{ServerCryptoValidator, UploadableKeyBundle};

pub async fn handle_register(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    username: String,
    password: String,
    key_bundle: UploadableKeyBundle,
) {
    // Validate password strength before proceeding
    if let Err(error_msg) = validate_password_strength(&password) {
        tracing::warn!("Registration rejected: weak password");
        handler.send_error("WEAK_PASSWORD", &error_msg).await;
        return;
    }

    // Validate the bundle using the V3 validator
    // Allow empty user_id during registration since it will be set after user creation
    if let Err(e) = ServerCryptoValidator::validate_uploadable_key_bundle(&key_bundle, true) {
        tracing::warn!("Key bundle validation failed: {}", e);
        handler.send_error("INVALID_KEY_BUNDLE", &e.to_string()).await;
        return;
    }

    match db::create_user(&ctx.db_pool, &username, &password).await {
        Ok(user) => {
            // Update bundle_data with correct user_id
            let mut updated_bundle = key_bundle.clone();

            // Decode bundle_data
            let bundle_data_bytes = match BASE64.decode(&key_bundle.bundle_data) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to decode bundle_data");
                    handler.send_error("SERVER_ERROR", "Failed to process key bundle").await;
                    return;
                }
            };

            // Parse BundleData
            let mut bundle_data: BundleData = match serde_json::from_slice(&bundle_data_bytes) {
                Ok(data) => data,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to parse bundle_data");
                    handler.send_error("SERVER_ERROR", "Failed to process key bundle").await;
                    return;
                }
            };

            // Update user_id with the actual created user ID
            bundle_data.user_id = user.id.to_string();

            // Re-serialize and encode
            let updated_json = match serde_json::to_string(&bundle_data) {
                Ok(json) => json,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to serialize bundle_data");
                    handler.send_error("SERVER_ERROR", "Failed to process key bundle").await;
                    return;
                }
            };
            updated_bundle.bundle_data = BASE64.encode(updated_json.as_bytes());

            // Store the updated key bundle
            if let Err(e) = crate::db::store_key_bundle(&ctx.db_pool, &user.id, &updated_bundle).await {
                tracing::error!(error = %e, "Failed to store key bundle during registration");
                handler.send_error("SERVER_ERROR", "Failed to store encryption keys").await;
                return;
            }

            if ctx.config.logging.enable_user_identifiers {
                tracing::info!(username = %user.username, "User registered");
            } else {
                tracing::info!(
                    user_hash = %log_safe_id(&user.id.to_string(), &ctx.config.logging.hash_salt),
                    "User registered"
                );
            }

            match ctx.auth_manager.create_token(&user.id) {
                Ok((token, jti, expires)) => {
                    if let Err(e_msg) = establish_session_and_set_user(handler, ctx, &user, &jti).await {
                        tracing::error!(error = %e_msg, "Failed to establish session");
                        handler.send_error("SESSION_CREATION_FAILED", "Could not create session").await;
                        return;
                    }

                    let response = ServerMessage::RegisterSuccess(crate::message::RegisterSuccessData {
                        user_id: user.id.to_string(),
                        username: user.username.clone(),
                        session_token: token,
                        expires,
                    });
                    if handler.send_msgpack(&response).await.is_err() {}
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to create token");
                    handler.send_error("TOKEN_CREATION_FAILED", "Could not create session token").await;
                }
            }
        }
        Err(e) => {
            if ctx.config.logging.enable_user_identifiers {
                tracing::error!(error = %e, username = %username, "Registration failed");
            } else {
                tracing::error!(error = %e, "Registration failed");
            }
            handler.send_error("REGISTRATION_FAILED", "An error occurred during registration. The username might be taken or the input is invalid.").await;
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
    // 1. Check rate limiting for failed login attempts
    let mut queue = ctx.queue.lock().await;
    let failed_attempts = match queue.increment_failed_login_count(&username).await {
        Ok(count) => count,
        Err(e) => {
            tracing::error!(error = %e, "Failed to check login rate limit");
            0 // Fail open
        }
    };
    drop(queue);

    let max_attempts = ctx.config.security.max_failed_login_attempts;
    if failed_attempts > max_attempts {
        tracing::warn!(
            username = %username,
            attempts = failed_attempts,
            limit = max_attempts,
            "Login rate limit exceeded"
        );
        handler
            .send_error(
                "RATE_LIMIT_EXCEEDED",
                &format!("Too many failed login attempts. Try again in 15 minutes."),
            )
            .await;
        return;
    }

    match db::get_user_by_username(&ctx.db_pool, &username).await {
        Ok(Some(user)) => {
            if db::verify_password(&user, &password).await.unwrap_or(false) {
                // Password correct - reset failed login counter
                let mut queue = ctx.queue.lock().await;
                if let Err(e) = queue.reset_failed_login_count(&username).await {
                    tracing::warn!(error = %e, "Failed to reset login counter");
                }
                drop(queue);
                if ctx.config.logging.enable_user_identifiers {
                    tracing::info!(
                        username = %user.username,
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

                        let response =
                            ServerMessage::LoginSuccess(crate::message::LoginSuccessData {
                                user_id: user.id.to_string(),
                                username: user.username.clone(),
                                session_token: token,
                                expires,
                            });
                        if handler.send_msgpack(&response).await.is_err() {}
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
                                establish_session_and_set_user(handler, ctx, &user, &claims.jti)
                                    .await
                            {
                                tracing::error!(error = %e_msg, "Failed to establish session");
                                handler
                                    .send_error(
                                        "SESSION_CREATION_FAILED",
                                        "Could not create session",
                                    )
                                    .await;
                                return;
                            }

                            let response =
                                ServerMessage::ConnectSuccess(crate::message::ConnectSuccessData {
                                    user_id: user.id.to_string(),
                                    username: user.username.clone(),
                                });
                            if handler.send_msgpack(&response).await.is_err() {}
                        }
                        _ => {
                            if handler
                                .send_msgpack(&ServerMessage::SessionExpired)
                                .await
                                .is_err()
                            {}
                        }
                    }
                }
                Ok(_) => {
                    if handler
                        .send_msgpack(&ServerMessage::SessionExpired)
                        .await
                        .is_err()
                    {}
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to validate session");
                    handler
                        .send_error("SERVER_ERROR", "Failed to validate session")
                        .await;
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

/// Handles password change
/// Validates old password, updates to new password
pub async fn handle_change_password(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    session_token: String,
    old_password: String,
    new_password: String,
    new_password_confirm: String,
) {
    // 1. Verify session token
    let claims = match ctx.auth_manager.verify_token(&session_token) {
        Ok(claims) => claims,
        Err(_) => {
            handler
                .send_error("INVALID_TOKEN", "Session token is invalid or expired")
                .await;
            return;
        }
    };

    // 2. Parse user_id from claims
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            handler
                .send_error("INVALID_USER_ID", "Invalid user ID in token")
                .await;
            return;
        }
    };

    // 2.5. Rate limiting check for password changes
    let mut queue = ctx.queue.lock().await;
    let change_count = match queue.increment_password_change_count(&user_id.to_string()).await {
        Ok(count) => count,
        Err(e) => {
            tracing::error!(error = %e, "Failed to check password change rate limit");
            // Fail open for now, but log it
            0
        }
    };

    let max_changes = ctx.config.security.max_password_changes_per_day;
    if change_count > max_changes {
        tracing::warn!(
            user_id = %user_id,
            count = change_count,
            limit = max_changes,
            "Password change rate limit exceeded"
        );
        drop(queue);
        handler
            .send_error(
                "RATE_LIMIT_EXCEEDED",
                &format!("Too many password changes. Limit: {}/day", max_changes),
            )
            .await;
        return;
    }
    drop(queue);

    // 3. Get user from database
    let user = match db::get_user_by_id(&ctx.db_pool, &user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            handler.send_error("USER_NOT_FOUND", "User not found").await;
            return;
        }
        Err(e) => {
            tracing::error!(error = %e, "Database error while fetching user");
            handler
                .send_error("SERVER_ERROR", "A server error occurred")
                .await;
            return;
        }
    };

    // 4. Verify old password is correct
    match db::verify_password(&user, &old_password).await {
        Ok(true) => {}
        Ok(false) => {
            if ctx.config.logging.enable_user_identifiers {
                tracing::warn!(user_id = %user_id, "Invalid old password during password change");
            } else {
                tracing::warn!(
                    user_hash = %log_safe_id(&user_id.to_string(), &ctx.config.logging.hash_salt),
                    "Invalid old password during password change"
                );
            }
            handler
                .send_error("INVALID_PASSWORD", "Old password is incorrect")
                .await;
            return;
        }
        Err(e) => {
            tracing::error!(error = %e, "Error verifying old password");
            handler
                .send_error("SERVER_ERROR", "Failed to verify password")
                .await;
            return;
        }
    }

    // 5. Validate new password confirmation matches
    if new_password != new_password_confirm {
        handler
            .send_error("PASSWORD_MISMATCH", "New passwords do not match")
            .await;
        return;
    }

    // 6. Validate new password is different from old password
    if old_password == new_password {
        handler
            .send_error(
                "SAME_PASSWORD",
                "New password must be different from old password",
            )
            .await;
        return;
    }

    // 7. Validate new password strength
    if let Err(error_msg) = validate_password_strength(&new_password) {
        tracing::warn!(
            user_id = %user_id,
            "Password change rejected: weak password"
        );
        handler.send_error("WEAK_PASSWORD", &error_msg).await;
        return;
    }

    // 8. Update password in database
    if let Err(e) = db::update_user_password(&ctx.db_pool, &user_id, &new_password).await {
        tracing::error!(error = %e, user_id = %user_id, "Failed to update password");
        handler
            .send_error("SERVER_ERROR", "Failed to update password")
            .await;
        return;
    }

    // 9. Log success
    if ctx.config.logging.enable_user_identifiers {
        tracing::info!(user_id = %user_id, username = %user.username, "Password changed successfully");
    } else {
        tracing::info!(
            user_hash = %log_safe_id(&user_id.to_string(), &ctx.config.logging.hash_salt),
            "Password changed successfully"
        );
    }

    // 10. Send success response
    if handler
        .send_msgpack(&ServerMessage::ChangePasswordSuccess)
        .await
        .is_err()
    {}
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
        
        // Phase 5: Untrack user online status
        if let Err(e) = queue_lock.untrack_user_online(&claims.sub).await {
            tracing::warn!(error = %e, user_id = %claims.sub, "Failed to untrack user online status on logout");
        }
        drop(queue_lock);

        handler.disconnect(&ctx.clients).await;
    }
    if handler
        .send_msgpack(&ServerMessage::LogoutSuccess)
        .await
        .is_err()
    {}
}

/// Handles account deletion
/// Deletes user account and all associated data (requires password confirmation)
pub async fn handle_delete_account(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    session_token: String,
    password: String,
) {
    // 1. Verify session token
    let claims = match ctx.auth_manager.verify_token(&session_token) {
        Ok(claims) => claims,
        Err(_) => {
            handler
                .send_error("INVALID_TOKEN", "Session token is invalid or expired")
                .await;
            return;
        }
    };

    // 2. Parse user_id from claims
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            handler
                .send_error("INVALID_USER_ID", "Invalid user ID in token")
                .await;
            return;
        }
    };

    // 3. Get user from database
    let user = match db::get_user_by_id(&ctx.db_pool, &user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            handler.send_error("USER_NOT_FOUND", "User not found").await;
            return;
        }
        Err(e) => {
            tracing::error!(error = %e, "Database error while fetching user");
            handler
                .send_error("SERVER_ERROR", "A server error occurred")
                .await;
            return;
        }
    };

    // 4. Verify password is correct
    match db::verify_password(&user, &password).await {
        Ok(true) => {}
        Ok(false) => {
            if ctx.config.logging.enable_user_identifiers {
                tracing::warn!(user_id = %user_id, "Invalid password during account deletion");
            } else {
                tracing::warn!(
                    user_hash = %log_safe_id(&user_id.to_string(), &ctx.config.logging.hash_salt),
                    "Invalid password during account deletion"
                );
            }
            handler
                .send_error("INVALID_PASSWORD", "Password is incorrect")
                .await;
            return;
        }
        Err(e) => {
            tracing::error!(error = %e, "Error verifying password");
            handler
                .send_error("SERVER_ERROR", "Failed to verify password")
                .await;
            return;
        }
    }

    // 5. Revoke all sessions for this user
    let mut queue_lock = ctx.queue.lock().await;
    if let Err(e) = queue_lock.revoke_all_sessions(&user_id.to_string()).await {
        tracing::warn!(error = %e, user_id = %user_id, "Failed to revoke all sessions");
    }
    drop(queue_lock);

    // 6. Delete delivery ACK data if available (GDPR compliance)
    if let Some(ack_manager) = &ctx.delivery_ack_manager {
        if let Err(e) = ack_manager.delete_user_data(&user_id.to_string()).await {
            tracing::warn!(
                error = %e,
                user_id = %user_id,
                "Failed to delete delivery ACK data"
            );
        }
    }

    // 7. Phase 5: Untrack user online status
    let mut queue_lock = ctx.queue.lock().await;
    if let Err(e) = queue_lock.untrack_user_online(&user_id.to_string()).await {
        tracing::warn!(error = %e, user_id = %user_id, "Failed to untrack user online status");
    }
    drop(queue_lock);
    
    // 8. Disconnect user from WebSocket clients
    handler.disconnect(&ctx.clients).await;

    // 8. Delete user account from database (cascade will handle related records)
    if let Err(e) = db::delete_user_account(&ctx.db_pool, &user_id).await {
        tracing::error!(error = %e, user_id = %user_id, "Failed to delete user account");
        handler
            .send_error("SERVER_ERROR", "Failed to delete account")
            .await;
        return;
    }

    // 9. Log success
    if ctx.config.logging.enable_user_identifiers {
        tracing::info!(user_id = %user_id, username = %user.username, "Account deleted successfully");
    } else {
        tracing::info!(
            user_hash = %log_safe_id(&user_id.to_string(), &ctx.config.logging.hash_salt),
            "Account deleted successfully"
        );
    }

    // 10. Send success response
    if handler
        .send_msgpack(&ServerMessage::DeleteAccountSuccess)
        .await
        .is_err()
    {}
}
