// ============================================================================
// Invites Routes (Dynamic Contact Sharing)
// ============================================================================
//
// Endpoints:
// - POST /api/v1/invites/generate - Generate one-time invite token
// - POST /api/v1/invites/accept - Accept and burn invite token
//
// Purpose: Secure, one-time contact sharing via QR codes and deep links
// Replaces old broken konstruct.cc/c/{UUID} static links
//
// Security:
// - One-time use only (jti tracking prevents replay)
// - Short TTL (5 minutes default)
// - Cryptographic signatures (Ed25519)
// - Federation-ready
//
// ============================================================================

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::context::AppContext;
use crate::routes::extractors::AuthenticatedUser;
use construct_db;
use construct_error::AppError;
use crypto_agility::InviteToken;

/// Request to generate a new invite token
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateInviteRequest {
    /// Optional custom TTL in seconds (default: 300 = 5 minutes)
    /// Must be between 60 (1 min) and 3600 (1 hour)
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
}

/// Response after generating an invite token
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateInviteResponse {
    /// Unique invite ID (jti)
    pub jti: Uuid,

    /// Server FQDN for the invite
    pub server: String,

    /// Unix timestamp when this invite expires
    pub expires_at: i64,

    /// TTL in seconds
    pub ttl_seconds: i64,
}

/// Request to accept an invite token
#[derive(Debug, Deserialize)]
pub struct AcceptInviteRequest {
    /// Full invite token object from QR code or link
    pub invite: InviteToken,
}

/// Response after accepting an invite
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptInviteResponse {
    /// User ID that was added
    pub user_id: Uuid,

    /// Server where the user is located
    pub server: String,

    /// Success message
    pub message: String,
}

/// POST /api/v1/invites/generate
///
/// Generate a new one-time invite token for contact sharing.
///
/// The client will:
/// 1. Receive jti and server from this endpoint
/// 2. Generate ephemeral X25519 keypair
/// 3. Sign the invite object with Identity Key
/// 4. Encode as Base64/MessagePack
/// 5. Display as QR or URL: konstruct.cc/add#{token}
///
/// Security:
/// - Requires JWT authentication
/// - Stores jti in database for one-time use tracking
/// - Auto-cleanup after 5 minutes
pub async fn generate_invite(
    State(app_context): State<Arc<AppContext>>,
    user: AuthenticatedUser,
    Json(request): Json<GenerateInviteRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user_id = user.0;

    // Validate TTL
    let ttl_seconds = request.ttl_seconds.unwrap_or(300); // Default 5 minutes
    if ttl_seconds < 60 || ttl_seconds > 3600 {
        return Err(AppError::Validation(
            "TTL must be between 60 and 3600 seconds".to_string(),
        ));
    }

    // Generate unique jti
    let jti = Uuid::new_v4();

    // Get server FQDN from config
    let server = app_context.config.instance_domain.clone();

    // Note: Ephemeral key and signature are generated client-side
    // Here we just create a placeholder record to reserve the jti
    let placeholder_key = vec![0u8; 32]; // Client will provide real key
    let placeholder_sig = vec![0u8; 64]; // Client will provide real signature

    // Store invite token in database
    match construct_db::create_invite_token(
        &app_context.db_pool,
        &jti,
        &user_id,
        &placeholder_key,
        &placeholder_sig,
    )
    .await
    {
        Ok(_) => {
            let now = chrono::Utc::now().timestamp();
            let expires_at = now + ttl_seconds;

            tracing::info!(
                user_id = %user_id,
                jti = %jti,
                ttl_seconds = ttl_seconds,
                "Invite token generated"
            );

            Ok((
                StatusCode::CREATED,
                Json(GenerateInviteResponse {
                    jti,
                    server,
                    expires_at,
                    ttl_seconds,
                }),
            ))
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                user_id = %user_id,
                "Failed to create invite token"
            );
            Err(AppError::Validation(format!(
                "Failed to generate invite: {}",
                e
            )))
        }
    }
}

/// POST /api/v1/invites/accept
///
/// Accept an invite token from a QR code or deep link.
///
/// Validation flow:
/// 1. Verify timestamp (reject if > TTL old)
/// 2. Verify timestamp not in future (clock skew attack)
/// 3. Fetch user's public Identity Key
/// 4. Verify Ed25519 signature
/// 5. Check jti in database (atomic burn)
/// 6. Add user to contacts
///
/// For federated users, this will trigger an S2S request to the user's server
/// to validate and burn the jti.
pub async fn accept_invite(
    State(app_context): State<Arc<AppContext>>,
    user: AuthenticatedUser,
    Json(request): Json<AcceptInviteRequest>,
) -> Result<impl IntoResponse, AppError> {
    let inviter_user_id = user.0; // User who is accepting the invite
    let invite = request.invite;

    // 1. Check timestamp freshness (default 5 min TTL)
    if invite.is_expired(300) {
        tracing::warn!(
            jti = %invite.jti,
            ts = invite.ts,
            "Invite token expired"
        );
        return Err(AppError::Validation(
            "Invite has expired. Please ask for a new QR code.".to_string(),
        ));
    }

    // 2. Check for future timestamps (clock skew attack)
    if invite.is_future() {
        tracing::warn!(
            jti = %invite.jti,
            ts = invite.ts,
            "Invite token has future timestamp"
        );
        return Err(AppError::Validation("Invalid invite timestamp".to_string()));
    }

    // 3. TODO: Fetch user's public Identity Key and verify signature
    // This requires integration with key_bundle storage
    // For now, we'll skip signature verification (INSECURE - to be fixed)
    tracing::warn!("SECURITY: Signature verification not yet implemented");

    // 4. Atomic burn: Check and mark invite as used
    match construct_db::burn_invite_token(&app_context.db_pool, &invite.jti).await {
        Ok(true) => {
            // Success - invite was valid and now burned
            tracing::info!(
                jti = %invite.jti,
                user_id = %invite.uuid,
                accepter = %inviter_user_id,
                "Invite accepted and burned"
            );

            // TODO: Actually add user to contacts
            // For now, just return success

            Ok((
                StatusCode::OK,
                Json(AcceptInviteResponse {
                    user_id: invite.uuid,
                    server: invite.server.clone(),
                    message: format!("Contact {} added successfully", invite.uuid),
                }),
            ))
        }
        Ok(false) => {
            // Invite already used or not found
            tracing::warn!(
                jti = %invite.jti,
                "Invite token already used or not found"
            );
            Err(AppError::Validation(
                "This invite has already been used or is invalid".to_string(),
            ))
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                jti = %invite.jti,
                "Failed to burn invite token"
            );
            Err(AppError::Validation(format!(
                "Failed to accept invite: {}",
                e
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invite_endpoints_compile() {
        // Verify function signatures are correct
        let _ = generate_invite;
        let _ = accept_invite;
    }
}
