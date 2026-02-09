// ============================================================================
// Axum Extractors Module
// ============================================================================
//
// Custom extractors for Axum routes:
// - AuthenticatedUser: JWT-based authentication (password login) [LEGACY]
// - DeviceAuth: Ed25519 signature-based authentication (passwordless)
// - TrustedUser: Gateway-propagated identity via X-User-Id header [NEW]
//
// Migration path (Phase 5.0.1):
// AuthenticatedUser → TrustedUser (handlers trust Gateway's JWT verification)
//
// ============================================================================

pub mod authenticated_user;
pub mod device_auth;
pub mod trusted_user;

pub use authenticated_user::AuthenticatedUser;
pub use device_auth::DeviceAuth;
pub use trusted_user::{OptionalTrustedUser, RequestTraceId, TrustedDeviceId, TrustedUser};
