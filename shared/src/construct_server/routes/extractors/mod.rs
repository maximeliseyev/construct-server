// ============================================================================
// Axum Extractors Module
// ============================================================================
//
// Custom extractors for Axum routes:
// - AuthenticatedUser: JWT-based authentication (password login)
// - DeviceAuth: Ed25519 signature-based authentication (passwordless)
//
// ============================================================================

pub mod authenticated_user;
pub mod device_auth;

pub use authenticated_user::AuthenticatedUser;
pub use device_auth::DeviceAuth;
