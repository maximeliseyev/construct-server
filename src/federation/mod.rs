// ============================================================================
// Federation Module - Cross-Instance Communication
// ============================================================================

pub mod client;
pub mod discovery;

pub use client::FederationClient;
pub use discovery::discover_instance;
