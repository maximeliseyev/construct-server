// ============================================================================
// Delivery Worker Modules
// ============================================================================
//
// Refactored delivery worker logic extracted from bin/delivery_worker.rs
// for better modularity and maintainability.
//
// Current structure (refactoring in progress):
// - state.rs - WorkerState and shared state
// - retry.rs - Redis retry logic with auto-reconnection
// - redis_streams.rs - Redis Streams operations (XADD, XREADGROUP, etc.)
//
// Implemented modules:
// - deduplication.rs - Message deduplication logic
// - processor.rs - Main message processing logic
//
// Planned modules (to be implemented):
// - listener.rs - User online notification listener
//
// NOTE: Old implementation in bin/delivery_worker.rs is preserved
// for compatibility until migration is complete and tested.
//
// ============================================================================

pub mod deduplication;
pub mod processor;
pub mod redis_streams;
pub mod retry;
pub mod state;

// Re-export commonly used types and functions
pub use processor::process_kafka_message;
pub use state::WorkerState;
