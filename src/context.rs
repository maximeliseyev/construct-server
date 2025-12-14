use crate::auth::AuthManager;
use crate::db::DbPool;
use crate::handlers::session::Clients;
use crate::queue::MessageQueue;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Application context containing shared dependencies
/// This reduces parameter passing and makes it easier to add new dependencies
#[derive(Clone)]
pub struct AppContext {
    pub db_pool: Arc<DbPool>,
    pub queue: Arc<Mutex<MessageQueue>>,
    pub auth_manager: Arc<AuthManager>,
    pub clients: Clients,
}

impl AppContext {
    /// Creates a new application context
    pub fn new(
        db_pool: Arc<DbPool>,
        queue: Arc<Mutex<MessageQueue>>,
        auth_manager: Arc<AuthManager>,
        clients: Clients,
    ) -> Self {
        Self {
            db_pool,
            queue,
            auth_manager,
            clients,
        }
    }
}
