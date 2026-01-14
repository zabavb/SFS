use crate::config::Config;
use sqlx::SqlitePool;
use std::sync::Arc;

// AppState holds data that needs to be shared across all HTTP requests.
// In Rust, we need to explicitly share data because of ownership rules.
#[derive(Clone)]
pub struct AppState {
    // Database connection pool - allows multiple requests to use the database simultaneously
    pub db: SqlitePool,
    // Arc allows multiple parts of the code to reference the same Config without copying it
    pub config: Arc<Config>,
}

impl AppState {
    // Create shared application state
    pub fn new(db: SqlitePool, config: Config) -> Self {
        Self {
            db,
            // Without Arc, Rust wouldn't allow sharing because of ownership rules
            config: Arc::new(config),
        }
    }
}
