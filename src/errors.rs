use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),
    
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("database error")]
    Db(#[from] sqlx::Error),

    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Serialize)]
struct AppErrorBody {
    error: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Convert from incoming http error to enum
        let (status, msg) = match &self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m.clone()),
            AppError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m.clone()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::Db(_) => (StatusCode::INTERNAL_SERVER_ERROR, "database error".to_string()),
            AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m.clone()),
        };

        (status, Json(AppErrorBody { error: msg })).into_response()
    }
}

// Helper function: check if a database error is a "username already exists" error
// This is used to return a more user-friendly error message
pub fn is_username_uniqueness_violated(e: &sqlx::Error) -> bool {
    // "if let" is like a match that only handles one case
    // Check if the error is a Database error
    if let sqlx::Error::Database(db_err) = e {
        // Get the error message and convert to lowercase for comparison
        let msg = db_err.message().to_lowercase();
        // Check if it's a unique constraint violation on the username column
        return msg.contains("unique constraint failed") && msg.contains("users.username");
    }
    false
}