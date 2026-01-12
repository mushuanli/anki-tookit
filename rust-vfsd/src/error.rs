// src/error.rs

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Authentication failed: {0}")]
    AuthError(String),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Conflict: {0}")]
    Conflict(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("File too large: {size} bytes (max: {max})")]
    FileTooLarge { size: usize, max: usize },
    
    #[error("File type not allowed: {0}")]
    FileTypeNotAllowed(String),
    
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AppError::AuthError(msg) => (StatusCode::UNAUTHORIZED, "AUTH_ERROR", msg.clone()),
            AppError::PermissionDenied(msg) => (StatusCode::FORBIDDEN, "PERMISSION_DENIED", msg.clone()),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "NOT_FOUND", msg.clone()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "CONFLICT", msg.clone()),
            AppError::ValidationError(msg) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR", msg.clone()),
            AppError::RateLimitExceeded => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMIT", "Rate limit exceeded".to_string()),
            AppError::FileTooLarge { size, max } => (
                StatusCode::PAYLOAD_TOO_LARGE, 
                "FILE_TOO_LARGE", 
                format!("File size {} exceeds limit {}", size, max)
            ),
            AppError::FileTypeNotAllowed(ext) => (StatusCode::BAD_REQUEST, "FILE_TYPE_NOT_ALLOWED", format!("File type {} not allowed", ext)),
            AppError::DatabaseError(e) => {
                tracing::error!("Database error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR", "Database error".to_string())
            }
            AppError::InternalError(msg) => {
                tracing::error!("Internal error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Internal server error".to_string())
            }
        };

        let body = Json(json!({
            "error": {
                "code": code,
                "message": message
            }
        }));

        (status, body).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
