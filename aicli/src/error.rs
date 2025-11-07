// src/error.rs
use log::SetLoggerError;
use thiserror::Error;
use std::string::FromUtf8Error; // <-- Add this

#[derive(Error, Debug)]
pub enum AppError {
    #[error("I/O Error: {0}")]
    Io(#[from] std::io::Error),

    // This wrapper allows adding context to I/O errors
    #[error("I/O Error: {context} ({source})")]
    IoWithContext { context: String, source: std::io::Error },

    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Base58 decoding error: {0}")]
    Bs58Error(#[from] bs58::decode::Error),

    // --- ADD/MODIFY THESE ---
    #[error("UUID parsing error: {0}")]
    UuidError(#[from] uuid::Error),

    #[error("Date/Time parsing error: {0}")]
    ChronoParseError(#[from] chrono::ParseError),
    
    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] FromUtf8Error),
    // --- END ADD/MODIFY ---

    #[error("Protocol parsing error: {0}")]
    ParseError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Database error: {0}")]
    DbError(String),
    
    #[error("AI service error: {0}")]
    AiServiceError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Authentication failed: {0}")]
    AuthError(String),
    
    #[error("Logger error: {0}")]
    LoggerError(#[from] SetLoggerError),

}

pub type Result<T> = std::result::Result<T, AppError>;
