// src/lib.rs

pub mod auth;
pub mod config;
pub mod metrics;
pub mod error;
pub mod handlers;
pub mod models;
pub mod storage;
pub mod sync;
pub mod utils;
pub mod cli; 

pub use config::Config;
pub use error::{AppError, AppResult};
