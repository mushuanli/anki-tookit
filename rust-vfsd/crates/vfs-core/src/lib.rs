pub mod config;
pub mod error;
pub mod models; // models 仍然是一个文件夹，里面有 mod.rs
pub mod utils;  // utils 也是一个文件夹

// 方便外部直接 use vfs_core::AppError;
pub use error::{AppError, AppResult};
pub use config::Config;