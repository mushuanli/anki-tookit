// crates/vfs-service/src/lib.rs

//! VFS Service - 核心服务层
//!
//! 提供所有业务逻辑的抽象，便于单元测试和集成测试。
//! 
//! # 架构
//! 
//! - `services/` - 业务服务层，包含所有核心逻辑
//! - `handlers/` - HTTP 处理器，负责请求/响应转换
//! - `auth/` - 认证和授权
//! - `metrics` - 指标收集

pub mod auth;
pub mod handlers;
pub mod metrics;
pub mod services;
pub mod server;

// Re-exports for convenience
pub use auth::{AuthState, Claims, JwtService, PermissionChecker};
pub use handlers::rest::AppState;
pub use server::{ServerBuilder, ServerConfig};
pub use services::*;
