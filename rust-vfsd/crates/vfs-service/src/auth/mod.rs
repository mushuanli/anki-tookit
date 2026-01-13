// crates/vfs-service/src/auth/mod.rs

pub mod jwt;
pub mod middleware;
pub mod permissions;
pub mod rate_limit;

pub use jwt::{Claims, JwtService};
pub use middleware::{auth_middleware, AuthState};
pub use permissions::PermissionChecker;
pub use rate_limit::{RateLimitConfig, RateLimitState, RateLimiter, rate_limit_middleware};
