// src/storage/mod.rs

pub mod database;
pub mod file_store;
pub mod cache_service;
pub mod cached_database;  // 添加这行
pub mod object_store;

pub use database::{Database};
pub use file_store::{FileStore};
pub use cache_service::{CacheServiceConfig,CacheService};
pub use cached_database::{CachedDatabase};  // 添加这行
pub use object_store::{ObjectStore, LocalStore, create_object_store};
