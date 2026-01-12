// src/sync/filter.rs

use crate::config::SyncConfig;
use crate::models::SyncChange;

pub struct SyncFilter {
    config: SyncConfig,
}

impl SyncFilter {
    pub fn new(config: SyncConfig) -> Self {
        Self { config }
    }

    /// 检查变更是否应该被同步
    pub fn should_sync(&self, change: &SyncChange) -> bool {
        // 检查文件大小
        if let Some(size) = change.size {
            if size as usize > self.config.max_file_size {
                tracing::debug!(
                    "Skipping {} due to size limit: {} > {}",
                    change.path,
                    size,
                    self.config.max_file_size
                );
                return false;
            }
        }

        // 检查文件扩展名
        let extension = self.get_extension(&change.path);
        
        if let Some(ref blocked) = self.config.blocked_extensions {
            if blocked.contains(&extension) {
                tracing::debug!("Skipping {} due to blocked extension: {}", change.path, extension);
                return false;
            }
        }

        if let Some(ref allowed) = self.config.allowed_extensions {
            if !extension.is_empty() && !allowed.contains(&extension) {
                tracing::debug!("Skipping {} due to extension not allowed: {}", change.path, extension);
                return false;
            }
        }

        // 排除隐藏文件和系统文件
        if self.is_system_path(&change.path) {
            return false;
        }

        true
    }

    /// 检查时间范围
    pub fn check_time_range(&self, timestamp: i64, from: Option<i64>, to: Option<i64>) -> bool {
        if let Some(from_ts) = from {
            if timestamp < from_ts {
                return false;
            }
        }
        if let Some(to_ts) = to {
            if timestamp > to_ts {
                return false;
            }
        }
        true
    }

    fn get_extension(&self, path: &str) -> String {
        path.rsplit('.')
            .next()
            .map(|s| s.to_lowercase())
            .unwrap_or_default()
    }

    fn is_system_path(&self, path: &str) -> bool {
        let system_prefixes = ["/__sync", "/.git", "/.svn", "/node_modules", "/.DS_Store"];
        system_prefixes.iter().any(|prefix| path.starts_with(prefix))
    }
}
