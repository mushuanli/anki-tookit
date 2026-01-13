// src/auth/permissions.rs

use vfs_core::error::{AppError, AppResult};
use vfs_core::models::{PathPermission, PermissionLevel};

/// 权限检查器
pub struct PermissionChecker;

impl PermissionChecker {
    /// 检查用户是否有权限访问指定路径
    pub fn check_path_permission(
        permission_level: &PermissionLevel,
        path_permissions: &Option<Vec<PathPermission>>,
        path: &str,
        required_level: &PermissionLevel,
    ) -> AppResult<()> {
        // Admin 拥有所有权限
        if *permission_level == PermissionLevel::Admin {
            return Ok(());
        }

        // 检查全局权限级别
        if !Self::has_sufficient_level(permission_level, required_level) {
            return Err(AppError::PermissionDenied(format!(
                "Insufficient permission level for path: {}",
                path
            )));
        }

        // 如果有路径级权限，检查路径是否匹配
        if let Some(path_perms) = path_permissions {
            if !Self::check_path_rules(path_perms, path, required_level) {
                return Err(AppError::PermissionDenied(format!(
                    "No permission for path: {}",
                    path
                )));
            }
        }

        Ok(())
    }

    /// 检查权限级别是否足够
    fn has_sufficient_level(current: &PermissionLevel, required: &PermissionLevel) -> bool {
        match (current, required) {
            (PermissionLevel::Admin, _) => true,
            (PermissionLevel::ReadWrite, PermissionLevel::ReadOnly) => true,
            (PermissionLevel::ReadWrite, PermissionLevel::ReadWrite) => true,
            (PermissionLevel::ReadOnly, PermissionLevel::ReadOnly) => true,
            _ => false,
        }
    }

    /// 检查路径规则
    fn check_path_rules(
        rules: &[PathPermission],
        path: &str,
        required_level: &PermissionLevel,
    ) -> bool {
        for rule in rules {
            if Self::path_matches(&rule.path, path) {
                if Self::has_sufficient_level(&rule.permission, required_level) {
                    return true;
                }
            }
        }
        false
    }

    /// 路径匹配（支持 glob 模式）
    fn path_matches(pattern: &str, path: &str) -> bool {
        if pattern == "*" || pattern == "**" {
            return true;
        }

        if pattern.ends_with("/**") {
            let prefix = &pattern[..pattern.len() - 3];
            return path.starts_with(prefix);
        }

        if pattern.starts_with("**/") {
            let suffix = &pattern[3..];
            return path.ends_with(suffix);
        }

        if pattern.contains('*') {
            // 简单的 glob 匹配
            let regex_pattern = pattern
                .replace('.', "\\.")
                .replace('*', ".*");
            if let Ok(re) = regex::Regex::new(&format!("^{}$", regex_pattern)) {
                return re.is_match(path);
            }
        }

        pattern == path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_matches() {
        assert!(PermissionChecker::path_matches("*", "/any/path"));
        assert!(PermissionChecker::path_matches("/docs/**", "/docs/file.md"));
        assert!(PermissionChecker::path_matches("/docs/**", "/docs/sub/file.md"));
        assert!(!PermissionChecker::path_matches("/docs/**", "/other/file.md"));
        assert!(PermissionChecker::path_matches("**/*.md", "/any/path/file.md"));
    }
}
