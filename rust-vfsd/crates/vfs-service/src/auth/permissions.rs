// crates/vfs-service/src/auth/permissions.rs
// 与原有代码相同

use vfs_core::error::{AppError, AppResult};
use vfs_core::models::{PathPermission, PermissionLevel};

pub struct PermissionChecker;

impl PermissionChecker {
    pub fn check_path_permission(
        permission_level: &PermissionLevel,
        path_permissions: &Option<Vec<PathPermission>>,
        path: &str,
        required_level: &PermissionLevel,
    ) -> AppResult<()> {
        if *permission_level == PermissionLevel::Admin {
            return Ok(());
        }

        if !Self::has_sufficient_level(permission_level, required_level) {
            return Err(AppError::PermissionDenied(format!(
                "Insufficient permission level for path: {}",
                path
            )));
        }

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

    fn has_sufficient_level(current: &PermissionLevel, required: &PermissionLevel) -> bool {
        match (current, required) {
            (PermissionLevel::Admin, _) => true,
            (PermissionLevel::ReadWrite, PermissionLevel::ReadOnly) => true,
            (PermissionLevel::ReadWrite, PermissionLevel::ReadWrite) => true,
            (PermissionLevel::ReadOnly, PermissionLevel::ReadOnly) => true,
            _ => false,
        }
    }

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
    fn test_path_matches_wildcard() {
        assert!(PermissionChecker::path_matches("*", "/any/path"));
        assert!(PermissionChecker::path_matches("**", "/any/path/deep"));
    }

    #[test]
    fn test_path_matches_prefix() {
        assert!(PermissionChecker::path_matches("/docs/**", "/docs/file.md"));
        assert!(PermissionChecker::path_matches("/docs/**", "/docs/sub/file.md"));
        assert!(!PermissionChecker::path_matches("/docs/**", "/other/file.md"));
    }

    #[test]
    fn test_path_matches_suffix() {
        assert!(PermissionChecker::path_matches("**/*.md", "/any/path/file.md"));
        assert!(!PermissionChecker::path_matches("**/*.md", "/any/path/file.txt"));
    }

    #[test]
    fn test_path_matches_exact() {
        assert!(PermissionChecker::path_matches("/exact/path", "/exact/path"));
        assert!(!PermissionChecker::path_matches("/exact/path", "/other/path"));
    }

    #[test]
    fn test_check_path_permission_admin() {
        let result = PermissionChecker::check_path_permission(
            &PermissionLevel::Admin,
            &None,
            "/any/path",
            &PermissionLevel::ReadWrite,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_path_permission_insufficient() {
        let result = PermissionChecker::check_path_permission(
            &PermissionLevel::ReadOnly,
            &None,
            "/some/path",
            &PermissionLevel::ReadWrite,
        );
        assert!(result.is_err());
    }
}
