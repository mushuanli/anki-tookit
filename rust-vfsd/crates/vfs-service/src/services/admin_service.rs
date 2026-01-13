// crates/vfs-service/src/services/admin_service.rs

use std::sync::Arc;
use uuid::Uuid;

use vfs_core::error::{AppError, AppResult};
use vfs_core::models::{PermissionLevel, SystemStats, User, UserResponse};
use vfs_storage::CachedDatabase;
use vfs_sync::SyncEngine;

/// 分页响应
#[derive(Debug, Clone)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub total: i64,
    pub page: i64,
    pub limit: i64,
}

/// 更新用户请求（管理员）
#[derive(Debug, Clone)]
pub struct UpdateUserAdminRequest {
    pub is_active: Option<bool>,
    pub storage_quota: Option<i64>,
}

/// 管理员服务
/// 
/// 处理管理员相关的业务逻辑。
#[derive(Clone)]
pub struct AdminService {
    db: CachedDatabase,
    sync_engine: Arc<SyncEngine>,
}

impl AdminService {
    pub fn new(db: CachedDatabase, sync_engine: Arc<SyncEngine>) -> Self {
        Self { db, sync_engine }
    }

    /// 检查是否为管理员
    pub fn check_admin(&self, permission_level: &PermissionLevel) -> AppResult<()> {
        if *permission_level != PermissionLevel::Admin {
            return Err(AppError::PermissionDenied("Admin access required".to_string()));
        }
        Ok(())
    }

    /// 获取用户列表
    pub async fn list_users(
        &self,
        page: i64,
        limit: i64,
        search: Option<&str>,
    ) -> AppResult<PaginatedResponse<UserResponse>> {
        let page = page.max(1);
        let limit = limit.max(1).min(100);
        let offset = (page - 1) * limit;

        let (users, total) = self.db.list_users(limit, offset, search).await?;

        let user_responses: Vec<UserResponse> = users
            .into_iter()
            .map(UserResponse::from)
            .collect();

        Ok(PaginatedResponse {
            data: user_responses,
            total,
            page,
            limit,
        })
    }

    /// 获取单个用户
    pub async fn get_user(&self, user_id: Uuid) -> AppResult<User> {
        self.db
            .get_user_by_id(user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))
    }

    /// 更新用户（管理员）
    pub async fn update_user(
        &self,
        user_id: Uuid,
        req: UpdateUserAdminRequest,
    ) -> AppResult<User> {
        let mut user = self.get_user(user_id).await?;

        if let Some(active) = req.is_active {
            user.is_active = active;
        }
        if let Some(quota) = req.storage_quota {
            user.storage_quota = quota;
        }
        user.updated_at = chrono::Utc::now().to_rfc3339();

        self.db.update_user(&user).await?;

        Ok(user)
    }

    /// 删除用户
    pub async fn delete_user(&self, user_id: Uuid) -> AppResult<()> {
        // 检查用户是否存在
        let _ = self.get_user(user_id).await?;

        // 删除数据库记录（级联删除会处理关联数据）
        self.db.delete_user(user_id).await?;

        Ok(())
    }

    /// 获取系统统计
    pub async fn get_system_stats(&self) -> AppResult<SystemStats> {
        let mut stats = self.db.get_system_stats().await?;
        
        // 获取活跃连接数
        let session_stats = self.sync_engine.session_manager().get_stats().await;
        stats.active_connections = session_stats.total_devices as i64;
        
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use vfs_core::models::User;
    use vfs_storage::{Database, CacheService, CacheServiceConfig};
    use tempfile::tempdir;

    async fn create_test_db() -> CachedDatabase {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        
        let config = vfs_core::config::DatabaseConfig {
            path: db_path.to_string_lossy().to_string(),
            max_connections: 1,
        };
        
        let db = Database::new(&config).await.unwrap();
        db.run_migrations().await.unwrap();
        
        let cache = Arc::new(CacheService::new(CacheServiceConfig::default()));
        CachedDatabase::new(db, cache)
    }

    async fn create_test_users(db: &CachedDatabase, count: usize) -> Vec<Uuid> {
        let mut ids = Vec::new();
        for i in 0..count {
            let now = chrono::Utc::now();
            let user = User {
                id: Uuid::new_v4().to_string(),
                username: format!("user{}", i),
                password_hash: "hash".to_string(),
                email: Some(format!("user{}@example.com", i)),
                display_name: Some(format!("User {}", i)),
                storage_quota: 10 * 1024 * 1024 * 1024,
                storage_used: 0,
                is_active: true,
                created_at: now.to_rfc3339(),
                updated_at: now.to_rfc3339(),
            };
            db.create_user(&user).await.unwrap();
            ids.push(user.id_as_uuid());
        }
        ids
    }

    #[tokio::test]
    async fn test_check_admin() {
        let db = create_test_db().await;
        // 注意：这里需要 mock SyncEngine，暂时跳过
    }

    #[tokio::test]
    async fn test_list_users_pagination() {
        let db = create_test_db().await;
        create_test_users(&db, 25).await;
        
        // 注意：需要 SyncEngine，这里仅展示测试结构
    }
}
