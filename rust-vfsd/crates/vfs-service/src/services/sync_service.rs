// crates/vfs-service/src/services/sync_service.rs

use std::sync::Arc;
use uuid::Uuid;

use vfs_core::error::{AppError, AppResult};
use vfs_core::models::{
    ConflictResolution, SyncChange, SyncConflict, SyncCursor,
};
use vfs_core::utils::CryptoUtils;
use vfs_storage::{CachedDatabase, FileStore};
use vfs_sync::SyncEngine;

/// 同步服务
/// 
/// 处理文件同步相关的业务逻辑。
#[derive(Clone)]
pub struct SyncService {
    db: CachedDatabase,
    file_store: Arc<FileStore>,
    sync_engine: Arc<SyncEngine>,
}

impl SyncService {
    pub fn new(
        db: CachedDatabase,
        file_store: Arc<FileStore>,
        sync_engine: Arc<SyncEngine>,
    ) -> Self {
        Self {
            db,
            file_store,
            sync_engine,
        }
    }

    /// 获取待同步的变更
    pub async fn get_pending_changes(
        &self,
        user_id: Uuid,
        device_id: &str,
        module_id: &str,
        limit: i64,
        from_time: Option<i64>,
        to_time: Option<i64>,
    ) -> AppResult<Vec<SyncChange>> {
        self.sync_engine
            .get_pending_changes(user_id, device_id, module_id, limit, from_time, to_time)
            .await
    }

    /// 获取内容
    pub async fn get_content(
        &self,
        user_id: Uuid,
        content_hash: &str,
    ) -> AppResult<Option<Vec<u8>>> {
        self.sync_engine.get_content(user_id, content_hash).await
    }

    /// 获取未解决的冲突列表
    pub async fn list_conflicts(&self, user_id: Uuid) -> AppResult<Vec<SyncConflict>> {
        self.db.get_unresolved_conflicts(user_id).await
    }

    /// 解决冲突
    pub async fn resolve_conflict(
        &self,
        user_id: Uuid,
        conflict_id: Uuid,
        resolution: ConflictResolution,
        merged_content: Option<String>,
    ) -> AppResult<bool> {
        // 获取冲突详情
        let conflicts = self.db.get_unresolved_conflicts(user_id).await?;
        let conflict = conflicts
            .iter()
            .find(|c| c.id == conflict_id)
            .ok_or_else(|| AppError::NotFound("Conflict not found".to_string()))?;

        // 如果是合并解决，处理合并内容
        if resolution == ConflictResolution::Merged {
            if let Some(content_base64) = merged_content {
                self.process_merged_content(user_id, conflict, &content_base64).await?;
            } else {
                return Err(AppError::ValidationError(
                    "Merged content is required for merge resolution".to_string()
                ));
            }
        }

        // 更新冲突状态
        self.db.resolve_conflict(conflict_id, user_id, resolution).await
    }

    /// 处理合并后的内容
    async fn process_merged_content(
        &self,
        user_id: Uuid,
        conflict: &SyncConflict,
        content_base64: &str,
    ) -> AppResult<()> {
        use base64::Engine as _;

        // 解码 Base64 内容
        let data = base64::engine::general_purpose::STANDARD
            .decode(content_base64)
            .map_err(|e| AppError::ValidationError(format!("Invalid base64: {}", e)))?;

        // 计算新的内容哈希
        let content_hash = CryptoUtils::hash_content(&data);

        // 保存合并后的内容
        let storage_path = self.file_store
            .save_content(user_id, &content_hash, &data)
            .await?;

        // 更新内容索引
        self.db
            .save_content_index(user_id, &content_hash, data.len() as i64, &storage_path)
            .await?;

        // 更新用户存储使用量
        self.db.update_user_storage(user_id, data.len() as i64).await?;

        Ok(())
    }

    /// 获取用户在线设备列表
    pub async fn get_online_devices(&self, user_id: Uuid) -> Vec<String> {
        self.sync_engine.get_online_devices(user_id).await
    }

    /// 获取同步引擎（用于 WebSocket 处理）
    pub fn engine(&self) -> Arc<SyncEngine> {
        self.sync_engine.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // 同步服务的测试需要更完整的测试环境
    // 这里提供基本的测试框架

    #[tokio::test]
    async fn test_get_online_devices_empty() {
        // 当没有设备连接时，应返回空列表
        // 这个测试需要完整的 SyncEngine mock
    }
}
