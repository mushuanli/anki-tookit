// src/sync/chunk_upload.rs

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// 分片上传状态
#[derive(Debug, Clone)]
pub struct PendingChunkUpload {
    pub content_hash: String,
    pub index: i32,
    pub total_chunks: i32,
    pub checksum: String,
    pub expected_size: i64,
    pub node_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// 分片上传管理器
/// 用于跟踪 WebSocket 连接中待接收的二进制分片
pub struct ChunkUploadManager {
    // device_id -> pending chunk info
    pending: RwLock<HashMap<String, PendingChunkUpload>>,
}

impl ChunkUploadManager {
    pub fn new() -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
        }
    }

    /// 设置待接收的分片信息
    pub async fn set_pending(&self, device_id: &str, upload: PendingChunkUpload) {
        let mut pending = self.pending.write().await;
        pending.insert(device_id.to_string(), upload);
    }

    /// 获取并清除待接收的分片信息
    pub async fn take_pending(&self, device_id: &str) -> Option<PendingChunkUpload> {
        let mut pending = self.pending.write().await;
        pending.remove(device_id)
    }

    /// 检查是否有待接收的分片
    pub async fn has_pending(&self, device_id: &str) -> bool {
        let pending = self.pending.read().await;
        pending.contains_key(device_id)
    }

    /// 清理超时的待接收分片（超过指定秒数）
    pub async fn cleanup_stale(&self, max_age_secs: i64) {
        let now = chrono::Utc::now();
        let mut pending = self.pending.write().await;
        
        pending.retain(|_, upload| {
            (now - upload.created_at).num_seconds() < max_age_secs
        });
    }

    /// 启动后台清理任务
    pub fn start_cleanup_task(self: Arc<Self>, interval_secs: u64, max_age_secs: i64) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                tokio::time::Duration::from_secs(interval_secs)
            );
            
            loop {
                interval.tick().await;
                self.cleanup_stale(max_age_secs).await;
            }
        });
    }
}

impl Default for ChunkUploadManager {
    fn default() -> Self {
        Self::new()
    }
}
