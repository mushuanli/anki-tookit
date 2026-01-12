// src/sync/engine.rs

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::models::*;
use crate::storage::Database;
use crate::utils::compression::CompressionUtils;
use crate::utils::vector_clock::VectorClockUtils;

use super::chunk_manager::ChunkManager;
use super::conflict::{ConflictDetector, ConflictResult};
use super::filter::SyncFilter;
use super::packet::{SyncPacket, SyncPacketResponse, WsMessage};
use super::session::SessionManager;

pub struct SyncEngine {
    db: Database,
    chunk_manager: ChunkManager,
    filter: SyncFilter,
    config: Arc<Config>,
    // 在线设备连接映射: user_id -> device_id -> channel
    online_devices: Arc<RwLock<HashMap<Uuid, HashMap<String, DeviceConnection>>>>,
}

pub struct DeviceConnection {
    pub device_id: String,
    pub device_name: Option<String>,
    // 可以添加 WebSocket sender channel
}

impl SyncEngine {
    pub fn new(db: Database, config: Arc<Config>) -> Self {
        let chunk_manager = ChunkManager::new(&config.storage, config.sync.chunk_size, db.clone());
        let filter = SyncFilter::new(config.sync.clone());
        let session_manager = Arc::new(SessionManager::new());

        // 启动会话清理任务
        session_manager.clone().start_cleanup_task(60, 300); // 每分钟检查，5分钟超时

        Self {
            db,
            chunk_manager,
            filter,
            config,
            session_manager,
        }
    }

    /// 获取会话管理器
    pub fn session_manager(&self) -> Arc<SessionManager> {
        self.session_manager.clone()
    }

    /// 处理来自设备的同步包
    pub async fn process_packet(
        &self,
        user_id: Uuid,
        device_id: &str,
        packet: SyncPacket,
    ) -> AppResult<SyncPacketResponse> {
        let mut processed_count = 0;
        let mut missing_chunks = Vec::new();
        let mut conflicts = Vec::new();

        // 1. 检查分片是否完整
        if let Some(refs) = &packet.chunk_refs {
            for chunk_ref in refs {
                let missing = self
                    .chunk_manager
                    .get_missing_chunks(user_id, &chunk_ref.content_hash, chunk_ref.total_chunks)
                    .await?;

                if !missing.is_empty() {
                    missing_chunks.push(format!(
                        "{}:{}",
                        chunk_ref.content_hash,
                        missing
                            .iter()
                            .map(|i| i.to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    ));
                }
            }
        }

        if !missing_chunks.is_empty() {
            return Ok(SyncPacketResponse {
                success: false,
                processed_count: 0,
                missing_chunks: Some(missing_chunks),
                conflicts: None,
                error: Some("Missing chunks".to_string()),
            });
        }

        // 2. 处理每个变更
        for change in &packet.changes {
            // 应用过滤器
            if !self.filter.should_sync(change) {
                continue;
            }

            // 获取本地状态进行冲突检测
            let local_log = self
                .db
                .get_latest_log(user_id, &packet.module_id, &change.node_id)
                .await?;

            let conflict_result = if let Some(ref local) = local_log {
                ConflictDetector::detect(&local.vector_clock, change)
            } else {
                ConflictResult::ApplyRemote
            };

            match conflict_result {
                ConflictResult::ApplyRemote => {
                    // 保存日志
                    self.save_sync_log(user_id, device_id, &packet.module_id, change)
                        .await?;

                    // 保存内容（如果有）
                    if let Some(hash) = &change.content_hash {
                        self.save_content(user_id, hash, &packet).await?;
                    }

                    processed_count += 1;
                }
                ConflictResult::KeepLocal => {
                    // 跳过，本地版本更新
                    tracing::debug!("Skipping change for {}: local is newer", change.node_id);
                }
                ConflictResult::Conflict => {
                    // 创建冲突记录
                    let conflict_id = self
                        .create_conflict(user_id, local_log.as_ref().unwrap(), change)
                        .await?;
                    conflicts.push(conflict_id.to_string());
                }
            }
        }

        // 3. 广播变更到用户的其他设备
        if processed_count > 0 {
            self.broadcast_to_other_devices(user_id, device_id, &packet)
                .await;
        }

        // 4. 更新游标
        if let Some(last_change) = packet.changes.last() {
            self.db
                .update_cursor(SyncCursor {
                    user_id,
                    device_id: device_id.to_string(),
                    module_id: packet.module_id.clone(),
                    last_log_id: last_change.log_id,
                    last_sync_time: chrono::Utc::now(),
                    last_content_hash: last_change.content_hash.clone(),
                })
                .await?;
        }

        Ok(SyncPacketResponse {
            success: true,
            processed_count,
            missing_chunks: None,
            conflicts: if conflicts.is_empty() {
                None
            } else {
                Some(conflicts)
            },
            error: None,
        })
    }

    /// 获取设备需要同步的变更
    pub async fn get_pending_changes(
        &self,
        user_id: Uuid,
        device_id: &str,
        module_id: &str,
        limit: i64,
        from_time: Option<i64>,
        to_time: Option<i64>,
    ) -> AppResult<Vec<SyncChange>> {
        // 获取设备游标
        let cursor = self.db.get_cursor(user_id, device_id, module_id).await?;
        let last_log_id = cursor.map(|c| c.last_log_id).unwrap_or(0);

        // 获取该用户所有设备的更新日志（排除当前设备）
        let logs = self
            .db
            .get_logs_after(user_id, module_id, last_log_id, limit, device_id)
            .await?;

        // 应用时间过滤
        let filtered: Vec<SyncChange> = logs
            .into_iter()
            .filter(|log| {
                let ts = log.created_at.timestamp_millis();
                self.filter.check_time_range(ts, from_time, to_time)
            })
            .map(SyncChange::from)
            .filter(|change| self.filter.should_sync(change))
            .collect();

        Ok(filtered)
    }

    /// 获取内容
    pub async fn get_content(
        &self,
        user_id: Uuid,
        content_hash: &str,
    ) -> AppResult<Option<Vec<u8>>> {
        self.db.get_content(user_id, content_hash).await
    }

    /// 注册设备连接
    pub async fn register_device(
        &self,
        user_id: Uuid,
        device_id: String,
        device_name: Option<String>,
    ) {
        let mut devices = self.online_devices.write().await;
        let user_devices = devices.entry(user_id).or_insert_with(HashMap::new);
        user_devices.insert(
            device_id.clone(),
            DeviceConnection {
                device_id,
                device_name,
            },
        );
    }

    /// 注销设备连接
    pub async fn unregister_device(&self, user_id: Uuid, device_id: &str) {
        let mut devices = self.online_devices.write().await;
        if let Some(user_devices) = devices.get_mut(&user_id) {
            user_devices.remove(device_id);
            if user_devices.is_empty() {
                devices.remove(&user_id);
            }
        }
    }

    /// 获取用户在线设备列表
    pub async fn get_online_devices(&self, user_id: Uuid) -> Vec<String> {
        let devices = self.online_devices.read().await;
        devices
            .get(&user_id)
            .map(|d| d.keys().cloned().collect())
            .unwrap_or_default()
    }

    // ==================== 私有方法 ====================

    async fn save_sync_log(
        &self,
        user_id: Uuid,
        device_id: &str,
        module_id: &str,
        change: &SyncChange,
    ) -> AppResult<i64> {
        let log = SyncLog {
            id: 0, // 自增
            user_id,
            module_id: module_id.to_string(),
            node_id: change.node_id.clone(),
            device_id: device_id.to_string(),
            operation: change.operation.clone(),
            path: change.path.clone(),
            previous_path: change.previous_path.clone(),
            content_hash: change.content_hash.clone(),
            size: change.size,
            metadata: change.metadata.clone(),
            version: change.version,
            vector_clock: change.vector_clock.clone(),
            created_at: chrono::Utc::now(),
        };

        self.db.save_log(&log).await
    
    }

    async fn save_content(
        &self,
        user_id: Uuid,
        content_hash: &str,
        packet: &SyncPacket,
    ) -> AppResult<()> {
        // 检查是否是内联内容
        if let Some(ref inline_contents) = packet.inline_contents {
            if let Some(inline) = inline_contents.get(content_hash) {
                let mut data = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &inline.data,
                )
                .map_err(|e| AppError::ValidationError(format!("Invalid base64: {}", e)))?;

                // 解压缩
                if inline.compressed {
                    if let Some(ref algorithm) = inline.compression_algorithm {
                        data = CompressionUtils::decompress(&data, algorithm)?;
                    }
                }

                self.db.save_content(user_id, content_hash, &data).await?;
                return Ok(());
            }
        }

        // 检查是否需要从分片重组
        if let Some(ref chunk_refs) = packet.chunk_refs {
            if let Some(chunk_ref) = chunk_refs.iter().find(|r| r.content_hash == content_hash) {
                let data = self
                    .chunk_manager
                    .reassemble(user_id, content_hash, chunk_ref.total_chunks)
                    .await?;

                self.db.save_content(user_id, content_hash, &data).await?;

                // 清理分片
                self.chunk_manager
                    .cleanup_chunks(user_id, content_hash)
                    .await?;

                return Ok(());
            }
        }

        Ok(())
    }

    async fn create_conflict(
        &self,
        user_id: Uuid,
        local_log: &SyncLog,
        remote_change: &SyncChange,
    ) -> AppResult<Uuid> {
        let conflict = SyncConflict {
            id: Uuid::new_v4(),
            user_id,
            node_id: remote_change.node_id.clone(),
            path: remote_change.path.clone(),
            local_change: SyncChange::from(local_log.clone()),
            remote_change: remote_change.clone(),
            conflict_type: ConflictDetector::determine_type(remote_change),
            resolved: false,
            resolution: None,
            resolved_at: None,
            created_at: chrono::Utc::now(),
        };

        self.db.save_conflict(&conflict).await?;

        Ok(conflict.id)
    }

    async fn broadcast_to_other_devices(
        &self,
        user_id: Uuid,
        sender_device_id: &str,
        packet: &SyncPacket,
    ) {
        let devices = self.online_devices.read().await;

        if let Some(user_devices) = devices.get(&user_id) {
            for (device_id, _conn) in user_devices {
                if device_id != sender_device_id {
                    // TODO: 通过 WebSocket channel 发送同步包
                    // 这需要在 DeviceConnection 中添加 sender channel
                    tracing::debug!(
                        "Would broadcast {} changes to device {}",
                        packet.changes.len(),
                        device_id
                    );
                }
            }
        }
    }
}
