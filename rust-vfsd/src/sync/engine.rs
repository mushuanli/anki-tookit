// src/sync/engine.rs

use std::sync::Arc;
use uuid::Uuid;

use crate::config::Config;
use crate::error::AppResult;
use crate::models::*;
use crate::storage::Database;
use tokio::sync::mpsc;

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
    session_manager: Arc<SessionManager>,
}

// 移除未使用的 DeviceConnection 结构体，因为 SessionManager 已经有 DeviceSession

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
        let mut changes_to_broadcast = Vec::new();

        // 1. 检查分片完整性
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
                        missing.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",")
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

                    changes_to_broadcast.push(change.clone());
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
        if !changes_to_broadcast.is_empty() {
            self.broadcast_changes(user_id, device_id, &packet.module_id, changes_to_broadcast)
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
            conflicts: if conflicts.is_empty() { None } else { Some(conflicts) },
            error: None,
        })
    }

    /// 广播变更到其他设备
    async fn broadcast_changes(
        &self,
        user_id: Uuid,
        sender_device_id: &str,
        module_id: &str,
        changes: Vec<SyncChange>,
    ) {
        let broadcast_packet = SyncPacket {
            packet_id: Uuid::new_v4().to_string(),
            peer_id: "server".to_string(),
            module_id: module_id.to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            changes,
            inline_contents: None, // 其他设备需要自行拉取内容
            chunk_refs: None,
            compression: None,
            signature: None,
        };

        let message = WsMessage::SyncPacket {
            req_id: Uuid::new_v4().to_string(),
            payload: broadcast_packet,
        };

        self.session_manager
            .broadcast_to_others(user_id, sender_device_id, message)
            .await;
    }

    /// 获取设备需要同步的变更（增量拉取）
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

    /// 获取分片管理器
    pub fn chunk_manager(&self) -> &ChunkManager {
        &self.chunk_manager
    }

    /// 注册设备连接 - 修复：使用 session_manager
    /// 注意：此方法现在需要一个 sender channel，但为了保持 API 兼容性，
    /// 我们创建一个虚拟的 channel。实际的 WebSocket 注册应该在 websocket handler 中完成。
    pub async fn register_device(
        &self,
        user_id: Uuid,
        device_id: String,
        device_name: Option<String>,
    ) {
        // 创建一个虚拟的 sender（实际不会使用，因为真正的注册在 WebSocket handler 中）
        // 这个方法主要用于记录设备注册意图
        let (tx, _rx) = mpsc::channel::<WsMessage>(1);
        
        self.session_manager
            .register(user_id, device_id, device_name, tx)
            .await;
    }

    /// 注销设备连接 - 修复：使用 session_manager
    pub async fn unregister_device(&self, user_id: Uuid, device_id: &str) {
        self.session_manager.unregister(user_id, device_id).await;
    }

    /// 获取用户在线设备列表 - 修复：使用 session_manager
    pub async fn get_online_devices(&self, user_id: Uuid) -> Vec<String> {
        self.session_manager
            .get_user_devices(user_id)
            .await
            .into_iter()
            .map(|session| session.device_id.clone())
            .collect()
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
        use crate::utils::CompressionUtils;

        // 检查内联内容
        if let Some(ref inline_contents) = packet.inline_contents {
            if let Some(inline) = inline_contents.get(content_hash) {
                let mut data = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &inline.data,
                )
                .map_err(|e| crate::error::AppError::ValidationError(format!("Invalid base64: {}", e)))?;

                // 解压缩
                if inline.compressed {
                    if let Some(ref algorithm) = inline.compression_algorithm {
                        data = CompressionUtils::decompress(&data, algorithm)?;
                    }
                }

                self.db.save_content(user_id, content_hash, &data).await?;
                
                // 更新用户存储使用量
                self.db.update_user_storage(user_id, data.len() as i64).await?;
                
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
                self.db.update_user_storage(user_id, data.len() as i64).await?;
                self.chunk_manager.cleanup_chunks(user_id, content_hash).await?;

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

        // 通知用户所有设备有冲突
        let message = WsMessage::Error {
            req_id: None,
            message: format!("Conflict detected for path: {}", conflict.path),
        };

        let devices = self.session_manager.get_user_devices(user_id).await;
        for device in devices {
            let _ = device.sender.send(message.clone()).await;
        }

        Ok(conflict.id)
    }
}
