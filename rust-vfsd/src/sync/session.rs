// src/sync/session.rs

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

use super::packet::WsMessage;

/// 设备会话
pub struct DeviceSession {
    pub user_id: Uuid,
    pub device_id: String,
    pub device_name: Option<String>,
    pub connected_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub sender: mpsc::Sender<WsMessage>,
}

/// 会话管理器
pub struct SessionManager {
    // user_id -> device_id -> session
    sessions: RwLock<HashMap<Uuid, HashMap<String, Arc<DeviceSession>>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// 注册新会话
    pub async fn register(
        &self,
        user_id: Uuid,
        device_id: String,
        device_name: Option<String>,
        sender: mpsc::Sender<WsMessage>,
    ) -> Arc<DeviceSession> {
        let now = chrono::Utc::now();
        let session = Arc::new(DeviceSession {
            user_id,
            device_id: device_id.clone(),
            device_name,
            connected_at: now,
            last_activity: now,
            sender,
        });

        let mut sessions = self.sessions.write().await;
        let user_sessions = sessions.entry(user_id).or_insert_with(HashMap::new);
        
        // 如果同一设备已有连接，先关闭旧连接
        if let Some(old_session) = user_sessions.get(&device_id) {
            let _ = old_session.sender.send(WsMessage::Error {
                req_id: None,
                message: "Session replaced by new connection".to_string(),
            }).await;
        }
        
        user_sessions.insert(device_id, session.clone());
        
        tracing::info!(
            "Session registered: user={}, device={}, total_devices={}",
            user_id,
            session.device_id,
            user_sessions.len()
        );

        session
    }

    /// 注销会话
    pub async fn unregister(&self, user_id: Uuid, device_id: &str) {
        let mut sessions = self.sessions.write().await;
        
        if let Some(user_sessions) = sessions.get_mut(&user_id) {
            user_sessions.remove(device_id);
            
            if user_sessions.is_empty() {
                sessions.remove(&user_id);
            }
            
            tracing::info!("Session unregistered: user={}, device={}", user_id, device_id);
        }
    }

    /// 获取用户的所有在线设备
    pub async fn get_user_devices(&self, user_id: Uuid) -> Vec<Arc<DeviceSession>> {
        let sessions = self.sessions.read().await;
        
        sessions
            .get(&user_id)
            .map(|user_sessions| user_sessions.values().cloned().collect())
            .unwrap_or_default()
    }

    /// 获取用户的其他设备（排除指定设备）
    pub async fn get_other_devices(
        &self,
        user_id: Uuid,
        exclude_device_id: &str,
    ) -> Vec<Arc<DeviceSession>> {
        let sessions = self.sessions.read().await;
        
        sessions
            .get(&user_id)
            .map(|user_sessions| {
                user_sessions
                    .iter()
                    .filter(|(id, _)| *id != exclude_device_id)
                    .map(|(_, session)| session.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 广播消息给用户的其他设备
    pub async fn broadcast_to_others(
        &self,
        user_id: Uuid,
        sender_device_id: &str,
        message: WsMessage,
    ) {
        let other_devices = self.get_other_devices(user_id, sender_device_id).await;
        
        for device in other_devices {
            if let Err(e) = device.sender.send(message.clone()).await {
                tracing::warn!(
                    "Failed to broadcast to device {}: {}",
                    device.device_id,
                    e
                );
            }
        }
    }

    /// 发送消息给指定设备
    pub async fn send_to_device(
        &self,
        user_id: Uuid,
        device_id: &str,
        message: WsMessage,
    ) -> Result<(), String> {
        let sessions = self.sessions.read().await;
        
        if let Some(user_sessions) = sessions.get(&user_id) {
            if let Some(session) = user_sessions.get(device_id) {
                session
                    .sender
                    .send(message)
                    .await
                    .map_err(|e| format!("Send failed: {}", e))?;
                return Ok(());
            }
        }
        
        Err("Device not found".to_string())
    }

    /// 获取在线统计
    pub async fn get_stats(&self) -> SessionStats {
        let sessions = self.sessions.read().await;
        
        let total_users = sessions.len();
        let total_devices: usize = sessions.values().map(|u| u.len()).sum();
        
        SessionStats {
            total_users,
            total_devices,
        }
    }

    /// 清理不活跃的会话
    pub async fn cleanup_inactive(&self, max_idle_seconds: i64) {
        let now = chrono::Utc::now();
        let mut sessions = self.sessions.write().await;
        
        let mut to_remove: Vec<(Uuid, String)> = Vec::new();
        
        for (user_id, user_sessions) in sessions.iter() {
            for (device_id, session) in user_sessions.iter() {
                let idle_seconds = (now - session.last_activity).num_seconds();
                if idle_seconds > max_idle_seconds {
                    to_remove.push((*user_id, device_id.clone()));
                }
            }
        }
        
        for (user_id, device_id) in to_remove {
            if let Some(user_sessions) = sessions.get_mut(&user_id) {
                if let Some(session) = user_sessions.remove(&device_id) {
                    let _ = session.sender.send(WsMessage::Error {
                        req_id: None,
                        message: "Session timeout".to_string(),
                    }).await;
                }
                
                if user_sessions.is_empty() {
                    sessions.remove(&user_id);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionStats {
    pub total_users: usize,
    pub total_devices: usize,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

// 添加定期清理任务
impl SessionManager {
    /// 启动后台清理任务
    pub fn start_cleanup_task(self: Arc<Self>, interval_secs: u64, max_idle_secs: i64) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                tokio::time::Duration::from_secs(interval_secs)
            );
            
            loop {
                interval.tick().await;
                self.cleanup_inactive(max_idle_secs).await;
                
                let stats = self.get_stats().await;
                tracing::debug!(
                    "Session cleanup complete: {} users, {} devices online",
                    stats.total_users,
                    stats.total_devices
                );
            }
        });
    }
}
