// src/handlers/websocket.rs

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::Response,
};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::auth::{Claims, JwtService, PermissionChecker};
use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::models::PermissionLevel;
use crate::sync::{packet::WsMessage, SyncEngine};

#[derive(Debug, serde::Deserialize)]
pub struct WsQuery {
    pub token: String,
}

pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsQuery>,
    State(state): State<WsState>,
) -> Result<Response, AppError> {
    // 验证 token
    let jwt_service = JwtService::new(&state.config.auth);
    let token_data = jwt_service.validate_token(&query.token)?;
    let claims = token_data.claims;

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, claims, state)))
}

#[derive(Clone)]
pub struct WsState {
    pub config: Arc<Config>,
    pub sync_engine: Arc<SyncEngine>,
}

async fn handle_socket(socket: WebSocket, claims: Claims, state: WsState) {
    let (mut ws_sender, mut ws_receiver) = socket.split();
    
    // 创建用于接收广播消息的 channel
    let (msg_tx, mut msg_rx) = mpsc::channel::<WsMessage>(32);

    let user_id = claims.sub;
    let device_id = claims.device_id.clone().unwrap_or_else(|| Uuid::new_v4().to_string());

    // 通过 SessionManager 注册设备会话
    let _session = state
        .sync_engine
        .session_manager()
        .register(user_id, device_id.clone(), None, msg_tx.clone())
        .await;

    tracing::info!("WebSocket connected: user={}, device={}", user_id, device_id);

    // 任务1: 将 channel 中的消息发送到 WebSocket
    let send_task = {
        let device_id = device_id.clone();
        tokio::spawn(async move {
            while let Some(msg) = msg_rx.recv().await {
                match serde_json::to_string(&msg) {
                    Ok(json) => {
                        if ws_sender.send(Message::Text(json)).await.is_err() {
                            tracing::warn!("Failed to send to WebSocket, device={}", device_id);
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to serialize WsMessage: {}", e);
                    }
                }
            }
        })
    };

    // 任务2: 从 WebSocket 接收消息并处理
    let recv_task = {
        let sync_engine = state.sync_engine.clone();
        let claims = claims.clone();
        let device_id = device_id.clone();
        let msg_tx = msg_tx.clone();

        tokio::spawn(async move {
            while let Some(result) = ws_receiver.next().await {
                match result {
                    Ok(Message::Text(text)) => {
                        if let Err(e) = handle_text_message(
                            &text,
                            &claims,
                            &device_id,
                            &sync_engine,
                            &msg_tx,
                        )
                        .await
                        {
                            tracing::error!("Error handling message: {}", e);
                            let error_msg = WsMessage::Error {
                                req_id: None,
                                message: e.to_string(),
                            };
                            let _ = msg_tx.send(error_msg).await;
                        }
                    }
                    Ok(Message::Binary(data)) => {
                        if let Err(e) = handle_binary_message(&data, &claims, &sync_engine).await {
                            tracing::error!("Error handling binary message: {}", e);
                        }
                    }
                    Ok(Message::Ping(_data)) => {
                        // Ping 需要直接响应，但我们已经 split 了 sender
                        // axum 的 WebSocket 会自动处理 Ping/Pong
                    }
                    Ok(Message::Close(_)) => {
                        tracing::info!("WebSocket close received: device={}", device_id);
                        break;
                    }
                    Err(e) => {
                        tracing::error!("WebSocket error: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
        })
    };

    // 等待任意一个任务结束
    tokio::select! {
        _ = send_task => {
            tracing::debug!("Send task ended for device={}", device_id);
        },
        _ = recv_task => {
            tracing::debug!("Recv task ended for device={}", device_id);
        },
    }

    // 注销设备会话
    state.sync_engine.session_manager().unregister(user_id, &device_id).await;
    tracing::info!("WebSocket disconnected: user={}, device={}", user_id, device_id);
}

async fn handle_text_message(
    text: &str,
    claims: &Claims,
    device_id: &str,
    sync_engine: &SyncEngine,
    tx: &mpsc::Sender<WsMessage>,
) -> AppResult<()> {
    let msg: WsMessage = serde_json::from_str(text)
        .map_err(|e| AppError::ValidationError(format!("Invalid message: {}", e)))?;

    match msg {
        WsMessage::Ping { timestamp } => {
            let pong = WsMessage::Pong { timestamp };
            tx.send(pong).await.ok();
        }

        WsMessage::SyncPacket { req_id, payload } => {
            // 检查权限
            for change in &payload.changes {
                PermissionChecker::check_path_permission(
                    &claims.permission_level,
                    &claims.path_permissions,
                    &change.path,
                    &PermissionLevel::ReadWrite,
                )?;
            }

            // 处理同步包
            let response = sync_engine
                .process_packet(claims.sub, device_id, payload)
                .await?;

            let ack = WsMessage::Ack { req_id, response };
            tx.send(ack).await.ok();
        }

        WsMessage::RequestChunk {
            req_id,
            content_hash,
            index,
            node_id: _,
        } => {
            // 获取分片数据
            match sync_engine.get_content(claims.sub, &content_hash).await {
                Ok(Some(content)) => {
                    // TODO: 实际应该从 chunk_manager 获取指定分片
                    let header = WsMessage::ChunkHeader {
                        req_id: req_id.clone(),
                        content_hash,
                        index,
                        total_chunks: 1,
                        checksum: "".to_string(),
                        size: content.len() as i64,
                    };
                    tx.send(header).await.ok();
                    
                    let chunk_data = WsMessage::ChunkData {
                        req_id,
                        data: content,
                    };
                    tx.send(chunk_data).await.ok();
                }
                Ok(None) => {
                    let error = WsMessage::Error {
                        req_id: Some(req_id),
                        message: "Content not found".to_string(),
                    };
                    tx.send(error).await.ok();
                }
                Err(e) => {
                    let error = WsMessage::Error {
                        req_id: Some(req_id),
                        message: e.to_string(),
                    };
                    tx.send(error).await.ok();
                }
            }
        }

        _ => {
            tracing::warn!("Unhandled message type");
        }
    }

    Ok(())
}

async fn handle_binary_message(
    _data: &[u8],
    _claims: &Claims,
    _sync_engine: &SyncEngine,
) -> AppResult<()> {
    // TODO: 处理分片上传
    // 需要维护一个状态机来跟踪当前正在上传的分片
    Ok(())
}
