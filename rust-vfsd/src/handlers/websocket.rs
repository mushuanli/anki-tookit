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
use crate::sync::{
    packet::{SyncPacket, SyncPacketResponse, WsMessage},
    SyncEngine,
};

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
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Message>(32);

    let user_id = claims.sub;
    let device_id = claims.device_id.clone().unwrap_or_else(|| Uuid::new_v4().to_string());

    // 注册设备
    state
        .sync_engine
        .register_device(user_id, device_id.clone(), None)
        .await;

    tracing::info!("WebSocket connected: user={}, device={}", user_id, device_id);

    // 发送任务
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(msg).await.is_err() {
                break;
            }
        }
    });

    // 接收任务
    let sync_engine = state.sync_engine.clone();
    let claims_clone = claims.clone();
    let device_id_clone = device_id.clone();
    let tx_clone = tx.clone();

    let recv_task = tokio::spawn(async move {
        while let Some(result) = receiver.next().await {
            match result {
                Ok(Message::Text(text)) => {
                    if let Err(e) = handle_text_message(
                        &text,
                        &claims_clone,
                        &device_id_clone,
                        &sync_engine,
                        &tx_clone,
                    )
                    .await
                    {
                        tracing::error!("Error handling message: {}", e);
                        let error_msg = WsMessage::Error {
                            req_id: None,
                            message: e.to_string(),
                        };
                        if let Ok(json) = serde_json::to_string(&error_msg) {
                            let _ = tx_clone.send(Message::Text(json)).await;
                        }
                    }
                }
                Ok(Message::Binary(data)) => {
                    // 处理二进制数据（分片）
                    if let Err(e) = handle_binary_message(&data, &claims_clone, &sync_engine).await
                    {
                        tracing::error!("Error handling binary message: {}", e);
                    }
                }
                Ok(Message::Ping(data)) => {
                    let _ = tx_clone.send(Message::Pong(data)).await;
                }
                Ok(Message::Close(_)) => break,
                Err(e) => {
                    tracing::error!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }
    });

    // 等待任何一个任务结束
    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    // 注销设备
    state.sync_engine.unregister_device(user_id, &device_id).await;
    tracing::info!("WebSocket disconnected: user={}, device={}", user_id, device_id);
}

async fn handle_text_message(
    text: &str,
    claims: &Claims,
    device_id: &str,
    sync_engine: &SyncEngine,
    tx: &mpsc::Sender<Message>,
) -> AppResult<()> {
    let msg: WsMessage = serde_json::from_str(text)
        .map_err(|e| AppError::ValidationError(format!("Invalid message: {}", e)))?;

    match msg {
        WsMessage::Ping { timestamp } => {
            let pong = WsMessage::Pong { timestamp };
            let json = serde_json::to_string(&pong)?;
            tx.send(Message::Text(json)).await.ok();
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

            let ack = WsMessage::Ack {
                req_id,
                response,
            };
            let json = serde_json::to_string(&ack)?;
            tx.send(Message::Text(json)).await.ok();
        }

        WsMessage::RequestChunk {
            req_id,
            content_hash,
            index,
            node_id,
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
                    let header_json = serde_json::to_string(&header)?;
                    tx.send(Message::Text(header_json)).await.ok();
                    tx.send(Message::Binary(content)).await.ok();
                }
                Ok(None) => {
                    let error = WsMessage::Error {
                        req_id: Some(req_id),
                        message: "Content not found".to_string(),
                    };
                    let json = serde_json::to_string(&error)?;
                    tx.send(Message::Text(json)).await.ok();
                }
                Err(e) => {
                    let error = WsMessage::Error {
                        req_id: Some(req_id),
                        message: e.to_string(),
                    };
                    let json = serde_json::to_string(&error)?;
                    tx.send(Message::Text(json)).await.ok();
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
