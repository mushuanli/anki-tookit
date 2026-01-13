// crates/vfs-service/src/handlers/websocket.rs

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
use crate::metrics::MetricsRecorder;
use vfs_core::config::Config;
use vfs_core::error::{AppError, AppResult};
use vfs_core::models::PermissionLevel;
use vfs_sync::{
    chunk_upload::PendingChunkUpload,
    packet::{OutgoingMessage, WsMessage},
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
    let (msg_tx, mut msg_rx) = mpsc::channel::<OutgoingMessage>(32);

    let user_id = claims.sub;
    let device_id = claims.device_id.clone().unwrap_or_else(|| Uuid::new_v4().to_string());
    let max_packet_size = state.config.sync.max_packet_size;

    let _session = state
        .sync_engine
        .session_manager()
        .register(user_id, device_id.clone(), None, msg_tx.clone())
        .await;

    MetricsRecorder::record_ws_connect();

    tracing::info!("WebSocket connected: user={}, device={}", user_id, device_id);

    let send_task = {
        let device_id = device_id.clone();
        tokio::spawn(async move {
            while let Some(msg) = msg_rx.recv().await {
                let result = match msg {
                    OutgoingMessage::Json(ws_msg) => {
                        match serde_json::to_string(&ws_msg) {
                            Ok(json) => ws_sender.send(Message::Text(json)).await,
                            Err(e) => {
                                tracing::error!("Failed to serialize WsMessage: {}", e);
                                continue;
                            }
                        }
                    }
                    OutgoingMessage::Binary(data) => {
                        ws_sender.send(Message::Binary(data)).await
                    }
                };

                if result.is_err() {
                    tracing::warn!("Failed to send to WebSocket, device={}", device_id);
                    break;
                }
            }
        })
    };

    let recv_task = {
        let sync_engine = state.sync_engine.clone();
        let claims = claims.clone();
        let device_id = device_id.clone();
        let msg_tx = msg_tx.clone();

        tokio::spawn(async move {
            while let Some(result) = ws_receiver.next().await {
                match result {
                    Ok(Message::Text(text)) => {
                        sync_engine.session_manager()
                            .update_activity(claims.sub, &device_id)
                            .await;

                        if let Err(e) = handle_text_message(
                            &text,
                            &claims,
                            &device_id,
                            &sync_engine,
                            &msg_tx,
                            max_packet_size,
                        )
                        .await
                        {
                            tracing::error!("Error handling message: {}", e);
                            let error_msg = WsMessage::Error {
                                req_id: None,
                                message: e.to_string(),
                            };
                            let _ = msg_tx.send(OutgoingMessage::Json(error_msg)).await;
                        }
                    }
                    Ok(Message::Binary(data)) => {
                        sync_engine.session_manager()
                            .update_activity(claims.sub, &device_id)
                            .await;

                        if let Err(e) = handle_binary_message(
                            &data,
                            &claims,
                            &device_id,
                            &sync_engine,
                            &msg_tx,
                        ).await {
                            tracing::error!("Error handling binary message: {}", e);
                        }
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

    tokio::select! {
        _ = send_task => {
            tracing::debug!("Send task ended for device={}", device_id);
        },
        _ = recv_task => {
            tracing::debug!("Recv task ended for device={}", device_id);
        },
    }

    state.sync_engine.session_manager().unregister(user_id, &device_id).await;
    MetricsRecorder::record_ws_disconnect();
    
    tracing::info!("WebSocket disconnected: user={}, device={}", user_id, device_id);
}

async fn handle_text_message(
    text: &str,
    claims: &Claims,
    device_id: &str,
    sync_engine: &SyncEngine,
    tx: &mpsc::Sender<OutgoingMessage>,
    max_size: usize,
) -> AppResult<()> {
    if text.len() > max_size {
        return Err(AppError::ValidationError(format!(
            "Message size exceeds limit: {} > {}", 
            text.len(), max_size
        )));
    }

    let msg: WsMessage = serde_json::from_str(text)
        .map_err(|e| AppError::ValidationError(format!("Invalid message: {}", e)))?;

    match msg {
        WsMessage::Ping { timestamp } => {
            let pong = WsMessage::Pong { timestamp };
            tx.send(OutgoingMessage::Json(pong)).await.ok();
        }

        WsMessage::SyncPacket { req_id, payload } => {
            for change in &payload.changes {
                PermissionChecker::check_path_permission(
                    &claims.permission_level,
                    &claims.path_permissions,
                    &change.path,
                    &PermissionLevel::ReadWrite,
                )?;
            }

            let response = sync_engine
                .process_packet(claims.sub, device_id, payload)
                .await?;

            let ack = WsMessage::Ack { req_id, response };
            tx.send(OutgoingMessage::Json(ack)).await.ok();
        }

        WsMessage::RequestChunk {
            req_id,
            content_hash,
            index,
            node_id: _,
        } => {
            match sync_engine.get_chunk(claims.sub, &content_hash, index).await {
                Ok(Some((data, chunk_info))) => {
                    let header = WsMessage::ChunkResponse {
                        req_id: req_id.clone(),
                        content_hash: content_hash.clone(),
                        index,
                        total_chunks: chunk_info.total_chunks,
                        checksum: chunk_info.checksum,
                        size: data.len() as i64,
                    };
                    tx.send(OutgoingMessage::Json(header)).await.ok();
                    tx.send(OutgoingMessage::Binary(data)).await.ok();
                }
                Ok(None) => {
                    match sync_engine.get_content(claims.sub, &content_hash).await {
                        Ok(Some(content)) => {
                            let chunk_size = sync_engine.chunk_manager().chunk_size();
                            let total_chunks = ((content.len() as f64) / (chunk_size as f64)).ceil() as i32;
                            
                            let start = (index as usize) * chunk_size;
                            let end = std::cmp::min(start + chunk_size, content.len());
                            
                            if start < content.len() {
                                let chunk_data = content[start..end].to_vec();
                                let checksum = vfs_core::utils::CryptoUtils::hash_content(&chunk_data);
                                
                                let header = WsMessage::ChunkResponse {
                                    req_id: req_id.clone(),
                                    content_hash: content_hash.clone(),
                                    index,
                                    total_chunks,
                                    checksum,
                                    size: chunk_data.len() as i64,
                                };
                                tx.send(OutgoingMessage::Json(header)).await.ok();
                                tx.send(OutgoingMessage::Binary(chunk_data)).await.ok();
                            } else {
                                let error = WsMessage::Error {
                                    req_id: Some(req_id),
                                    message: format!("Chunk index {} out of range", index),
                                };
                                tx.send(OutgoingMessage::Json(error)).await.ok();
                            }
                        }
                        Ok(None) => {
                            let error = WsMessage::Error {
                                req_id: Some(req_id),
                                message: "Content not found".to_string(),
                            };
                            tx.send(OutgoingMessage::Json(error)).await.ok();
                        }
                        Err(e) => {
                            let error = WsMessage::Error {
                                req_id: Some(req_id),
                                message: e.to_string(),
                            };
                            tx.send(OutgoingMessage::Json(error)).await.ok();
                        }
                    }
                }
                Err(e) => {
                    let error = WsMessage::Error {
                        req_id: Some(req_id),
                        message: e.to_string(),
                    };
                    tx.send(OutgoingMessage::Json(error)).await.ok();
                }
            }
        }

        WsMessage::ChunkUpload {
            req_id: _,
            content_hash,
            index,
            total_chunks,
            checksum,
            size,
            node_id,
        } => {
            let pending = PendingChunkUpload {
                content_hash: content_hash.clone(),
                index,
                total_chunks,
                checksum: checksum.clone(),
                expected_size: size,
                node_id,
                created_at: chrono::Utc::now(),
            };
            
            sync_engine.chunk_upload_manager()
                .set_pending(device_id, pending)
                .await;
            
            tracing::debug!(
                "Expecting chunk upload: hash={}, index={}/{}",
                content_hash, index, total_chunks
            );
        }

        _ => {
            tracing::warn!("Unhandled message type");
        }
    }

    Ok(())
}

async fn handle_binary_message(
    data: &[u8],
    claims: &Claims,
    device_id: &str,
    sync_engine: &SyncEngine,
    tx: &mpsc::Sender<OutgoingMessage>,
) -> AppResult<()> {
    let pending = sync_engine.chunk_upload_manager()
        .take_pending(device_id)
        .await;

    if let Some(pending) = pending {
        if data.len() as i64 != pending.expected_size {
            let error = WsMessage::ChunkAck {
                req_id: String::new(),
                content_hash: pending.content_hash.clone(),
                index: pending.index,
                success: false,
                error: Some(format!(
                    "Size mismatch: expected {}, got {}",
                    pending.expected_size,
                    data.len()
                )),
            };
            tx.send(OutgoingMessage::Json(error)).await.ok();
            return Ok(());
        }

        match sync_engine.handle_chunk_upload(
            claims.sub,
            &pending.content_hash,
            pending.index,
            pending.total_chunks,
            data,
            &pending.checksum,
        ).await {
            Ok(()) => {
                let ack = WsMessage::ChunkAck {
                    req_id: String::new(),
                    content_hash: pending.content_hash,
                    index: pending.index,
                    success: true,
                    error: None,
                };
                tx.send(OutgoingMessage::Json(ack)).await.ok();
                
                tracing::debug!(
                    "Chunk stored: index={}/{} for user={}",
                    pending.index, pending.total_chunks, claims.sub
                );
            }
            Err(e) => {
                let error = WsMessage::ChunkAck {
                    req_id: String::new(),
                    content_hash: pending.content_hash,
                    index: pending.index,
                    success: false,
                    error: Some(e.to_string()),
                };
                tx.send(OutgoingMessage::Json(error)).await.ok();
            }
        }
    } else {
        tracing::warn!(
            "Received binary data without pending chunk info, device={}",
            device_id
        );
    }

    Ok(())
}
