use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use futures::{SinkExt, StreamExt};
use proxy_core::models::WsMessage;

use crate::AppState;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();

    // Send history on connect
    let requests = state.db.list_requests(None, None, None, None, Some(500)).unwrap_or_default();
    let history_json = serde_json::to_string(&WsMessage::History { requests }).ok();
    if let Some(json) = history_json {
        let _ = sender.send(Message::Text(json.into())).await;
    }

    let hooks = state.db.list_hooks().unwrap_or_default();
    let hook_history = serde_json::to_string(&WsMessage::HookHistory { events: hooks }).ok();
    if let Some(json) = hook_history {
        let _ = sender.send(Message::Text(json.into())).await;
    }

    let mcp = state.db.list_mcp().unwrap_or_default();
    let mcp_history = serde_json::to_string(&WsMessage::McpHistory { requests: mcp }).ok();
    if let Some(json) = mcp_history {
        let _ = sender.send(Message::Text(json.into())).await;
    }

    let dest = state.mcp_destination.read().await.clone();
    let mcp_config = serde_json::to_string(&WsMessage::McpConfigChanged {
        destination_url: dest,
    })
    .ok();
    if let Some(json) = mcp_config {
        let _ = sender.send(Message::Text(json.into())).await;
    }

    let upstream_msg = serde_json::to_string(&WsMessage::UpstreamChanged {
        active_url: state.upstream_target.read().await.clone(),
        upstreams: state.upstream_info_list().await,
    })
    .ok();
    if let Some(json) = upstream_msg {
        let _ = sender.send(Message::Text(json.into())).await;
    }

    // Send current capture status
    let tee_status = serde_json::to_string(&WsMessage::TeeStatusChanged {
        enabled: state.tee_writer.is_enabled(),
    })
    .ok();
    if let Some(json) = tee_status {
        let _ = sender.send(Message::Text(json.into())).await;
    }

    // Subscribe to broadcast
    let mut broadcast_rx = state.broadcast_subscribe();

    loop {
        tokio::select! {
            msg = broadcast_rx.recv() => {
                match msg {
                    Ok(ws_msg) => {
                        if let Ok(json) = serde_json::to_string(&ws_msg) {
                            if sender.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("WebSocket broadcast lagged by {} messages", n);
                    }
                    Err(_) => break,
                }
            }
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        let _ = handle_client_message(&state, &text).await;
                    }
                    Some(Ok(Message::Close(_))) => break,
                    None => break,
                    _ => {}
                }
            }
        }
    }
}

async fn handle_client_message(_state: &AppState, text: &str) -> Result<(), String> {
    let _cmd: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("Invalid JSON: {}", e))?;
    // Client commands are no longer needed — all operations go through REST API
    Ok(())
}
