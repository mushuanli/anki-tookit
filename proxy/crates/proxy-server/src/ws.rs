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
    let history_json = serde_json::to_string(&WsMessage::History {
        requests: state.request_store.get_all(),
    })
    .ok();
    if let Some(json) = history_json {
        let _ = sender.send(Message::Text(json.into())).await;
    }

    let hook_history = serde_json::to_string(&WsMessage::HookHistory {
        events: state.hook_store.get_all(),
    })
    .ok();
    if let Some(json) = hook_history {
        let _ = sender.send(Message::Text(json.into())).await;
    }

    let mcp_history = serde_json::to_string(&WsMessage::McpHistory {
        requests: state.mcp_store.get_all(),
    })
    .ok();
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

    // Subscribe to broadcast
    let mut broadcast_rx = state.broadcast_subscribe();

    loop {
        tokio::select! {
            // Broadcast message → forward to WebSocket
            msg = broadcast_rx.recv() => {
                match msg {
                    Ok(ws_msg) => {
                        if let Ok(json) = serde_json::to_string(&ws_msg) {
                            if sender.send(Message::Text(json.into())).await.is_err() {
                                break; // Client disconnected
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("WebSocket broadcast lagged by {} messages", n);
                    }
                    Err(_) => break, // Channel closed
                }
            }
            // WebSocket message from client → handle commands
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        let _ = handle_client_message(&state, &text).await;
                    }
                    Some(Ok(Message::Close(_))) => break,
                    None => break, // Stream ended
                    _ => {}
                }
            }
        }
    }
}

async fn handle_client_message(state: &AppState, text: &str) -> Result<(), String> {
    let cmd: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("Invalid JSON: {}", e))?;
    let action = cmd
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match action {
        "clear" => {
            state.request_store.clear();
            state.hook_store.clear();
            let _ = state.broadcast_send(WsMessage::Cleared);
        }
        "clear_mcp" => {
            state.mcp_store.clear();
            let _ = state.broadcast_send(WsMessage::McpCleared);
        }
        _ => {}
    }
    Ok(())
}
