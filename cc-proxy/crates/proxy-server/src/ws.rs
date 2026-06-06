use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;

use futures::{SinkExt, StreamExt};
use proxy_core::models::WsMessage;
use tokio::time::interval;

use crate::AppState;

/// How often to send a WebSocket Ping frame to keep the connection alive.
const PING_INTERVAL: Duration = Duration::from_secs(10);

/// Close the connection if no Pong has been received within this window.
const DEAD_TIMEOUT: Duration = Duration::from_secs(300);


pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();

    // ── Send lightweight state snapshot on connect ──
    // NOTE: request history is intentionally NOT sent here.
    //       The client fetches it via GET /api/requests (REST) immediately after
    //       connecting, which avoids sending potentially large payloads over the
    //       WebSocket and causing the connection to time out before the ping loop starts.

    let hooks = state.db.list_hooks().unwrap_or_default();
    send_json(&mut sender, &WsMessage::HookHistory { events: hooks }).await;

    let mcp = state.db.list_mcp().unwrap_or_default();
    send_json(&mut sender, &WsMessage::McpHistory { requests: mcp }).await;

    let dest = state.mcp_destination.read().await.clone();
    send_json(&mut sender, &WsMessage::McpConfigChanged { destination_url: dest }).await;

    send_json(&mut sender, &state.upstream_changed_msg().await).await;

    send_json(
        &mut sender,
        &WsMessage::TeeStatusChanged { enabled: state.tee_writer.is_enabled() },
    )
    .await;

    // ── Main loop ──
    let mut broadcast_rx = state.broadcast_subscribe();
    let mut ping_ticker = interval(PING_INTERVAL);
    ping_ticker.tick().await; // skip the immediate first tick

    // Timestamp of the last pong (or connection start).
    let mut last_pong = tokio::time::Instant::now();
    // Warning thresholds: track the last warning level to avoid log spam.
    let mut last_warned: u8 = 0;

    loop {
        tokio::select! {
            // ── Heartbeat ping ──
            _ = ping_ticker.tick() => {
                let elapsed = last_pong.elapsed().as_secs();
                // Early warnings before dead timeout
                if elapsed > 240 && last_warned < 3 {
                    tracing::warn!("WebSocket no pong for {}s", elapsed);
                    last_warned = 3;
                } else if elapsed > 220 && last_warned < 2 {
                    tracing::warn!("WebSocket no pong for {}s", elapsed);
                    last_warned = 2;
                } else if elapsed > 200 && last_warned < 1 {
                    tracing::warn!("WebSocket no pong for {}s", elapsed);
                    last_warned = 1;
                }
                // Disconnect only if silent for longer than DEAD_TIMEOUT.
                if elapsed > DEAD_TIMEOUT.as_secs() {
                    tracing::debug!(
                        "WebSocket dead — no pong for {}s, closing",
                        elapsed
                    );
                    break;
                }
                tracing::trace!("WebSocket ping →");
                if sender.send(Message::Ping(vec![])).await.is_err() {
                    break;
                }
            }

            // ── Broadcast messages from the rest of the server ──
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

            // ── Incoming frames from the client ──
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Pong(_))) => {
                        tracing::trace!("WebSocket ← pong");
                        last_pong = tokio::time::Instant::now();
                        last_warned = 0;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        // Browser-initiated ping — respond immediately
                        let _ = sender.send(Message::Pong(data.to_vec())).await;
                    }
                    Some(Ok(Message::Text(text))) => {
                        let _ = handle_client_message(&state, &text).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
}

async fn send_json<T: serde::Serialize>(
    sender: &mut futures::stream::SplitSink<WebSocket, Message>,
    msg: &T,
) {
    if let Ok(json) = serde_json::to_string(msg) {
        let _ = sender.send(Message::Text(json.into())).await;
    }
}

async fn handle_client_message(_state: &AppState, text: &str) -> Result<(), String> {
    let _cmd: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("Invalid JSON: {}", e))?;
    Ok(())
}
