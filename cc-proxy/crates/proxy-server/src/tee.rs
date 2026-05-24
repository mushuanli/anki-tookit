use chrono::Utc;
use proxy_core::models::{ProxiedRequest, SseEvent};
use proxy_core::sse::SseParser;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

/// Side-channel packet capture writer.
/// When enabled, writes every proxied request/response pair to disk,
/// organized by date and session_id:
///   captures/YYYY-MM-DD/session_<session_id>.txt
pub struct TeeWriter {
    enabled: Arc<AtomicBool>,
    output_dir: PathBuf,
    /// Map from "YYYY-MM-DD/session_<id>" → open file handle
    files: Mutex<HashMap<String, tokio::fs::File>>,
}

impl TeeWriter {
    pub fn new(enabled: Arc<AtomicBool>, output_dir: PathBuf) -> Self {
        Self {
            enabled,
            output_dir,
            files: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_enabled(&self, val: bool) {
        self.enabled.store(val, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// No-op: files are now opened on-demand per (date, session_id) in write_exchange.
    pub async fn start_new_file(&self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Write a captured request/response pair to the appropriate session file.
    pub async fn write_exchange(&self, request: &ProxiedRequest) {
        if !self.is_enabled() {
            return;
        }

        let today = Utc::now().format("%Y-%m-%d").to_string();
        let sid = request.session_id.as_deref().unwrap_or("unknown");
        let key = format!("{}/{}", today, sid);

        let mut files = self.files.lock().await;

        // Open file if not already cached
        if !files.contains_key(&key) {
            let dir = self.output_dir.join(&today);
            if let Err(e) = tokio::fs::create_dir_all(&dir).await {
                tracing::error!("Failed to create capture dir {}: {}", dir.display(), e);
                return;
            }
            let path = dir.join(format!("session_{}.txt", sid));
            match tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await
            {
                Ok(file) => {
                    tracing::info!("Capture → {}", path.display());
                    files.insert(key.clone(), file);
                }
                Err(e) => {
                    tracing::error!("Failed to open capture file {}: {}", path.display(), e);
                    return;
                }
            }
        }

        if let Some(file) = files.get_mut(&key) {
            let content = format_raw_exchange(request);
            let _ = file.write_all(content.as_bytes()).await;
            let _ = file.flush().await;
        }
    }
}

fn format_raw_exchange(req: &ProxiedRequest) -> String {
    let mut out = String::new();
    let sep = "=".repeat(60);
    let sub = "-".repeat(40);

    // ── Request header ──
    out.push_str(&format!(
        "{}\n{} {} {}\n",
        sep, req.timestamp.to_rfc3339(), req.method, req.path
    ));
    for (k, v) in &req.request_headers {
        out.push_str(&format!("{}: {}\n", k, v));
    }
    out.push('\n');

    // ── Request body (pretty JSON) ──
    if let Some(ref body) = req.request_body {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) {
            out.push_str(
                &serde_json::to_string_pretty(&parsed).unwrap_or_else(|_| body.clone()),
            );
        } else {
            out.push_str(body);
        }
        out.push_str("\n\n");
    }

    // ── Response header ──
    out.push_str(&format!(
        "{}\n{} {} — {}ms\n",
        sep,
        req.status_code
            .map(|s| s.to_string())
            .unwrap_or_else(|| "???".to_string()),
        status_text(req.status_code),
        req.duration_ms.unwrap_or(0),
    ));
    for (k, v) in &req.response_headers {
        out.push_str(&format!("{}: {}\n", k, v));
    }
    out.push('\n');

    if let Some(ref err) = req.error {
        out.push_str(&format!("ERROR: {}\n\n", err));
    }

    // ── SSE or plain response body ──
    if !req.sse_events.is_empty() {
        format_sse_events(&mut out, &req.sse_events, &sub);
    } else if let Some(ref body) = req.response_body {
        out.push_str(&format!("{sub} Response Body {sub}\n"));
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) {
            out.push_str(
                &serde_json::to_string_pretty(&parsed).unwrap_or_else(|_| body.clone()),
            );
        } else {
            out.push_str(body);
        }
        out.push('\n');
    }

    // ── Token summary ──
    let has_usage = req.input_tokens.is_some() || req.output_tokens.is_some();
    let has_meta = req.stop_reason.is_some() || req.model.is_some() || req.message_id.is_some();
    if has_usage || has_meta {
        out.push_str(&format!("{sub} Summary {sub}\n"));
        out.push('\n');
        if let Some(ref model) = req.model {
            out.push_str(&format!("Model: {}\n", model));
        }
        if let Some(ref msg_id) = req.message_id {
            out.push_str(&format!("Message ID: {}\n", msg_id));
        }
        if let Some(ref reason) = req.stop_reason {
            out.push_str(&format!("Stop reason: {}\n", reason));
        }
        if has_usage {
            out.push_str(&format!(
                "Tokens: {} in / {} out",
                req.input_tokens.unwrap_or(0),
                req.output_tokens.unwrap_or(0)
            ));
            if let Some(cached) = req.cache_read_input_tokens {
                if cached > 0 {
                    out.push_str(&format!(" | Cache read: {}", cached));
                }
            }
            if let Some(created) = req.cache_creation_input_tokens {
                if created > 0 {
                    out.push_str(&format!(" | Cache created: {}", created));
                }
            }
            if let Some(ttft) = req.time_to_first_token_ms {
                out.push_str(&format!(" | TTFT: {}ms", ttft));
            }
            out.push('\n');
        }
        out.push('\n');
    }

    out.push_str(&sep);
    out.push_str("\n\n");
    out
}

/// Format SSE events: merge content_block_delta fragments into readable output.
fn format_sse_events(out: &mut String, events: &[SseEvent], sub: &str) {
    let parser = SseParser::new();

    // Collect content blocks with type tracking
    struct Block {
        text: String,
        block_type: String, // "thinking", "text", "tool_use"
    }
    let mut blocks: Vec<Block> = Vec::new();
    let mut current = Block {
        text: String::new(),
        block_type: "text".into(),
    };

    for ev in events {
        let data_str = match &ev.data {
            Some(d) => d,
            None => continue,
        };
        let parsed = match parser.parse_message_data(data_str) {
            Some(v) => v,
            None => continue,
        };

        match parser.event_kind(&parsed) {
            Some("content_block_start") => {
                if !current.text.is_empty() {
                    blocks.push(std::mem::replace(
                        &mut current,
                        Block {
                            text: String::new(),
                            block_type: "text".into(),
                        },
                    ));
                }
                // Extract block type from content_block_start
                let block_type = parsed
                    .get("content_block")
                    .and_then(|cb| cb.get("type"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("text");
                current.block_type = block_type.to_string();
            }
            Some("content_block_delta") => {
                // Handle text_delta, thinking_delta, and input_json_delta
                let delta = parsed.get("delta").and_then(|d| d.get("type")).and_then(|t| t.as_str());
                match delta {
                    Some("text_delta") => {
                        if let Some(text) = parsed
                            .get("delta")
                            .and_then(|d| d.get("text"))
                            .and_then(|t| t.as_str())
                        {
                            current.text.push_str(text);
                        }
                    }
                    Some("thinking_delta") => {
                        if let Some(text) = parsed
                            .get("delta")
                            .and_then(|d| d.get("thinking"))
                            .and_then(|t| t.as_str())
                        {
                            current.text.push_str(text);
                        }
                    }
                    Some("input_json_delta") => {
                        if let Some(text) = parsed
                            .get("delta")
                            .and_then(|d| d.get("partial_json"))
                            .and_then(|t| t.as_str())
                        {
                            current.text.push_str(text);
                        }
                    }
                    _ => {}
                }
            }
            Some("content_block_stop") => {
                if !current.text.is_empty() {
                    blocks.push(std::mem::replace(
                        &mut current,
                        Block {
                            text: String::new(),
                            block_type: "text".into(),
                        },
                    ));
                }
            }
            _ => {}
        }
    }
    // Don't forget the last block
    if !current.text.is_empty() {
        blocks.push(current);
    }

    // ── Output merged content, grouped by type ──
    let thinking: Vec<&str> = blocks
        .iter()
        .filter(|b| b.block_type == "thinking")
        .map(|b| b.text.as_str())
        .collect();
    let response: Vec<&str> = blocks
        .iter()
        .filter(|b| b.block_type == "text")
        .map(|b| b.text.as_str())
        .collect();
    let tool_use: Vec<&str> = blocks
        .iter()
        .filter(|b| b.block_type == "tool_use")
        .map(|b| b.text.as_str())
        .collect();

    if !thinking.is_empty() {
        out.push_str(&format!("{sub} Thinking {sub}\n"));
        for t in &thinking {
            out.push_str(t);
            out.push('\n');
        }
        out.push('\n');
    }
    if !response.is_empty() {
        out.push_str(&format!("{sub} Response {sub}\n"));
        for t in &response {
            out.push_str(t);
            out.push('\n');
        }
        out.push('\n');
    }
    if !tool_use.is_empty() {
        out.push_str(&format!("{sub} Tool Use {sub}\n"));
        for t in &tool_use {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(t) {
                out.push_str(&serde_json::to_string_pretty(&parsed).unwrap_or_else(|_| t.to_string()));
            } else {
                out.push_str(t);
            }
            out.push('\n');
        }
        out.push('\n');
    }

    // ── Header events (message_start, etc.) ──
    let mut header_events: Vec<&SseEvent> = Vec::new();
    for ev in events {
        if let Some(ref data_str) = ev.data {
            if let Some(parsed) = parser.parse_message_data(data_str) {
                match parser.event_kind(&parsed) {
                    Some("content_block_delta")
                    | Some("content_block_start")
                    | Some("content_block_stop")
                    | Some("ping") => continue,
                    _ => {}
                }
            }
        }
        header_events.push(ev);
    }

    if !header_events.is_empty() {
        out.push_str(&format!("{sub} SSE Events {sub}\n"));
        for ev in &header_events {
            if let Some(ref ev_type) = ev.event_type {
                out.push_str(&format!("[{}]\n", ev_type));
            }
            if let Some(ref data) = ev.data {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(data) {
                    out.push_str(
                        &serde_json::to_string_pretty(&parsed).unwrap_or_else(|_| data.clone()),
                    );
                } else {
                    out.push_str(data);
                }
                out.push('\n');
            }
            out.push('\n');
        }
        out.push('\n');
    }
}

fn status_text(code: Option<u16>) -> &'static str {
    match code {
        Some(200) => "OK",
        Some(400) => "Bad Request",
        Some(401) => "Unauthorized",
        Some(403) => "Forbidden",
        Some(404) => "Not Found",
        Some(429) => "Too Many Requests",
        Some(500) => "Internal Server Error",
        Some(502) => "Bad Gateway",
        _ => "",
    }
}
