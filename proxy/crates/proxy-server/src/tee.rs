use chrono::Utc;
use proxy_core::models::ProxiedRequest;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

/// Side-channel packet capture writer.
/// When enabled, writes every proxied request/response pair to disk.
pub struct TeeWriter {
    enabled: Arc<AtomicBool>,
    output_dir: PathBuf,
    current_file: Mutex<Option<tokio::fs::File>>,
}

#[derive(Debug, Clone, Copy)]
pub enum TeeFormat {
    Raw,
    Jsonl,
}

impl TeeFormat {
    fn extension(&self) -> &str {
        match self {
            TeeFormat::Raw => "txt",
            TeeFormat::Jsonl => "jsonl",
        }
    }
}

impl TeeWriter {
    pub fn new(enabled: Arc<AtomicBool>, output_dir: PathBuf) -> Self {
        Self {
            enabled,
            output_dir,
            current_file: Mutex::new(None),
        }
    }

    /// Open a new timestamped capture file.
    pub async fn start_new_file(&self, format: TeeFormat) -> anyhow::Result<()> {
        tokio::fs::create_dir_all(&self.output_dir).await?;
        let filename = format!(
            "capture_{}.{}",
            Utc::now().format("%Y%m%d_%H%M%S"),
            format.extension()
        );
        let path = self.output_dir.join(&filename);
        let file = tokio::fs::File::create(&path).await?;
        *self.current_file.lock().await = Some(file);
        tracing::info!("Tee capture started → {}", path.display());
        Ok(())
    }

    /// Write a captured request to the tee file (raw format).
    pub async fn write_exchange(&self, request: &ProxiedRequest) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }

        let mut guard = self.current_file.lock().await;
        if let Some(ref mut file) = *guard {
            let content = format_raw_exchange(request);
            let _ = file.write_all(content.as_bytes()).await;
            let _ = file.flush().await;
        }
    }
}

fn format_raw_exchange(req: &ProxiedRequest) -> String {
    let mut out = String::new();
    let sep = "=".repeat(60);

    // Request section
    out.push_str(&format!(
        "{}\n{} {} {}\n",
        sep,
        req.timestamp.to_rfc3339(),
        req.method,
        req.path
    ));
    for (k, v) in &req.request_headers {
        out.push_str(&format!("{}: {}\n", k, v));
    }
    out.push('\n');
    if let Some(ref body) = req.request_body {
        // Pretty-print JSON if possible
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) {
            out.push_str(&serde_json::to_string_pretty(&parsed).unwrap_or_else(|_| body.clone()));
        } else {
            out.push_str(body);
        }
        out.push('\n');
    }

    // Response section
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

    // SSE events
    if !req.sse_events.is_empty() {
        for ev in &req.sse_events {
            if let Some(ref ev_type) = ev.event_type {
                out.push_str(&format!("event: {}\n", ev_type));
            }
            if let Some(ref data) = ev.data {
                out.push_str(&format!("data: {}\n", data));
            }
            out.push('\n');
        }
    } else if let Some(ref body) = req.response_body {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) {
            out.push_str(&serde_json::to_string_pretty(&parsed).unwrap_or_else(|_| body.clone()));
        } else {
            out.push_str(body);
        }
        out.push('\n');
    }

    if let Some(ref err) = req.error {
        out.push_str(&format!("ERROR: {}\n", err));
    }

    // Token summary
    if req.input_tokens.is_some() || req.output_tokens.is_some() {
        out.push_str(&format!(
            "Tokens: {} in / {} out",
            req.input_tokens.unwrap_or(0),
            req.output_tokens.unwrap_or(0)
        ));
        if let Some(ttft) = req.time_to_first_token_ms {
            out.push_str(&format!(" | TTFT: {}ms", ttft));
        }
        out.push('\n');
    }

    out.push_str(&sep);
    out.push_str("\n\n");
    out
}

fn status_text(code: Option<u16>) -> &'static str {
    match code {
        Some(200) => "OK",
        Some(201) => "Created",
        Some(400) => "Bad Request",
        Some(401) => "Unauthorized",
        Some(403) => "Forbidden",
        Some(404) => "Not Found",
        Some(429) => "Too Many Requests",
        Some(500) => "Internal Server Error",
        Some(502) => "Bad Gateway",
        Some(503) => "Service Unavailable",
        _ => "",
    }
}
