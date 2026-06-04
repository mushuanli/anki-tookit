use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Trait for items that have a string id (used by RingBuffer::get_by_id).
pub trait HasId {
    fn id(&self) -> &str;
}

impl HasId for ProxiedRequest {
    fn id(&self) -> &str {
        &self.id
    }
}

impl HasId for HookEvent {
    fn id(&self) -> &str {
        &self.id
    }
}

fn short_id() -> String {
    Uuid::new_v4().to_string()[..12].to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxiedRequest {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    // Request
    pub method: String,
    pub path: String,
    pub request_headers: HashMap<String, String>,
    pub request_body: Option<String>,
    pub model: Option<String>,
    pub is_streaming: bool,
    pub max_tokens: Option<u32>,
    // Response
    pub status_code: Option<u16>,
    pub response_headers: HashMap<String, String>,
    pub response_body: Option<String>,
    pub message_id: Option<String>,
    pub stop_reason: Option<String>,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub cache_creation_input_tokens: Option<u32>,
    pub cache_read_input_tokens: Option<u32>,
    // Streaming
    pub sse_events: Vec<SseEvent>,
    pub content_text: Option<String>,
    // Timing
    pub duration_ms: Option<u64>,
    pub time_to_first_token_ms: Option<u64>,
    // Session tracking
    pub session_id: Option<String>,
    // Error
    pub error: Option<String>,
}

impl ProxiedRequest {
    pub fn new(method: &str, path: &str) -> Self {
        Self {
            id: short_id(),
            timestamp: Utc::now(),
            method: method.to_string(),
            path: path.to_string(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseEvent {
    pub event_type: Option<String>,
    pub data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub hook_event_name: String,
    pub session_id: String,
    pub cwd: String,
    pub permission_mode: String,
    pub transcript_path: String,
    pub hook_input: serde_json::Value,
    pub environment_variables: HashMap<String, String>,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl HookEvent {
    pub fn new(hook_event_name: String, session_id: String, cwd: String) -> Self {
        Self {
            id: short_id(),
            timestamp: Utc::now(),
            hook_event_name,
            session_id,
            cwd,
            permission_mode: String::new(),
            transcript_path: String::new(),
            hook_input: serde_json::Value::Null,
            environment_variables: HashMap::new(),
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<serde_json::Value>,
    pub id: Option<serde_json::Value>,
}

// ── Session model ──

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionStatus {
    Recording,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub label: Option<String>,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub request_ids: Vec<String>,
    pub status: SessionStatus,
}

impl Session {
    pub fn new(label: Option<String>) -> Self {
        let label = label.filter(|l| !l.is_empty()).unwrap_or_else(|| {
            Utc::now().format("Recording %Y-%m-%d %H:%M").to_string()
        });
        Self {
            id: short_id(),
            label: Some(label),
            started_at: Utc::now(),
            ended_at: None,
            request_ids: Vec::new(),
            status: SessionStatus::Recording,
        }
    }

    pub fn stop(&mut self) {
        self.ended_at = Some(Utc::now());
        self.status = SessionStatus::Stopped;
    }
}

// ── Provider info (for frontend) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub name: String,
    pub url: String,
    pub has_token: bool,
    pub models: Vec<String>,
}

// ── Upstream info (for frontend) ──

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TierRuleInfo {
    pub keywords: Vec<String>,
    pub provider: String,
    pub model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamInfo {
    pub name: String,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub high: Option<TierRuleInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mid: Option<TierRuleInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub low: Option<TierRuleInfo>,
    pub default_provider: String,
    pub default_model: String,
}

// ── WebSocket message envelope ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum WsMessage {
    NewRequest(ProxiedRequest),
    SseEvent { request_id: String, event: SseEvent },
    RequestUpdated(ProxiedRequest),
    NewHook(HookEvent),
    NewMcp(ProxiedRequest),
    Cleared,
    McpCleared,
    McpConfigChanged { destination_url: Option<String> },
    UpstreamChanged {
        active_upstream: String,
        upstreams: Vec<UpstreamInfo>,
        providers: Vec<ProviderInfo>,
    },
    History { requests: Vec<ProxiedRequest> },
    HookHistory { events: Vec<HookEvent> },
    McpHistory { requests: Vec<ProxiedRequest> },
    SessionStarted(Session),
    SessionStopped(Session),
    SessionUpdated { request_id: String },
    TeeStatusChanged { enabled: bool },
}
