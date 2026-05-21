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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub content_text: Option<String>, // merged content_block_delta text, for display
    // Timing
    pub duration_ms: Option<u64>,
    pub time_to_first_token_ms: Option<u64>,
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
            request_headers: HashMap::new(),
            request_body: None,
            model: None,
            is_streaming: false,
            max_tokens: None,
            status_code: None,
            response_headers: HashMap::new(),
            response_body: None,
            message_id: None,
            stop_reason: None,
            input_tokens: None,
            output_tokens: None,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
            sse_events: Vec::new(),
            content_text: None,
            duration_ms: None,
            time_to_first_token_ms: None,
            error: None,
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

// ── Session model for request recording + export ──

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
        Self {
            id: short_id(),
            label,
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

// ── Model name translation ──

/// Translate a Claude model name to the upstream's equivalent using a model map.
///
/// Matching strategy (in order):
/// 1. Exact match on the full model name
/// 2. Strip `[1m]` suffix → exact match on the base name
/// 3. Longest prefix match (handles dated versions like `claude-sonnet-4-6-20250514`)
/// 4. If input had `[1m]` and the target doesn't, append `[1m]` to the result
/// 5. Fallback: return the original model name unchanged
pub fn translate_model(model: &str, model_map: &HashMap<String, String>) -> String {
    if model_map.is_empty() {
        return model.to_string();
    }

    // 1. Exact match
    if let Some(mapped) = model_map.get(model) {
        return mapped.clone();
    }

    // 2. Strip [1m] suffix and try exact match
    let has_1m = model.ends_with("[1m]");
    let base = if has_1m {
        model.strip_suffix("[1m]").unwrap()
    } else {
        model
    };

    if let Some(mapped) = model_map.get(base) {
        if has_1m && !mapped.ends_with("[1m]") {
            return format!("{}[1m]", mapped);
        }
        return mapped.clone();
    }

    // 3. Longest prefix match (for dated versions)
    let mut best: Option<(&String, &String)> = None;
    for (pattern, target) in model_map {
        if base.starts_with(pattern.as_str()) {
            match best {
                Some((ref p, _)) if pattern.len() <= p.len() => {}
                _ => best = Some((pattern, target)),
            }
        }
    }

    if let Some((_, target)) = best {
        if has_1m && !target.ends_with("[1m]") {
            return format!("{}[1m]", target);
        }
        return target.clone();
    }

    // 4. No match — return original
    model.to_string()
}

#[cfg(test)]
mod translate_tests {
    use super::*;

    fn sample_map() -> HashMap<String, String> {
        HashMap::from([
            ("claude-sonnet-4-6".into(), "deepseek-v4-pro".into()),
            ("claude-opus-4-6".into(), "deepseek-v4-pro[1m]".into()),
            ("claude-haiku-4-5".into(), "deepseek-chat".into()),
        ])
    }

    #[test]
    fn exact_match() {
        let map = sample_map();
        assert_eq!(translate_model("claude-sonnet-4-6", &map), "deepseek-v4-pro");
    }

    #[test]
    fn prefix_match_dated_version() {
        let map = sample_map();
        assert_eq!(
            translate_model("claude-sonnet-4-6-20250514", &map),
            "deepseek-v4-pro"
        );
    }

    #[test]
    fn prefix_match_dated_opus() {
        let map = sample_map();
        assert_eq!(
            translate_model("claude-opus-4-6-20250514", &map),
            "deepseek-v4-pro[1m]"
        );
    }

    #[test]
    fn exact_match_with_1m() {
        let map = sample_map();
        assert_eq!(
            translate_model("claude-sonnet-4-6[1m]", &map),
            "deepseek-v4-pro[1m]"
        );
    }

    #[test]
    fn prefix_match_dated_with_1m() {
        let map = sample_map();
        assert_eq!(
            translate_model("claude-sonnet-4-6-20250514[1m]", &map),
            "deepseek-v4-pro[1m]"
        );
    }

    #[test]
    fn haiku_exact() {
        let map = sample_map();
        assert_eq!(
            translate_model("claude-haiku-4-5-20251001", &map),
            "deepseek-chat"
        );
    }

    #[test]
    fn no_match_returns_original() {
        let map = sample_map();
        assert_eq!(
            translate_model("gpt-4-turbo", &map),
            "gpt-4-turbo"
        );
    }

    #[test]
    fn empty_map_returns_original() {
        let map = HashMap::new();
        assert_eq!(
            translate_model("claude-sonnet-4-6", &map),
            "claude-sonnet-4-6"
        );
    }

    #[test]
    fn opus_dated_with_1m_target_already_has_1m() {
        // Input has [1m], target already has [1m] → no double append
        let map = sample_map();
        assert_eq!(
            translate_model("claude-opus-4-6-20250514[1m]", &map),
            "deepseek-v4-pro[1m]"
        );
    }

    #[test]
    fn longest_prefix_wins_over_short() {
        let mut map = sample_map();
        map.insert("claude-sonnet".into(), "wrong-model".into());
        assert_eq!(
            translate_model("claude-sonnet-4-6-20250514", &map),
            "deepseek-v4-pro"
        );
    }
}

// ── Upstream info (for frontend) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamInfo {
    pub name: String,
    pub url: String,
    pub active: bool,
    pub has_token: bool,
    pub model_map: HashMap<String, String>,
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
        active_url: String,
        upstreams: Vec<UpstreamInfo>,
    },
    History { requests: Vec<ProxiedRequest> },
    HookHistory { events: Vec<HookEvent> },
    McpHistory { requests: Vec<ProxiedRequest> },
    SessionStarted(Session),
    SessionStopped(Session),
    SessionUpdated { request_id: String },
    TeeStatusChanged { enabled: bool },
}
