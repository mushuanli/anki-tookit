use crate::models::{ProxiedRequest, Session};
use chrono::Utc;
use serde_json::{Map, Value};

/// Export a session as JSON (full structured data, re-importable).
pub fn export_json(session: &Session, requests: &[ProxiedRequest]) -> Value {
    let mut map = Map::new();
    map.insert("exported_at".into(), Value::String(Utc::now().to_rfc3339()));
    map.insert("version".into(), Value::String(env!("CARGO_PKG_VERSION").into()));
    map.insert(
        "session".into(),
        serde_json::to_value(session).unwrap_or_default(),
    );
    map.insert(
        "requests".into(),
        serde_json::to_value(requests).unwrap_or_default(),
    );
    Value::Object(map)
}

/// Export a session as HAR (HTTP Archive 1.2) — compatible with Chrome DevTools HAR Viewer.
pub fn export_har(_session: &Session, requests: &[ProxiedRequest]) -> Value {
    let entries: Vec<Value> = requests
        .iter()
        .map(|r| {
            let req_headers: Vec<Value> = r
                .request_headers
                .iter()
                .map(|(k, v)| {
                    serde_json::json!({ "name": k, "value": v })
                })
                .collect();
            let res_headers: Vec<Value> = r
                .response_headers
                .iter()
                .map(|(k, v)| {
                    serde_json::json!({ "name": k, "value": v })
                })
                .collect();

            serde_json::json!({
                "startedDateTime": r.timestamp.to_rfc3339(),
                "time": r.duration_ms.unwrap_or(0),
                "request": {
                    "method": r.method,
                    "url": format!("https://api.anthropic.com{}", r.path),
                    "httpVersion": "HTTP/1.1",
                    "headers": req_headers,
                    "queryString": [],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": -1,
                    "postData": r.request_body.as_ref().map(|b| {
                        serde_json::json!({
                            "mimeType": "application/json",
                            "text": b
                        })
                    })
                },
                "response": {
                    "status": r.status_code.unwrap_or(0),
                    "statusText": status_text(r.status_code),
                    "httpVersion": "HTTP/1.1",
                    "headers": res_headers,
                    "cookies": [],
                    "content": {
                        "size": r.response_body.as_ref().map(|b| b.len()).unwrap_or(0),
                        "mimeType": if r.is_streaming { "text/event-stream" } else { "application/json" },
                        "text": r.response_body
                    },
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": -1
                },
                "cache": {},
                "timings": {
                    "send": 0,
                    "wait": r.time_to_first_token_ms.unwrap_or(0),
                    "receive": 0
                }
            })
        })
        .collect();

    serde_json::json!({
        "log": {
            "version": "1.2",
            "creator": {
                "name": "CodingAgentExplorer",
                "version": env!("CARGO_PKG_VERSION")
            },
            "entries": entries
        }
    })
}

/// Export a session as readable Markdown.
pub fn export_markdown(session: &Session, requests: &[ProxiedRequest]) -> String {
    let total_tokens_in: u64 = requests.iter().filter_map(|r| r.input_tokens).map(|t| t as u64).sum();
    let total_tokens_out: u64 = requests
        .iter()
        .filter_map(|r| r.output_tokens)
        .map(|t| t as u64)
        .sum();
    let total_duration_ms: u64 = requests.iter().filter_map(|r| r.duration_ms).sum();
    let duration = format_duration(total_duration_ms);

    let mut md = String::new();
    md.push_str(&format!("# Session: {}\n", session.id));
    if let Some(ref label) = session.label {
        md.push_str(&format!("**Label**: {}\n", label));
    }
    md.push_str(&format!(
        "**Duration**: {} | **Requests**: {} | **Tokens**: {} in / {} out\n\n",
        duration,
        requests.len(),
        total_tokens_in,
        total_tokens_out
    ));
    md.push_str("---\n\n");

    for (i, req) in requests.iter().enumerate() {
        let status = req
            .status_code
            .map(|s| format!("{} {}", s, status_text(Some(s))))
            .unwrap_or_else(|| "pending".to_string());
        let dur = req
            .duration_ms
            .map(|d| format_duration(d))
            .unwrap_or_else(|| "—".to_string());

        md.push_str(&format!(
            "## Request #{} — {} {} — {} — {}\n",
            i + 1,
            req.method,
            req.path,
            status,
            dur
        ));
        if let Some(ref model) = req.model {
            md.push_str(&format!(
                "**Model**: {} | **Streaming**: {} | **Tokens**: {} in / {} out\n\n",
                model,
                req.is_streaming,
                req.input_tokens.unwrap_or(0),
                req.output_tokens.unwrap_or(0)
            ));
        }

        // Request body
        if let Some(ref body) = req.request_body {
            md.push_str("### Request Body\n\n```json\n");
            md.push_str(&truncate(body, 2000));
            md.push_str("\n```\n\n");
        }

        // Response
        if let Some(ref body) = req.response_body {
            md.push_str("### Response\n\n```json\n");
            md.push_str(&truncate(body, 2000));
            md.push_str("\n```\n\n");
        }

        // SSE events
        if !req.sse_events.is_empty() {
            md.push_str("### SSE Events\n\n");
            md.push_str("| # | Type | Data |\n");
            md.push_str("|---|------|------|\n");
            for (j, ev) in req.sse_events.iter().enumerate() {
                let ev_type = ev.event_type.as_deref().unwrap_or("—");
                let data = ev
                    .data
                    .as_deref()
                    .map(|d| truncate(d, 80))
                    .unwrap_or_else(|| "—".to_string());
                md.push_str(&format!(
                    "| {} | {} | {} |\n",
                    j + 1,
                    ev_type,
                    data.replace('\n', " ")
                ));
            }
            md.push('\n');
        }

        // Error
        if let Some(ref err) = req.error {
            md.push_str(&format!("**Error**: {}\n\n", err));
        }

        md.push_str("---\n\n");
    }

    md
}

fn status_text(code: Option<u16>) -> &'static str {
    match code {
        Some(200) => "OK",
        Some(201) => "Created",
        Some(204) => "No Content",
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

fn format_duration(ms: u64) -> String {
    let secs = ms / 1000;
    let mins = secs / 60;
    let hours = mins / 60;
    if hours > 0 {
        format!(
            "{:02}:{:02}:{:02}.{:03}",
            hours,
            mins % 60,
            secs % 60,
            ms % 1000
        )
    } else if mins > 0 {
        format!("{:02}:{:02}.{:03}", mins, secs % 60, ms % 1000)
    } else {
        format!("{}.{:03}s", secs, ms % 1000)
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}... (truncated, {} total chars)", &s[..max_len], s.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ProxiedRequest;

    fn sample_request() -> ProxiedRequest {
        let mut req = ProxiedRequest::new("POST", "/v1/messages");
        req.model = Some("claude-sonnet-4-6".into());
        req.is_streaming = true;
        req.status_code = Some(200);
        req.input_tokens = Some(500);
        req.output_tokens = Some(300);
        req.duration_ms = Some(1234);
        req.request_body = Some(r#"{"model":"claude-sonnet-4-6","messages":[]}"#.into());
        req.response_body = Some(r#"{"id":"msg_123","type":"message"}"#.into());
        req
    }

    #[test]
    fn export_json_has_expected_keys() {
        let session = Session::new(Some("test".into()));
        let json = export_json(&session, &[sample_request()]);
        assert!(json.get("exported_at").is_some());
        assert!(json.get("session").is_some());
        assert!(json.get("requests").is_some());
    }

    #[test]
    fn export_har_is_valid() {
        let session = Session::new(Some("har test".into()));
        let har = export_har(&session, &[sample_request()]);
        let log = har.get("log").expect("log missing");
        let entries = log.get("entries").expect("entries missing");
        assert_eq!(entries.as_array().unwrap().len(), 1);
    }

    #[test]
    fn export_markdown_has_content() {
        let session = Session::new(Some("md test".into()));
        let md = export_markdown(&session, &[sample_request()]);
        assert!(md.contains("# Session:"));
        assert!(md.contains("claude-sonnet-4-6"));
        assert!(md.contains("POST"));
    }
}
