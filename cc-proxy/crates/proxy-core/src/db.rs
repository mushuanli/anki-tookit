use std::sync::Mutex;

use rusqlite::{params, Connection};

use crate::models::{HookEvent, ProxiedRequest, Session, SessionStatus, SseEvent};

/// Thin wrapper around a SQLite connection, providing typed CRUD operations
/// for sessions, requests, SSE events, hooks, and MCP requests.
pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    /// Open (or create) the database at `path` and run migrations.
    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    // ── Schema ──

    fn migrate(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS sessions (
                id          TEXT PRIMARY KEY,
                label       TEXT,
                started_at  TEXT NOT NULL,
                ended_at    TEXT,
                status      TEXT NOT NULL DEFAULT 'Recording'
            );

            CREATE TABLE IF NOT EXISTS requests (
                id              TEXT PRIMARY KEY,
                session_id      TEXT,
                timestamp       TEXT NOT NULL,
                method          TEXT NOT NULL,
                path            TEXT NOT NULL,
                model           TEXT,
                status_code     INTEGER,
                input_tokens    INTEGER,
                output_tokens   INTEGER,
                cache_creation_input_tokens INTEGER,
                cache_read_input_tokens     INTEGER,
                duration_ms     INTEGER,
                ttft_ms         INTEGER,
                stop_reason     TEXT,
                message_id      TEXT,
                error           TEXT,
                request_headers TEXT,
                request_body    TEXT,
                content_text    TEXT,
                is_streaming    INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS sse_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id  TEXT NOT NULL,
                event_type  TEXT,
                data        TEXT,
                seq         INTEGER NOT NULL,
                FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS hook_events (
                id                      TEXT PRIMARY KEY,
                timestamp               TEXT NOT NULL,
                hook_event_name         TEXT NOT NULL,
                session_id              TEXT NOT NULL,
                cwd                     TEXT NOT NULL DEFAULT '',
                permission_mode         TEXT NOT NULL DEFAULT '',
                transcript_path         TEXT NOT NULL DEFAULT '',
                hook_input              TEXT NOT NULL DEFAULT 'null',
                environment_variables   TEXT NOT NULL DEFAULT '{}',
                exit_code               INTEGER NOT NULL DEFAULT 0,
                stdout                  TEXT NOT NULL DEFAULT '',
                stderr                  TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS mcp_requests (
                id              TEXT PRIMARY KEY,
                timestamp       TEXT NOT NULL,
                method          TEXT NOT NULL DEFAULT '',
                model           TEXT NOT NULL DEFAULT '',
                status_code     INTEGER,
                request_body    TEXT,
                response_body   TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_requests_session ON requests(session_id);
            CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp);
            CREATE INDEX IF NOT EXISTS idx_sse_request ON sse_events(request_id);
            CREATE INDEX IF NOT EXISTS idx_hooks_timestamp ON hook_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_mcp_timestamp ON mcp_requests(timestamp);
            ",
        )?;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════
    // Sessions
    // ═══════════════════════════════════════════════════════════════

    pub fn insert_session(&self, session: &Session) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sessions (id, label, started_at, ended_at, status) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                session.id,
                session.label,
                session.started_at.to_rfc3339(),
                session.ended_at.map(|t| t.to_rfc3339()),
                session.status.as_str(),
            ],
        )?;
        Ok(())
    }

    /// Ensure a session exists for the given id (auto-created from traffic).
    /// If it already exists, do nothing.
    pub fn ensure_session(&self, id: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO sessions (id, label, started_at, status) VALUES (?1, ?2, ?3, 'Recording')",
            params![id, id, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn rename_session(&self, id: &str, label: &str) -> Result<bool, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE sessions SET label = ?1 WHERE id = ?2",
            params![label, id],
        )?;
        Ok(n > 0)
    }

    pub fn delete_session(&self, id: &str) -> Result<bool, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        // FK cascade will NULL session_id in requests and delete sse_events
        let n = conn.execute("DELETE FROM sessions WHERE id = ?1", params![id])?;
        Ok(n > 0)
    }

    pub fn get_session(&self, id: &str) -> Result<Option<Session>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, label, started_at, ended_at, status FROM sessions WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], |row| row_to_session(row))?;
        match rows.next() {
            Some(Ok(mut s)) => {
                s.request_ids = self.get_session_request_ids(&conn, &s.id)?;
                Ok(Some(s))
            }
            _ => Ok(None),
        }
    }

    fn get_session_request_ids(&self, conn: &Connection, session_id: &str) -> Result<Vec<String>, rusqlite::Error> {
        let mut stmt = conn.prepare(
            "SELECT id FROM requests WHERE session_id = ?1 ORDER BY timestamp ASC",
        )?;
        let ids = stmt
            .query_map(params![session_id], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(ids)
    }

    pub fn list_sessions(&self, query: Option<&str>) -> Result<Vec<Session>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let pattern = query.map(|q| format!("%{}%", q));
        let (sql, has_param) = if pattern.is_some() {
            ("SELECT id, label, started_at, ended_at, status FROM sessions WHERE id LIKE ?1 OR label LIKE ?1 ORDER BY started_at DESC", true)
        } else {
            ("SELECT id, label, started_at, ended_at, status FROM sessions ORDER BY started_at DESC", false)
        };
        let mut stmt = conn.prepare(sql)?;
        let rows: Vec<Session> = if has_param {
            stmt.query_map(params![pattern], |row| row_to_session(row))?
                .filter_map(|r| r.ok())
                .collect()
        } else {
            stmt.query_map([], |row| row_to_session(row))?
                .filter_map(|r| r.ok())
                .collect()
        };

        let mut sessions = rows;
        for s in &mut sessions {
            s.request_ids = self.get_session_request_ids(&conn, &s.id)?;
        }
        Ok(sessions)
    }

    // ═══════════════════════════════════════════════════════════════
    // Requests
    // ═══════════════════════════════════════════════════════════════

    pub fn insert_request(&self, req: &ProxiedRequest) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO requests (id, session_id, timestamp, method, path, model,
             status_code, input_tokens, output_tokens, cache_creation_input_tokens,
             cache_read_input_tokens, duration_ms, ttft_ms, stop_reason, message_id,
             error, request_headers, request_body, content_text, is_streaming)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
            params![
                req.id,
                req.session_id,
                req.timestamp.to_rfc3339(),
                req.method,
                req.path,
                req.model,
                req.status_code,
                req.input_tokens,
                req.output_tokens,
                req.cache_creation_input_tokens,
                req.cache_read_input_tokens,
                req.duration_ms.map(|v| v as i64),
                req.time_to_first_token_ms.map(|v| v as i64),
                req.stop_reason,
                req.message_id,
                req.error,
                serde_json::to_string(&req.request_headers).ok(),
                req.request_body,
                req.content_text,
                req.is_streaming as i32,
            ],
        )?;
        Ok(())
    }

    pub fn update_request_response(&self, req: &ProxiedRequest) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE requests SET status_code=?1, input_tokens=?2, output_tokens=?3,
             cache_creation_input_tokens=?4, cache_read_input_tokens=?5,
             duration_ms=?6, ttft_ms=?7, stop_reason=?8, message_id=?9,
             error=?10, content_text=?11, model=?12
             WHERE id=?13",
            params![
                req.status_code,
                req.input_tokens,
                req.output_tokens,
                req.cache_creation_input_tokens,
                req.cache_read_input_tokens,
                req.duration_ms.map(|v| v as i64),
                req.time_to_first_token_ms.map(|v| v as i64),
                req.stop_reason,
                req.message_id,
                req.error,
                req.content_text,
                req.model,
                req.id,
            ],
        )?;
        Ok(())
    }

    pub fn get_request(&self, id: &str) -> Result<Option<ProxiedRequest>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(&request_select_sql(false))?;
        let mut rows = stmt.query_map(params![id], |row| row_to_request(row))?;
        match rows.next() {
            Some(Ok(r)) => Ok(Some(r)),
            _ => Ok(None),
        }
    }

    pub fn list_requests(
        &self,
        session_id: Option<&str>,
        query: Option<&str>,
        from: Option<&str>,
        to: Option<&str>,
        limit: Option<i64>,
    ) -> Result<Vec<ProxiedRequest>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut sql = request_select_sql(true);
        let mut conditions = Vec::new();
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(sid) = session_id {
            conditions.push(format!("session_id = ?{}", param_values.len() + 1));
            param_values.push(Box::new(sid.to_string()));
        }
        if let Some(q) = query {
            conditions.push(format!(
                "(path LIKE ?{} OR model LIKE ?{} OR request_body LIKE ?{})",
                param_values.len() + 1,
                param_values.len() + 2,
                param_values.len() + 3
            ));
            let pattern = format!("%{}%", q);
            param_values.push(Box::new(pattern.clone()));
            param_values.push(Box::new(pattern.clone()));
            param_values.push(Box::new(pattern));
        }
        if let Some(f) = from {
            conditions.push(format!("timestamp >= ?{}", param_values.len() + 1));
            param_values.push(Box::new(f.to_string()));
        }
        if let Some(t) = to {
            conditions.push(format!("timestamp <= ?{}", param_values.len() + 1));
            param_values.push(Box::new(t.to_string()));
        }

        if !conditions.is_empty() {
            sql.push_str(" AND ");
            sql.push_str(&conditions.join(" AND "));
        }
        sql.push_str(" ORDER BY timestamp DESC");

        if let Some(l) = limit {
            sql.push_str(&format!(" LIMIT {}", l));
        }

        let mut stmt = conn.prepare(&sql)?;
        let param_refs: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();
        let rows = stmt.query_map(param_refs.as_slice(), |row| row_to_request(row))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn delete_request(&self, id: &str) -> Result<bool, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute("DELETE FROM requests WHERE id = ?1", params![id])?;
        Ok(n > 0)
    }

    pub fn delete_requests(&self, ids: &[String]) -> Result<usize, rusqlite::Error> {
        if ids.is_empty() {
            return Ok(0);
        }
        let conn = self.conn.lock().unwrap();
        let placeholders: Vec<String> = ids.iter().enumerate().map(|(i, _)| format!("?{}", i + 1)).collect();
        let sql = format!("DELETE FROM requests WHERE id IN ({})", placeholders.join(","));
        let param_refs: Vec<&dyn rusqlite::types::ToSql> = ids
            .iter()
            .map(|id| id as &dyn rusqlite::types::ToSql)
            .collect();
        let n = conn.execute(&sql, param_refs.as_slice())?;
        Ok(n)
    }

    pub fn count_requests(&self) -> Result<i64, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM requests", [], |row| row.get(0))
    }

    pub fn clear_requests(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch("DELETE FROM sse_events; DELETE FROM requests;")?;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════
    // SSE Events
    // ═══════════════════════════════════════════════════════════════

    pub fn insert_sse_events(&self, request_id: &str, events: &[SseEvent]) -> Result<(), rusqlite::Error> {
        if events.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "INSERT INTO sse_events (request_id, event_type, data, seq) VALUES (?1, ?2, ?3, ?4)",
        )?;
        for (i, ev) in events.iter().enumerate() {
            stmt.execute(params![request_id, ev.event_type, ev.data, i as i64])?;
        }
        Ok(())
    }

    pub fn get_sse_events(&self, request_id: &str) -> Result<Vec<SseEvent>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT event_type, data FROM sse_events WHERE request_id = ?1 ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map(params![request_id], |row| {
            Ok(SseEvent {
                event_type: row.get(0)?,
                data: row.get(1)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    // ═══════════════════════════════════════════════════════════════
    // Hook Events
    // ═══════════════════════════════════════════════════════════════

    pub fn insert_hook(&self, hook: &HookEvent) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO hook_events (id, timestamp, hook_event_name, session_id,
             cwd, permission_mode, transcript_path, hook_input, environment_variables,
             exit_code, stdout, stderr)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                hook.id,
                hook.timestamp.to_rfc3339(),
                hook.hook_event_name,
                hook.session_id,
                hook.cwd,
                hook.permission_mode,
                hook.transcript_path,
                hook.hook_input.to_string(),
                serde_json::to_string(&hook.environment_variables).unwrap_or_default(),
                hook.exit_code,
                hook.stdout,
                hook.stderr,
            ],
        )?;
        Ok(())
    }

    pub fn list_hooks(&self) -> Result<Vec<HookEvent>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, hook_event_name, session_id, cwd, permission_mode,
             transcript_path, hook_input, environment_variables, exit_code, stdout, stderr
             FROM hook_events ORDER BY timestamp DESC LIMIT 1000",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(HookEvent {
                id: row.get(0)?,
                timestamp: parse_dt(&row.get::<_, String>(1)?),
                hook_event_name: row.get(2)?,
                session_id: row.get(3)?,
                cwd: row.get(4)?,
                permission_mode: row.get(5)?,
                transcript_path: row.get(6)?,
                hook_input: serde_json::from_str(&row.get::<_, String>(7)?).unwrap_or_default(),
                environment_variables: serde_json::from_str(
                    &row.get::<_, String>(8)?,
                )
                .unwrap_or_default(),
                exit_code: row.get(9)?,
                stdout: row.get(10)?,
                stderr: row.get(11)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn clear_hooks(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM hook_events", [])?;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════
    // MCP Requests
    // ═══════════════════════════════════════════════════════════════

    pub fn insert_mcp(&self, req: &ProxiedRequest) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO mcp_requests (id, timestamp, method, model, status_code, request_body, response_body)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                req.id,
                req.timestamp.to_rfc3339(),
                req.method,
                req.model.as_deref().unwrap_or(""),
                req.status_code,
                req.request_body,
                req.response_body,
            ],
        )?;
        Ok(())
    }

    pub fn list_mcp(&self) -> Result<Vec<ProxiedRequest>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, method, model, status_code, request_body, response_body
             FROM mcp_requests ORDER BY timestamp DESC LIMIT 500",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ProxiedRequest {
                id: row.get(0)?,
                timestamp: parse_dt(&row.get::<_, String>(1)?),
                method: row.get(2)?,
                path: String::new(),
                model: row.get(3)?,
                status_code: row.get(4)?,
                request_body: row.get(5)?,
                response_body: row.get(6)?,
                ..Default::default()
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn clear_mcp(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM mcp_requests", [])?;
        Ok(())
    }
}

// ── Helpers ──

fn request_select_sql(with_where: bool) -> String {
    let mut s = String::from(
        "SELECT id, session_id, timestamp, method, path, model, status_code,
         input_tokens, output_tokens, cache_creation_input_tokens, cache_read_input_tokens,
         duration_ms, ttft_ms, stop_reason, message_id, error, request_headers,
         request_body, content_text, is_streaming
         FROM requests",
    );
    if with_where {
        s.push_str(" WHERE 1=1");
    }
    s
}

fn row_to_request(row: &rusqlite::Row) -> rusqlite::Result<ProxiedRequest> {
    let headers_str: Option<String> = row.get(16)?;
    Ok(ProxiedRequest {
        id: row.get(0)?,
        session_id: row.get(1)?,
        timestamp: parse_dt(&row.get::<_, String>(2)?),
        method: row.get(3)?,
        path: row.get(4)?,
        model: row.get(5)?,
        status_code: row.get(6)?,
        input_tokens: row.get(7)?,
        output_tokens: row.get(8)?,
        cache_creation_input_tokens: row.get(9)?,
        cache_read_input_tokens: row.get(10)?,
        duration_ms: row.get::<_, Option<i64>>(11)?.map(|v| v as u64),
        time_to_first_token_ms: row.get::<_, Option<i64>>(12)?.map(|v| v as u64),
        stop_reason: row.get(13)?,
        message_id: row.get(14)?,
        error: row.get(15)?,
        request_headers: headers_str
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default(),
        request_body: row.get(17)?,
        content_text: row.get(18)?,
        is_streaming: row.get::<_, i32>(19)? != 0,
        ..Default::default()
    })
}

fn parse_dt(s: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now())
}

fn parse_status(s: &str) -> SessionStatus {
    match s {
        "Recording" => SessionStatus::Recording,
        _ => SessionStatus::Stopped,
    }
}

fn row_to_session(row: &rusqlite::Row) -> rusqlite::Result<Session> {
    Ok(Session {
        id: row.get(0)?,
        label: row.get(1)?,
        started_at: parse_dt(&row.get::<_, String>(2)?),
        ended_at: row.get::<_, Option<String>>(3)?.map(|s| parse_dt(&s)),
        status: parse_status(&row.get::<_, String>(4)?),
        request_ids: Vec::new(),
    })
}

// ── SessionStatus helper ──

impl SessionStatus {
    fn as_str(&self) -> &'static str {
        match self {
            SessionStatus::Recording => "Recording",
            SessionStatus::Stopped => "Stopped",
        }
    }
}
