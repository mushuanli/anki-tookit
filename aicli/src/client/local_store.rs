// src/client/local_store.rs

use crate::common::protocol::{format_chat_log, parse_chat_file, truncate_after_last_user}; // <-- Add truncate helper
use crate::common::types::{ChatLog, Interaction};
use crate::error::{AppError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;
use super::cli::{CLIENT_DATA_DIR, CLIENT_INDEX_PATH};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum SyncStatus {
    Local,    // Only exists locally, never sent
    Modified, // Modified locally, not yet synced
    Pending,  // Sent to server, waiting for response
    Processing, // Server is currently processing
    Done,     // Server successfully completed, waiting for client to fetch result
    Failed,   // Server failed to process, with an error message
    Finish,   // Client has fetched the result (Done or Failed) and updated local state
    Conflict, // Remote has changed since last sync (future enhancement)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LocalSessionInfo {
    pub uuid: Uuid,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>, // Important new field
    pub sync_status: SyncStatus,
    pub remote_status: Option<String>,
}

pub struct LocalStore {
    sessions_dir: PathBuf,
    index_path: PathBuf,
    // MODIFIED: Make index public so the TUI can update it directly during a light refresh
    pub index: HashMap<Uuid, LocalSessionInfo>,
}

impl LocalStore {
    /// Loads the session index from disk.
    pub fn load() -> Result<Self> {
        let sessions_dir = PathBuf::from(CLIENT_DATA_DIR);
        let index_path = PathBuf::from(CLIENT_INDEX_PATH);

        let index_content = fs::read_to_string(&index_path).map_err(|e| AppError::IoWithContext {
            context: format!("Failed to read index file '{}'. Did you run 'client init'?", index_path.display()),
            source: e,
        })?;

        let index: HashMap<Uuid, LocalSessionInfo> = serde_json::from_str(&index_content)?;
        Ok(Self { sessions_dir, index_path, index })
    }
    
    /// Saves the current in-memory index to the index.json file.
    pub fn save_index(&self) -> Result<()> {
        let content = serde_json::to_string_pretty(&self.index)?;
        fs::write(&self.index_path, content)?;
        Ok(())
    }

    /// Creates a new session template for the 'new' command.
    pub fn create_new_template(&mut self, title: String) -> Result<ChatLog> {
        let mut log = ChatLog::new(title);
        // Add a placeholder user prompt.
        log.interactions.push(Interaction::User {
            content: "Replace this with your prompt.".to_string(),
            created_at: Utc::now(),
        });

        // The status starts as Local.
        self.save_session(&log, SyncStatus::Local)?;
        self.save_index()?;
        Ok(log)
    }

    /// Appends a prompt for the 'append' command.
    pub fn append_prompt(&mut self, uuid: Uuid, prompt: String) -> Result<ChatLog> {
        let mut log = self.get_session(uuid)?;
        log.interactions.push(Interaction::User { content: prompt, created_at: Utc::now() });
        log.updated_at = Utc::now(); // Explicitly update timestamp
        // Status becomes Modified.
        self.save_session(&log, SyncStatus::Modified)?;
        self.save_index()?;
        Ok(())
    }

    /// Prepares a session for the 'run' command by clearing trailing AI responses.
    pub fn prepare_for_run(&mut self, uuid: Uuid) -> Result<ChatLog> {
        let mut log = self.get_session(uuid)?;
        truncate_after_last_user(&mut log);
        log.updated_at = Utc::now(); // Truncating is a change, update timestamp

        // Save the cleaned version, marking it as Modified.
        self.save_session(&log, SyncStatus::Modified)?;
        Ok(log)
    }

    /// Registers a session file that exists but is not in the index.
    pub fn register_external_session(&mut self, log: &ChatLog) -> Result<()> {
        let now = Utc::now();
        if !self.index.contains_key(&log.uuid) {
            let info = LocalSessionInfo {
                uuid: log.uuid,
                title: log.title.clone(),
                created_at: log.get_creation_time(),
                modified_at: now,
                sync_status: SyncStatus::Local, // Treat it as a new local file
                remote_status: None,
            };
            self.index.insert(log.uuid, info);
            self.save_index()?;
        }
        Ok(())
    }

    /// Saves a ChatLog to a .md file and updates the in-memory index.
    pub fn save_session(&mut self, log: &ChatLog, new_status: SyncStatus) -> Result<()> {
        let content = format_chat_log(log);
        let file_path = self.sessions_dir.join(format!("{}.md", log.uuid));
        fs::write(&file_path, content)?;

        let info = self.index.entry(log.uuid).or_insert_with(|| LocalSessionInfo {
            uuid: log.uuid,
            title: log.title.clone(),
            created_at: log.get_creation_time(),
            updated_at: log.updated_at,
            sync_status: new_status.clone(),
            remote_status: None,
        });

        // Update fields for existing entries
        info.title = log.title.clone();
        info.updated_at = log.updated_at; // CRITICAL: Update the index timestamp
        info.sync_status = new_status;

        self.save_index()?;
        Ok(())
    }

    /// Reads the content of a session's .md file.
    pub fn get_session_content(&self, uuid: Uuid) -> Result<String> {
        if !self.index.contains_key(&uuid) {
            return Err(AppError::ParseError(format!("Session with UUID '{}' not found in local index.", uuid)));
        }
        let file_path = self.sessions_dir.join(format!("{}.md", uuid));
        fs::read_to_string(&file_path).map_err(|e| AppError::IoWithContext {
            context: format!("Failed to read session file '{}'", file_path.display()),
            source: e,
        })
    }

    /// Gets a full ChatLog object from a local session file.
    pub fn get_session(&self, uuid: Uuid) -> Result<ChatLog> {
        let content = self.get_session_content(uuid)?;
        parse_chat_file(&content)
    }

    /// Lists all sessions from the in-memory index.
    pub fn list_sessions(&self) -> Vec<&LocalSessionInfo> {
        let mut sessions: Vec<_> = self.index.values().collect();
        // Sort by creation date, newest first
        sessions.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        sessions
    }

    /// Deletes a session from the index and removes its .md file.
    pub fn delete_session(&mut self, uuid: Uuid) -> Result<()> {
        self.index.remove(&uuid);
        let file_path = self.sessions_dir.join(format!("{}.md", uuid));
        if file_path.exists() {
            // Ignore error if file doesn't exist, as it might have been deleted already.
            fs::remove_file(file_path).ok();
        }
        self.save_index()?;
        Ok(())
    }
    
    /// Updates the local session based on content and metadata from the server.
    pub fn update_from_remote(&mut self, content: &str, remote_task: &super::network::RemoteTask) -> Result<()> {
        let mut log = parse_chat_file(content)?;
        log.updated_at = remote_task.updated_at.unwrap_or_else(Utc::now);

        // --- REFACTORED LOGIC ---
        // Determine the new local status based on the AUTHORITATIVE remote status.
        let new_local_status = match remote_task.status.as_str() {
            "completed" => SyncStatus::Finish,
            "failed" => SyncStatus::Failed,
            _ => SyncStatus::Pending,
        };
        
        self.save_session(&log, new_local_status)?;
        Ok(())
    }

    /// (NEW) `update_from_remote_list` is for metadata sync (`synclist` command)
    pub fn update_from_remote_list(&mut self, remote_tasks: Vec<super::network::RemoteTask>) -> Result<()> {
        let mut changed = false;
        for task in remote_tasks {
            if let Some(info) = self.index.get_mut(&task.uuid) {
                // If local is newer, don't let metadata sync overwrite our `Modified` status
                if info.updated_at > task.updated_at.unwrap_or_default() {
                    continue;
                }
                
                // Update remote status string for display
                let new_remote_status_str = if let Some(err) = &task.error_message {
                    format!("failed: {}", err)
                } else {
                    task.status.clone()
                };
                if info.remote_status.as_deref() != Some(&new_remote_status_str) {
                    info.remote_status = Some(new_remote_status_str);
                    changed = true;
                }

                // Update local sync status enum
                let new_sync_status = match task.status.as_str() {
                    "pending" => SyncStatus::Pending, "processing" => SyncStatus::Processing,
                    "completed" => SyncStatus::Done, "failed" => SyncStatus::Failed,
                    _ => info.sync_status.clone(),
                };
                if info.sync_status != new_sync_status {
                    info.sync_status = new_sync_status;
                    changed = true;
                }
            }
        }
        if changed { self.save_index()?; }
        Ok(())
    }

    /// Updates just the status of a session in the index.
    pub fn update_session_status(&mut self, uuid: Uuid, sync_status: SyncStatus, remote_status: Option<String>) -> Result<()> {
        if let Some(info) = self.index.get_mut(&uuid) {
            info.sync_status = sync_status;
            if let Some(rs) = remote_status {
                info.remote_status = Some(rs);
            }
            self.save_index()?;
        } else {
            return Err(AppError::ParseError(format!("Cannot update status for non-existent session {}", uuid)));
        }
        Ok(())
    }
}