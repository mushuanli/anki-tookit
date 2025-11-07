// src/client/actions.rs

use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use ratatui_textarea::TextArea;
use std::cmp::Ordering;

use crate::error::{Result, AppError};
use crate::common::protocol::{format_chat_log, parse_chat_file};
use crate::common::types::ChatLog;
use super::network::NetworkClient;
use super::tui::app::{App, AppMode};
use super::tui::action::Action;
use super::local_store::SyncStatus;
use super::cli::{SERVER_ADDR, CLIENT_USERNAME, USER_PRIVATE_KEY_PATH};

/// Handles actions that require network communication.
/// Each match arm is self-contained and responsible for its own network connection.
pub async fn handle_network_action(
    action: Action,
    app: Arc<Mutex<App<'static>>>,
    // The tx is for sending follow-up actions, but we're not using it yet.
    _tx: mpsc::UnboundedSender<Action>,
) -> Result<()> {
    log::info!("Handling network action: {:?}", action);

    match action {
        Action::Refresh => {
            let mut client = NetworkClient::connect(&SERVER_ADDR, &CLIENT_USERNAME, USER_PRIVATE_KEY_PATH).await?;
            
            // After connection, update the models in the app state
            app.lock().await.set_models(client.models.clone(), &client.default_model);
            
            let remote_tasks = client.list_tasks().await?;
            let mut app_lock = app.lock().await;
            app_lock.status_message = Some(format!("Found {} remote tasks. Syncing metadata...", remote_tasks.len()));
            
            // Delegate metadata merging to the store
            app_lock.store.update_from_remote_list(remote_tasks)?;
            
            app_lock.reload_sessions();
            app_lock.status_message = Some("Metadata sync complete.".into());
            log::info!("Metadata sync completed");
        }

        Action::SendNewTask(log) => {
            let mut client = NetworkClient::connect(&SERVER_ADDR, &CLIENT_USERNAME, USER_PRIVATE_KEY_PATH).await?;
            let content = format_chat_log(&log);
            
            // Save locally, send, then update status
            {
                let mut app_lock = app.lock().await;
                app_lock.store.save_session(&log, SyncStatus::Local)?;
                app_lock.store.save_index()?;
            }
            client.execute_chat(&content).await?;
            {
                let mut app_lock = app.lock().await;
                app_lock.store.update_session_status(log.uuid, SyncStatus::Pending, None)?;
                app_lock.reload_sessions();
                app_lock.status_message = Some(format!("Session {} sent.", log.uuid));
            }
            log::info!("Successfully sent new session {}", log.uuid);
        }

        Action::SendAppendedPrompt { uuid, prompt } => {
            let mut client = NetworkClient::connect(&SERVER_ADDR, &CLIENT_USERNAME, USER_PRIVATE_KEY_PATH).await?;
            let content = {
                let mut app_lock = app.lock().await;
                app_lock.store.append_prompt(uuid, prompt)?;
                app_lock.reload_sessions();
                app_lock.store.get_session_content(uuid)?
            };
            
            client.execute_chat(&content).await?;
            {
                let mut app_lock = app.lock().await;
                app_lock.store.update_session_status(uuid, SyncStatus::Pending, None)?;
                app_lock.reload_sessions();
                app_lock.status_message = Some(format!("Appended prompt sent for {}.", uuid));
            }
            log::info!("Successfully sent appended session {}", uuid);
        }

        Action::SyncSelected { uuid, .. } => {
            log::info!("Starting timestamp-based sync for session {}", uuid);
            let mut client = NetworkClient::connect(&SERVER_ADDR, &CLIENT_USERNAME, USER_PRIVATE_KEY_PATH).await?;
            
            // 1. Get local and remote timestamps
            let local_updated_at = app.lock().await.store.index.get(&uuid).map(|info| info.updated_at);

            let remote_tasks = client.list_tasks().await?;
            let remote_info = remote_tasks.into_iter().find(|t| t.uuid == uuid);
            let remote_updated_at = remote_info.as_ref().and_then(|info| info.updated_at);

            // 2. Compare timestamps and decide action
            let ordering = match (local_updated_at, remote_updated_at) {
                (Some(local), Some(remote)) => local.cmp(&remote),
                (Some(_), None) => Ordering::Greater, // Local exists, remote doesn't -> Upload
                (None, Some(_)) => Ordering::Less,    // Remote exists, local doesn't -> Download
                (None, None) => return Err(AppError::NetworkError(format!("Session {} not found locally or on server.", uuid))),
            };

            match ordering {
                Ordering::Greater => {
                    // --- UPLOAD FLOW ---
                    log::info!("Client is newer for {}. Uploading...", uuid);
                    let content = {
                        let mut app_lock = app.lock().await;
                        // prepare_for_run cleans the log and updates its timestamp before saving
                        let log_to_run = app_lock.store.prepare_for_run(uuid)?;
                        format_chat_log(&log_to_run)
                    };
                    client.execute_chat(&content).await?;
                    
                    let mut app_lock = app.lock().await;
                    app_lock.store.update_session_status(uuid, SyncStatus::Pending, None)?;
                    app_lock.reload_sessions();
                    app_lock.status_message = Some(format!("Session {} sent to server.", uuid));
                }
                Ordering::Less => {
                    // --- DOWNLOAD FLOW ---
                    log::info!("Server is newer for {}. Downloading...", uuid);
                    let remote_task_info = remote_info.unwrap(); // We know it exists from the comparison logic
                    let content = client.download_task(uuid).await?;

                    let mut app_lock = app.lock().await;
                    app_lock.store.update_from_remote(&content, &remote_task_info)?;
                    app_lock.reload_sessions();
                    app_lock.status_message = Some(format!("Session {} downloaded from server.", uuid));
                }
                Ordering::Equal => {
                    // --- NO-OP FLOW ---
                    log::info!("Timestamps match for {}. Already in sync.", uuid);
                    app.lock().await.status_message = Some(format!("Session {} is already in sync.", uuid));
                }
            }
        }

        Action::DeleteTask(uuid) => {
            let mut client = NetworkClient::connect(&SERVER_ADDR, &CLIENT_USERNAME, USER_PRIVATE_KEY_PATH).await?;
            client.delete_task(uuid).await?;

            let mut app_lock = app.lock().await;
            app_lock.store.delete_session(uuid)?;
            app_lock.reload_sessions();
            app_lock.status_message = Some(format!("Task {} deleted.", uuid));
        }

        Action::SaveEdit => {
            let mut client = NetworkClient::connect(&SERVER_ADDR, &CLIENT_USERNAME, USER_PRIVATE_KEY_PATH).await?;
            
            let (uuid, content) = {
                let mut app_lock = app.lock().await;
                if let Some(uuid) = app_lock.editor_task_uuid {
                    let content = app_lock.editor_textarea.lines().join("\n");
                    let log_to_save = parse_chat_file(&content)?;
                    app_lock.store.save_session(&log_to_save, SyncStatus::Modified)?;
                    app_lock.store.save_index()?;
                    app_lock.reload_sessions();
                    Some((uuid, content))
                } else { None }
            }.ok_or_else(|| AppError::ParseError("No active editor task".to_string()))?;
            
            client.update_task(uuid, &content).await?;
            
            let mut app_lock = app.lock().await;
            app_lock.store.update_session_status(uuid, SyncStatus::Pending, None)?;
            app_lock.status_message = Some(format!("Session {} saved and synced.", uuid));
            app_lock.mode = AppMode::TaskList;
        }

        // Non-network actions are filtered out before this function is called.
        _ => {},
    };

    Ok(())
}

/// Handles actions that only modify local state and do not require network access.
pub async fn handle_local_action(action: Action, app: Arc<Mutex<App<'static>>>) -> Result<()> {
    log::debug!("Handling local action: {:?}", action);
    
    match action {
        Action::StartEdit(uuid) => {
            // Lock once and perform all state updates
            let mut app_lock = app.lock().await; 
            let content = app_lock.store.get_session_content(uuid)?;
            
            // --- NEW: Calculate block positions ---
            app_lock.editor_block_positions = content
                .lines()
                .enumerate()
                .filter_map(|(i, line)| {
                    if line.starts_with("::>user:") || line.starts_with("::>response:") || line.starts_with("::>error:") {
                        Some(i) // Store the line number
                    } else {
                        None
                    }
                })
                .collect();
            // --- END NEW ---

            app_lock.editor_textarea = TextArea::new(content.lines().map(String::from).collect());
            app_lock.editor_task_uuid = Some(uuid);
            app_lock.mode = AppMode::EditingTask;
            app_lock.status_message = Some("Editor. Save: Ctrl+S, Cancel: Esc, Jump: Ctrl+N/P, Help: Ctrl+H".into());
        },
        Action::ViewTask(_) | Action::EnterAppendPrompt(_) => {
            // These actions are simple enough to be handled directly in app.update()
            // We can just pass through here, or move the logic here for consistency.
            // For now, let app.update handle it as it's purely state change.
            app.lock().await.update(action);
        }
        // Other local actions are UI-only and handled by App::update
        _ => {}
    }
    Ok(())
}
