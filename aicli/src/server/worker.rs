// src/server/worker.rs

use crate::common::config::CONFIG;
use crate::common::protocol::{format_chat_log, parse_chat_file};
use crate::common::types::{ChatLog, Interaction};
use crate::error::{Result};
use crate::server::ai_gateway::{self, AiMessage};
use crate::server::db::Database;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use uuid::Uuid;
use chrono::Utc;

// The task that the handler sends to the worker
#[derive(Debug)]
pub struct AiTask {
    pub uuid: Uuid,
    pub client_ip: String,
    pub username: String, // <-- NEW: Add username field
}

/// The main loop for the worker pool.
/// It listens for tasks and processes them concurrently up to a specified limit.
pub async fn run_worker_pool(
    db: Arc<Database>,
    semaphore: Arc<Semaphore>,
    mut rx: mpsc::Receiver<AiTask>,
) {
    while let Some(task) = rx.recv().await {
        // Wait for a permit from the semaphore. This limits concurrency.
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let db_clone = db.clone();
        
        tokio::spawn(async move {
            let task_uuid = task.uuid;
            info!("Processing task {} for user '{}' from client {}...", task_uuid, task.username, task.client_ip);
            
            // This top-level error catch is for unexpected I/O or other unhandled errors within process_task.
            if let Err(e) = process_task(db_clone.clone(), task).await {
                error!("Unhandled error during processing for task {}: {}. Updating status to failed.", task_uuid, e);
                if let Err(db_err) = db_clone.update_status(&task_uuid, "failed", Some(&e.to_string())).await {
                    error!("CRITICAL: Failed to update DB status for task {}: {}", task_uuid, db_err);
                }
            }
            // The permit is automatically released when `permit` goes out of scope.
            drop(permit);
        });
    }
}

/// The logic for processing a single AI task.
async fn process_task(db: Arc<Database>, task: AiTask) -> Result<()> {
    // 1. Update status to 'processing'
    db.update_status(&task.uuid, "processing", None, Utc::now()).await?;

    // 2. Read and parse the chat file from disk
    let chat_file_path = Path::new(&CONFIG.storage.chat_dir).join(format!("{}.txt", task.uuid));
    let content = fs::read_to_string(&chat_file_path)?;
    let mut chat_log = parse_chat_file(&content)?;
    
    // 3. Prepare request for AI
    if chat_log.model.is_none() {
        chat_log.model = Some(CONFIG.server.default.clone());
    }
    let model_identifier = chat_log.model.as_ref().unwrap();

    let ai_client = ai_gateway::create_client(&CONFIG, model_identifier)?;
    let messages = convert_chat_log_to_ai_messages(&chat_log);

    // --- 4. REFACTORED: Send request to AI, log the result, and handle the outcome robustly ---
    let ai_response_result = ai_client.send_request(messages).await;

    // We are about to modify the log, so capture the new timestamp now.
    let new_updated_at = Utc::now();
    chat_log.updated_at = new_updated_at; // Update the in-memory log object

    match ai_response_result {
        Ok(ai_response_content) => {
            // NEW: Log the successful result immediately
            info!(
                "AI_RESULT_SUCCESS | User: {} | UUID: {} | Result: \"{}...\"",
                task.username,
                task.uuid,
                ai_response_content.chars().take(100).collect::<String>() 
            );

            // Update the ChatLog with the successful response
            chat_log.interactions.push(Interaction::Ai {
                content: ai_response_content,
                created_at: Utc::now(),
            });
            chat_log.status = Some("completed".to_string());
            
            // Update database status
            db.update_status(&task.uuid, "completed", None, new_updated_at).await?;
            info!("Task {} completed successfully.", task.uuid);
        }
        Err(e) => {
            // NEW: Log the failure result immediately
            error!(
                "AI_RESULT_FAILURE | User: {} | UUID: {} | Error: {}",
                task.username,
                task.uuid,
                e
            );

            // Update the ChatLog with a structured error block
            chat_log.interactions.push(Interaction::Error {
                reason: e.to_string(),
                created_at: Utc::now(),
            });
            chat_log.status = Some("failed".to_string());

            // Update database status with the error message
            db.update_status(&task.uuid, "failed", Some(&e.to_string()), new_updated_at).await?;
            warn!("Task {} marked as failed. Wrote error details to session file.", task.uuid);
        }
    }

    // Write the final state (with the new updated_at header) back to the file
    let updated_content = format_chat_log(&chat_log);
    fs::write(&chat_file_path, updated_content)?;

    Ok(())
}

/// Converts a ChatLog into a sequence of messages for an AI model.
fn convert_chat_log_to_ai_messages(log: &ChatLog) -> Vec<AiMessage> {
    let mut messages = Vec::new();
    if let Some(prompt) = &log.system_prompt {
        messages.push(AiMessage { role: "system".to_string(), content: prompt.clone() });
    }
    // We only process up to the last user interaction.
    for interaction in &log.interactions {
        match interaction {
            Interaction::User { content, .. } => {
                messages.push(AiMessage { role: "user".to_string(), content: content.clone() });
            }
            Interaction::Ai { content, .. } => {
                messages.push(AiMessage { role: "assistant".to_string(), content: content.clone() });
            }
            // Errors and Attachments are not sent to the AI.
            _ => {}
        }
    }
    messages
}
