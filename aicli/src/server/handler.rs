// src/server/handler.rs

use crate::common::config::CONFIG;
use crate::common::frame::{encode_frame, read_frame};
use crate::common::protocol::{parse_chat_file, format_chat_log, truncate_after_last_user}; // Ensure all are imported
use crate::common::types::PacketType;
use crate::common::crypto::verify_signature;
use crate::error::{AppError, Result};
use crate::server::db::Database;
use crate::server::worker::AiTask;
use rand::RngCore;
use serde_json::{from_slice, json, Value};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use uuid::Uuid;

// REMOVED: This type alias was causing the E0225 error and is not needed.
// type GenericStream = Box<dyn AsyncRead + AsyncWrite + Unpin + Send>;

pub async fn handle_connection<S>(
    mut stream: S,
    addr: SocketAddr,
    db: Arc<Database>,
    task_sender: mpsc::Sender<AiTask>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let username = match authenticate(&mut stream, db.clone()).await {
        Ok(username) => username,
        Err(e) => {
            let error_frame = encode_frame(PacketType::Error, e.to_string().as_bytes());
            stream.write_all(&error_frame).await.ok();
            return Err(e);
        }
    };
    info!("User '{}' from {} authenticated successfully.", username, addr);
    db.update_last_seen(&username).await?;

    // 2. Command loop
    loop {
        // Read a frame from the client
        let frame = match read_frame(&mut stream).await {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                info!("Client {} ({}) disconnected.", addr, username);
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        // Pass username to the relevant handlers
        let result = match frame.packet_type {
            PacketType::CmdExec => handle_exec(&mut stream, &db, &task_sender, &frame.payload, &addr, &username).await,
            PacketType::CmdList => handle_list(&mut stream, &db).await,
            PacketType::CmdGet => handle_get(&mut stream, &frame.payload).await,
            PacketType::CmdDelete => handle_delete(&mut stream, &db, &frame.payload).await,
            PacketType::CmdUpdate => handle_update(&mut stream, &frame.payload).await,
            _ => {
                let err_msg = format!("Unsupported command: {:?}", frame.packet_type);
                warn!("{}", err_msg);
                let err_frame = encode_frame(PacketType::Error, err_msg.as_bytes());
                stream.write_all(&err_frame).await?;
                Ok(())
            }
        };

        if let Err(e) = result {
            error!("Error processing command for {} ({}): {}", addr, username, e);
            let err_frame = encode_frame(PacketType::Error, e.to_string().as_bytes());
            stream.write_all(&err_frame).await.ok();
        }
    }
}

// --- MODIFIED: handle_exec now accepts the username ---
async fn handle_exec<S: AsyncWrite + Unpin>(
    stream: &mut S,
    db: &Database,
    task_sender: &mpsc::Sender<AiTask>,
    payload: &[u8],
    addr: &SocketAddr,
    username: &str,
) -> Result<()> {
    // 1. Parse content and save file (same as before)
    let content = String::from_utf8(payload.to_vec())?;
    let mut chat_log = parse_chat_file(&content)?;
    
    // --- SERVER-SIDE ROBUSTNESS ---
    // ALWAYS truncate any trailing AI/Error responses from the client payload
    // before saving and processing. This ensures every run starts from a clean user prompt.
    truncate_after_last_user(&mut chat_log);
    
    // Save the cleaned content.
    let cleaned_content = format_chat_log(&chat_log);
    let file_path = Path::new(&CONFIG.storage.chat_dir).join(format!("{}.txt", chat_log.uuid));
    fs::write(&file_path, &cleaned_content)?;
    debug!("Upserting cleaned chat log {} for user '{}'", chat_log.uuid, username);

    // This logic remains correct: create or update DB record.
    if db.log_exists(&chat_log.uuid).await? {
        info!("Queueing existing task {} for re-processing", chat_log.uuid);
        // The timestamp in the DB will be updated by the worker.
        db.update_status(&chat_log.uuid, "pending", None, chat_log.updated_at).await?;
    } else {
        info!("Creating and queueing new task {}", chat_log.uuid);
        db.create_chat_log(&chat_log, &addr.ip().to_string()).await?;
    }

    // --- MODIFIED: Create AiTask with the username ---
    task_sender.send(AiTask { 
        uuid: chat_log.uuid, 
        client_ip: addr.ip().to_string(),
        username: username.to_string(),
    }).await.map_err(|e| AppError::NetworkError(format!("Failed to queue task: {}", e)))?;

    let ack_frame = encode_frame(PacketType::Ack, chat_log.uuid.to_string().as_bytes());
    stream.write_all(&ack_frame).await?;
    
    Ok(())
}

// --- NEW HANDLER FUNCTIONS ---

async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    db: Arc<Database>,
) -> Result<String> {
    // 1. Read username from client
    let frame = read_frame(stream).await?
        .ok_or_else(|| AppError::AuthError("Client disconnected before auth".to_string()))?;

    if frame.packet_type != PacketType::CmdAuthRequest {
        return Err(AppError::AuthError("Expected auth request".to_string()));
    }

    let auth_req: serde_json::Value = from_slice(&frame.payload)?;
    let username = auth_req["username"].as_str()
        .ok_or_else(|| AppError::AuthError("Username not provided".to_string()))?
        .to_string();

    // 2. Get pubkey, generate challenge, send to client
    let pub_key = db.get_user_pubkey(&username).await?
        .ok_or_else(|| AppError::AuthError(format!("User '{}' not found", username)))?;
    
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    
    let challenge_payload = json!({ "challenge": bs58::encode(&challenge).into_string() }).to_string();
    let challenge_frame = encode_frame(PacketType::CmdAuthChallenge, challenge_payload.as_bytes());
    stream.write_all(&challenge_frame).await?;

    // 3. Read signature from client and verify
    let response_frame = read_frame(stream).await?
        .ok_or_else(|| AppError::AuthError("Client disconnected during challenge".to_string()))?;
    
    if response_frame.packet_type != PacketType::CmdAuthResponse {
        return Err(AppError::AuthError("Expected auth response".to_string()));
    }

    let auth_resp: serde_json::Value = from_slice(&response_frame.payload)?;
    let signature_bs58 = auth_resp["signature"].as_str()
        .ok_or_else(|| AppError::AuthError("Signature not provided".to_string()))?;
    
    let signature = bs58::decode(signature_bs58).into_vec()?;
    
    verify_signature(&pub_key, &challenge, &signature)?;

    // 4. Success! Send final ACK with the new flattened model list
    let mut model_list = Vec::new();
    for (server_name, details) in &CONFIG.server.servers {
        for display_name in details.model_list.keys() {
            model_list.push(format!("{}:{}", server_name, display_name));
        }
    }
    model_list.sort(); // Sort for consistent order

    // Ensure the default model is the first in the list for client convenience
    if let Some(pos) = model_list.iter().position(|m| m == &CONFIG.server.default) {
        let default_model = model_list.remove(pos);
        model_list.insert(0, default_model);
    }
    
    let ack_payload = json!({
        "models": model_list,
        "default_model": &CONFIG.server.default, // The default is now the full identifier
    }).to_string();
    
    let ack_frame = encode_frame(PacketType::Ack, ack_payload.as_bytes());
    stream.write_all(&ack_frame).await?;

    Ok(username)
}

async fn handle_list<S: AsyncWrite + Unpin>(stream: &mut S, db: &Database) -> Result<()> {
    let tasks = db.list_all_tasks().await?;
    let payload = serde_json::to_vec(&tasks)?;
    let frame = encode_frame(PacketType::ResponseList, &payload);
    stream.write_all(&frame).await?;
    Ok(())
}

async fn handle_get<S: AsyncWrite + Unpin>(stream: &mut S, payload: &[u8]) -> Result<()> {
    let uuid_str = String::from_utf8_lossy(payload);
    let file_path = Path::new(&CONFIG.storage.chat_dir).join(format!("{}.txt", uuid_str));
    let content = fs::read(file_path)?;
    let frame = encode_frame(PacketType::ResponseChatLog, &content);
    stream.write_all(&frame).await?;
    Ok(())
}

async fn handle_delete<S: AsyncWrite + Unpin>(stream: &mut S, db: &Database, payload: &[u8]) -> Result<()> {
    let uuid_str = String::from_utf8_lossy(payload);
    let uuid = Uuid::parse_str(&uuid_str)
        .map_err(|_| AppError::ParseError("Invalid UUID".into()))?;

    // Delete from DB first
    db.delete_task(&uuid).await?;
    
    // Then delete file
    let file_path = Path::new(&CONFIG.storage.chat_dir).join(format!("{}.txt", uuid_str));
    if file_path.exists() {
        fs::remove_file(file_path)?;
    }
    
    let frame = encode_frame(PacketType::Ack, &[]);
    stream.write_all(&frame).await?;
    Ok(())
}


async fn handle_update<S: AsyncWrite + Unpin>(stream: &mut S, db: &Database, payload: &[u8]) -> Result<()> {
    let v: Value = serde_json::from_slice(payload)?;
    let uuid_str = v["uuid"].as_str().ok_or_else(|| AppError::ParseError("Missing UUID".into()))?;
    let uuid = Uuid::parse_str(uuid_str)?;
    let content = v["content"].as_str().ok_or_else(|| AppError::ParseError("Missing content".into()))?;

    // Overwrite the file on disk
    let file_path = Path::new(&CONFIG.storage.chat_dir).join(format!("{}.txt", uuid_str));
    fs::write(&file_path, content)?;
    debug!("Updated chat file for task {} at {:?}", uuid_str, file_path);

    // Also update the database timestamp to reflect this manual edit from the client.
    let log = parse_chat_file(content)?;
    db.update_status(&uuid, "modified", None, log.updated_at).await?;

    let frame = encode_frame(PacketType::Ack, &[]);
    stream.write_all(&frame).await?;
    Ok(())
}
