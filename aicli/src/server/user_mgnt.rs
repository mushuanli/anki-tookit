// src/server/user_mgnt.rs (NEW)
use crate::common::config::CONFIG;
use crate::error::{AppError, Result};
use crate::server::db::{Database};
use std::sync::Arc;
use std::path::PathBuf; // 引入 PathBuf
use std::fs; // 引入 fs

// Helper to get a DB connection
async fn get_db() -> Result<Arc<Database>> {
    let db = Database::connect(&CONFIG.database.path).await?;
    Ok(Arc::new(db))
}

pub async fn add_user(username: String, key_file: PathBuf) -> Result<()> {
    // 从文件读取公钥字符串
    let public_key = fs::read_to_string(&key_file)
        .map_err(|e| AppError::IoWithContext { 
            context: format!("Failed to read public key file '{}'", key_file.display()), 
            source: e 
        })?
        .trim() // 去除可能的空白符和换行符
        .to_string();

    if public_key.is_empty() {
        return Err(AppError::ConfigError(format!("Public key file '{}' is empty.", key_file.display())));
    }

    let db = get_db().await?;
    db.add_user(&username, &public_key).await?;
    println!("Successfully added user '{}' using key from '{}'", username, key_file.display());
    Ok(())
}

pub async fn delete_user(username: String) -> Result<()> {
    let db = get_db().await?;
    db.delete_user(&username).await?;
    println!("Successfully deleted user '{}'", username);
    Ok(())
}

pub async fn set_user(username: String, key_file: PathBuf) -> Result<()> {
    // 从文件读取公钥字符串
    let public_key = fs::read_to_string(&key_file)
        .map_err(|e| AppError::IoWithContext { 
            context: format!("Failed to read public key file '{}'", key_file.display()), 
            source: e 
        })?
        .trim()
        .to_string();
    
    if public_key.is_empty() {
        return Err(AppError::ConfigError(format!("Public key file '{}' is empty.", key_file.display())));
    }

    let db = get_db().await?;
    db.update_user_key(&username, &public_key).await?;
    println!("Successfully updated public key for user '{}' using key from '{}'", username, key_file.display());
    Ok(())
}

pub async fn list_users() -> Result<()> {
    let db = get_db().await?;
    let users = db.list_users().await?;
    if users.is_empty() {
        println!("No users found.");
        return Ok(());
    }
    println!("{:<20} {:<30} {:<30} {:<30}", "Username", "Created At", "Key Modified At", "Last Seen At");
    println!("{}", "-".repeat(113));
    for user in users {
        let last_seen = user.last_seen_at.map_or("Never".to_string(), |ts| ts.to_rfc3339());
        println!(
            "{:<20} {:<30} {:<30} {:<30}",
            user.username,
            user.created_at.to_rfc3339(),
            user.key_modified_at.to_rfc3339(),
            last_seen
        );
    }
    Ok(())
}

