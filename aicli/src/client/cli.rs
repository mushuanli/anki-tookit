// src/client/cli.rs

// We need the new TlsClientStream type in this file's scope
use crate::client::network::{NetworkClient};
use crate::error::{AppError, Result};

use crate::ClientCommands;
use crate::client::local_store::{LocalStore, SyncStatus};
use crate::common::protocol::{format_chat_log};

use std::fs;
use std::path::Path;

use uuid::Uuid;
use once_cell::sync::Lazy;

// NEW: Use Lazy static to read env vars once
pub static SERVER_ADDR: Lazy<String> = Lazy::new(|| {
    std::env::var("AICLI_SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:9501".to_string())
});
pub static CLIENT_USERNAME: Lazy<String> = Lazy::new(|| {
    std::env::var("AICLI_USERNAME").unwrap_or_else(|_| "admin".to_string())
});

// NEW constants for paths
pub const USER_PRIVATE_KEY_PATH: &str = "data/user.key";
pub const USER_PUBLIC_KEY_PATH: &str = "data/user.pub";
pub const CLIENT_DATA_DIR: &str = "data/client";
pub const CLIENT_INDEX_PATH: &str = "data/client/index.json";

// Helper for CLI output
fn print_session_list(store: &LocalStore) {
    let sessions = store.list_sessions();
    if sessions.is_empty() {
        println!("No local sessions found. Use 'client new --title \"My Chat\"' to create one.");
    } else {
        println!("{:<38} {:<10} {:<18} {}", "UUID", "Status", "Remote Status", "Title");
        println!("{}", "-".repeat(85));
        for s in sessions {
            let remote_status = s.remote_status.as_deref().unwrap_or("-");
            println!("{:<38} {:<10} {:<18} {}", s.uuid, format!("{:?}", s.sync_status), remote_status, s.title);
        }
    }
}

// Main dispatcher function for all client commands
pub async fn handle_client_command(command: ClientCommands) -> Result<()> {
    // Ensure client data directory exists for downloads
    fs::create_dir_all(CLIENT_DATA_DIR)?;

    match command {
        // MODIFIED: Init command logic
        ClientCommands::Init => {
            use crate::common::crypto::KeyPair;

            println!("Initializing client...");

            // 1. Create directories
            fs::create_dir_all(CLIENT_DATA_DIR)
                .map_err(|e| AppError::IoWithContext { context: format!("Failed to create directory '{}'", CLIENT_DATA_DIR), source: e })?;

            // 2. Create keys if they don't exist
            if Path::new(USER_PRIVATE_KEY_PATH).exists() {
                println!(" ✓ Key pair already exists at '{}'. Skipping generation.", USER_PRIVATE_KEY_PATH);
            } else {
                let keypair = KeyPair::new();
                fs::write(USER_PRIVATE_KEY_PATH, keypair.private_key_to_bs58())?;
                fs::write(USER_PUBLIC_KEY_PATH, keypair.public_key_to_bs58())?;
                println!(" ✓ Generated new key pair.");
                println!("   - Private Key: {}", USER_PRIVATE_KEY_PATH);
                println!("   - Public Key : {}", USER_PUBLIC_KEY_PATH);
                println!("   (Share the public key with the server admin)");
            }
            
            // 3. Create index file if it doesn't exist
            if !Path::new(CLIENT_INDEX_PATH).exists() {
                 fs::write(CLIENT_INDEX_PATH, "{}")?;
                 println!(" ✓ Created empty session index at '{}'.", CLIENT_INDEX_PATH);
            } else {
                 println!(" ✓ Session index already exists at '{}'.", CLIENT_INDEX_PATH);
            }

            println!("\nInitialization complete.");
        }

        ClientCommands::New { title } => {
            let mut store = LocalStore::load()?;
            let new_log = store.create_new_template(title)?;
            println!("Successfully created new local session template.");
            println!("  UUID: {}", new_log.uuid);
            println!("  File: data/client/{}.md", new_log.uuid);
            println!("You can now edit the file and send it with 'client run --uuid {}'", new_log.uuid);
        }

        ClientCommands::Append { uuid, prompt } => {
            let uuid = Uuid::parse_str(&uuid)?;
            let mut store = LocalStore::load()?;
            store.append_prompt(uuid, prompt)?;
            println!("Appended prompt to session {}. Status set to 'Modified'.", uuid);
            println!("Run with 'client run --uuid {}'", uuid);
        }

        ClientCommands::Run { uuid } => {
            let uuid = Uuid::parse_str(&uuid)?;
            let mut store = LocalStore::load()?;
            
            println!("Preparing session {} for run...", uuid);
            let log_to_run = store.prepare_for_run(uuid)?;
            let content = format_chat_log(&log_to_run);

            println!("Connecting to server and sending...");
            let mut client = NetworkClient::connect(&SERVER_ADDR, &CLIENT_USERNAME, USER_PRIVATE_KEY_PATH).await?;
            client.execute_chat(&content).await?;
            
            store.update_session_status(uuid, SyncStatus::Pending, None)?;
            println!("Session {} sent successfully. Status set to 'Pending'.", uuid);
            println!("Check progress with 'client list' or 'client tui'.");
        }
        // MODIFIED: List now shows local sessions
        ClientCommands::List => {
            let store = LocalStore::load()?;
            print_session_list(&store);
        }

        ClientCommands::SyncList => {
            println!("Connecting to server to sync remote task list...");
            let mut client = NetworkClient::connect(&SERVER_ADDR, &CLIENT_USERNAME, USER_PRIVATE_KEY_PATH).await?;
            let remote_tasks = client.list_tasks().await?;
            println!("Found {} tasks on server. Merging with local index...", remote_tasks.len());
            
            let mut store = LocalStore::load()?;
            store.update_from_remote_list(remote_tasks)?;
            println!("Metadata sync complete.");
            print_session_list(&store);
        }
        // MODIFIED: Delete acts locally and remotely
        ClientCommands::Delete { uuid } => {
            let uuid = Uuid::parse_str(&uuid)?;
            println!("Requesting deletion of remote task {}...", uuid);
            match NetworkClient::connect(&SERVER_ADDR, &CLIENT_USERNAME, USER_PRIVATE_KEY_PATH).await {
                Ok(mut client) => {
                    if let Err(e) = client.delete_task(uuid).await {
                        println!("Warning: Failed to delete remote task (it may not exist): {}", e);
                    } else {
                        println!("Remote task deleted or confirmed not present.");
                    }
                },
                Err(e) => println!("Warning: Could not connect to server to delete remote task: {}", e),
            };

            println!("Deleting local session files for {}...", uuid);
            let mut store = LocalStore::load()?;
            store.delete_session(uuid)?;
            println!("Local session deleted.");
        }

        ClientCommands::Sync { uuid } => {
            let uuid = Uuid::parse_str(&uuid)?;
            println!("Connecting to server to download session {}...", uuid);
            let mut client = NetworkClient::connect(&SERVER_ADDR, &CLIENT_USERNAME, USER_PRIVATE_KEY_PATH).await?;
            
            // We need metadata to pass to the store update function. Let's get it.
            let remote_tasks = client.list_tasks().await?;
            let remote_task_info = remote_tasks.into_iter().find(|t| t.uuid == uuid)
                .ok_or_else(|| AppError::NetworkError(format!("Session {} not found on server.", uuid)))?;

            let content = client.download_task(uuid).await?;
            println!("Download complete. Updating local store...");

            let mut store = LocalStore::load()?;
            store.update_from_remote(&content, &remote_task_info)?;
            println!("Session {} synced successfully. Status set to 'Finish'.", uuid);
        }
        
        ClientCommands::Tui => {
            crate::client::tui::run().await?;
        }
    }
    Ok(())
}
