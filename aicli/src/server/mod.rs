// src/server/mod.rs

use crate::common::config::CONFIG;
use crate::error::Result;
use crate::server::db::Database;
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};

// Re-export modules to make them accessible from main.rs
pub mod db;
pub mod ai_gateway;
pub mod init;
pub mod user_mgnt; // 添加这一行

mod listener;
mod handler;
mod worker;

/// Starts the AI chat server.
pub async fn run() -> Result<()> {
    // 1. Initialize global components
    log::info!("Starting server...");
    
    // Create a database pool, wrapped in an Arc for safe sharing
    let db = Arc::new(Database::connect(&CONFIG.database.path).await?);
    log::info!("Database connected and migrations run.");

    // Create a task queue (MPSC channel)
    // The buffer size (e.g., 100) means we can hold up to 100 tasks waiting for a worker
    let (tx, rx) = mpsc::channel::<worker::AiTask>(100);

    // Create a semaphore for concurrency control
    let semaphore = Arc::new(Semaphore::new(CONFIG.concurrency.max_concurrent_tasks));
    log::info!("Concurrency limit set to {} tasks.", CONFIG.concurrency.max_concurrent_tasks);

    // 2. Start the background worker pool
    // The worker pool will listen on the receiving end of the channel (rx)
    tokio::spawn(worker::run_worker_pool(
        db.clone(),
        semaphore.clone(),
        rx,
    ));
    log::info!("Background worker pool started.");

    // 3. Start the TCP listener
    // The listener will accept connections and spawn a handler for each.
    // Each handler will use the sending end of the channel (tx) to dispatch tasks.
    listener::run(db, tx).await?;

    Ok(())
}
