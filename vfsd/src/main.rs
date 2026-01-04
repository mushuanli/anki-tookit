// src/main.rs
mod db;
mod server;
mod tui;
mod types;

use clap::{Parser, Subcommand};
use daemonize::Daemonize;
use dashmap::DashMap;
use ipnetwork::IpNetwork;
use rand::{distributions::Alphanumeric, Rng};
use rcgen::generate_simple_self_signed;
use sqlx::{Pool, Row, Sqlite};
use std::{
    fs::{self, File},
    sync::Arc,
};
use bcrypt::{hash, DEFAULT_COST};
use sha2::{Digest, Sha256};

use crate::types::{AppState, DEFAULT_QUOTA_BYTES};
use crate::server::run_server;
use crate::tui::start_tui;
use crate::db::init_db;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Secure VFS Sync Server (TLS)
    Serve {
        #[arg(long, default_value = "cert.pem")]
        cert: String,
        #[arg(long, default_value = "key.pem")]
        key: String,
        #[arg(long, default_value = "3443")]
        port: u16,
        /// Run in background (Daemon mode)
        #[arg(short, long)]
        daemon: bool, 
    },
    /// Generate self-signed certs for testing
    GenCert,
    User {
        #[command(subcommand)]
        action: UserAction,
    },
    /// Show server status and statistics
    Status,
    /// Launch the Admin TUI Dashboard
    Tui,
}

#[derive(Subcommand)]
enum UserAction {
    List,
    Add { username: String }, 
    Passwd { username: String, pass: String },
    Quota { username: String, mb: i64 },
    Kick { username: String },
    Del { username: String },
    Ip { #[command(subcommand)] action: IpAction },
    Token { #[command(subcommand)] action: TokenAction },
}

#[derive(Subcommand)]
enum IpAction {
    List { username: String },
    Add { username: String, cidr: String },
    Del { username: String, cidr: String },
}

#[derive(Subcommand)]
enum TokenAction {
    List { username: String },
    /// Generate a new API token
    Gen { 
        username: String, 
        note: String,
        /// Restrict token path scope (e.g. /docs)
        #[arg(long, default_value = "/")]
        scope: String,
        /// Read-only permission
        #[arg(long)]
        ro: bool,
    },
    Del { username: String, token_id: i64 },
}

// --- Main Entry Point ---
fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Some(Commands::Serve { daemon: true, .. }) = &cli.command {
        println!("Starting in daemon mode...");
        println!("Logs will be written to vfs-server.log / vfs-server.err");
        
        let stdout = File::create("vfs-server.log").expect("Failed to create log file");
        let stderr = File::create("vfs-server.err").expect("Failed to create err file");

        let daemonize = Daemonize::new()
            .pid_file("vfs-server.pid")
            .working_directory(".")
            .stdout(stdout)
            .stderr(stderr);

        if let Err(e) = daemonize.start() {
            eprintln!("Error starting daemon: {}", e);
            std::process::exit(1);
        }
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    // GenCert Helper (No DB needed)
    if let Some(Commands::GenCert) = cli.command {
        let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let cert = generate_simple_self_signed(subject_alt_names).unwrap();
        fs::write("cert.pem", cert.serialize_pem()?)?;
        fs::write("key.pem", cert.serialize_private_key_pem())?;
        println!("Generated cert.pem and key.pem");
        return Ok(());
    }

    // DB Init
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:sync.db".to_string());
    let pool = init_db(&db_url).await?;

    let state = Arc::new(AppState { 
        db: pool.clone(),
        login_attempts: Arc::new(DashMap::new())
    });

    match cli.command {
        Some(Commands::User { action }) => handle_user_cli(action, &pool).await?,
        Some(Commands::Status) => handle_status_cli(&pool).await?,
        Some(Commands::Tui) => start_tui(pool).await?,
        Some(Commands::Serve { cert, key, port, .. }) => run_server(state, cert, key, port).await?,
        // 修复: 匹配分支返回类型不一致。这里应该返回 ()，因为上面用了 await? 解包后的结果是 ()
        Some(Commands::GenCert) => {}, 
        None => run_server(state, "cert.pem".to_string(), "key.pem".to_string(), 3443).await?,
    }

    Ok(())
}

// --- CLI Handlers ---

async fn handle_user_cli(action: UserAction, pool: &Pool<Sqlite>) -> anyhow::Result<()> {
    match action {
        UserAction::List => {
            let rows = sqlx::query("SELECT id, username, quota_bytes FROM users").fetch_all(pool).await?;
            println!("{:<5} | {:<20} | Quota (MB)", "ID", "Username");
            println!("{:-<40}", "");
            for row in rows {
                let q: i64 = row.get("quota_bytes");
                println!("{:<5} | {:<20} | {:.2}", row.get::<i64, _>("id"), row.get::<String, _>("username"), q as f64 / 1024.0 / 1024.0);
            }
        }
        // 修改: 不再接受密码，自动生成随机哈希禁用密码登录，并自动生成 TOKEN
        UserAction::Add { username } => {
            // 生成一个随机密码哈希，实际上是禁用密码登录
            let rng_pass: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32) // 足够长的随机字符串
                .map(char::from)
                .collect();
            let hash = hash(rng_pass, DEFAULT_COST)?;

            // 插入用户
            let res = sqlx::query("INSERT INTO users (username, password_hash, quota_bytes) VALUES (?, ?, ?)")
                .bind(&username).bind(hash).bind(DEFAULT_QUOTA_BYTES).execute(pool).await;

            match res {
                Ok(_) => {
                    println!("User '{}' created successfully (Password login disabled).", username);
                    // 自动生成一个初始 Token
                    println!("Generating initial API Token...");
                    // 自动调用 TokenAction::Gen 来创建第一个 Token
                    let gen_token_action = TokenAction::Gen { 
                        username, 
                        note: "Initial CLI User Creation".to_string(), 
                        scope: "/".to_string(), 
                        ro: false 
                    };
                    match handle_token_cli(gen_token_action, pool).await {
                        Ok(_) => println!("Initial token generated."),
                        Err(e) => eprintln!("Failed to generate initial token: {}", e),
                    }
                },
                Err(_) => println!("Error creating user (username likely exists)."),
            }
        }
        UserAction::Passwd { username, pass } => {
            // 强制要求修改密码，因为没有密码就无法登录
            let hash = hash(pass, DEFAULT_COST)?;
            let res = sqlx::query("UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE username = ?").bind(hash).bind(&username).execute(pool).await?;
            if res.rows_affected() > 0 { println!("Password updated for '{}'. JWT Sessions revoked.", username); } else { println!("User '{}' not found.", username); }
        }
        UserAction::Quota { username, mb } => {
            let bytes = mb * 1024 * 1024;
            let res = sqlx::query("UPDATE users SET quota_bytes = ? WHERE username = ?").bind(bytes).bind(&username).execute(pool).await?;
            if res.rows_affected() > 0 {
                println!("Quota updated for '{}' to {} MB.", username, mb);
            } else {
                println!("User '{}' not found.", username);
            }
        }
        UserAction::Kick { username } => {
            // 踢人等同于强制 re-login，通过增加 token_version 实现
            let res = sqlx::query("UPDATE users SET token_version = token_version + 1 WHERE username = ?").bind(&username).execute(pool).await?;
            if res.rows_affected() > 0 {
                println!("User '{}' kicked from Web sessions (API Keys unaffected).", username);
            } else {
                println!("User '{}' not found.", username);
            }
        }
        UserAction::Del { username } => {
            let row = sqlx::query("SELECT id FROM users WHERE username = ?").bind(&username).fetch_optional(pool).await?;
            if let Some(r) = row {
                let uid: i64 = r.get("id");
                // 修复: 补全 access_logs 删除逻辑
                sqlx::query("DELETE FROM files WHERE user_id = ?").bind(uid).execute(pool).await?;
                sqlx::query("DELETE FROM user_ips WHERE user_id = ?").bind(uid).execute(pool).await?;
                sqlx::query("DELETE FROM api_keys WHERE user_id = ?").bind(uid).execute(pool).await?;
                sqlx::query("DELETE FROM access_logs WHERE user_id = ?").bind(uid).execute(pool).await?;
                sqlx::query("DELETE FROM users WHERE id = ?").bind(uid).execute(pool).await?;
                println!("User '{}' and all associated data/keys/logs deleted.", username);
            } else { println!("User '{}' not found.", username); }
        }
        UserAction::Ip { action } => handle_ip_cli(action, pool).await?,
        UserAction::Token { action } => handle_token_cli(action, pool).await?,
    }
    Ok(())
}

async fn handle_token_cli(action: TokenAction, pool: &Pool<Sqlite>) -> anyhow::Result<()> {
    match action {
        TokenAction::List { username } => {
            let user = sqlx::query("SELECT id FROM users WHERE username = ?").bind(&username).fetch_optional(pool).await?;
            if let Some(u) = user {
                let uid: i64 = u.get("id");
                let rows = sqlx::query("SELECT id, note, prefix, scope_path, permission, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC").bind(uid).fetch_all(pool).await?;
                println!("API Tokens for user '{}':", username);
                println!("{:<5} | {:<10} | {:<5} | {:<10} | {:<15} | Created", "ID", "Prefix", "Perm", "Scope", "Note");
                println!("{:-<80}", "");
                for r in rows {
                    println!("{:<5} | {}... | {:<5} | {:<10} | {:<15} | {}", 
                        r.get::<i64,_>("id"), 
                        r.get::<String,_>("prefix"), 
                        r.get::<String,_>("permission"),
                        r.get::<String,_>("scope_path"),
                        r.get::<String,_>("note"),
                        r.get::<i64,_>("created_at")
                    );
                }
            } else { println!("User '{}' not found.", username); }
        }
        TokenAction::Gen { username, note, scope, ro } => {
            let user = sqlx::query("SELECT id FROM users WHERE username = ?").bind(&username).fetch_optional(pool).await?;
            if let Some(u) = user {
                let rng = rand::thread_rng();
                let random_part: String = rng.sample_iter(&Alphanumeric).take(48).map(char::from).collect();
                let token = format!("sk-{}", random_part);
                // Hash the actual token for storage
                let hash_str = hex::encode(Sha256::digest(token.as_bytes()));
                let prefix = &token[0..10]; // First 10 chars for prefix
                let uid: i64 = u.get("id");
                
                // Phase 1: 写入 Scope 和 Perm
                let perm = if ro { "ro" } else { "rw" };
                
                // Ensure scope starts with /
                let validated_scope = if scope.starts_with('/') { scope } else { format!("/{}", scope) };

                // 修正：validated_scope 使用引用绑定，避免 Move
                sqlx::query("INSERT INTO api_keys (user_id, note, prefix, key_hash, created_at, scope_path, permission) VALUES (?, ?, ?, ?, ?, ?, ?)")
                    .bind(uid).bind(&note).bind(prefix).bind(hash_str)
                    .bind(chrono::Utc::now().timestamp())
                    .bind(&validated_scope).bind(perm) // 修正
                    .execute(pool).await?;
                
                println!("Token: {}", token);
                println!("Scope: {}", validated_scope); // 修正
                println!("Keep it safe!");
            } else { println!("User not found."); }
        }
        TokenAction::Del { username, token_id } => {
            let user = sqlx::query("SELECT id FROM users WHERE username = ?").bind(&username).fetch_optional(pool).await?;
            if let Some(u) = user {
                let uid: i64 = u.get("id");
                let res = sqlx::query("DELETE FROM api_keys WHERE id = ? AND user_id = ?").bind(token_id).bind(uid).execute(pool).await?;
                if res.rows_affected() > 0 { println!("Token ID {} deleted.", token_id); } else { println!("Token ID {} not found for user '{}'.", token_id, username); }
            } else { println!("User '{}' not found.", username); }
        }
    }
    Ok(())
}

async fn handle_ip_cli(action: IpAction, pool: &Pool<Sqlite>) -> anyhow::Result<()> {
    match action {
        IpAction::List { username } => {
             let row = sqlx::query("SELECT id FROM users WHERE username = ?").bind(&username).fetch_optional(pool).await?;
             if let Some(r) = row {
                 let uid: i64 = r.get("id");
                 let ips = sqlx::query("SELECT ip_cidr FROM user_ips WHERE user_id = ?").bind(uid).fetch_all(pool).await?;
                 println!("IP Whitelist for user '{}':", username);
                 if ips.is_empty() {
                     println!("  (No IPs whitelisted)");
                 } else {
                     for ip_row in ips { println!(" - {}", ip_row.get::<String, _>("ip_cidr")); }
                 }
             } else { println!("User '{}' not found.", username); }
        }
        IpAction::Add { username, cidr } => {
            if cidr.parse::<IpNetwork>().is_err() { println!("Invalid CIDR format: '{}'", cidr); return Ok(()); }
            let row = sqlx::query("SELECT id FROM users WHERE username = ?").bind(&username).fetch_optional(pool).await?;
            if let Some(r) = row {
                let uid = r.get::<i64, _>("id");
                let res = sqlx::query("INSERT OR IGNORE INTO user_ips (user_id, ip_cidr) VALUES (?, ?)").bind(uid).bind(&cidr).execute(pool).await?;
                if res.rows_affected() > 0 {
                    println!("Added '{}' to IP whitelist for user '{}'.", cidr, username);
                } else {
                    println!("IP '{}' is already whitelisted for user '{}'.", cidr, username);
                }
            } else { println!("User '{}' not found.", username); }
        }
        IpAction::Del { username, cidr } => {
            let row = sqlx::query("SELECT id FROM users WHERE username = ?").bind(&username).fetch_optional(pool).await?;
            if let Some(r) = row {
                let uid = r.get::<i64, _>("id");
                // 修正：cidr 使用引用绑定
                sqlx::query("DELETE FROM user_ips WHERE user_id = ? AND ip_cidr = ?").bind(uid).bind(&cidr).execute(pool).await?;
                println!("IP '{}' removed.", cidr); // 修正
            }
        }
    }
    Ok(())
}

async fn handle_status_cli(pool: &Pool<Sqlite>) -> anyhow::Result<()> {
    let u: i64 = sqlx::query("SELECT COUNT(*) as c FROM users").fetch_one(pool).await?.get("c");
    let t: i64 = sqlx::query("SELECT COUNT(*) as c FROM api_keys").fetch_one(pool).await?.get("c");
    let f: i64 = sqlx::query("SELECT COUNT(*) as c FROM files").fetch_one(pool).await?.get("c");
    
    // 修正：处理 SQL 结果类型，显式指定 Option<i64>
    let size_res: Option<i64> = sqlx::query("SELECT SUM(LENGTH(content)) as size FROM files")
        .fetch_one(pool).await?
        .try_get::<Option<i64>, _>("size")?;

    println!("--- Secure VFS Status ---");
    println!("Users:     {}", u);
    println!("API Tokens:{}", t);
    println!("Files:     {}", f);
    println!("Storage:   {:.2} MB", size_res.unwrap_or(0) as f64 / 1024.0 / 1024.0);
    Ok(())
}
