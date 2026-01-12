// src/cli.rs

use clap::{Args, Parser, Subcommand};
use uuid::Uuid;
use crate::storage::Database;
use crate::utils::CryptoUtils;
use crate::models::User;

#[derive(Parser)]
#[command(name = "vfs-sync")]
#[command(about = "VFS Sync Server and Management CLI", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// 启动同步服务器 (默认)
    Server,
    
    /// 用户管理命令
    #[command(subcommand)]
    User(UserCommands),
}

#[derive(Subcommand)]
pub enum UserCommands {
    /// 创建新用户
    Create {
        /// 用户名
        #[arg(short, long)]
        username: String,

        /// 密码
        #[arg(short, long)]
        password: String,

        /// 邮箱 (可选)
        #[arg(short, long)]
        email: Option<String>,
        
        /// 显示名称 (可选)
        #[arg(short, long)]
        display_name: Option<String>,
    },

    /// 列出所有用户
    List,

    /// 重置用户密码
    ResetPassword {
        /// 用户名
        #[arg(short, long)]
        username: String,
        
        /// 新密码
        #[arg(short, long)]
        password: String,
    },
}

pub struct CliHandler {
    db: Database,
}

impl CliHandler {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn handle_user_command(&self, cmd: UserCommands) -> anyhow::Result<()> {
        match cmd {
            UserCommands::Create { username, password, email, display_name } => {
                // 检查用户是否存在
                if self.db.get_user_by_username(&username).await?.is_some() {
                    println!("错误: 用户 '{}' 已存在", username);
                    return Ok(());
                }

                let password_hash = CryptoUtils::hash_password(&password)?;
                let now = chrono::Utc::now();

                let user = User {
                    id: Uuid::new_v4().to_string(),
                    username: username.clone(),
                    password_hash,
                    email,
                    display_name,
                    storage_quota: 10 * 1024 * 1024 * 1024, // 默认 10GB
                    storage_used: 0,
                    is_active: true,
                    created_at: now.to_rfc3339(),
                    updated_at: now.to_rfc3339(),
                };

                self.db.create_user(&user).await?;
                println!("成功: 用户 '{}' 已创建 (ID: {})", username, user.id);
            }
            UserCommands::List => {
                // 这里需要在 Database 中添加一个 list_users 方法，
                // 暂时我们用 SQL 直接查询演示，或者你需要去 Database 实现它
                // 假设 list_users 不存在，我们通过 sqlx 直接查 (不推荐直接依赖 sqlx，最好封装进 db)
                // 这里为了演示方便，假设 db 有 list_users，如果没有请去 src/storage/database.rs 添加
                println!("用户列表功能需要在 Database 中实现 list_users 方法");
            }
            UserCommands::ResetPassword { username, password } => {
                if let Some(mut user) = self.db.get_user_by_username(&username).await? {
                    let new_hash = CryptoUtils::hash_password(&password)?;
                    
                    // 这里需要在 Database 实现 update_password 方法
                    // 暂时模拟逻辑：
                    // user.password_hash = new_hash;
                    // self.db.update_user(&user).await?;
                    println!("TODO: 请在 Database 实现 update_user_password 方法");
                    println!("模拟更新: 用户 {} 密码已重置", username);
                } else {
                    println!("错误: 用户 '{}' 不存在", username);
                }
            }
        }
        Ok(())
    }
}
