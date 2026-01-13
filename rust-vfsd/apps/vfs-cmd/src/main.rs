// apps/vfs-cmd/src/main.rs

use clap::{Parser, Subcommand};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

use vfs_core::config::Config;
use vfs_core::models::{CreateUserRequest, User};
use vfs_core::utils::CryptoUtils;
use vfs_service::{ServerBuilder, UserService};
use vfs_storage::{Database, CacheService, CacheServiceConfig, CachedDatabase};

#[derive(Parser)]
#[command(name = "vfs")]
#[command(author, version, about = "VFS Sync Server and Management CLI", long_about = None)]
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
    
    /// 数据库管理命令
    #[command(subcommand)]
    Db(DbCommands),
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
    List {
        /// 每页数量
        #[arg(short, long, default_value = "20")]
        limit: i64,
        
        /// 搜索关键词
        #[arg(short, long)]
        search: Option<String>,
    },

    /// 重置用户密码
    ResetPassword {
        /// 用户名
        #[arg(short, long)]
        username: String,
        
        /// 新密码
        #[arg(short, long)]
        password: String,
    },
    
    /// 禁用用户
    Disable {
        /// 用户名
        #[arg(short, long)]
        username: String,
    },
    
    /// 启用用户
    Enable {
        /// 用户名
        #[arg(short, long)]
        username: String,
    },
}

#[derive(Subcommand)]
pub enum DbCommands {
    /// 运行数据库迁移
    Migrate,
    
    /// 显示数据库状态
    Status,
}

/// CLI 处理器
struct CliHandler {
    db: CachedDatabase,
    user_service: UserService,
}

impl CliHandler {
    async fn new(config: &Config) -> anyhow::Result<Self> {
        let db = Database::new(&config.database).await?;
        db.run_migrations().await?;
        
        let cache = Arc::new(CacheService::new(CacheServiceConfig::default()));
        let cached_db = CachedDatabase::new(db, cache);
        
        let user_service = UserService::new(cached_db.clone());
        
        Ok(Self {
            db: cached_db,
            user_service,
        })
    }

    async fn handle_user_command(&self, cmd: UserCommands) -> anyhow::Result<()> {
        match cmd {
            UserCommands::Create { username, password, email, display_name } => {
                self.create_user(username, password, email, display_name).await
            }
            UserCommands::List { limit, search } => {
                self.list_users(limit, search).await
            }
            UserCommands::ResetPassword { username, password } => {
                self.reset_password(username, password).await
            }
            UserCommands::Disable { username } => {
                self.set_user_active(username, false).await
            }
            UserCommands::Enable { username } => {
                self.set_user_active(username, true).await
            }
        }
    }

    async fn create_user(
        &self,
        username: String,
        password: String,
        email: Option<String>,
        display_name: Option<String>,
    ) -> anyhow::Result<()> {
        // 检查用户是否存在
        if self.user_service.get_by_username(&username).await?.is_some() {
            println!("❌ 错误: 用户 '{}' 已存在", username);
            return Ok(());
        }

        let req = CreateUserRequest {
            username: username.clone(),
            password,
            email,
            display_name,
        };

        match self.user_service.create(req).await {
            Ok(user) => {
                println!("✅ 成功: 用户 '{}' 已创建", username);
                println!("   ID: {}", user.id);
                println!("   配额: {} GB", user.storage_quota / 1024 / 1024 / 1024);
            }
            Err(e) => {
                println!("❌ 错误: 创建用户失败 - {}", e);
            }
        }

        Ok(())
    }

    async fn list_users(&self, limit: i64, search: Option<String>) -> anyhow::Result<()> {
        let (users, total) = self.db.list_users(limit, 0, search.as_deref()).await?;

        println!("📋 用户列表 (共 {} 个用户)\n", total);
        println!("{:<36} {:<20} {:<30} {:<10}", "ID", "用户名", "邮箱", "状态");
        println!("{}", "-".repeat(100));

        for user in users {
            let status = if user.is_active { "✅ 活跃" } else { "❌ 禁用" };
            let email = user.email.unwrap_or_else(|| "-".to_string());
            println!("{:<36} {:<20} {:<30} {:<10}", user.id, user.username, email, status);
        }

        Ok(())
    }

    async fn reset_password(&self, username: String, password: String) -> anyhow::Result<()> {
        let user = self.user_service.get_by_username(&username).await?;
        
        match user {
            Some(mut user) => {
                user.password_hash = CryptoUtils::hash_password(&password)?;
                user.updated_at = chrono::Utc::now().to_rfc3339();
                
                self.db.update_user(&user).await?;
                println!("✅ 成功: 用户 '{}' 的密码已重置", username);
            }
            None => {
                println!("❌ 错误: 用户 '{}' 不存在", username);
            }
        }

        Ok(())
    }

    async fn set_user_active(&self, username: String, is_active: bool) -> anyhow::Result<()> {
        let user = self.user_service.get_by_username(&username).await?;
        
        match user {
            Some(mut user) => {
                user.is_active = is_active;
                user.updated_at = chrono::Utc::now().to_rfc3339();
                
                self.db.update_user(&user).await?;
                
                let action = if is_active { "启用" } else { "禁用" };
                println!("✅ 成功: 用户 '{}' 已{}", username, action);
            }
            None => {
                println!("❌ 错误: 用户 '{}' 不存在", username);
            }
        }

        Ok(())
    }

    async fn handle_db_command(&self, cmd: DbCommands) -> anyhow::Result<()> {
        match cmd {
            DbCommands::Migrate => {
                println!("✅ 数据库迁移已完成（在初始化时自动执行）");
            }
            DbCommands::Status => {
                let stats = self.db.get_system_stats().await?;
                println!("📊 数据库状态:");
                println!("   总用户数: {}", stats.total_users);
                println!("   活跃用户: {}", stats.active_users);
                println!("   总存储使用: {} MB", stats.total_storage_used / 1024 / 1024);
                println!("   同步日志数: {}", stats.total_sync_logs);
            }
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vfs=info,vfs_service=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // 加载配置
    let config = Config::load().unwrap_or_else(|e| {
        tracing::warn!("Failed to load config, using defaults: {}", e);
        Arc::new(Config::default())
    });

    // 解析命令行参数
    let cli = Cli::parse();

    // 根据命令分发
    match cli.command {
        // 用户管理命令
        Some(Commands::User(user_cmd)) => {
            let handler = CliHandler::new(&config).await?;
            handler.handle_user_command(user_cmd).await?;
        }
        
        // 数据库管理命令
        Some(Commands::Db(db_cmd)) => {
            let handler = CliHandler::new(&config).await?;
            handler.handle_db_command(db_cmd).await?;
        }
        
        // 启动服务器（默认）
        Some(Commands::Server) | None => {
            run_server(config).await?;
        }
    }

    Ok(())
}

async fn run_server(config: Arc<Config>) -> anyhow::Result<()> {
    tracing::info!("Starting VFS Sync Server v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Server configuration: {}:{}", config.server.host, config.server.port);
    tracing::info!("Database path: {}", config.database.path);
    tracing::info!("Data directory: {:?}", config.storage.data_dir);

    let server = ServerBuilder::new()
        .with_config(config)
        .build()
        .await?;

    server.run().await?;

    Ok(())
}
