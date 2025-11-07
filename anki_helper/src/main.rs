// src/main.rs

mod cli;
mod models;
mod modules;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command};
use dotenvy::dotenv;

// --- 修改：使用 tokio 的异步 main 函数 ---
#[tokio::main]
async fn main() -> Result<()> {
    // 加载 .env 文件中的环境变量
    dotenv().ok();

    // 1. 解析命令行参数
    let cli = Cli::parse();

    // 2. 根据子命令进行分发
    match cli.command {
        Command::Pack(args) => {
            // pack 功能是同步的，所以可以直接调用
            modules::pack::handle_pack_command(args)?;
        }
        Command::Init(args) => {
            // init 功能是异步的，需要 .await
            modules::init::handle_init_command(args).await?;
        }
        // --- 新增: 分发到新的 md 模块 ---
        Command::Md(args) => {
            // md 功能是同步的，所以可以直接调用
            modules::md::handle_md_command(args)?;
        }
        // --- 新增: 分发到新的 pkg2md 模块 ---
        Command::Pkg2md(args) => {
            modules::pkg2md::handle_pkg2md_command(args)?;
        }
    }

    Ok(())
}