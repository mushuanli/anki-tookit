// src/cli.rs
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// 一个帮助从目录生成和打包 Anki .apkg 文件的工具
#[derive(Parser, Debug)]
#[command(name = "helper", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// 将指定目录打包成一个 .apkg 文件
    Pack(PackArgs),
    /// 初始化项目目录，通过 AI 生成单词卡片和媒体文件
    Init(InitArgs),
    /// 生成 Markdown 文件并智能更新数据源
    Md(MdArgs),
    /// 从 .apkg 文件反向生成 Markdown 文件
    Pkg2md(Pkg2mdArgs),
}

/// "pack" 子命令的参数
#[derive(Args, Debug)]
pub struct PackArgs {
    /// 要打包的目录路径
    #[arg(required = true)]
    pub pack_dir: PathBuf,

    /// ankimodel.json 模板文件的路径
    #[arg(short, long, default_value = "template/ankimodel.json")]
    pub template: PathBuf,
}

/// "init" 子命令的参数
#[derive(Args, Debug)]
pub struct InitArgs {
    /// 要初始化的输出目录
    #[arg(required = true)]
    pub output_dir: PathBuf,

    /// 包含单词列表的索引文件路径 (txt 或 json)
    /// 如果省略，则默认为 <output-dir>/index.json
    #[arg(short, long)]
    pub template: Option<PathBuf>,
}

/// 生成 Markdown 文件并智能更新数据源。
///
/// 此命令从指定的数据源（目录或 index.json 文件）生成用于背诵的 Markdown 文件。
/// 如果 index.json 中的单词条目不完整 (如缺少例句 'example_en')，
/// 它会自动从同级的 'word_json/' 目录中查找并补全信息。
///
/// 最重要的是，所有补全后的完整数据将自动回写至 index.json 文件，实现数据源的“一次性”更新。
#[derive(Args, Debug)]
pub struct MdArgs {
    /// 数据源路径 (可为包含 index.json 的工作目录，或直接指定该文件)
    #[arg(required = true)]
    pub path: PathBuf,

    /// [可选] 指定输出 Markdown 文件的目录
    #[arg(short, long, default_value = "output")]
    pub output_dir: PathBuf,
}

/// "pkg2md" 子命令的参数 (新增)
#[derive(Args, Debug)]
pub struct Pkg2mdArgs {
    /// 要处理的 Anki .apkg 文件路径
    #[arg(required = true)]
    pub pkg_file: PathBuf,

    /// [可选] 输出 Markdown 文件的目录
    #[arg(short, long, default_value = ".")]
    pub output_dir: PathBuf,
}