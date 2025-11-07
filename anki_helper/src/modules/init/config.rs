// src/modules/init/config.rs
use std::env;

// --- AI 服务配置 ---
pub fn openai_base_url() -> String {
    env::var("OPENAI_BASEURL").unwrap_or_else(|_| "https://api.deepseek.com/v1/chat/completions".to_string())
}
pub fn openai_api_key() -> String {
    env::var("OPENAI_API_KEY").expect("错误：未设置 OPENAI_API_KEY 环境变量")
}
pub fn openai_model() -> String {
    env::var("OPENAI_MODEL").unwrap_or_else(|_| "deepseek-chat".to_string())
}
pub fn flux_api_key() -> String {
    env::var("FLUX_API_KEY").expect("错误：未设置 FLUX_API_KEY 环境变量")
}
pub const FLUX_API_GEN_URL: &str = "https://dashscope.aliyuncs.com/api/v1/services/aigc/text2image/image-synthesis";
pub const FLUX_API_QUERY_URL: &str = "https://dashscope.aliyuncs.com/api/v1/tasks/";
pub const FLUX_API_MODEL: &str = "flux-schnell";


// --- 目录配置 ---
pub const AUDIO_DIR: &str = "audio";
pub const IMAGE_DIR: &str = "images";
pub const JSON_DIR: &str = "word_json"; // 注意：与 pack 模块对齐

// --- 生成延迟 ---
pub const IMAGE_GEN_DELAY_MS: u64 = 5 * 1000; // 提交图片生成任务后的等待时间
pub const IMAGE_RETRY_DELAY_S: u64 = 30; // 每次轮询多媒体任务的间隔