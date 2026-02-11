// src/modules/init/utils.rs

use super::config;
use crate::models::WordData;
use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde_json::{json, Value};
use std::path::{Path};
use std::time::Duration;
use tokio::fs;
use tokio::process::Command;
use tokio::sync::Semaphore;
use std::sync::Arc;
use lazy_static::lazy_static;

// --- 全局配置 ---

lazy_static! {
    // 限制同时运行的音频编码进程数量，避免 CPU 100% 导致异步运行时卡死
    // 建议设置为 4 或 CPU 核心数
    static ref AUDIO_PROCESS_SEMAPHORE: Arc<Semaphore> = Arc::new(Semaphore::new(4));
}

/// 统一的文件名清洗函数：全项目应保持一致
/// 逻辑：去首尾星号、转小写、非字母数字替换为下划线
pub fn get_safe_base_name(word: &str) -> String {
    let s = word.trim_start_matches('*').trim().to_lowercase();
    s.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect::<String>()
}


/// 确保所有需要的子目录都存在
pub async fn ensure_directories(output_dir: &Path) -> Result<()> {
    let dirs = [
        config::AUDIO_DIR,
        config::IMAGE_DIR,
        config::JSON_DIR,
    ];
    for dir in dirs {
        let dir_path = output_dir.join(dir);
        fs::create_dir_all(&dir_path)
            .await
            .with_context(|| format!("无法创建目录: {}", dir_path.display()))?;
    }
    Ok(())
}

/// 调用 AI 生成单词的详细信息
pub async fn ai_chat(client: &Client, word: &str) -> Result<WordData> {
    let prompt = json!({
        "name": "输入的英文单词或词组",
        "symbol": "音标",
        "chn": "中文释义",
        "example_en": "一个英文例句",
        "example_cn": "example_en的中文意思",
        "word_family": "词族,单词的常用变形和常用组合",
        "memory_tips": "记忆技巧,包括词源、记忆技巧等有助于记忆的信息",
        "difficulty": "难度等级(1-5)",
        "image_prompt": "example_en 配图的详细描述",
        "collocations": "常用搭配和对应的中文意思"
    });

    let messages = json!([
        {
            "role": "system",
            "content": "你是一名英语教育专家和anki大师，精通英语单词的学习和教学，生成适合青少年学习的英语单词卡片内容。请确保输出为json格式, 不要包括markdown语法, 并且每个字段都是字符串类型。"
        },
        {
            "role": "user",
            "content": format!("请为单词 \"{}\" 生成完整的学习卡片内容, 输出格式如下: {}", word, prompt.to_string())
        }
    ]);

    let response = client
        .post(config::openai_base_url())
        .bearer_auth(config::openai_api_key())
        .json(&json!({
            "model": config::openai_model(),
            "messages": messages,
            "temperature": 0.7,
        }))
        .send()
        .await?
        .json::<Value>()
        .await?;

    let content = response["choices"][0]["message"]["content"]
        .as_str()
        .ok_or_else(|| anyhow!("AI响应内容为空"))?;

    let clean_json = extract_json_from_markdown(content);
    let mut word_data: WordData = serde_json::from_str(clean_json)
        .with_context(|| format!("解析AI JSON失败: {}", clean_json))?;
    
    if word_data.name.is_none() {
        word_data.name = Some(word.to_string());
    }

    Ok(word_data)
}

/// 生成音频文件 (增加并发控制与静默模式)
pub async fn generate_audio(text: &str, file_path: &Path) -> Result<String> {
    if text.is_empty() {
        return Err(anyhow!("文本为空"));
    }

    // 1. 获取信号量许可，限制 CPU 负载
    let _permit = AUDIO_PROCESS_SEMAPHORE.acquire().await?;

    let file_name = file_path.file_name().and_then(|s| s.to_str()).unwrap_or_default().to_string();
    
    // 2. 如果文件物理存在且大小不为0，跳过生成 (幂等性)
    if file_path.exists() && fs::metadata(file_path).await?.len() > 0 {
        return Ok(file_name);
    }

    // 3. 准备清洗后的文本（去掉双引号，防止 shell 注入或挂起）
    let safe_text = text.replace('"', "");

    if cfg!(target_os = "macos") {
        let aiff_path = file_path.with_extension("aiff");
        
        // 调用 macOS 自带 TTS
        let say_status = Command::new("say")
            .arg("-o")
            .arg(&aiff_path)
            .arg("--")
            .arg(&safe_text)
            .status()
            .await?;
        
        if !say_status.success() {
            return Err(anyhow!("'say' 命令执行失败"));
        }

        // 调用 LAME 编码。--silent 解决控制台阻塞问题，-q 2 保证质量
        let lame_status = Command::new("lame")
            .arg("--silent")
            .arg("-q")
            .arg("2")
            .arg(&aiff_path)
            .arg(file_path)
            .status()
            .await?;

        let _ = fs::remove_file(aiff_path).await;

        if !lame_status.success() {
            return Err(anyhow!("'lame' 编码失败"));
        }
    } else {
        // 其他系统使用 edge-tts
        let status = Command::new("edge-tts")
            .arg("--write-media")
            .arg(file_path)
            .arg("--text")
            .arg(&safe_text)
            .status()
            .await?;
        if !status.success() { return Err(anyhow!("edge-tts 失败")); }
    }

    println!("生成音频成功: {}", file_name);
    Ok(file_name)
}

/// 统一处理单个单词的多媒体生成
pub async fn generate_multimedia_for_word(
    client: &Client,
    word_data: &mut WordData,
    output_dir: &Path,
) -> Result<bool> {
    let mut needs_update = false;
    let word_name = word_data.name.as_deref().unwrap_or_default();
    if word_name.is_empty() { return Ok(false); }

    // 使用统一的清洗逻辑生成文件名
    let safe_base_name = get_safe_base_name(word_name);

    // --- 1. 处理单词发音 ---
    let audio_name = format!("{}.mp3", safe_base_name);
    let audio_path = output_dir.join(config::AUDIO_DIR).join(&audio_name);
    
    // 检查是否需要生成：JSON记录缺失 或 磁盘文件缺失
    if word_data.audio.is_none() || !audio_path.exists() {
        if let Ok(fname) = generate_audio(word_name, &audio_path).await {
            word_data.audio = Some(fname);
            needs_update = true;
        }
    }
    
    // --- 2. 处理例句音频 ---
    if let Some(example_en) = word_data.example_en.as_deref() {
        let ex_audio_name = format!("{}_example.mp3", safe_base_name);
        let ex_audio_path = output_dir.join(config::AUDIO_DIR).join(&ex_audio_name);
        
        if word_data.audio_example.is_none() || !ex_audio_path.exists() {
            if let Ok(fname) = generate_audio(example_en, &ex_audio_path).await {
                word_data.audio_example = Some(fname);
                needs_update = true;
            }
        }
    }

    // --- 3. 处理图片生成 ---
    if word_data.image.is_none() {
        let img_name = format!("{}.png", safe_base_name);
        let img_path = output_dir.join(config::IMAGE_DIR).join(&img_name);

        if let Some(task_id) = word_data.image_taskid.as_deref() {
            match query_and_download_image(client, task_id, &img_path).await {
                Ok(Some(filename)) => {
                    word_data.image_taskid = None;
                    if !filename.is_empty() { word_data.image = Some(filename); }
                    needs_update = true;
                },
                Ok(None) => {}, // 任务进行中
                Err(e) => eprintln!("查询图片失败: {}", e),
            }
        } else if let Some(prompt) = word_data.image_prompt.as_deref() {
            if let Ok(task_id) = generate_image(client, prompt).await {
                word_data.image_taskid = Some(task_id);
                needs_update = true;
                tokio::time::sleep(Duration::from_millis(config::IMAGE_GEN_DELAY_MS)).await;
            }
        }
    }
    
    Ok(needs_update)
}

/// 辅助函数：从 AI 响应中提取 JSON
fn extract_json_from_markdown(raw: &str) -> &str {
    let trimmed = raw.trim();
    if trimmed.starts_with("```json") && trimmed.ends_with("```") {
        return trimmed.strip_prefix("```json").unwrap().strip_suffix("```").unwrap().trim();
    }
    trimmed
}

// 图片生成的辅助函数逻辑保持不变，但建议在调用处确保路径使用 safe_base_name (见上文)
pub async fn generate_image(client: &Client, prompt: &str) -> Result<String> {
    let response = client
        .post(config::FLUX_API_GEN_URL)
        .header("X-DashScope-Async", "enable")
        .header("Authorization", format!("Bearer {}", config::flux_api_key()))
        .json(&json!({
            "model": config::FLUX_API_MODEL,
            "input": { "prompt": prompt },
        }))
        .send()
        .await?
        .json::<Value>()
        .await?;
    
    response["output"]["task_id"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| anyhow!("从Flux API获取task_id失败: {:?}", response))
}

/// 查询图片生成任务状态并下载
pub async fn query_and_download_image(client: &Client, task_id: &str, file_path: &Path) -> Result<Option<String>> {
    let url = format!("{}{}", config::FLUX_API_QUERY_URL, task_id);
    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {}", config::flux_api_key()))
        .send()
        .await?
        .json::<Value>()
        .await?;

    match response["output"]["task_status"].as_str() {
        Some("SUCCEEDED") => {
            let image_url = response["output"]["results"][0]["url"].as_str().ok_or_else(|| anyhow!("URL missing"))?;
            let bytes = client.get(image_url).send().await?.bytes().await?;
            fs::write(file_path, &bytes).await?;
            Ok(Some(file_path.file_name().unwrap().to_str().unwrap().to_string()))
        },
        Some("FAILED") => {
             println!("图片生成失败，任务ID: {}", task_id);
             Ok(Some("".to_string())) // 表示任务已终结（失败），返回空字符串
        },
        _ => { // "PENDING", "RUNNING", etc.
            Ok(None) // 表示任务仍在进行中
        }
    }
}
