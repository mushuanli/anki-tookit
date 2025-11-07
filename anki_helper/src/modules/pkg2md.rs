// src/modules/pkg2md.rs

use crate::cli::Pkg2mdArgs;
use crate::models::WordData;
use anyhow::{anyhow, Context, Result};
use rusqlite::Connection;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tempfile::Builder;
use std::io::Read; // <--- 添加这一行

/// "pkg2md" 子命令的公共处理函数
pub fn handle_pkg2md_command(args: Pkg2mdArgs) -> Result<()> {
    // 1. 验证输入文件和输出目录
    if !args.pkg_file.exists() {
        return Err(anyhow!("错误: 输入文件 {} 不存在", args.pkg_file.display()));
    }
    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("错误: 无法创建输出目录 {}", args.output_dir.display()))?;

    let deck_name = args.pkg_file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("anki_deck")
        .replace("_Deck", "");

    println!("正在处理 Anki 包: {}", deck_name);

    // 2. 解压 .apkg 到临时目录
    let temp_dir = Builder::new().prefix("pkg2md").tempdir()?;
    let db_path = extract_collection_db(&args.pkg_file, temp_dir.path())?;

    // 3. 连接数据库并读取笔记
    let conn = Connection::open(&db_path)?;
    let mut stmt = conn.prepare("SELECT flds FROM notes")?;
    let notes_iter = stmt.query_map([], |row| row.get::<_, String>(0))?;

    // 4. 反向映射和分组
    let mut units: HashMap<String, Vec<WordData>> = HashMap::new();
    let mut count = 0;
    for note_result in notes_iter {
        let flds_str = note_result?;
        let fields: Vec<&str> = flds_str.split('\x1f').collect();
        
        // 我们只处理符合 WordData 结构的笔记
        // 简单检查：单词字段(0)不为空
        if fields.get(0).map_or(true, |s| s.is_empty()) {
            continue;
        }

        let word_data = fields_to_word_data(&fields);
        let unit_key = word_data.unit
            .as_ref()
            .and_then(|v| {
                if let Some(s) = v.as_str() {
                    Some(s.to_string())
                } else if let Some(i) = v.as_i64() {
                    Some(i.to_string())
                } else {
                    None
                }
            })
            .map(|s| s.trim_matches('"').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_default();
        
        units.entry(unit_key).or_default().push(word_data);
        count += 1;
    }
    println!("从包中解析出 {} 个有效笔记", count);

    if units.is_empty() {
        println!("警告: 未找到可转换为 Markdown 的笔记。");
        return Ok(());
    }

    // 5. 生成 Markdown 文件
    println!("\n--- 开始写入 Markdown 文件 ---");
    for (unit, words) in units {
        let output_filename = if unit.is_empty() {
            args.output_dir.join(format!("{}.md", deck_name))
        } else {
            args.output_dir.join(format!("{} - unit{}.md", deck_name, unit))
        };

        let mut content = "| 中文 | 单词 |\n| :--- | :--- |\n".to_string();

        for word in words {
            let row = format_word_to_markdown_row(&word);
            content.push_str(&row);
        }

        match fs::write(&output_filename, content) {
            Ok(_) => println!("  [✓] 成功生成文件: {}", output_filename.display()),
            Err(e) => eprintln!("  [✗] 错误: 写入文件 '{}' 失败. {}", output_filename.display(), e),
        }
    }

    println!("\n处理完成!");
    Ok(())
}

/// 解压 .apkg 文件并返回 collection 数据库文件的路径
/// [最终解决方案] 根据新信息，正确处理 zstd 压缩的 collection.anki21b 文件。
fn extract_collection_db(pkg_path: &Path, temp_dir: &Path) -> Result<std::path::PathBuf> {
    let file = fs::File::open(pkg_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let mut anki21_path: Option<String> = None;
    let mut anki21b_path: Option<String> = None;
    let mut anki2_path: Option<String> = None;

    // 1. 扫描所有可能的数据库文件名
    for i in 0..archive.len() {
        if let Some(filename_str) = archive.by_index(i)?.name().split('/').last().filter(|s| !s.is_empty()) {
            match filename_str {
                "collection.anki21" => anki21_path = Some(filename_str.to_string()),
                "collection.anki21b" => anki21b_path = Some(filename_str.to_string()),
                "collection.anki2" => anki2_path = Some(filename_str.to_string()),
                _ => {}
            }
        }
    }
    
    // 2. 根据优先级选择要处理的文件
    if let Some(db_name) = anki21_path {
        // 最高优先级：如果存在标准的 .anki21，直接使用
        println!("找到标准数据库文件: {}", &db_name);
        let outpath = temp_dir.join(&db_name);
        let mut file_in_archive = archive.by_name(&db_name)?;
        let mut outfile = fs::File::create(&outpath)?;
        std::io::copy(&mut file_in_archive, &mut outfile)?;
        return Ok(outpath);

    } else if let Some(db_name) = anki21b_path {
        // 第二优先级：处理压缩的 .anki21b
        println!("找到压缩的数据库文件: {}", &db_name);
        let mut file_in_archive = archive.by_name(&db_name)?;
        
        let mut compressed_bytes = Vec::new();
        file_in_archive.read_to_end(&mut compressed_bytes)?;

        // --- [核心逻辑] ---
        // 使用 zstd 库解压缩
        let decompressed_bytes = zstd::decode_all(&compressed_bytes[..])
            .with_context(|| format!("解压缩文件 {} 失败", db_name))?;
        // --- [核心逻辑结束] ---

        let target_path = temp_dir.join("collection.anki21");
        fs::write(&target_path, &decompressed_bytes)
            .with_context(|| format!("无法将解压后的数据写入 {}", target_path.display()))?;

        println!("成功解压并创建数据库: {}", target_path.display());
        return Ok(target_path); // 返回新创建的、可用的数据库路径

    } else if let Some(db_name) = anki2_path {
        // 最低优先级：使用旧的 .anki2
        println!("找到旧版数据库文件: {}", &db_name);
        let outpath = temp_dir.join(&db_name);
        let mut file_in_archive = archive.by_name(&db_name)?;
        let mut outfile = fs::File::create(&outpath)?;
        std::io::copy(&mut file_in_archive, &mut outfile)?;
        return Ok(outpath);
    }
    
    Err(anyhow!("在 .apkg 文件中未找到任何有效的数据库文件"))
}

/// 将 Anki 笔记字段向量转换为 WordData 结构
fn fields_to_word_data(fields: &[&str]) -> WordData {
    let get_field = |i: usize| fields.get(i).map(|s| s.to_string());
    
    // 从serde_json::Value转换回字符串或数字
    let get_json_value = |i: usize| {
        fields.get(i).and_then(|s| {
            if s.is_empty() {
                None
            } else {
                match serde_json::from_str(s) {
                    Ok(val) => Some(val),
                    Err(_) => Some(serde_json::Value::String(s.to_string())),
                }
            }
        })
    };

    WordData {
        name: get_field(0),
        chn: get_field(5),
        symbol: get_field(4),
        unit: get_json_value(3),
        grade: get_json_value(2),
        difficulty: get_json_value(14),
        example_en: get_field(7),
        example_cn: get_field(11),
        word_family: get_field(12),
        memory_tips: get_field(13),
        collocations: get_field(15),
        // 以下字段无法从笔记中恢复，但为了结构完整性保留
        audio: None,
        audio_example: None,
        image: None,
        image_prompt: None,
        image_taskid: None,
    }
}


/// 清理来自 Anki 的文本，将其转换为 md 命令所需的格式
fn clean_anki_text(text_opt: &Option<String>) -> String {
    match text_opt {
        Some(text) => text
            .trim()
            .replace("<br>", "¶") // anki的换行是<br>
            .replace("<br />", "¶")
            .replace('\n', "¶"),
        None => "N/A".to_string(),
    }
}


/// 将单个 WordData 格式化为 Markdown 表格的一行
fn format_word_to_markdown_row(word: &WordData) -> String {
    let cleaned_chn = clean_anki_text(&word.chn);
    let cleaned_word_family = clean_anki_text(&word.word_family);
    let cleaned_collocations = clean_anki_text(&word.collocations);
    let cleaned_example_en = clean_anki_text(&word.example_en);
    let cleaned_example_cn = clean_anki_text(&word.example_cn);

    let word_name = word.name.as_deref().unwrap_or("");
    let audio_word = word_name.trim_start_matches('*').trim();
    let audio_example_en = clean_anki_text(&word.example_en);

    format!(
        "| {} | -- {} : {} . ¶{}¶{}¶{}¶{} --^^audio: {} . {} ^^|\n",
        cleaned_chn,
        word_name,
        word.symbol.as_deref().unwrap_or(""),
        cleaned_word_family,
        cleaned_collocations,
        cleaned_example_en,
        cleaned_example_cn,
        audio_word,
        audio_example_en
    )
}