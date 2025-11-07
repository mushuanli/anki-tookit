// src/modules/pack.rs

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use genanki_rs::{Deck, Field, Model, Note, Package, Template};
use glob::glob;
use rand::Rng;
use serde_json::Value;

// 导入在项目其他文件中定义的结构
use crate::cli::PackArgs;
use crate::models::{AnkiModelTemplate, ReciteData, WordData};

/// “pack” 子命令的公共处理函数
///
/// 这是此模块的入口点，由 main.rs 调用。
pub fn handle_pack_command(args: PackArgs) -> Result<()> {
    let base_dir = args
        .pack_dir
        .canonicalize()
        .with_context(|| format!("错误: 无法解析目录路径 {}", args.pack_dir.display()))?;
    let deck_name = base_dir.file_name().and_then(|s| s.to_str()).unwrap_or("UnnamedDeck");

    // 配置路径
    let word_json_dir = base_dir.join("word_json");
    let recite_json_dir = base_dir.join("recite_json");
    let audio_dir = base_dir.join("audio");
    let images_dir = base_dir.join("images");
    let output_file = base_dir.join(format!("{}_Deck.apkg", deck_name));

    // 确保媒体目录存在 (如果不存在则创建)
    for dir in [&audio_dir, &images_dir] {
        if !dir.exists() {
            println!("创建目录: {}", dir.display());
            fs::create_dir_all(dir)?;
        }
    }

    // 加载模板
    let template_path = &args.template;
    if !template_path.exists() {
        return Err(anyhow!("错误: 模板文件 {} 不存在", template_path.display()));
    }
    let model_template = load_model_template(template_path)?;
    let model = create_genanki_model(model_template);

    // 创建牌组
    let deck_id: i64 = rand::thread_rng().gen_range(1..i64::MAX);
    let mut deck = Deck::new(deck_id, &format!("{} 综合学习", deck_name), "");

    // 媒体文件集合和笔记计数器
    let mut media_files: HashSet<PathBuf> = HashSet::new();
    let mut note_count = 0;

    // 处理文件
    process_word_files(&model, &word_json_dir, (&audio_dir, &images_dir), &mut deck, &mut media_files, &mut note_count)?;
    process_recite_files(&model, &recite_json_dir, (&audio_dir, &images_dir), &mut deck, &mut media_files, &mut note_count)?;

    // 检查是否有笔记被添加
    if note_count == 0 {
        return Err(anyhow!("错误: 没有找到可用的笔记，请检查JSON文件"));
    }
    println!("正在生成Anki包，包含 {} 张卡片...", note_count);

    // 打包
    let media_files_vec: Vec<PathBuf> = media_files.into_iter().collect();
    let media_files_str: Vec<&str> = media_files_vec.iter().filter_map(|p| p.to_str()).collect();
    let mut package = Package::new(vec![deck], media_files_str)?;
    package.write_to_file(output_file.to_str().context("输出路径包含无效字符")?)?;
    println!("成功生成Anki包: {}", output_file.display());

    Ok(())
}

// --- 以下是所有的辅助函数，它们是此模块的私有实现细节 ---

/// 加载并解析 ankimodel.json 模板
fn load_model_template(path: &Path) -> Result<AnkiModelTemplate> {
    let file = File::open(path).with_context(|| format!("错误: 无法打开模板文件 {}", path.display()))?;
    let reader = BufReader::new(file);
    let template: AnkiModelTemplate = serde_json::from_reader(reader)
        .with_context(|| format!("错误: 模板文件JSON解析失败 {}", path.display()))?;
    Ok(template)
}

/// 根据模板创建 genanki-rs 模型
fn create_genanki_model(template: AnkiModelTemplate) -> Model {
    let fields = template.flds.into_iter().map(|f| Field::new(&f.name)).collect();
    let templates = template.tmpls.into_iter().map(|t| Template::new(&t.name).qfmt(&t.qfmt).afmt(&t.afmt)).collect();
    let is_cloze = template.model_type.unwrap_or(0) == 1;
    let css = template.css;

    Model::new_with_options(
        template.id,
        &template.name,
        fields,
        templates,
        css.as_deref(),
        None,
        None,
        Some(if is_cloze { "1" } else { "0" }),
        None,
    )
}

/// 处理单词JSON文件
fn process_word_files(
    model: &Model,
    json_dir: &Path,
    media_dirs: (&Path, &Path),
    deck: &mut Deck,
    media_files: &mut HashSet<PathBuf>,
    note_count: &mut usize,
) -> Result<()> {
    if !json_dir.exists() {
        println!("警告: 单词JSON目录不存在 {}", json_dir.display());
        return Ok(());
    }

    let pattern = json_dir.join("*.json");
    let word_files: Vec<_> = glob(pattern.to_str().unwrap_or_default())?.filter_map(Result::ok).collect();
    if !word_files.is_empty() {
        println!("找到 {} 个单词文件", word_files.len());
    }

    for word_file in word_files {
        let file = File::open(&word_file)?;
        let data: WordData = match serde_json::from_reader(BufReader::new(file)) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("错误: JSON解析失败 {}: {}", word_file.display(), e);
                continue;
            }
        };

        let mut current_media: Vec<PathBuf> = Vec::new();
        let audio_filename = check_media_file(data.audio, media_dirs.0, "音频", &mut current_media);
        let example_audio_filename = check_media_file(data.audio_example, media_dirs.0, "例句音频", &mut current_media);
        let image_filename = check_media_file(data.image, media_dirs.1, "图片", &mut current_media);
        
        let value_to_string = |v: Option<Value>| {
            v.map_or(String::new(), |val| val.to_string().trim_matches('"').to_string())
        };

        let mut fields = vec![String::new(); 51];
        fields[0] = data.name.unwrap_or_default();
        fields[2] = value_to_string(data.grade);
        fields[3] = value_to_string(data.unit);
        fields[4] = data.symbol.unwrap_or_default();
        fields[5] = data.chn.unwrap_or_default();
        fields[6] = image_filename.map(|f| format!(r#"<img src="{}">"#, f)).unwrap_or_default();
        fields[7] = data.example_en.unwrap_or_default();
        fields[8] = example_audio_filename.map(|f| format!("[sound:{}]", f)).unwrap_or_default();
        fields[9] = audio_filename.map(|f| format!("[sound:{}]", f)).unwrap_or_default();
        fields[11] = data.example_cn.unwrap_or_default();
        fields[12] = data.word_family.unwrap_or_default();
        fields[13] = data.memory_tips.unwrap_or_default();
        fields[14] = value_to_string(data.difficulty);
        fields[15] = data.collocations.unwrap_or_default();
        
        let fields_str: Vec<&str> = fields.iter().map(AsRef::as_ref).collect();
        let note = Note::new(model.clone(), fields_str)?;
        deck.add_note(note);
        *note_count += 1;
        media_files.extend(current_media);
        println!("添加单词: {}", &fields[0]);
    }

    Ok(())
}

/// 处理背诵JSON文件
fn process_recite_files(
    model: &Model,
    json_dir: &Path,
    media_dirs: (&Path, &Path),
    deck: &mut Deck,
    media_files: &mut HashSet<PathBuf>,
    note_count: &mut usize,
) -> Result<()> {
    if !json_dir.exists() {
        println!("警告: 背诵JSON目录不存在 {}", json_dir.display());
        return Ok(());
    }

    let pattern = json_dir.join("*.json");
    let recite_files: Vec<_> = glob(pattern.to_str().unwrap_or_default())?.filter_map(Result::ok).collect();
    if !recite_files.is_empty() {
        println!("找到 {} 个背诵文件", recite_files.len());
    }

    for recite_file in recite_files {
        let file = File::open(&recite_file)?;
        let data: ReciteData = match serde_json::from_reader(BufReader::new(file)) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("错误: JSON解析失败 {}: {}", recite_file.display(), e);
                continue;
            }
        };

        let mut current_media: Vec<PathBuf> = Vec::new();
        let replace_br = |s: Option<String>| s.unwrap_or_default().replace('\n', "<br>");

        let audios = [
            check_media_file(data.audio, media_dirs.0, "音频", &mut current_media),
            check_media_file(data.audio1, media_dirs.0, "音频1", &mut current_media),
            check_media_file(data.audio2, media_dirs.0, "音频2", &mut current_media),
            check_media_file(data.audio3, media_dirs.0, "音频3", &mut current_media),
            check_media_file(data.audio4, media_dirs.0, "音频4", &mut current_media),
            check_media_file(data.audio5, media_dirs.0, "音频5", &mut current_media),
            check_media_file(data.audio6, media_dirs.0, "音频6", &mut current_media),
            check_media_file(data.audio7, media_dirs.0, "音频7", &mut current_media),
            check_media_file(data.audio8, media_dirs.0, "音频8", &mut current_media),
            check_media_file(data.audio9, media_dirs.0, "音频9", &mut current_media),
        ];

        let image_filename = check_media_file(data.image, media_dirs.1, "图片", &mut current_media);

        let mut fields = vec![String::new(); 51];
        fields[16] = data.name.clone().unwrap_or_default();
        fields[17] = data.author.unwrap_or_default();
        fields[18] = replace_br(data.text);
        fields[19] = replace_br(data.hint);
        fields[20] = audios[0].as_ref().map_or(String::new(), |f| format!("[sound:{}]", f));
        fields[21] = replace_br(data.text1);
        fields[22] = replace_br(data.hint1);
        fields[23] = audios[1].as_ref().map_or(String::new(), |f| format!("[sound:{}]", f));
        fields[24] = replace_br(data.text2);
        fields[25] = replace_br(data.hint2);
        fields[26] = audios[2].as_ref().map_or(String::new(), |f| format!("[sound:{}]", f));
        fields[27] = replace_br(data.text3);
        fields[28] = replace_br(data.hint3);
        fields[29] = audios[3].as_ref().map_or(String::new(), |f| format!("[sound:{}]", f));
        fields[30] = replace_br(data.text4);
        fields[31] = replace_br(data.hint4);
        fields[32] = audios[4].as_ref().map_or(String::new(), |f| format!("[sound:{}]", f));
        fields[33] = replace_br(data.text5);
        fields[34] = replace_br(data.hint5);
        fields[35] = audios[5].as_ref().map_or(String::new(), |f| format!("[sound:{}]", f));
        fields[36] = replace_br(data.text6);
        fields[37] = replace_br(data.hint6);
        fields[38] = audios[6].as_ref().map_or(String::new(), |f| format!("[sound:{}]", f));
        fields[39] = replace_br(data.text7);
        fields[40] = replace_br(data.hint7);
        fields[41] = audios[7].as_ref().map_or(String::new(), |f| format!("[sound:{}]", f));
        fields[42] = replace_br(data.text8);
        fields[43] = replace_br(data.hint8);
        fields[44] = audios[8].as_ref().map_or(String::new(), |f| format!("[sound:{}]", f));
        fields[45] = replace_br(data.text9);
        fields[46] = replace_br(data.hint9);
        fields[47] = audios[9].as_ref().map_or(String::new(), |f| format!("[sound:{}]", f));
        fields[48] = replace_br(data.translate);
        fields[49] = image_filename.map_or(String::new(), |f| format!(r#"<img src="{}">"#, f));
        fields[50] = data.imageprompt.unwrap_or_default();
        
        let fields_str: Vec<&str> = fields.iter().map(AsRef::as_ref).collect();
        let note = Note::new(model.clone(), fields_str)?;
        deck.add_note(note);
        *note_count += 1;
        media_files.extend(current_media);
        println!("添加背诵: {}", data.name.unwrap_or_else(|| "无标题".to_string()));
    }
    Ok(())
}

/// 辅助函数：检查媒体文件是否存在并返回其文件名
fn check_media_file(filename_opt: Option<String>, media_dir: &Path, file_type: &str, media_list: &mut Vec<PathBuf>) -> Option<String> {
    filename_opt.and_then(|filename| {
        if filename.is_empty() { return None; }
        let path = media_dir.join(&filename);
        if path.exists() {
            media_list.push(path);
            Some(filename)
        } else {
            eprintln!("警告: {}文件不存在 {}", file_type, path.display());
            None
        }
    })
}