#!/usr/bin/env python3
import os
import sys
import json
import glob
import random
from pathlib import Path
import genanki

def load_model_template(template_path):
    """加载Anki模型模板"""
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"错误: 模板文件不存在 {template_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"错误: 模板文件JSON解析失败 {template_path}: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"错误: 加载模板失败 {template_path}: {e}")
        sys.exit(1)

def create_genanki_model(model_template):
    """根据模板创建genanki模型"""
    try:
        model = genanki.Model(
            model_template['id'],
            model_template['name'],
            fields=[{'name': f['name']} for f in model_template['flds']],
            templates=[
                {
                    'name': t['name'],
                    'qfmt': t['qfmt'],
                    'afmt': t['afmt'],
                } for t in model_template['tmpls']
            ],
            css=model_template.get('css', ''),
            model_type=genanki.Model.CLOZE if model_template.get('type') == 1 else genanki.Model.FRONT_BACK
        )
        return model
    except KeyError as e:
        print(f"错误: 模型创建失败，缺少必要字段 {e}")
        sys.exit(1)
    except Exception as e:
        print(f"错误: 创建Anki模型失败: {e}")
        sys.exit(1)

def process_word_files(model, json_dir, media_dirs, deck, media_files):
    """处理单词JSON文件"""
    if not json_dir.exists():
        print(f"警告: 单词JSON目录不存在 {json_dir}")
        return
    
    word_files = glob.glob(str(json_dir / "*.json"))
    print(f"找到 {len(word_files)} 个单词文件")
    
    for word_file in word_files:
        try:
            with open(word_file, 'r', encoding='utf-8') as f:
                word_data = json.load(f)
            
            # 处理媒体文件
            current_media = []
            audio_filename = word_data.get('audio')
            if audio_filename:
                audio_path = media_dirs['audio'] / audio_filename
                if audio_path.exists():
                    current_media.append(str(audio_path))
                else:
                    print(f"警告: 音频文件不存在 {audio_path}")
                    audio_filename = None
            
            example_audio_filename = word_data.get('audio_example')
            if example_audio_filename:
                example_audio_path = media_dirs['audio'] / example_audio_filename
                if example_audio_path.exists():
                    current_media.append(str(example_audio_path))
                else:
                    print(f"警告: 例句音频文件不存在 {example_audio_path}")
                    example_audio_filename = None
            
            image_filename = word_data.get('image')
            if image_filename:
                image_path = media_dirs['images'] / image_filename
                if image_path.exists():
                    current_media.append(str(image_path))
                else:
                    print(f"警告: 图片文件不存在 {image_path}")
                    image_filename = None
            
            # 创建字段列表 - 共51个字段
            fields = [
                str(word_data.get('name', '')),        # 0: name
                str(''),                               # 1: 个人笔记
                str(word_data.get('grade', '')),       # 2: grade
                str(word_data.get('unit', '')),        # 3: unit
                str(word_data.get('symbol', '')),      # 4: symbol
                str(word_data.get('chn', '')),         # 5: chn
                f'<img src="{image_filename}">' if image_filename else '',  # 6: photo
                str(word_data.get('example_en', '')),   # 7: example_en
                f'[sound:{example_audio_filename}]' if example_audio_filename else '',  # 8: ssound
                f'[sound:{audio_filename}]' if audio_filename else '',  # 9: audio
                str(''),                               # 10: Photo2
                str(word_data.get('example_cn', '')),   # 11: example_cn
                str(word_data.get('word_family', '')),  # 12: word_family
                str(word_data.get('memory_tips', '')),  # 13: memory_tips
                str(word_data.get('difficulty', '')),   # 14: difficulty
                str(word_data.get('collocations', '')), # 15: collocations
                # 剩余字段保持为空
                *[''] * 35
            ]
            
            # 添加笔记
            note = genanki.Note(model=model, fields=fields)
            deck.add_note(note)
            media_files.update(current_media)
            print(f"添加单词: {word_data.get('name', '')}")
            
        except json.JSONDecodeError as e:
            print(f"错误: JSON解析失败 {word_file}: {e}")
        except Exception as e:
            print(f"错误: 处理单词文件失败 {word_file}: {e}")

def process_recite_files(model, json_dir, media_dirs, deck, media_files):
    """处理背诵JSON文件"""
    if not json_dir.exists():
        print(f"警告: 背诵JSON目录不存在 {json_dir}")
        return
    
    recite_files = glob.glob(str(json_dir / "*.json"))
    print(f"找到 {len(recite_files)} 个背诵文件")
    
    for recite_file in recite_files:
        try:
            with open(recite_file, 'r', encoding='utf-8') as f:
                recite_data = json.load(f)
            
            # 处理媒体文件
            current_media = []
            
            # 处理音频文件
            audio_fields = {}
            for i in range(10):
                audio_key = f'audio{i}' if i > 0 else 'audio'
                audio_file = recite_data.get(audio_key, '')
                if audio_file:
                    audio_path = media_dirs['audio'] / audio_file
                    if audio_path.exists():
                        current_media.append(str(audio_path))
                        audio_fields[audio_key] = audio_file
                    else:
                        print(f"警告: 音频文件不存在 {audio_path}")
                        audio_fields[audio_key] = ''
                else:
                    audio_fields[audio_key] = ''
            
            # 处理图片文件
            image_file = recite_data.get('image', '')
            if image_file:
                image_path = media_dirs['images'] / image_file
                if image_path.exists():
                    current_media.append(str(image_path))
                else:
                    print(f"警告: 图片文件不存在 {image_path}")
                    image_file = ''
            
            # 创建字段列表 - 共51个字段
            fields = [
                # 前16个字段为单词字段，保持为空
                *[''] * 16,
                # 背诵相关字段
                str(recite_data.get('name', '')),      # 16: Name
                str(recite_data.get('author', '')),    # 17: Author
                str(recite_data.get('text', '').replace('\n', '<br>')),  # 18: Text
                str(recite_data.get('hint', '').replace('\n', '<br>')),  # 19: Hint <-- 已修正
                f'[sound:{audio_fields["audio"]}]',    # 20: Audio
                # Text1-Hint1-Audio1 到 Text9-Hint9-Audio9
                str(recite_data.get('text1', '').replace('\n', '<br>')),  # 21: Text1
                str(recite_data.get('hint1', '').replace('\n', '<br>')),  # 22: Hint1
                f'[sound:{audio_fields["audio1"]}]',   # 23: Audio1
                str(recite_data.get('text2', '').replace('\n', '<br>')),  # 24: Text2
                str(recite_data.get('hint2', '').replace('\n', '<br>')),  # 25: Hint2
                f'[sound:{audio_fields["audio2"]}]',   # 26: Audio2
                str(recite_data.get('text3', '').replace('\n', '<br>')),  # 27: Text3
                str(recite_data.get('hint3', '').replace('\n', '<br>')),  # 28: Hint3
                f'[sound:{audio_fields["audio3"]}]',   # 29: Audio3
                str(recite_data.get('text4', '').replace('\n', '<br>')),  # 30: Text4
                str(recite_data.get('hint4', '').replace('\n', '<br>')),  # 31: Hint4
                f'[sound:{audio_fields["audio4"]}]',   # 32: Audio4
                str(recite_data.get('text5', '').replace('\n', '<br>')),  # 33: Text5
                str(recite_data.get('hint5', '').replace('\n', '<br>')),  # 34: Hint5
                f'[sound:{audio_fields["audio5"]}]',   # 35: Audio5
                str(recite_data.get('text6', '').replace('\n', '<br>')),  # 36: Text6
                str(recite_data.get('hint6', '').replace('\n', '<br>')),  # 37: Hint6
                f'[sound:{audio_fields["audio6"]}]',   # 38: Audio6
                str(recite_data.get('text7', '').replace('\n', '<br>')),  # 39: Text7
                str(recite_data.get('hint7', '').replace('\n', '<br>')),  # 40: Hint7
                f'[sound:{audio_fields["audio7"]}]',   # 41: Audio7
                str(recite_data.get('text8', '').replace('\n', '<br>')),  # 42: Text8
                str(recite_data.get('hint8', '').replace('\n', '<br>')),  # 43: Hint8
                f'[sound:{audio_fields["audio8"]}]',   # 44: Audio8
                str(recite_data.get('text9', '').replace('\n', '<br>')),  # 45: Text9
                str(recite_data.get('hint9', '').replace('\n', '<br>')),  # 46: Hint9
                f'[sound:{audio_fields["audio9"]}]',   # 47: Audio9
                str(recite_data.get('translate', '').replace('\n', '<br>')),  # 48: Translate
                f'<img src="{image_file}">' if image_file else '',  # 49: Image
                str(recite_data.get('imageprompt', ''))  # 50: ImagePrompt
            ]
            
            # 添加笔记
            note = genanki.Note(model=model, fields=fields)
            deck.add_note(note)
            media_files.update(current_media)
            print(f"添加背诵: {recite_data.get('name', '')}")
            
        except json.JSONDecodeError as e:
            print(f"错误: JSON解析失败 {recite_file}: {e}")
        except Exception as e:
            print(f"错误: 处理背诵文件失败 {recite_file}: {e}")

def main():
    # 检查参数
    if len(sys.argv) < 2:
        print("使用方法: python combined_anki_generator.py <目录路径>")
        print("目录结构应包含:")
        print("  /word_json - 单词JSON文件")
        print("  /recite_json - 背诵JSON文件")
        print("  /audio - 音频文件")
        print("  /images - 图片文件")
        sys.exit(1)
    
    base_dir = Path(sys.argv[1]).resolve()
    deck_name = base_dir.name
    
    # 配置路径
    word_json_dir = base_dir / "word_json"
    recite_json_dir = base_dir / "recite_json"
    audio_dir = base_dir / "audio"
    images_dir = base_dir / "images"
    output_file = base_dir / f"{deck_name}_Deck.apkg"
    
    # 确保目录存在
    for d in [word_json_dir, recite_json_dir, audio_dir, images_dir]:
        if not d.exists():
            print(f"创建目录: {d}")
            d.mkdir(parents=True, exist_ok=True)
    
    # 加载模板
    template_path = Path(__file__).parent / "template/ankimodel.json"
    if not template_path.exists():
        print(f"错误: 模板文件不存在 {template_path}")
        sys.exit(1)
    
    model_template = load_model_template(template_path)
    model = create_genanki_model(model_template)
    
    # 创建牌组
    deck_id = random.randrange(1 << 30, 1 << 31)
    deck = genanki.Deck(deck_id, f"{deck_name} 综合学习")
    
    # 媒体文件集合
    media_files = set()
    media_dirs = {'audio': audio_dir, 'images': images_dir}
    
    # 处理单词文件
    process_word_files(model, word_json_dir, media_dirs, deck, media_files)
    
    # 处理背诵文件
    process_recite_files(model, recite_json_dir, media_dirs, deck, media_files)
    
    # 生成Anki包
    if not deck.notes:
        print("错误: 没有找到可用的笔记，请检查JSON文件")
        sys.exit(1)
    
    print(f"正在生成Anki包，包含 {len(deck.notes)} 张卡片...")
    
    try:
        package = genanki.Package(deck)
        package.media_files = list(media_files)
        package.write_to_file(str(output_file))
        print(f"成功生成Anki包: {output_file}")
    except Exception as e:
        print(f"错误: 生成Anki包失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()