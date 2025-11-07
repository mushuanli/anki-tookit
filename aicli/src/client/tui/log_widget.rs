// src/client/tui/log_widget.rs

use std::collections::VecDeque;
use log::{Record, Level, Metadata, Log, LevelFilter}; 
use chrono::Local;
use ratatui::widgets::{Block, Borders, List, ListItem};
use ratatui::text::Span;
use ratatui::style::{Style, Color,Modifier};
use flume::{Sender, Receiver}; // 使用 flume 替代 std::sync::mpsc
use std::sync::{Arc, Mutex, Once};
use once_cell::sync::OnceCell;

// 定义一个结构来保存日志条目
#[derive(Clone, Debug)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: Level,
    pub message: String,
}

// 用于 TUI 中显示的日志视图组件
pub struct LogView {
    max_entries: usize,
    entries: VecDeque<LogEntry>,
}

impl LogView {
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries,
            entries: VecDeque::with_capacity(max_entries),
        }
    }
    
    pub fn add_entry(&mut self, entry: LogEntry) {
        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    // 创建 ratatui 的 List 控件
pub fn widget(&self) -> impl ratatui::widgets::Widget + '_ {
        let items: Vec<ListItem> = self.entries.iter()
            .map(|entry| {
                let color = match entry.level {
                    Level::Error => Color::Red,
                    Level::Warn => Color::Yellow,
                    Level::Info => Color::Green,
                    Level::Debug => Color::Blue,
                    Level::Trace => Color::Gray,
                };

                // 使用 Line 和 Span 
                let content = ratatui::text::Line::from(vec![
                    Span::styled(format!("{} ", entry.timestamp), Style::default().fg(Color::DarkGray)), // 将灰色调暗一点，对比更柔和
                    Span::styled(format!("[{}] ", entry.level), Style::default().fg(color).add_modifier(Modifier::BOLD)), // 给级别加粗
                    Span::raw(&entry.message), // 这部分将使用终端默认颜色
                ]);

                ListItem::new(content)
            })
            .collect();
        
        // 使用更明显的边框和标题
        List::new(items)
            .block(Block::default()
                .borders(Borders::ALL)
                .title(" 📝 Logs ")
                .border_type(ratatui::widgets::BorderType::Rounded))
            .highlight_style(Style::default().add_modifier(ratatui::style::Modifier::BOLD))
            // 添加滚动条样式，使日志区域更直观
            //.style(Style::default().fg(Color::White))
    }
}

// 全局日志通道
static LOG_CHANNEL: OnceCell<(Sender<LogEntry>, Receiver<LogEntry>)> = OnceCell::new();

// 初始化全局日志通道 - 在main函数开始时调用
pub fn init_global_log_channel() {
    if LOG_CHANNEL.get().is_none() {
        let (sender, receiver) = flume::unbounded();
        let _ = LOG_CHANNEL.set((sender, receiver));
    }
}

// 日志管理器
pub struct TuiLogManager {
    receiver: Receiver<LogEntry>,
}

impl TuiLogManager {
    pub fn new() -> Self {
        // 确保全局通道已初始化
        init_global_log_channel();
        
        // 从全局通道获取接收器
        let receiver = LOG_CHANNEL.get()
            .expect("Log channel should be initialized")
            .1
            .clone(); // flume的Receiver可以被克隆
        
        Self { receiver }
    }
    
    pub fn process_logs_to(&self, log_view: &mut LogView) {
        // 尽可能多地处理日志
        while let Ok(entry) = self.receiver.try_recv() {
            log_view.add_entry(entry);
        }
    }
}

// TUI日志处理器
pub struct TuiLogger {
    sender: Sender<LogEntry>,
    level: LevelFilter,
}

impl TuiLogger {
    pub fn new(level: Level) -> Self {
        // 确保全局通道已初始化
        init_global_log_channel();
        
        // 从全局通道获取发送器
        let sender = LOG_CHANNEL.get()
            .expect("Log channel should be initialized")
            .0
            .clone();
        
        Self { 
            sender,
            level: level.to_level_filter(),
        }
    }
    
    // 安装日志处理器，仅在TUI模式下调用
    pub fn install(self) -> Result<(), log::SetLoggerError> {
        static INSTALL_ONCE: Once = Once::new();
        let level = self.level;
        let sender = self.sender;
        
        let result = Arc::new(Mutex::new(None));
        let result_clone = Arc::clone(&result);
        
        INSTALL_ONCE.call_once(|| {
            // 创建并设置日志处理器
            struct LoggerImpl {
                sender: Sender<LogEntry>,
                level: LevelFilter,
            }
            
            impl Log for LoggerImpl {
                fn enabled(&self, metadata: &Metadata) -> bool {
                    metadata.level() <= self.level
                }
                
                fn log(&self, record: &Record) {
                    if self.enabled(record.metadata()) {
                        let entry = LogEntry {
                            timestamp: Local::now().format("%H:%M:%S").to_string(),
                            level: record.level(),
                            message: format!("{}", record.args()),
                        };
                        
                        // 尝试发送，忽略错误
                        let _ = self.sender.send(entry);
                    }
                }
                
                fn flush(&self) {}
            }
            
            // 创建实例
            let logger = LoggerImpl { 
                sender,
                level,
            };
            
            // 设置全局日志处理器
            match log::set_boxed_logger(Box::new(logger)) {
                Ok(_) => {
                    log::set_max_level(level);
                    *result_clone.lock().unwrap() = None;
                },
                Err(e) => {
                    *result_clone.lock().unwrap() = Some(e);
                }
            }
        });
        
        // 解决result生命周期问题
        let error = {
            let mut lock = result.lock().unwrap();
            lock.take()
        };
        
        match error {
            Some(e) => Err(e),
            None => Ok(())
        }
    }
}
