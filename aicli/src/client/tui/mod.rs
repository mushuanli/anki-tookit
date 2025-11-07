// src/client/tui/mod.rs

use crate::error::Result;
//use crate::common::protocol::{parse_chat_file, format_chat_log}; // <-- 修改这里，添加 format_chat_log
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
    text::Text,
};
use std::{io, sync::Arc, time::Duration};
use tokio::sync::{mpsc, Mutex};
//use ratatui_textarea::TextArea;

// MODIFIED: Use shared constants from the cli module
//use super::cli::{SERVER_ADDR, CLIENT_USERNAME, USER_PRIVATE_KEY_PATH};
use super::actions::{handle_network_action, handle_local_action}; // <-- ADD THIS LINE

//use crate::client::network::NetworkClient;
//use crate::client::local_store::SyncStatus; // Add this
//use crate::client::network::RemoteTask; // Add this import

use self::{
    app::{App, AppMode},
    ui::draw,
    action::Action,
//    log_widget::{LogEntry, LogView},
};

pub mod app;
pub mod ui;
pub mod action;
mod log_widget; // 新增: 导入日志控件模块

pub async fn run() -> Result<()> {
    // 初始化TUI日志系统 - 确保全局通道已设置
    log_widget::init_global_log_channel();
    
    // 创建TUI日志处理器并安装
    let tui_logger = log_widget::TuiLogger::new(log::Level::Info);
    if let Err(e) = tui_logger.install() {
        eprintln!("Failed to install TUI logger: {}", e);
        // 继续执行，即使日志重定向失败
    }
    
    // 创建日志视图和管理器
    let log_manager = log_widget::TuiLogManager::new();
    let mut log_view = log_widget::LogView::new(100);
    
    // 记录TUI启动日志
    log::info!("TUI mode started"); 
    
    // 创建Tui实例
    let mut tui = Tui::new()?;
    // Then, call methods on the now-owned struct.
    tui.enter()?;
    
    // 创建一个用于 action 的通道
    let (tx, mut rx) = mpsc::unbounded_channel::<Action>();

    // Create App state
    let app = Arc::new(Mutex::new(App::new()?));

    // 初始刷新
    tx.send(Action::Refresh).ok();

    // Main loop
    loop {
        // 处理日志
        log_manager.process_logs_to(&mut log_view);
        
        let mut app_lock = app.lock().await;
        
        // 绘制界面，包括应用和日志视图
        tui.terminal.draw(|f| {
            let screen_size = f.size();
                
            // 创建一个三段式布局：主应用区域、状态/帮助区域、日志区域
            let main_layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    // --- 修改这里 ---
                    // 将 Min(10) 改为 Min(0)，使其能够灵活适应屏幕大小
                    Constraint::Min(0),          // 应用主界面区域 (填充所有剩余空间)
                    // --- 修改结束 ---
                    Constraint::Length(3),       // 状态和帮助区域
                    Constraint::Length(8),       // 日志区域，固定高度
                ])
                .split(screen_size);
            
            // 主应用区域，传递给draw函数
            draw(f, &mut app_lock, main_layout[0]);
            
            // 状态和帮助信息区域 - 这部分需要从原来draw函数中分离出来
            // 可能需要修改app模块中的draw函数，让它不再负责绘制状态栏
            if app_lock.mode == AppMode::TaskList {
                let status_help_layout = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([
                        Constraint::Percentage(50),  // 状态区域
                        Constraint::Percentage(50),  // 帮助区域
                    ])
                    .split(main_layout[1]);
                
                // 绘制状态信息
                if let Some(msg) = &app_lock.status_message {
                    let status_block = Block::default()
                        .title(" Status ")
                        .borders(Borders::ALL)
                        .border_type(ratatui::widgets::BorderType::Rounded); // 添加圆角让UI更美观
                    let status_text = Paragraph::new(Text::from(msg.clone()))
                        .block(status_block)
                        .wrap(Wrap { trim: true });
                    f.render_widget(status_text, status_help_layout[0]);
                }
                
                // 绘制帮助信息
                // 可以为帮助信息提供更详细的上下文
                let help_text = match app_lock.get_selected_session() {
                    Some(_) => "[q]uit | [j/k]nav | [n]ew | [r]efresh | [a]ppend | [e]dit | [d]elete | [s]ync",
                    None => "[q]uit | [n]ew | [r]efresh",
                };
                let help_block = Block::default()
                    .title(" Help ")
                    .borders(Borders::ALL)
                    .border_type(ratatui::widgets::BorderType::Rounded);
                let help_widget = Paragraph::new(Text::from(help_text))
                    .block(help_block)
                    .wrap(Wrap { trim: true });
                f.render_widget(help_widget, status_help_layout[1]);
            }
            
            // 日志区域 - 清晰分隔的独立区域
            f.render_widget(log_view.widget(), main_layout[2]);
        })?;
        if app_lock.should_quit {
            break;
        }
        
        // Handle events and actions
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                // FIX: get_action_for_key needs a mutable lock
                if let Some(action) = app_lock.get_action_for_key(key) {
                    // FIX: Handle potential send error
                    tx.send(action).ok();
                }
            }
        }

        if let Ok(action) = rx.try_recv() {
            // Only update needs a mutable lock
            app_lock.update(action.clone());
            // Drop the lock before spawning a task to avoid deadlocks
            drop(app_lock);
            
            // --- FIX HERE: Correctly identify all network and local actions ---
            
            let is_network_action = matches!(action,
                Action::Refresh |
                Action::DeleteTask(_) |
                Action::SaveEdit |
                Action::SendNewTask(_) |
                Action::SendAppendedPrompt { .. } | // <-- ADD THIS LINE
                Action::SyncSelected { .. }
            );

            let is_local_action = matches!(action,
                Action::StartEdit(_) |
                Action::ViewTask(_) |             // <-- ADD THIS LINE
                Action::EnterAppendPrompt(_)      // <-- ADD THIS LINE
            );

            if is_network_action {
                let app_clone = app.clone();
                let tx_clone = tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_network_action(action, app_clone.clone(), tx_clone).await {
                        let mut app = app_clone.lock().await;
                        app.status_message = Some(format!("Network Error: {}", e));
                        log::error!("Network action failed: {}", e);
                    }
                });
            } else if is_local_action {
                let app_clone = app.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_local_action(action, app_clone.clone()).await {
                        let mut app = app_clone.lock().await;
                        app.status_message = Some(format!("Local Error: {}", e));
                        log::error!("Local action failed: {}", e);
                    }
                });
            }
        }
        
        // 再次处理日志，确保循环中新产生的日志被捕获
        log_manager.process_logs_to(&mut log_view);
    }

    tui.exit()?;
    Ok(())
}


// --- TUI Boilerplate Helper ---
struct Tui {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}
impl Tui {
    fn new() -> Result<Self> {
        let backend = CrosstermBackend::new(io::stdout());
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }
    fn enter(&mut self) -> Result<()> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
        Ok(())
    }
    fn exit(&mut self) -> Result<()> {
        disable_raw_mode()?;
        execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
        self.terminal.show_cursor()?;
        Ok(())
    }
}
