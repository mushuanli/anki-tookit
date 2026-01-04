// src/tui/ui.rs
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect, Alignment},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Tabs, BorderType},
    Frame,
};
use crate::tui::state::{AppState, Focus, MainTab, PopupState, UserDetailTab, TokenInput};
use chrono::{DateTime, Utc};
use std::time::{UNIX_EPOCH, Duration};

pub fn draw_ui(f: &mut Frame, app: &mut AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header/Tabs
            Constraint::Min(0),    // Main Content
            Constraint::Length(1), // Footer/Status
        ].as_ref())
        .split(f.size());

    // 1. Top Tabs
    // Fix: 添加显式类型注解 Vec<Line>
    let tab_titles: Vec<Line> = vec![ " 1. Dashboard ", " 2. Users & Auth ", " 3. Logs " ]
        .iter().map(|&t| Line::from(t)).collect();
        
    let tabs = Tabs::new(tab_titles)
        .block(Block::default().borders(Borders::ALL).title(" Secure VFS Admin "))
        .select(app.tab as usize)
        .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    f.render_widget(tabs, chunks[0]);

    // 2. Main Area
    match app.tab {
        MainTab::Dashboard => draw_dashboard(f, app, chunks[1]),
        MainTab::Users => draw_users_tab(f, app, chunks[1]),
        MainTab::Logs => draw_logs_tab(f, app, chunks[1]),
    }

    // 3. Status Bar
    let status_style = if app.message.is_empty() { Style::default().fg(Color::DarkGray) } else { Style::default().fg(app.message_color) };
    let status_text = if app.message.is_empty() {
        // Updated global help message
        match app.tab {
            MainTab::Users => "'q': Quit | 'Tab': Switch Tab | 'r': Refresh | 'a': Add User | 'q': Quota | 'hjkl': Navigate".to_string(),
            _ => "'q': Quit | 'Tab': Switch Tab | 'r': Refresh".to_string(),
        }
    } else {
        app.message.clone()
    };
    f.render_widget(Paragraph::new(status_text).style(status_style), chunks[2]);

    // 4. Popups (Overlay)
    if app.popup != PopupState::None {
        draw_popup(f, app);
    }
}

fn draw_dashboard(f: &mut Frame, app: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    
    let stats_text = vec![
        Line::from(vec![Span::raw("Users:      "), Span::styled(app.stats.0.to_string(), Style::default().fg(Color::Green))]),
        Line::from(vec![Span::raw("Files:      "), Span::styled(app.stats.1.to_string(), Style::default().fg(Color::Blue))]),
        Line::from(vec![Span::raw("Tokens:     "), Span::styled(app.stats.2.to_string(), Style::default().fg(Color::Yellow))]),
        Line::from(vec![Span::raw("Storage:    "), Span::styled(format!("{:.2} MB", app.stats.3), Style::default().fg(Color::Magenta))]),
    ];
    let stats_block = Paragraph::new(stats_text)
        .block(Block::default().borders(Borders::ALL).title(" Overview "));
    f.render_widget(stats_block, chunks[0]);
}

fn draw_users_tab(f: &mut Frame, app: &mut AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(area);

    // --- Left: User List ---
    let items: Vec<ListItem> = app.users.iter().map(|u| {
        ListItem::new(format!("{: <12} | {:.1}MB", u.username, u.quota as f64 / 1024.0/1024.0))
    }).collect();

    let border_style = if app.focus == Focus::UserList { Style::default().fg(Color::Cyan) } else { Style::default() };
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Users (a: Add, q: Quota, d: Del) ").border_style(border_style))
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");
    f.render_stateful_widget(list, chunks[0], &mut app.user_list_state);

    // --- Right: Details Area ---
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(chunks[1]);

    // Detail Tabs
    // Fix: 添加显式类型注解 Vec<Line>
    let titles: Vec<Line> = vec!["[1] Profile", "[2] Tokens", "[3] IP Whitelist"]
        .iter().map(|&t| Line::from(t)).collect();
        
    let detail_tabs = Tabs::new(titles)
        .select(app.user_detail_tab as usize)
        .block(Block::default().borders(Borders::ALL).title(" Details ").border_style(
            if app.focus == Focus::DetailTabs { Style::default().fg(Color::Cyan) } else { Style::default() }
        ))
        .highlight_style(Style::default().fg(Color::Yellow));
    f.render_widget(detail_tabs, right_chunks[0]);

    // Detail Content
    let content_area = right_chunks[1];
    match app.user_detail_tab {
        UserDetailTab::Tokens => draw_token_list(f, app, content_area),
        UserDetailTab::IPs => {
             let ips: Vec<ListItem> = app.current_ips.iter().map(|i| ListItem::new(i.ip_cidr.clone())).collect();
             
             // [修改] 使用 render_stateful_widget 并添加高亮样式
             let border_style = if app.focus == Focus::DetailContent { Style::default().fg(Color::Cyan) } else { Style::default() };
             let list = List::new(ips)
                .block(Block::default().borders(Borders::ALL).title(" Allowed IPs (a: Add, d: Del) ").border_style(border_style))
                .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD));
             
             f.render_stateful_widget(list, content_area, &mut app.ip_list_state);
        },
        UserDetailTab::Profile => {
             if let Some(uid) = app.get_selected_user_id() {
                 // Display user ID and indicate actions available
                 let text = format!("User ID: {}\n\nSelect 'Tokens' tab to manage API Keys.\nSelect 'IP Whitelist' tab to manage allowed IPs.\n\n'q' to update quota.", uid);
                 f.render_widget(Paragraph::new(text).block(Block::default().borders(Borders::ALL)), content_area);
             } else {
                 f.render_widget(Paragraph::new("Select a user from the list.").block(Block::default().borders(Borders::ALL)), content_area);
             }
        }
    }
}

fn draw_token_list(f: &mut Frame, app: &mut AppState, area: Rect) {
    let items: Vec<ListItem> = app.current_tokens.iter().map(|t| {
        let perm_color = if t.perm == "rw" { Color::Green } else { Color::Yellow };
        
        // [新增] 格式化时间
        let d = UNIX_EPOCH + Duration::from_secs(t.created_at as u64);
        let datetime = DateTime::<Utc>::from(d);
        let time_str = datetime.format("%Y-%m-%d").to_string();

        let content = Line::from(vec![
            Span::raw(format!("{:<12} ", t.prefix)),
            Span::styled(format!("[{}] ", t.perm.to_uppercase()), Style::default().fg(perm_color)),
            Span::raw(format!("Scope: {:<8} | ", t.scope)),
            Span::styled(format!("{} ", time_str), Style::default().fg(Color::DarkGray)),
            Span::raw(format!("| Note: {}", t.note)),
        ]);
        ListItem::new(content)
    }).collect();

    let border_style = if app.focus == Focus::DetailContent { Style::default().fg(Color::Cyan) } else { Style::default() };
    
    let title = " API Tokens (n: New, d: Delete) ";
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title).border_style(border_style))
        .highlight_style(Style::default().bg(Color::DarkGray));
    
    f.render_stateful_widget(list, area, &mut app.token_list_state);
}

fn draw_logs_tab(f: &mut Frame, app: &mut AppState, area: Rect) {
    let items: Vec<ListItem> = app.logs.iter().map(|log| {
        // Status Color Coding
        let status_style = match log.status {
            200..=299 => Style::default().fg(Color::Green),
            400..=499 => Style::default().fg(Color::Yellow),
            500..=599 => Style::default().fg(Color::Red),
            _ => Style::default(),
        };

        // Time Formatting
        let d = UNIX_EPOCH + Duration::from_secs(log.timestamp as u64);
        let datetime = DateTime::<Utc>::from(d);
        let time_str = datetime.format("%H:%M:%S").to_string();

        // Display User ID if available
        let user_id_str = match log.user_id {
            Some(uid) => format!("#{}", uid),
            None => "-".to_string(),
        };

        let content = Line::from(vec![
            Span::styled(format!(" {:<8} ", time_str), Style::default().fg(Color::DarkGray)),
            Span::styled(format!(" {:<4} ", log.method), Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(format!(" {:<3} ", log.status), status_style),
            Span::raw(format!(" {:<30} ", log.path)),
            Span::styled(format!(" {:<15} ", log.ip), Style::default().fg(Color::Blue)),
            Span::styled(format!(" {:<5} ", user_id_str), Style::default().fg(Color::Cyan)), // User ID
            Span::styled(format!(" {}ms", log.latency), Style::default().fg(Color::DarkGray)),
        ]);
        
        ListItem::new(content)
    }).collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Access Logs (Latest 50) - Auto Refresh "))
        .highlight_style(Style::default().bg(Color::DarkGray));
    
    f.render_stateful_widget(list, area, &mut app.logs_state);
}

// --- Popup Rendering ---

fn draw_popup(f: &mut Frame, app: &AppState) {
    match &app.popup {
        PopupState::CreateToken => {
            let block = Block::default().title(" Create API Token ").borders(Borders::ALL).border_type(BorderType::Rounded);
            let area = centered_rect(60, 40, f.size());
            
            f.render_widget(Clear, area); // Clear background
            f.render_widget(block, area);

            let chunks = Layout::default()
                 .direction(Direction::Vertical)
                 .margin(2)
                 .constraints([
                     Constraint::Length(3), // Note
                     Constraint::Length(3), // Scope
                     Constraint::Length(3), // ReadOnly Checkbox
                     Constraint::Length(3), // Buttons
                 ].as_ref())
                 .split(area);

            // 1. Note Input
            let note_style = if app.token_input.active_field == TokenInput::NOTE_FIELD { Style::default().fg(Color::Cyan) } else { Style::default() };
            f.render_widget(Paragraph::new(app.token_input.note.clone())
                .block(Block::default().borders(Borders::ALL).title(" Note ").border_style(note_style)), chunks[0]);

            // 2. Scope Input
            let scope_style = if app.token_input.active_field == TokenInput::SCOPE_FIELD { Style::default().fg(Color::Cyan) } else { Style::default() };
            f.render_widget(Paragraph::new(app.token_input.scope.clone())
                .block(Block::default().borders(Borders::ALL).title(" Scope (Prefix, e.g. /docs) ").border_style(scope_style)), chunks[1]);

            // 3. Read Only
            let ro_style = if app.token_input.active_field == TokenInput::RO_FIELD { Style::default().fg(Color::Cyan) } else { Style::default() };
            let check = if app.token_input.is_ro { "[x] Read Only (Space to toggle)" } else { "[ ] Read Only (Space to toggle)" };
            f.render_widget(Paragraph::new(check).style(ro_style), chunks[2]);

            // 4. Submit Button
            let btn_style = if app.token_input.active_field == TokenInput::SUBMIT_FIELD { Style::default().fg(Color::Black).bg(Color::Green) } else { Style::default().fg(Color::Green) };
            f.render_widget(Paragraph::new(" [ Create Token ] ").style(btn_style).alignment(Alignment::Center), chunks[3]);

        },
        // [新增] 绘制 Token 展示弹窗
        PopupState::ShowToken(token) => {
            let area = centered_rect(60, 25, f.size());
            f.render_widget(Clear, area);
            
            let block = Block::default()
                .title(" Token Created Successfully ")
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::Green));
            f.render_widget(block, area);

            let layout = Layout::default()
                .direction(Direction::Vertical)
                .margin(2)
                .constraints([
                    Constraint::Length(2), // Warning text
                    Constraint::Length(3), // Token display
                    Constraint::Length(2), // Copy instruction
                    Constraint::Min(1),    // Close instruction
                ].as_ref())
                .split(area);

            // 1. Warning
            f.render_widget(
                Paragraph::new("Make sure to copy this token now. You won't be able to see it again!")
                    .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
                    .alignment(Alignment::Center),
                layout[0]
            );

            // 2. The Token
            f.render_widget(
                Paragraph::new(token.as_str())
                    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Yellow)))
                    .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                    .alignment(Alignment::Center),
                layout[1]
            );

            // 3. Copy Instruction
            f.render_widget(
                Paragraph::new("Press 'c' to Copy to Clipboard")
                    .style(Style::default().fg(Color::Cyan))
                    .alignment(Alignment::Center),
                layout[2]
            );
            
            // 4. Close Instruction
            f.render_widget(
                Paragraph::new("[ Enter / Esc to Close ]")
                    .style(Style::default().fg(Color::DarkGray))
                    .alignment(Alignment::Center),
                layout[3]
            );
        },

        PopupState::CreateUser => {
            let area = centered_rect(50, 20, f.size());
            f.render_widget(Clear, area);
            let block = Block::default().title(" Create New User ").borders(Borders::ALL);
            f.render_widget(block, area);
            
            let chunks = Layout::default().direction(Direction::Vertical).margin(2)
                .constraints([Constraint::Length(3), Constraint::Min(1)].as_ref()).split(area);
                
            f.render_widget(Paragraph::new(app.input_buffer.as_str())
                .block(Block::default().borders(Borders::ALL).title(" Username (Enter to confirm) ")), chunks[0]);
        },
        PopupState::UpdateQuota => {
            let area = centered_rect(50, 20, f.size());
            f.render_widget(Clear, area);
            f.render_widget(Block::default().title(" Update Quota (MB) ").borders(Borders::ALL), area);
            let inner = Layout::default().margin(2).constraints([Constraint::Length(3)].as_ref()).split(area)[0];
            f.render_widget(Paragraph::new(app.input_buffer.as_str())
                .block(Block::default().borders(Borders::ALL).title(" Size in MB ")), inner);
        },
        PopupState::AddIp => {
            let area = centered_rect(50, 20, f.size());
            f.render_widget(Clear, area);
            f.render_widget(Block::default().title(" Add IP Whitelist ").borders(Borders::ALL), area);
            let inner = Layout::default().margin(2).constraints([Constraint::Length(3)].as_ref()).split(area)[0];
            f.render_widget(Paragraph::new(app.input_buffer.as_str())
                .block(Block::default().borders(Borders::ALL).title(" CIDR (e.g. 192.168.1.0/24) ")), inner);
        },
        PopupState::ConfirmDeleteUser => {
            let area = centered_rect(50, 20, f.size());
            f.render_widget(Clear, area);
            
            let block = Block::default().title(" DANGER: Delete User ").borders(Borders::ALL).style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD));
            f.render_widget(block, area);
            
            let chunks = Layout::default().direction(Direction::Vertical).margin(2)
                .constraints([Constraint::Min(1), Constraint::Length(3)].as_ref()).split(area);
                
            let warning_text = "Are you sure you want to delete this USER?\nAll files, tokens, and logs will be lost permanently.";
            f.render_widget(Paragraph::new(warning_text).alignment(Alignment::Center).wrap(ratatui::widgets::Wrap { trim: true }), chunks[0]);
            
            f.render_widget(Paragraph::new("[Y] Yes (Delete)    [N] No").alignment(Alignment::Center).style(Style::default().add_modifier(Modifier::BOLD)), chunks[1]);
        },
        PopupState::ConfirmDeleteToken => {
            let area = centered_rect(40, 20, f.size());
            f.render_widget(Clear, area);
            
            let block = Block::default().title(" Confirm Deletion ").borders(Borders::ALL).style(Style::default().fg(Color::Red));
            f.render_widget(block, area);
            
            let chunks = Layout::default().direction(Direction::Vertical).margin(2)
                .constraints([Constraint::Min(1), Constraint::Length(3)].as_ref()).split(area);
                
            f.render_widget(Paragraph::new("Are you sure you want to delete this token?\nThis action cannot be undone.").alignment(Alignment::Center), chunks[0]);
            f.render_widget(Paragraph::new("[Y] Yes    [N] No").alignment(Alignment::Center).style(Style::default().add_modifier(Modifier::BOLD)), chunks[1]);
        },
        // Add ConfirmDelIp popup if needed, similar to ConfirmDeleteToken
        // 修复: 处理 None 情况 (虽然逻辑上可能不进入这里，但必须满足编译器要求)
        PopupState::None => {},
    }
}

// Helper to center a rect
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
