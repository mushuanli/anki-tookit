// src/tui/mod.rs
pub mod state;
pub mod ui;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::{Backend, CrosstermBackend}, Terminal, style::{Color}};
use sqlx::{Pool, Sqlite, Row};
use std::{io, time::Duration};
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256};
use arboard::Clipboard; 

use self::state::{AppState, Focus, MainTab, PopupState, TokenInput, UserData, TokenData, IpData, LogData};
use self::ui::draw_ui;

pub async fn start_tui(pool: Pool<Sqlite>) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = AppState::new(pool);
    
    // Initial Load
    refresh_dashboard(&mut app).await;
    refresh_users(&mut app).await;
    // Pre-fetch details for the first user if exists
    if !app.users.is_empty() {
        fetch_details(&mut app).await;
    }
    refresh_logs(&mut app).await;

    let res = run_tui_loop(&mut terminal, &mut app).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    if let Err(err) = res { println!("Error: {:?}", err) }
    Ok(())
}

async fn run_tui_loop<B: Backend>(terminal: &mut Terminal<B>, app: &mut AppState) -> io::Result<()> {
    let mut last_log_refresh = std::time::Instant::now();

    loop {
        terminal.draw(|f| draw_ui(f, app))?;

        if app.tab == MainTab::Logs && last_log_refresh.elapsed() > Duration::from_secs(2) {
            refresh_logs(app).await;
            last_log_refresh = std::time::Instant::now();
        }

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press { continue; }

                if app.popup != PopupState::None {
                    handle_popup_input(key.code, app).await;
                    continue; 
                }

                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Tab => {
                        app.tab = match app.tab {
                            MainTab::Dashboard => MainTab::Users,
                            MainTab::Users => MainTab::Logs,
                            MainTab::Logs => MainTab::Dashboard,
                        };
                        app.set_msg(String::new(), Color::Reset);
                        match app.tab {
                            MainTab::Logs => refresh_logs(app).await,
                            MainTab::Dashboard => refresh_dashboard(app).await,
                            MainTab::Users => { 
                                refresh_users(app).await;
                                if app.user_list_state.selected().is_some() { fetch_details(app).await; }
                            }
                        }
                    }
                    KeyCode::Char('r') => {
                        match app.tab {
                            MainTab::Dashboard => refresh_dashboard(app).await,
                            MainTab::Users => {
                                refresh_users(app).await;
                                if app.user_list_state.selected().is_some() { fetch_details(app).await; }
                            },
                            MainTab::Logs => refresh_logs(app).await,
                        }
                        app.set_msg("Refreshed.".to_string(), Color::Green);
                    }
                    _ => {
                        match app.tab {
                            MainTab::Users => handle_users_tab_input(key.code, app).await,
                            MainTab::Logs => handle_logs_tab_input(key.code, app).await,
                            MainTab::Dashboard => {},
                        }
                    }
                }
            }
        }
    }
}

// [新增] 辅助函数：复制到剪贴板
fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let mut clipboard = Clipboard::new().map_err(|e| format!("Clipboard init fail: {}", e))?;
    clipboard.set_text(text).map_err(|e| format!("Copy fail: {}", e))?;
    Ok(())
}

// --- Input Handlers ---

async fn handle_popup_input(code: KeyCode, app: &mut AppState) {
    // Clone popup state to avoid borrowing app.popup while mutating app
    let current_popup = app.popup.clone();

    match current_popup {
        PopupState::CreateToken => {
            match code {
                KeyCode::Esc => app.popup = PopupState::None,
                KeyCode::Tab => app.token_input.active_field = (app.token_input.active_field + 1) % 4,
                KeyCode::Enter => {
                    if app.token_input.active_field == TokenInput::SUBMIT_FIELD {
                         create_token(app).await; 
                         // 注意：create_token 内部现在应该设置 popup 为 ShowToken
                    }
                }
                // 修复: 将特定字符 ' ' 的匹配移到通用字符匹配之前
                KeyCode::Char(' ') => if app.token_input.active_field == TokenInput::RO_FIELD { app.token_input.is_ro = !app.token_input.is_ro; },
                
                KeyCode::Char(c) => match app.token_input.active_field {
                    TokenInput::NOTE_FIELD => app.token_input.note.push(c),
                    TokenInput::SCOPE_FIELD => app.token_input.scope.push(c),
                    _ => {} 
                },
                KeyCode::Backspace => match app.token_input.active_field {
                    TokenInput::NOTE_FIELD => { app.token_input.note.pop(); },
                    TokenInput::SCOPE_FIELD => { app.token_input.scope.pop(); },
                    _ => {}
                },
                _ => {} 
            }
        },
        // [新增] ShowToken 逻辑
        PopupState::ShowToken(token) => {
            match code {
                KeyCode::Char('c') => {
                    match copy_to_clipboard(&token) {
                        Ok(_) => app.set_msg("Copied to clipboard!".to_string(), Color::Green),
                        Err(e) => app.set_msg(format!("Clipboard Error: {}", e), Color::Red),
                    }
                },
                KeyCode::Enter | KeyCode::Esc => {
                    app.popup = PopupState::None;
                    // 关闭弹窗后刷新列表
                    fetch_details(app).await; 
                },
                _ => {}
            }
        },

        PopupState::CreateUser => {
            match code {
                KeyCode::Esc => app.popup = PopupState::None,
                KeyCode::Enter => { create_user(app).await; app.popup = PopupState::None; }
                KeyCode::Char(c) => app.input_buffer.push(c),
                KeyCode::Backspace => { app.input_buffer.pop(); },
                _ => {}
            }
        },
        PopupState::UpdateQuota => {
             match code {
                KeyCode::Esc => app.popup = PopupState::None,
                KeyCode::Enter => { update_user_quota(app).await; app.popup = PopupState::None; }
                KeyCode::Char(c) if c.is_digit(10) => app.input_buffer.push(c),
                KeyCode::Backspace => { app.input_buffer.pop(); },
                _ => {}
            }
        },
        PopupState::AddIp => {
            match code {
                KeyCode::Esc => app.popup = PopupState::None,
                KeyCode::Enter => { add_ip_whitelist(app).await; app.popup = PopupState::None; }
                KeyCode::Char(c) => app.input_buffer.push(c),
                KeyCode::Backspace => { app.input_buffer.pop(); },
                _ => {}
            }
        },
        PopupState::ConfirmDeleteUser => {
             match code {
                 KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => { delete_selected_user(app).await; app.popup = PopupState::None; }
                 KeyCode::Char('n') | KeyCode::Esc => app.popup = PopupState::None,
                 _ => {}
             }
        }
        PopupState::ConfirmDeleteToken => {
             match code {
                 KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => { delete_selected_token(app).await; app.popup = PopupState::None; }
                 KeyCode::Char('n') | KeyCode::Esc => app.popup = PopupState::None,
                 _ => {}
             }
        }
        _ => if code == KeyCode::Esc { app.popup = PopupState::None; }
    }
}

async fn handle_users_tab_input(code: KeyCode, app: &mut AppState) {
    match code {
        KeyCode::Right | KeyCode::Char('l') => {
            app.focus = match app.focus {
                Focus::UserList => { fetch_details(app).await; Focus::DetailTabs },
                Focus::DetailTabs => Focus::DetailContent,
                Focus::DetailContent => Focus::DetailContent,
            };
        }
        KeyCode::Left | KeyCode::Char('h') => {
            app.focus = match app.focus {
                Focus::UserList => Focus::UserList,
                Focus::DetailTabs => Focus::UserList,
                Focus::DetailContent => Focus::DetailTabs,
            };
        }
        _ => match app.focus {
            Focus::UserList => {
                match code {
                    KeyCode::Down | KeyCode::Char('j') => app.next_user(),
                    KeyCode::Up | KeyCode::Char('k') => app.prev_user(),
                    KeyCode::Enter => { fetch_details(app).await; app.focus = Focus::DetailTabs; }
                    KeyCode::Char('a') => { app.input_buffer.clear(); app.popup = PopupState::CreateUser; },
                    KeyCode::Char('q') => if app.get_selected_user_id().is_some() { app.input_buffer.clear(); app.popup = PopupState::UpdateQuota; },
                    KeyCode::Char('d') => if app.get_selected_user_id().is_some() { app.popup = PopupState::ConfirmDeleteUser; },
                    _ => {}
                }
            }
            Focus::DetailTabs => {
                 match code {
                     KeyCode::Char('1') => app.user_detail_tab = crate::tui::state::UserDetailTab::Profile,
                     KeyCode::Char('2') => app.user_detail_tab = crate::tui::state::UserDetailTab::Tokens,
                     KeyCode::Char('3') => app.user_detail_tab = crate::tui::state::UserDetailTab::IPs,
                     KeyCode::Down | KeyCode::Char('j') => app.focus = Focus::DetailContent,
                     _ => {}
                 }
            }
            Focus::DetailContent => {
                match app.user_detail_tab {
                    crate::tui::state::UserDetailTab::Tokens => {
                         match code {
                             KeyCode::Down | KeyCode::Char('j') => app.next_token(),
                             KeyCode::Up | KeyCode::Char('k') => app.prev_token(),
                             KeyCode::Char('n') => { app.token_input = TokenInput::default(); app.popup = PopupState::CreateToken; },
                             KeyCode::Char('d') => if app.get_selected_token_id().is_some() { app.popup = PopupState::ConfirmDeleteToken; },
                             _ => {}
                         }
                    }
                    crate::tui::state::UserDetailTab::IPs => {
                        match code {
                             KeyCode::Down | KeyCode::Char('j') => app.next_ip(),
                             KeyCode::Up | KeyCode::Char('k') => app.prev_ip(),
                             KeyCode::Char('a') => if app.get_selected_user_id().is_some() { app.input_buffer.clear(); app.popup = PopupState::AddIp; },
                             KeyCode::Char('d') => delete_selected_ip(app).await,
                             _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn handle_logs_tab_input(code: KeyCode, app: &mut AppState) {
    match code {
        KeyCode::Down | KeyCode::Char('j') => {
             let i = match app.logs_state.selected() {
                 Some(i) => if i >= app.logs.len().saturating_sub(1) { 0 } else { i + 1 },
                 None => 0,
             };
             app.logs_state.select(Some(i));
        }
        KeyCode::Up | KeyCode::Char('k') => {
             let i = match app.logs_state.selected() {
                 Some(i) => if i == 0 { app.logs.len().saturating_sub(1) } else { i - 1 },
                 None => 0,
             };
             app.logs_state.select(Some(i));
        }
        _ => {}
    }
}

// --- Logic & DB Actions ---

async fn create_token(app: &mut AppState) {
    if let Some(uid) = app.get_selected_user_id() {
        let rng = rand::thread_rng();
        let random_part: String = rng.sample_iter(&Alphanumeric).take(48).map(char::from).collect();
        let token = format!("sk-{}", random_part);
        let hash_str = hex::encode(Sha256::digest(token.as_bytes()));
        let prefix = &token[0..10];
        let perm = if app.token_input.is_ro { "ro" } else { "rw" };
        let scope = if app.token_input.scope.starts_with('/') { app.token_input.scope.clone() } else { format!("/{}", app.token_input.scope) };

        let res = sqlx::query("INSERT INTO api_keys (user_id, note, prefix, key_hash, created_at, scope_path, permission) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(uid).bind(&app.token_input.note).bind(prefix).bind(hash_str).bind(chrono::Utc::now().timestamp()).bind(scope).bind(perm)
            .execute(&app.db).await;

        match res {
            Ok(_) => { 
                // [修改] 成功后不再直接设置为 None，而是进入 ShowToken 状态
                app.set_msg("Token Created. Please Copy it now.".to_string(), Color::LightGreen);
                app.popup = PopupState::ShowToken(token); 
                // 注意：fetch_details 这里可以先不调，等用户关闭弹窗再调，或者现在调也可以
            },
            Err(e) => {
                app.set_msg(format!("Error: {}", e), Color::Red);
                app.popup = PopupState::None; // 失败则关闭
            }
        }
    }
}

async fn create_user(app: &mut AppState) {
    let username = app.input_buffer.trim().to_string();
    if username.is_empty() { return; }
    let rng_pass: String = rand::thread_rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect();
    let hash = bcrypt::hash(rng_pass, bcrypt::DEFAULT_COST).unwrap();

    let res = sqlx::query("INSERT INTO users (username, password_hash, quota_bytes) VALUES (?, ?, ?)")
        .bind(&username).bind(hash).bind(crate::types::DEFAULT_QUOTA_BYTES).execute(&app.db).await;

    match res {
        Ok(_) => { app.set_msg(format!("User '{}' created.", username), Color::Green); refresh_users(app).await; refresh_dashboard(app).await; },
        // 修复: 类型不匹配，添加 .to_string()
        Err(_) => app.set_msg("Error creating user.".to_string(), Color::Red),
    }
}

async fn delete_selected_token(app: &mut AppState) {
    if let Some(tid) = app.get_selected_token_id() {
        if let Some(uid) = app.get_selected_user_id() {
            let _ = sqlx::query("DELETE FROM api_keys WHERE id = ? AND user_id = ?").bind(tid).bind(uid).execute(&app.db).await;
            app.set_msg("Token deleted.".to_string(), Color::Yellow);
            fetch_details(app).await;
        }
    }
}

// [新增]：实现删除用户的级联逻辑
async fn delete_selected_user(app: &mut AppState) {
    if let Some(uid) = app.get_selected_user_id() {
        // 级联删除：Files -> IPs -> Keys -> User
        let _ = sqlx::query("DELETE FROM files WHERE user_id = ?").bind(uid).execute(&app.db).await;
        let _ = sqlx::query("DELETE FROM user_ips WHERE user_id = ?").bind(uid).execute(&app.db).await;
        let _ = sqlx::query("DELETE FROM api_keys WHERE user_id = ?").bind(uid).execute(&app.db).await;
        let _ = sqlx::query("DELETE FROM access_logs WHERE user_id = ?").bind(uid).execute(&app.db).await;
        let _ = sqlx::query("DELETE FROM users WHERE id = ?").bind(uid).execute(&app.db).await;
        app.set_msg("User deleted.".to_string(), Color::Red);
        
        // 刷新列表
        refresh_users(app).await;
        refresh_dashboard(app).await;
        
        // 如果用户被删除了，详情页数据也应该清空
        app.current_tokens.clear();
        app.current_ips.clear();
    }
}

async fn update_user_quota(app: &mut AppState) {
    if let Some(uid) = app.get_selected_user_id() {
        if let Ok(mb) = app.input_buffer.parse::<i64>() {
            let bytes = mb * 1024 * 1024;
            let _ = sqlx::query("UPDATE users SET quota_bytes = ? WHERE id = ?").bind(bytes).bind(uid).execute(&app.db).await;
            app.set_msg(format!("Quota updated: {} MB", mb), Color::Green);
            refresh_users(app).await;
        }
    }
}

async fn add_ip_whitelist(app: &mut AppState) {
    if let Some(uid) = app.get_selected_user_id() {
        let cidr = app.input_buffer.trim().to_string();
        if cidr.parse::<ipnetwork::IpNetwork>().is_ok() {
            let _ = sqlx::query("INSERT OR IGNORE INTO user_ips (user_id, ip_cidr) VALUES (?, ?)").bind(uid).bind(&cidr).execute(&app.db).await;
            app.set_msg("IP added.".to_string(), Color::Green);
            fetch_details(app).await;
        } else {
            app.set_msg("Invalid CIDR.".to_string(), Color::Red);
        }
    }
}

async fn delete_selected_ip(app: &mut AppState) {
    if let Some(idx) = app.ip_list_state.selected() {
        if let Some(ip_data) = app.current_ips.get(idx) {
            let cidr = ip_data.ip_cidr.clone();
            if let Some(uid) = app.get_selected_user_id() {
                let _ = sqlx::query("DELETE FROM user_ips WHERE user_id = ? AND ip_cidr = ?").bind(uid).bind(cidr).execute(&app.db).await;
                app.set_msg("IP removed.".to_string(), Color::Yellow);
                fetch_details(app).await;
            }
        }
    }
}

async fn refresh_dashboard(app: &mut AppState) {
    let u = sqlx::query("SELECT COUNT(*) as c FROM users").fetch_one(&app.db).await.map(|r| r.get("c")).unwrap_or(0);
    let f = sqlx::query("SELECT COUNT(*) as c FROM files").fetch_one(&app.db).await.map(|r| r.get("c")).unwrap_or(0);
    let t = sqlx::query("SELECT COUNT(*) as c FROM api_keys").fetch_one(&app.db).await.map(|r| r.get("c")).unwrap_or(0);
    let s: i64 = sqlx::query("SELECT SUM(LENGTH(content)) as size FROM files").fetch_one(&app.db).await.map(|r| r.try_get("size").unwrap_or(0)).unwrap_or(0);
    app.stats = (u, f, t, s as f64 / 1024.0 / 1024.0);
}

async fn refresh_users(app: &mut AppState) {
    let rows = sqlx::query("SELECT id, username, quota_bytes FROM users ORDER BY username").fetch_all(&app.db).await.unwrap_or_default();
    app.users = rows.into_iter().map(|r| UserData {
        id: r.get("id"), username: r.get("username"), quota: r.get("quota_bytes"),
    }).collect();
    if app.users.is_empty() { app.user_list_state.select(None); } 
    else if let Some(i) = app.user_list_state.selected() { if i >= app.users.len() { app.user_list_state.select(Some(app.users.len()-1)); } } 
    else { app.user_list_state.select(Some(0)); }
}

async fn refresh_logs(app: &mut AppState) {
    let rows = sqlx::query("SELECT id, timestamp, remote_ip, method, path, status, user_id, latency_ms FROM access_logs ORDER BY timestamp DESC LIMIT 50")
        .fetch_all(&app.db).await.unwrap_or_default();
    app.logs = rows.into_iter().map(|r| LogData {
        id: r.get("id"),
        timestamp: r.get("timestamp"),
        ip: r.get("remote_ip"),
        method: r.get("method"),
        path: r.get("path"),
        status: r.get("status"),
        user_id: r.get("user_id"), // 修正：补全字段
        latency: r.get("latency_ms"),
    }).collect();
    if app.logs.is_empty() { app.logs_state.select(None); } else if app.logs_state.selected().is_none() { app.logs_state.select(Some(0)); }
}

async fn fetch_details(app: &mut AppState) {
    if let Some(uid) = app.get_selected_user_id() {
        let t_rows = sqlx::query("SELECT id, prefix, note, scope_path, permission, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC").bind(uid).fetch_all(&app.db).await.unwrap_or_default();
        app.current_tokens = t_rows.into_iter().map(|r| TokenData {
            id: r.get("id"), prefix: r.get("prefix"), note: r.get("note"), scope: r.get("scope_path"), perm: r.get("permission"), created_at: r.get("created_at"),
        }).collect();
        if !app.current_tokens.is_empty() { app.token_list_state.select(Some(0)); }

        let i_rows = sqlx::query("SELECT ip_cidr FROM user_ips WHERE user_id = ? ORDER BY ip_cidr").bind(uid).fetch_all(&app.db).await.unwrap_or_default();
        app.current_ips = i_rows.into_iter().map(|r| IpData { ip_cidr: r.get("ip_cidr") }).collect();
        if !app.current_ips.is_empty() { app.ip_list_state.select(Some(0)); }
    } else {
        app.current_tokens.clear(); app.current_ips.clear();
    }
}