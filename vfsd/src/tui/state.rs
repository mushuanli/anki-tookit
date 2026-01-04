// src/tui/state.rs
use ratatui::{widgets::ListState, style::Color};
use sqlx::{Pool, Sqlite};

#[derive(PartialEq, Clone, Copy)]
pub enum MainTab {
    Dashboard,
    Users,
    Logs, // Phase 3 placeholder
}

#[derive(PartialEq, Clone, Copy)]
pub enum UserDetailTab {
    Profile,
    Tokens,
    IPs,
}

// 界面焦点状态机
#[derive(PartialEq)]
pub enum Focus {
    UserList,       // Left side user list
    DetailTabs,     // Right side detail tab headers
    DetailContent,  // Right side specific content area (tokens, IPs, etc.)
}

// Popup states
#[derive(PartialEq, Debug, Clone)] // <--- 添加 Clone
pub enum PopupState {
    None,
    CreateToken,
    CreateUser,      // For creating a new user via TUI
    UpdateQuota,     // For updating user quota
    AddIp,           // For adding an IP to whitelist
    ConfirmDeleteUser, // Confirmation for deleting a user
    ConfirmDeleteToken, // Confirmation for deleting a token
    // ConfirmDelIp, // Optional: confirmation for deleting an IP
    // [新增] 用于展示刚生成的 Token，携带 Token 字符串
    ShowToken(String), 
}

// Struct for the Create API Token form
pub struct TokenInput {
    pub note: String,
    pub scope: String,
    pub is_ro: bool, // Read-only flag
    pub active_field: usize, // Index of the currently active input field
}

// Constants for TokenInput fields for clarity
impl TokenInput {
    pub const NOTE_FIELD: usize = 0;
    pub const SCOPE_FIELD: usize = 1;
    pub const RO_FIELD: usize = 2;
    pub const SUBMIT_FIELD: usize = 3;
}

impl Default for TokenInput {
    fn default() -> Self {
        Self {
            note: String::new(),
            scope: "/".to_string(), // Default scope is root
            is_ro: false, // Default is read-write
            active_field: Self::NOTE_FIELD, // Start with the Note field
        }
    }
}

// Data structures for TUI display

#[derive(Clone, Debug)]
pub struct LogData {
    pub id: i64,
    pub timestamp: i64,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub user_id: Option<i64>, // User ID can be null for anonymous requests
    pub latency: i64,
}

#[derive(Clone, Debug)]
pub struct UserData {
    pub id: i64,
    pub username: String,
    pub quota: i64, // Quota in bytes
}

#[derive(Clone, Debug)]
pub struct TokenData {
    pub id: i64,
    pub prefix: String, // First 10 chars of the token
    pub note: String,
    pub scope: String,      // Path scope
    pub perm: String,       // 'rw' or 'ro'
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct IpData {
    pub ip_cidr: String, // e.g., "192.168.1.0/24"
}

// Main application state
pub struct AppState {
    pub db: Pool<Sqlite>,
    
    // --- Navigation State ---
    pub tab: MainTab,
    pub focus: Focus,
    pub popup: PopupState,
    
    // --- User Tab State ---
    pub user_detail_tab: UserDetailTab,
    pub user_list_state: ListState,      // State for the user list
    pub token_list_state: ListState,     // State for the token list
    pub ip_list_state: ListState,        // State for the IP whitelist list

    // --- Input Handling ---
    pub token_input: TokenInput,         // State for the create token form
    pub input_buffer: String,            // General-purpose buffer for string inputs (username, CIDR, quota)

    // --- Data Cache ---
    pub stats: (i64, i64, i64, f64), // (users, files, tokens, storage_mb)
    pub users: Vec<UserData>,
    pub current_tokens: Vec<TokenData>, // Tokens for the currently selected user
    pub current_ips: Vec<IpData>,       // IPs for the currently selected user
    
    // --- Feedback Messages ---
    pub message: String,                // Status message to display
    pub message_color: Color,           // Color of the status message

    // --- Logs Tab State ---
    pub logs: Vec<LogData>,
    pub logs_state: ListState,          // State for the logs list
}

impl AppState {
    pub fn new(db: Pool<Sqlite>) -> Self {
        Self {
            db,
            tab: MainTab::Dashboard,
            focus: Focus::UserList,
            popup: PopupState::None,
            user_detail_tab: UserDetailTab::Profile, // Default to Profile tab
            user_list_state: ListState::default(),
            token_list_state: ListState::default(),
            ip_list_state: ListState::default(),
            token_input: TokenInput::default(),
            input_buffer: String::new(), // Initialize empty input buffer
            stats: (0, 0, 0, 0.0),
            users: vec![],
            current_tokens: vec![],
            current_ips: vec![],
            message: String::new(),
            message_color: Color::Gray,
            logs: vec![],
            logs_state: ListState::default(),
        }
    }

    // Set a status message and its color
    pub fn set_msg(&mut self, msg: String, color: Color) {
        self.message = msg;
        self.message_color = color;
    }

    // Get the ID of the currently selected user
    pub fn get_selected_user_id(&self) -> Option<i64> {
        self.user_list_state.selected().and_then(|i| self.users.get(i).map(|u| u.id))
    }
    
    // Get the ID of the currently selected token
    pub fn get_selected_token_id(&self) -> Option<i64> {
        self.token_list_state.selected().and_then(|i| self.current_tokens.get(i).map(|t| t.id))
    }

    // --- List Navigation Helpers ---
    // Move selection down in a list, wrapping around
    pub fn next_user(&mut self) { Self::nav_list(&mut self.user_list_state, self.users.len()); }
    pub fn prev_user(&mut self) { Self::nav_list_rev(&mut self.user_list_state, self.users.len()); }
    pub fn next_token(&mut self) { Self::nav_list(&mut self.token_list_state, self.current_tokens.len()); }
    pub fn prev_token(&mut self) { Self::nav_list_rev(&mut self.token_list_state, self.current_tokens.len()); }
    pub fn next_ip(&mut self) { Self::nav_list(&mut self.ip_list_state, self.current_ips.len()); }
    pub fn prev_ip(&mut self) { Self::nav_list_rev(&mut self.ip_list_state, self.current_ips.len()); }

    // Generic helper for list navigation (downwards)
    fn nav_list(state: &mut ListState, len: usize) {
        if len == 0 { return; } // Do nothing if list is empty
        let i = match state.selected() {
            Some(i) => if i >= len - 1 { 0 } else { i + 1 }, // Wrap around to first item
            None => 0, // Select first item if nothing was selected
        };
        state.select(Some(i));
    }

    // Generic helper for list navigation (upwards)
    fn nav_list_rev(state: &mut ListState, len: usize) {
        if len == 0 { return; } // Do nothing if list is empty
        let i = match state.selected() {
            Some(i) => if i == 0 { len - 1 } else { i - 1 }, // Wrap around to last item
            None => 0, // Select first item if nothing was selected
        };
        state.select(Some(i));
    }
}
