// src/client/tui/app.rs

use super::action::Action;
use super::super::local_store::{LocalStore, LocalSessionInfo};
use crate::common::types::{ChatLog, Interaction};
use crate::error::Result;
use crate::client::cli::{SERVER_ADDR, CLIENT_USERNAME};

use ratatui::widgets::{Block, Borders, ListState};
use ratatui_textarea::{Input, TextArea, CursorMove};
use uuid::Uuid;
use chrono::Utc;


pub enum InputMode {
    Title,
    UserPrompt,
    Model,
    SystemPrompt,
}

#[derive(PartialEq, Clone, Copy)]
pub enum AppMode {
    TaskList,
    NewChatPopup,
    EditingTask,
    ViewingTask,
    AppendPromptPopup,
    HelpPopup,
}

// TUI 核心状态
pub struct App<'a> {
    pub should_quit: bool,
    pub mode: AppMode,
    pub previous_mode: AppMode,
    pub sessions: Vec<LocalSessionInfo>, 
    pub task_list_state: ListState,
    pub status_message: Option<String>,
    
    // NEW: Fields to store config info for display in TUI
    pub server_addr: String,
    pub username: String,

    // The store is now part of the app state
    pub store: LocalStore,

    pub models: Vec<String>,
    pub selected_model_index: usize,

    // State for Viewer <-- MODIFIED
    pub viewer_content: String,
    pub viewer_scroll: u16,

    pub append_prompt_input: TextArea<'a>,
    pub active_append_uuid: Option<Uuid>,

    pub new_chat_popup_active_input: InputMode,
    pub title_input: TextArea<'a>,
    pub system_prompt_input: TextArea<'a>,
    pub user_prompt_input: TextArea<'a>,
    
    // State for Editor <-- MODIFIED
    pub editor_task_uuid: Option<Uuid>,
    pub editor_textarea: TextArea<'a>,
    pub editor_block_positions: Vec<usize>,
}

impl<'a> App<'a> {
    pub fn new() -> Result<Self> {
        // ... initialization of text areas ...
        let mut title_input = TextArea::new(vec!["".to_string()]);
        title_input.set_block(Block::default().borders(Borders::ALL).title(" Title (Required) "));
        let mut system_prompt_input = TextArea::default();
        system_prompt_input.set_block(Block::default().borders(Borders::ALL).title(" System Prompt (Optional) "));
        let mut user_prompt_input = TextArea::default();
        user_prompt_input.set_block(Block::default().borders(Borders::ALL).title(" Initial User Prompt (Required) "));

        let store = LocalStore::load()?;
        let sessions = store.list_sessions().into_iter().cloned().collect();

        Ok(Self {
            should_quit: false,
            mode: AppMode::TaskList,
            previous_mode: AppMode::TaskList,
            sessions,
            task_list_state: ListState::default(),
            status_message: Some("Welcome! Press 'r' to sync, Ctrl+H for help.".into()),
            
            server_addr: SERVER_ADDR.clone(),
            username: CLIENT_USERNAME.clone(),

            store,
            models: Vec::new(),
            selected_model_index: 0,

            viewer_content: String::new(),
            viewer_scroll: 0,
            append_prompt_input: TextArea::default(),
            active_append_uuid: None,

            new_chat_popup_active_input: InputMode::Title,
            title_input,
            system_prompt_input,
            user_prompt_input,
            
            editor_task_uuid: None,
            editor_textarea: TextArea::default(),
            editor_block_positions: Vec::new(),
        })
    }

    pub fn set_models(&mut self, models: Vec<String>, default_model: &str) {
        self.models = models;
        self.selected_model_index = self.models.iter().position(|m| m == default_model).unwrap_or(0);
    }

    // A helper to reload sessions from the store
    pub fn reload_sessions(&mut self) {
        self.sessions = self.store.list_sessions().into_iter().cloned().collect();
    }

    // MODIFIED: get_selected_task is now get_selected_session
    pub fn get_selected_session(&self) -> Option<&LocalSessionInfo> {
        self.task_list_state.selected().and_then(|i| self.sessions.get(i))
    }

    // REFACTOR: Update method now takes an action and modifies state.
    pub fn update(&mut self, action: Action) {
        match action {
            Action::Quit => self.should_quit = true,
            Action::NextTask => self.next_task(),
            Action::PrevTask => self.prev_task(),
            Action::EnterNewChat => self.enter_new_chat_mode(),
            Action::ExitPopup => self.exit_popup_mode(),
            Action::ToggleHelp => self.toggle_help(),
            Action::CyclePopupInput => self.cycle_popup_input(), // <-- Was unused, now called

            // --- FIX: Add handler for EnterAppendPrompt ---
            Action::EnterAppendPrompt(uuid) => {
                self.active_append_uuid = Some(uuid); // <-- Now using the uuid, fixing the warning
                self.append_prompt_input = TextArea::default();
                self.append_prompt_input.set_block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Add to Conversation ")
                );
                self.mode = AppMode::AppendPromptPopup; // <-- Now constructing this variant
                self.status_message = Some("Enter new prompt. Press Enter to send, Esc to cancel.".into());
            },

            Action::ViewTask(uuid) => {
                if let Ok(content) = self.store.get_session_content(uuid) {
                    self.viewer_content = content;
                    self.viewer_scroll = 0;
                    self.mode = AppMode::ViewingTask;
                    self.status_message = Some("Viewing. Scroll: j/k, PgUp/Down, g/G. Exit: Esc. Help: Ctrl+H".into());
                }
            },
            
            Action::ViewerScroll(delta) => {
                let current = self.viewer_scroll as i32;
                let next = (current + delta as i32).max(0);
                self.viewer_scroll = next as u16;
            },
            Action::ViewerScrollToTop => self.viewer_scroll = 0,
            Action::ViewerScrollToBottom => self.viewer_scroll = u16::MAX,

            Action::EditorJumpToNextBlock => {
                let current_line = self.editor_textarea.cursor().0;
                if let Some(&next_pos) = self.editor_block_positions.iter().find(|&&pos| pos > current_line) {
                    self.editor_textarea.move_cursor(CursorMove::Jump(next_pos as u16, 0));
                } else if let Some(&first_pos) = self.editor_block_positions.first() {
                    self.editor_textarea.move_cursor(CursorMove::Jump(first_pos as u16, 0));
                }
            },
            Action::EditorJumpToPrevBlock => {
                let current_line = self.editor_textarea.cursor().0;
                if let Some(&prev_pos) = self.editor_block_positions.iter().rfind(|&&pos| pos < current_line) {
                    self.editor_textarea.move_cursor(CursorMove::Jump(prev_pos as u16, 0));
                } else if let Some(&last_pos) = self.editor_block_positions.last() {
                    self.editor_textarea.move_cursor(CursorMove::Jump(last_pos as u16, 0));
                }
            },
            
            // --- Actions that just set a message for the network handler ---
            Action::Refresh => self.status_message = Some("Syncing with server...".into()),
            Action::SendNewTask(log) => {
                self.exit_popup_mode();
                self.status_message = Some(format!("Session '{}' created locally. Sending...", log.title));
            },
            Action::SendAppendedPrompt { .. } => {
                self.mode = AppMode::TaskList;
                self.status_message = Some("Appending prompt and sending...".into());
            },
            Action::DeleteTask(uuid) => self.status_message = Some(format!("Deleting task {}...", uuid)),
            Action::SyncSelected { uuid, .. } => self.status_message = Some(format!("Sync action for {}...", uuid)),
            Action::SaveEdit => self.status_message = Some("Saving and uploading changes...".into()),
            Action::StartEdit(_) => self.status_message = Some("Loading task for editing...".into()),
            Action::CancelEdit => {
                self.mode = AppMode::TaskList;
                self.editor_textarea = TextArea::default();
                self.editor_task_uuid = None;
                self.status_message = Some("Edit cancelled.".into());
            },
        }
    }

    pub fn get_action_for_key(&mut self, key: crossterm::event::KeyEvent) -> Option<Action> {
        match self.mode {
            AppMode::TaskList => self.get_tasklist_action(key),
            AppMode::NewChatPopup => self.get_popup_action(key),
            AppMode::EditingTask => self.get_editor_action(key),
            AppMode::ViewingTask => self.get_viewer_action(key),
            AppMode::AppendPromptPopup => self.get_append_popup_action(key),
            AppMode::HelpPopup => self.get_help_action(key),
        }
    }
    
    // --- MAPPING KEYS TO ACTIONS ---
    fn get_tasklist_action(&self, key: crossterm::event::KeyEvent) -> Option<Action> {
        use crossterm::event::{KeyCode, KeyModifiers};
        match key {
            crossterm::event::KeyEvent { code: KeyCode::Char('h'), modifiers: KeyModifiers::CONTROL, .. } => Some(Action::ToggleHelp),
            crossterm::event::KeyEvent { code: KeyCode::Char('q'), .. } => Some(Action::Quit),
            crossterm::event::KeyEvent { code: KeyCode::Char('j') | KeyCode::Down, .. } => Some(Action::NextTask),
            crossterm::event::KeyEvent { code: KeyCode::Char('k') | KeyCode::Up, .. } => Some(Action::PrevTask),
            crossterm::event::KeyEvent { code: KeyCode::Char('n'), .. } => Some(Action::EnterNewChat),
            crossterm::event::KeyEvent { code: KeyCode::Char('r') | KeyCode::Char('l'), .. } => Some(Action::Refresh),
            crossterm::event::KeyEvent { code: KeyCode::Char('d'), .. } => self.get_selected_session().map(|t| Action::DeleteTask(t.uuid)),
            crossterm::event::KeyEvent { code: KeyCode::Enter, .. } => self.get_selected_session().map(|t| Action::ViewTask(t.uuid)),
            crossterm::event::KeyEvent { code: KeyCode::Char('e'), .. } => self.get_selected_session().map(|t| Action::StartEdit(t.uuid)),
            crossterm::event::KeyEvent { code: KeyCode::Char('a'), .. } => self.get_selected_session().map(|t| Action::EnterAppendPrompt(t.uuid)),
            crossterm::event::KeyEvent { code: KeyCode::Char('s'), .. } => {
                self.get_selected_session().map(|s| Action::SyncSelected { uuid: s.uuid, local_status: s.sync_status.clone() })
            },
	    _ => None,
        }
    }
    
    fn get_viewer_action(&self, key: crossterm::event::KeyEvent) -> Option<Action> {
        use crossterm::event::{KeyCode, KeyModifiers};
        match key {
            crossterm::event::KeyEvent { code: KeyCode::Char('h'), modifiers: KeyModifiers::CONTROL, .. } => Some(Action::ToggleHelp),
            crossterm::event::KeyEvent { code: KeyCode::Esc | KeyCode::Char('q'), .. } => Some(Action::ExitPopup),
            crossterm::event::KeyEvent { code: KeyCode::Char('k') | KeyCode::Up, .. } => Some(Action::ViewerScroll(-1)),
            crossterm::event::KeyEvent { code: KeyCode::Char('j') | KeyCode::Down, .. } => Some(Action::ViewerScroll(1)),
            crossterm::event::KeyEvent { code: KeyCode::PageUp, .. } => Some(Action::ViewerScroll(-10)),
            crossterm::event::KeyEvent { code: KeyCode::PageDown, .. } => Some(Action::ViewerScroll(10)),
            crossterm::event::KeyEvent { code: KeyCode::Char('g') | KeyCode::Home, .. } => Some(Action::ViewerScrollToTop),
            crossterm::event::KeyEvent { code: KeyCode::Char('G') | KeyCode::End, .. } => Some(Action::ViewerScrollToBottom),
            _ => None,
        }
    }

    fn get_append_popup_action(&mut self, key: crossterm::event::KeyEvent) -> Option<Action> {
        use crossterm::event::KeyCode;
        match key.code {
            KeyCode::Esc => Some(Action::ExitPopup),
            KeyCode::Enter => {
                if let Some(uuid) = self.active_append_uuid {
                    let prompt = self.append_prompt_input.lines().join("\n");
                    if !prompt.trim().is_empty() {
                        return Some(Action::SendAppendedPrompt { uuid, prompt });
                    }
                }
                None
            }
            _ => {
                self.append_prompt_input.input(Input::from(key));
                None
            }
        }
    }

    // --- FIX: Add Tab key handling to generate CyclePopupInput action ---
    fn get_popup_action(&mut self, key: crossterm::event::KeyEvent) -> Option<Action> {
        use crossterm::event::KeyCode;
        
        // Handle model selection with arrow keys when the model selector is active
        if let InputMode::Model = self.new_chat_popup_active_input {
            match key.code {
                KeyCode::Up => { self.selected_model_index = self.selected_model_index.saturating_sub(1); return None; },
                KeyCode::Down => { if !self.models.is_empty() { self.selected_model_index = (self.selected_model_index + 1).min(self.models.len() - 1); } return None; },
                _ => {}
            }
        }

        match key.code {
            KeyCode::Esc => Some(Action::ExitPopup),
            KeyCode::Tab => Some(Action::CyclePopupInput), // <-- THIS WAS MISSING
            KeyCode::Enter => {
                // 1. Get content from text areas
                let title = self.title_input.lines().join("\n");
                let user_content = self.user_prompt_input.lines().join("\n");
                if title.trim().is_empty() { self.status_message = Some("Error: Title cannot be empty.".to_string()); return None; }
                if user_content.trim().is_empty() { self.status_message = Some("Error: Initial prompt cannot be empty.".to_string()); return None; }
                
                // 3. Create ChatLog object
                let log = self.create_chat_log_from_popup();

                // 4. Return the new action to be handled by the main loop
                Some(Action::SendNewTask(log))
            }
            _ => {
                let input = Input::from(key);
                match self.new_chat_popup_active_input {
                    InputMode::Title => self.title_input.input(input),
                    InputMode::UserPrompt => self.user_prompt_input.input(input),
                    InputMode::SystemPrompt => self.system_prompt_input.input(input),
                    InputMode::Model => false,
                };
                None
            }
        }
	
    }

    // NEW: handler for editor mode
    fn get_editor_action(&mut self, key: crossterm::event::KeyEvent) -> Option<Action> {
        use crossterm::event::{KeyCode, KeyModifiers};
        match key {
            crossterm::event::KeyEvent { code: KeyCode::Char('h'), modifiers: KeyModifiers::CONTROL, .. } => Some(Action::ToggleHelp),
            crossterm::event::KeyEvent { code: KeyCode::Char('s'), modifiers: KeyModifiers::CONTROL, .. } => Some(Action::SaveEdit),
            crossterm::event::KeyEvent { code: KeyCode::Esc, .. } => Some(Action::CancelEdit),
            crossterm::event::KeyEvent { code: KeyCode::Char('n'), modifiers: KeyModifiers::CONTROL, .. } => Some(Action::EditorJumpToNextBlock),
            crossterm::event::KeyEvent { code: KeyCode::Char('p'), modifiers: KeyModifiers::CONTROL, .. } => Some(Action::EditorJumpToPrevBlock),
            _ => {
                self.editor_textarea.input(Input::from(key));
                None
            }
        }
    }

    fn get_help_action(&self, key: crossterm::event::KeyEvent) -> Option<Action> {
        use crossterm::event::{KeyCode, KeyModifiers};
         match key {
            crossterm::event::KeyEvent { code: KeyCode::Char('h'), modifiers: KeyModifiers::CONTROL, .. } => Some(Action::ToggleHelp),
            crossterm::event::KeyEvent { code: KeyCode::Esc | KeyCode::Char('q'), .. } => Some(Action::ToggleHelp),
            _ => None,
        }
    }

    // --- Helper methods for state mutation ---

    fn toggle_help(&mut self) {
        if self.mode == AppMode::HelpPopup {
            self.mode = self.previous_mode;
            self.status_message = None;
        } else {
            self.previous_mode = self.mode;
            self.mode = AppMode::HelpPopup;
            self.status_message = Some("Displaying help. Press Esc or Ctrl+H to close.".into());
        }
    }
    
    fn exit_popup_mode(&mut self) { 
        self.mode = AppMode::TaskList; 
        self.status_message = None;
    }

    fn next_task(&mut self) {
        if self.sessions.is_empty() { return; } 
        let i = match self.task_list_state.selected() {
            Some(i) => if i >= self.sessions.len() - 1 { 0 } else { i + 1 }, 
            None => 0,
        };
        self.task_list_state.select(Some(i));
    }

    fn prev_task(&mut self) {
        if self.sessions.is_empty() { return; } 
        let i = match self.task_list_state.selected() {
            Some(i) => if i == 0 { self.sessions.len() - 1 } else { i - 1 },
            None => self.sessions.len() - 1,
        };
        self.task_list_state.select(Some(i));
    }

    // MODIFIED: Reset fields when entering this mode
    fn enter_new_chat_mode(&mut self) { 
        self.mode = AppMode::NewChatPopup;
        self.title_input = TextArea::new(vec!["".to_string()]);
        self.title_input.set_block(Block::default().borders(Borders::ALL).title(" Title (Required) "));
        self.system_prompt_input = TextArea::default();
        self.system_prompt_input.set_block(Block::default().borders(Borders::ALL).title(" System Prompt (Optional) "));
        self.user_prompt_input = TextArea::default();
        self.user_prompt_input.set_block(Block::default().borders(Borders::ALL).title(" Initial User Prompt (Required) "));
        self.status_message = Some("Press Tab to cycle, Enter to send, Esc to cancel.".to_string());
    }


    fn cycle_popup_input(&mut self) { 
        self.new_chat_popup_active_input = match self.new_chat_popup_active_input {
            InputMode::Title => InputMode::UserPrompt,
            InputMode::UserPrompt => InputMode::Model,
            InputMode::Model => InputMode::SystemPrompt,
            InputMode::SystemPrompt => InputMode::Title,
        };
    }
    fn create_chat_log_from_popup(&self) -> ChatLog {
        let title = self.title_input.lines().join("\n");
        let system_prompt = self.system_prompt_input.lines().join("\n");
        let user_content = self.user_prompt_input.lines().join("\n");
        
        let mut log = ChatLog::new(title);
        
        if let Some(model_identifier) = self.models.get(self.selected_model_index) {
            log.model = Some(model_identifier.clone());
        }
        
        if !system_prompt.trim().is_empty() {
            log.system_prompt = Some(system_prompt);
        }

        // This is correct. It creates an Interaction object.
        // `format_chat_log` will handle turning it into a block.
        log.interactions.push(Interaction::User {
            content: user_content,
            created_at: Utc::now(),
        });
        
        log
    }
}
