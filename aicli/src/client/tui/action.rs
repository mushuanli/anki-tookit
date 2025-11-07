// src/client/tui/action.rs

use uuid::Uuid;
use crate::common::types::ChatLog;
use crate::client::local_store::SyncStatus;

#[derive(Debug, Clone)]
pub enum Action {
    Quit,
    Refresh,
    NextTask,
    PrevTask,
    
    // Task List Actions
    EnterNewChat,
    StartEdit(Uuid),
    ViewTask(Uuid),
    EnterAppendPrompt(Uuid),
    
    // Viewer Actions <-- NEW
    ViewerScroll(i16), // A single action with a delta: +1, -1, +10, -10 etc.
    ViewerScrollToTop,
    ViewerScrollToBottom,

    // Editor Actions <-- NEW
    EditorJumpToNextBlock,
    EditorJumpToPrevBlock,

    // Popup/Modal Actions
    ExitPopup, 
    ToggleHelp, // <-- NEW: Show/hide help popup
    CyclePopupInput,
    SendNewTask(ChatLog),
    SendAppendedPrompt { uuid: Uuid, prompt: String },
    
    // Network/Sync Actions
    DeleteTask(Uuid),
    SyncSelected { uuid: Uuid, local_status: SyncStatus },
    SaveEdit,
    CancelEdit,
}
