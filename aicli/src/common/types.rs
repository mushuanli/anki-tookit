// src/common/types.rs
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChatLog {
    pub uuid: Uuid,
    pub title: String,
    pub model: Option<String>,
    pub status: Option<String>, // Still useful for display purposes
    pub updated_at: DateTime<Utc>, // The new source of truth for sync
    pub system_prompt: Option<String>,
    pub interactions: Vec<Interaction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Interaction {
    User {
        content: String,
        created_at: DateTime<Utc>,
    },
    Ai {
        content: String,
        created_at: DateTime<Utc>,
    },
    Error { // This variant now handles all interaction-level failures
        reason: String,
        created_at: DateTime<Utc>,
    },
    Attachment {
        filename: String,
        mime_type: String,
    },
}

impl ChatLog {
    pub fn new(title: String) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            title,
            model: None,
            status: Some("local".to_string()),
            updated_at: Utc::now(), // Set on creation
            system_prompt: None,
            interactions: Vec::new(),
        }
    }

    /// Helper to get the creation time of the whole log.
    pub fn get_creation_time(&self) -> DateTime<Utc> {
        self.interactions.first().map_or_else(Utc::now, |interaction| {
            match interaction {
                Interaction::User { created_at, .. } => *created_at,
                Interaction::Ai { created_at, .. } => *created_at,
                Interaction::Error { created_at, .. } => *created_at,
                Interaction::Attachment { .. } => Utc::now(),
            }
        })
    }

    /// Checks if the log content represents a successfully completed interaction.
    /// A correctly finished log must end with an AI response.
    pub fn is_finished_correctly(&self) -> bool {
        if let Some(last_interaction) = self.interactions.last() {
            matches!(last_interaction, Interaction::Ai { .. })
        } else {
            false // A log with no interactions is not finished.
        }
    }
}


// PacketType enum remains the same...
#[derive(PartialEq, Debug, Clone, Copy)]
#[repr(u8)]
pub enum PacketType {
    CmdAuthRequest = 0x00,
    CmdAuthChallenge = 0x8A,
    CmdAuthResponse = 0x0A,

    CmdExec = 0x01,        
    CmdList = 0x02,
    CmdGet = 0x03,         
    CmdDelete = 0x04,      
    CmdUpdate = 0x06,
    AttachmentChunk = 0x10,
    Ack = 0x80,            
    ResponseList = 0x81,   
    ResponseChatLog = 0x82,
    Error = 0xFF,
}

impl PacketType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(PacketType::CmdAuthRequest),
            0x8A => Some(PacketType::CmdAuthChallenge),
            0x0A => Some(PacketType::CmdAuthResponse),
            0x01 => Some(PacketType::CmdExec),
            0x02 => Some(PacketType::CmdList),
            0x03 => Some(PacketType::CmdGet),
            0x04 => Some(PacketType::CmdDelete),
            0x06 => Some(PacketType::CmdUpdate),
            0x10 => Some(PacketType::AttachmentChunk),
            0x80 => Some(PacketType::Ack),
            0x81 => Some(PacketType::ResponseList),
            0x82 => Some(PacketType::ResponseChatLog),
            0xFF => Some(PacketType::Error),
            _ => None,
        }
    }
}