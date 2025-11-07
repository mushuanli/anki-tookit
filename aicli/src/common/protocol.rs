// src/common/protocol.rs

use crate::common::types::{ChatLog, Interaction};
use crate::error::{AppError, Result};
use chrono::{DateTime, Utc};
use std::str::FromStr;
use uuid::Uuid;

// Header prefixes (Global metadata)
const PREFIX_UUID: &str = "::>uuid:";
const PREFIX_TITLE: &str = "::>title:";
const PREFIX_MODEL: &str = "::>model:";
const PREFIX_STATUS: &str = "::>status:";
const PREFIX_UPDATED_AT: &str = "::>updated_at:"; // New
const PREFIX_SYSTEM: &str = "::>system:";

// Interaction block prefixes (Per-interaction metadata and content)
const PREFIX_CREATED_AT: &str = "::>created_at:";
const PREFIX_ATTACH: &str = "::>attach:";
const PREFIX_USER: &str = "::>user:";
const PREFIX_RESPONSE: &str = "::>response:";
const PREFIX_ERROR: &str = "::>error:";

/// Parses a string in the new block-based chat format into a ChatLog struct.
pub fn parse_chat_file(content: &str) -> Result<ChatLog> {
    let mut log = ChatLog::new("Untitled".to_string());
    
    let (header_str, body_str) = if let Some(pos) = content.find("\n\n::>") {
        let (h, b) = content.split_at(pos);
        (h, b.trim_start())
    } else {
        (content.trim(), "")
    };

    // --- 1. Parse Header ---
    let mut system_prompt_lines: Vec<&str> = Vec::new();
    let mut in_system_prompt = false;
    let mut updated_at_found = false;

    for line in header_str.lines() {
        if line.is_empty() { continue; }
        
        if line.starts_with("::>") {
            in_system_prompt = false; 
            if let Some(val) = line.strip_prefix(PREFIX_UUID) { log.uuid = Uuid::from_str(val.trim())?; }
            else if let Some(val) = line.strip_prefix(PREFIX_TITLE) { log.title = val.trim().to_string(); }
            else if let Some(val) = line.strip_prefix(PREFIX_MODEL) { log.model = Some(val.trim().to_string()); }
            else if let Some(val) = line.strip_prefix(PREFIX_STATUS) { log.status = Some(val.trim().to_string()); }
            else if let Some(val) = line.strip_prefix(PREFIX_UPDATED_AT) {
                log.updated_at = DateTime::parse_from_rfc3339(val.trim())?.with_timezone(&Utc);
                updated_at_found = true;
            }
            else if let Some(val) = line.strip_prefix(PREFIX_SYSTEM) {
                system_prompt_lines.push(val.trim_start());
                in_system_prompt = true;
            }
        } else if in_system_prompt {
            system_prompt_lines.push(line);
        }
    }
    
    // If no timestamp was found in the file, use the file's modification time or now.
    if !updated_at_found {
        log.updated_at = Utc::now();
    }

    if !system_prompt_lines.is_empty() {
        log.system_prompt = Some(system_prompt_lines.join("\n"));
    }

    // --- 2. Parse Interaction Blocks ---
    if body_str.is_empty() { return Ok(log); }

    for block_str in body_str.split("\n\n") {
        if block_str.trim().is_empty() { continue; }

        let mut created_at: Option<DateTime<Utc>> = None;
        let mut attachments: Vec<Interaction> = Vec::new();
        let mut content_lines: Vec<&str> = Vec::new();
        
        enum BlockType { None, User, Ai, Error }
        let mut block_type = BlockType::None;

        for line in block_str.lines() {
            if !matches!(block_type, BlockType::None) {
                content_lines.push(line);
                continue;
            }
            
            if let Some(val) = line.strip_prefix(PREFIX_CREATED_AT) {
                created_at = Some(DateTime::parse_from_rfc3339(val.trim())?.with_timezone(&Utc));
            } else if let Some(val) = line.strip_prefix(PREFIX_ATTACH) {
                let parts: Vec<&str> = val.split(':').map(str::trim).collect();
                if parts.len() == 2 {
                    attachments.push(Interaction::Attachment { filename: parts[0].to_string(), mime_type: parts[1].to_string() });
                }
            } else if let Some(val) = line.strip_prefix(PREFIX_USER) {
                block_type = BlockType::User;
                content_lines.push(val.trim_start());
            } else if let Some(val) = line.strip_prefix(PREFIX_RESPONSE) {
                block_type = BlockType::Ai;
                content_lines.push(val.trim_start());
            } else if let Some(val) = line.strip_prefix(PREFIX_ERROR) {
                block_type = BlockType::Error;
                content_lines.push(val.trim_start());
            }
        }

        // If a block has a content tag but no `created_at` tag, we also default to now.
        let interaction_time = created_at.unwrap_or_else(Utc::now);
        let content = content_lines.join("\n");

        // Add attachments first, as they belong to the following interaction
        log.interactions.extend(attachments);
        
        let interaction = match block_type {
            BlockType::User => Interaction::User { content, created_at: interaction_time },
            BlockType::Ai => Interaction::Ai { content, created_at: interaction_time },
            BlockType::Error => Interaction::Error { reason: content, created_at: interaction_time },
            // Only return an error if there's no content tag at all.
            BlockType::None if content.is_empty() => continue,
            BlockType::None => return Err(AppError::ParseError("Interaction block is missing a type tag (user, response, or error)".to_string())),
        };
        log.interactions.push(interaction);
    }
    
    Ok(log)
}

/// Formats a ChatLog struct back into the new block-based chat format string.
pub fn format_chat_log(log: &ChatLog) -> String {
    let mut builder = String::new();

    // --- 1. Format Header ---
    builder.push_str(&format!("{} {}\n", PREFIX_UUID, log.uuid));
    builder.push_str(&format!("{} {}\n", PREFIX_TITLE, log.title));
    builder.push_str(&format!("{} {}\n", PREFIX_UPDATED_AT, log.updated_at.to_rfc3339()));
    if let Some(status) = &log.status { builder.push_str(&format!("{} {}\n", PREFIX_STATUS, status)); }
    if let Some(model) = &log.model { builder.push_str(&format!("{} {}\n", PREFIX_MODEL, model)); }
    if let Some(prompt) = &log.system_prompt {
        // Ensure system prompt does not end with newlines that could create extra blocks
        builder.push_str(&format!("{} {}", PREFIX_SYSTEM, prompt.trim_end()));
    }

    // --- 2. Format Interaction Blocks ---
    let mut attachments_for_next_block: Vec<&Interaction> = Vec::new();

    for interaction in &log.interactions {
        // Collect attachments until we find a non-attachment interaction to associate them with.
        if let Interaction::Attachment { .. } = interaction {
            attachments_for_next_block.push(interaction);
            continue;
        }

        builder.push_str("\n\n"); // Separator for a new block
        
        let (created_at, tag, content) = match interaction {
            Interaction::User { created_at, content } => (created_at, PREFIX_USER, content.as_str()),
            Interaction::Ai { created_at, content } => (created_at, PREFIX_RESPONSE, content.as_str()),
            Interaction::Error { created_at, reason } => (created_at, PREFIX_ERROR, reason.as_str()),
            Interaction::Attachment {..} => unreachable!(),
        };
        
        // Write the block's metadata
        builder.push_str(&format!("{} {}\n", PREFIX_CREATED_AT, created_at.to_rfc3339()));

        // Write any pending attachments
        for attach in attachments_for_next_block.drain(..) {
            if let Interaction::Attachment { filename, mime_type } = attach {
                builder.push_str(&format!("{} {} : {}\n", PREFIX_ATTACH, filename, mime_type));
            }
        }
        
        // Write the block's main content line
        builder.push_str(&format!("{} {}", tag, content.trim_end()));
    }
    
    // Ensure the file ends with a single newline for consistency
    if !builder.ends_with('\n') {
        builder.push('\n');
    }
    builder
}

/// Finds the last user interaction and removes any AI/Error interactions that follow it.
/// This function's logic remains correct and is now even more reliable.
pub fn truncate_after_last_user(log: &mut ChatLog) {
    if let Some(last_user_pos) = log.interactions.iter().rposition(|i| matches!(i, Interaction::User { .. })) {
        // We want to keep all interactions up to and including the last user prompt.
        // So we truncate the vector to `last_user_pos + 1`.
        log.interactions.truncate(last_user_pos + 1);
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_format_parse_and_format_roundtrip() {
        let original_content = format!(
r#"::>uuid: 550e8400-e29b-41d4-a716-446655440000
::>title: Test Chat
::>status: failed
::>model: deepseek:chat
::>system: You are a test assistant.
This is a multi-line prompt.

::>created_at: 2023-01-01T12:00:00Z
::>attach: image.png : image/png
::>user: Hello there.
This is a multi-line user question.

::>created_at: 2023-01-01T12:01:00Z
::>response: General Kenobi.

::>created_at: 2023-01-01T12:02:00Z
::>error: Something went wrong.
And here are the details.
"#);
        
        let log = parse_chat_file(&original_content).expect("Parsing failed");

        assert_eq!(log.uuid.to_string(), "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(log.title, "Test Chat");
        assert_eq!(log.status.as_deref(), Some("failed"));
        assert_eq!(log.system_prompt.as_deref(), Some("You are a test assistant.\nThis is a multi-line prompt."));
        assert_eq!(log.interactions.len(), 4); // attachment + user + response + error

        // Check user interaction
        let user_interaction = &log.interactions[1];
        if let Interaction::User { content, .. } = user_interaction {
            assert_eq!(content, "Hello there.\nThis is a multi-line user question.");
        } else {
            panic!("Expected user interaction, found {:?}", user_interaction);
        }
        
        // Test roundtrip
        let formatted_content = format_chat_log(&log);
        let re_parsed_log = parse_chat_file(&formatted_content).expect("Re-parsing failed");

        assert_eq!(log, re_parsed_log, "The formatted content did not parse back to the original struct.");
    }
}