// src/server/ai_gateway/mod.rs

use async_trait::async_trait;
use serde::{ Serialize};

use crate::common::config::{Config};
use crate::error::{AppError, Result};
use crate::server::ai_gateway::openai::OpenAiClient;

// A generic message structure that all AI clients can work with.
#[derive(Debug, Serialize, Clone)]
pub struct AiMessage {
    pub role: String, // "system", "user", "assistant"
    pub content: String,
}

#[async_trait]
pub trait AiClient: Send + Sync {
    async fn send_request(&self, messages: Vec<AiMessage>) -> Result<String>;
}

// REFACTORED: Factory function now takes a composite model identifier
pub fn create_client(config: &Config, model_identifier: &str) -> Result<Box<dyn AiClient>> {
    // 1. Parse "server_name:model_display_name"
    let parts: Vec<&str> = model_identifier.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(AppError::ConfigError(format!("Invalid model identifier format: '{}'. Expected 'server:model'.", model_identifier)));
    }
    let server_name = parts[0];
    let model_display_name = parts[1];

    // 2. Find the server configuration
    let server_details = config.server.servers.get(server_name)
        .ok_or_else(|| AppError::ConfigError(format!("Server configuration for '{}' not found.", server_name)))?;

    // 3. Find the real model name from the display name
    let real_model_name = server_details.model_list.get(model_display_name)
        .ok_or_else(|| AppError::ConfigError(format!("Model '{}' not found for server '{}'.", model_display_name, server_name)))?;

    // 4. Create the client based on the specific server's `type`
    match server_details.server_type.as_str() {
        "openai" => Ok(Box::new(OpenAiClient::new(
            &server_details.url,
            &server_details.token,
            real_model_name,
        ))),
        // "gemini" => Ok(Box::new(GeminiClient::new(...))), // Future implementation
        _ => Err(AppError::ConfigError(format!("Unsupported AI server type: '{}' for server '{}'", server_details.server_type, server_name))),
    }
}

// Sub-modules
pub mod openai;
