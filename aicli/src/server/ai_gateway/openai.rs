// src/server/ai_gateway/openai.rs

use super::{AiClient, AiMessage};
use crate::error::{AppError, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct OpenAiRequest {
    model: String,
    messages: Vec<AiMessage>,
}

#[derive(Deserialize)]
struct OpenAiResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: MessageContent,
}

#[derive(Deserialize)]
struct MessageContent {
    content: String,
}

pub struct OpenAiClient {
    http_client: Client,
    api_url: String,
    api_key: String,
    model: String,
}

impl OpenAiClient {
    pub fn new(api_url: &str, api_key: &str, model: &str) -> Self {
        Self {
            http_client: Client::new(),
            api_url: api_url.to_string(),
            api_key: api_key.to_string(),
            model: model.to_string(),
        }
    }
}

#[async_trait]
impl AiClient for OpenAiClient {
    async fn send_request(&self, messages: Vec<AiMessage>) -> Result<String> {
        let request_body = OpenAiRequest {
            model: self.model.clone(),
            messages,
        };

        let response = self
            .http_client
            .post(&self.api_url)
            .bearer_auth(&self.api_key)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| AppError::AiServiceError(e.to_string()))?;

        // ---- FIX IS HERE ----
        // 1. Get the status first.
        let status = response.status();

        // 2. Check the status.
        if !status.is_success() {
            // 3. Now consume the response to get the error body.
            let error_body = response.text().await.unwrap_or_default();
            return Err(AppError::AiServiceError(format!(
                "API request failed with status {}: {}",
                status,
                error_body
            )));
        }
        // ---- END OF FIX ----

        let response_data: OpenAiResponse = response
            .json()
            .await
            .map_err(|e| AppError::AiServiceError(e.to_string()))?;
        
        response_data
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .ok_or_else(|| AppError::AiServiceError("No content in AI response".to_string()))
    }
}
