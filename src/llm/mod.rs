use async_trait::async_trait;
use serde_json::Value;
use crate::errors::SecurityError;

#[async_trait]
pub trait LLMProvider {
    async fn query(&self, prompt: &str) -> Result<String, SecurityError>;
}

pub struct DeepSeekProvider {
    http_client: reqwest::Client,
    api_key: String,
}

impl DeepSeekProvider {
    pub fn new() -> Result<Self, SecurityError> {
        dotenv::dotenv().ok();
        let api_key = std::env::var("DEEPSEEK_API_KEY")
            .map_err(|_| SecurityError::ConfigError("DEEPSEEK_API_KEY not set".to_string()))?;
            
        Ok(Self {
            http_client: reqwest::Client::new(),
            api_key,
        })
    }
}

#[async_trait]
impl LLMProvider for DeepSeekProvider {
    async fn query(&self, prompt: &str) -> Result<String, SecurityError> {
        let response = self.http_client
            .post("https://api.deepseek.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&serde_json::json!({
                "model": "deepseek-coder",
                "messages": [{
                    "role": "user",
                    "content": prompt
                }],
                "temperature": 0.3,
                "max_tokens": 1000
            }))
            .send()
            .await
            .map_err(|e| SecurityError::APIError(e.to_string()))?;

        let response_data: Value = response.json().await
            .map_err(|e| SecurityError::APIError(e.to_string()))?;

        Ok(response_data["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string())
    }
} 