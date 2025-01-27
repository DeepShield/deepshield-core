#[derive(Debug)]
pub enum SecurityError {
    AIAgentVulnerability(String),
    InvalidAddress,
    ContractNotFound,
    APIError(String),
    ConfigError(String),
    ChainError(String),
    // ... other error variants
} 