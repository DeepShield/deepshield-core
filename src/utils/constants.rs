use ethers::types::U256;
use std::time::Duration;

pub const MAX_GAS_LIMIT: U256 = U256([0, 0, 0, 15_000_000]); // 15M gas
pub const MIN_CONFIRMATION_BLOCKS: u64 = 12;
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_PRICE_IMPACT: f64 = 0.03; // 3%
pub const SECURITY_LEVELS: [&str; 4] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

pub const COMMON_DEX_METHODS: [&str; 4] = [
    "swapExactTokensForTokens",
    "swapTokensForExactTokens",
    "swapExactETHForTokens",
    "swapTokensForExactETH",
]; 