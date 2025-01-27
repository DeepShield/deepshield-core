use async_trait::async_trait;
use std::collections::HashMap;
use web3::types::Address;
use ethers::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::utils::logger::SecurityLogger;
use std::sync::Arc;

#[async_trait]
pub trait OracleValidator {
    async fn validate_price_feed(&self, oracle_address: Address) -> Result<OracleHealth, SecurityError>;
    async fn detect_manipulation(&self, price_data: &PriceData) -> Result<bool, SecurityError>;
}

pub struct ChainlinkOracleValidator {
    trusted_feeds: HashMap<Address, OracleConfig>,
    historical_deviations: Vec<PriceDeviation>,
    logger: Arc<SecurityLogger>,
}

#[derive(Debug)]
pub struct OracleHealth {
    is_healthy: bool,
    last_update: u64,
    deviation_threshold: f64,
    manipulation_score: f64,
}

const STALE_DATA_THRESHOLD: u64 = 3600; // 1 hour in seconds
const PRICE_DEVIATION_THRESHOLD: f64 = 0.03; // 3% deviation threshold
const FLASH_LOAN_WINDOW: u64 = 15; // 15 seconds window for flash loan detection
const VOLUME_WINDOW_BLOCKS: u64 = 20; // Look back period for volume analysis
const VOLUME_SPIKE_THRESHOLD: f64 = 3.0; // 300% increase from baseline
const MIN_VOLUME_THRESHOLD: f64 = 1000.0; // Minimum volume in USD to consider
const MAX_ACCEPTABLE_VOLUME_MULTIPLIER: f64 = 10.0; // Maximum acceptable volume increase

impl ChainlinkOracleValidator {
    pub async fn check_stale_data(&self, feed: Address) -> Result<bool, SecurityError> {
        let config = self.trusted_feeds.get(&feed)
            .ok_or(SecurityError::InvalidOracle("Unknown oracle feed".to_string()))?;
            
        // Get the current timestamp
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| SecurityError::TimeError(e.to_string()))?
            .as_secs();

        // Get the last update timestamp from the oracle
        let last_update = self.get_last_update_timestamp(feed).await?;
        
        // Check if the data is stale
        let time_since_update = current_time.saturating_sub(last_update);
        if time_since_update > STALE_DATA_THRESHOLD {
            return Ok(true);
        }

        // Check heartbeat deviation
        if time_since_update > config.heartbeat_interval {
            return Ok(true);
        }

        Ok(false)
    }

    pub async fn verify_multiple_sources(&self, price: f64) -> Result<bool, SecurityError> {
        let mut price_data = Vec::new();
        
        // Collect prices from multiple oracle sources
        for (oracle_address, config) in &self.trusted_feeds {
            let oracle_price = self.get_oracle_price(*oracle_address).await?;
            price_data.push((oracle_price, config.weight));
        }

        // Calculate weighted average
        let weighted_avg = self.calculate_weighted_average(&price_data);
        
        // Calculate deviation from weighted average
        let deviation = ((price - weighted_avg) / weighted_avg).abs();
        
        // Check if deviation exceeds threshold
        if deviation > PRICE_DEVIATION_THRESHOLD {
            return Ok(false);
        }

        // Verify minimum number of sources
        if price_data.len() < self.min_required_sources {
            return Ok(false);
        }

        Ok(true)
    }

    pub async fn detect_flash_loan_manipulation(&self) -> Result<bool, SecurityError> {
        // Get recent price updates within flash loan window
        let recent_updates = self.get_recent_price_updates(FLASH_LOAN_WINDOW).await?;
        
        if recent_updates.is_empty() {
            return Ok(false);
        }

        // Calculate price volatility metrics
        let (volatility, price_impact) = self.calculate_volatility_metrics(&recent_updates)?;

        // Check for suspicious patterns
        let mut manipulation_detected = false;

        // 1. Check for extreme price movements
        if volatility > self.max_allowed_volatility {
            manipulation_detected = true;
        }

        // 2. Check for price reversal pattern (common in flash loan attacks)
        if let Some(price_reversal) = self.detect_price_reversal_pattern(&recent_updates) {
            if price_reversal > self.reversal_threshold {
                manipulation_detected = true;
            }
        }

        // 3. Check trading volume spikes
        if let Some(volume_spike) = self.detect_volume_spike(&recent_updates).await? {
            if volume_spike > self.volume_spike_threshold {
                manipulation_detected = true;
            }
        }

        if manipulation_detected {
            self.logger.log_oracle_manipulation(
                "flash_loan_attack",
                self.calculate_price_deviation().await?,
            ).map_err(|e| SecurityError::LoggingError(e.to_string()))?;
        }

        Ok(manipulation_detected)
    }

    // Helper methods
    async fn get_last_update_timestamp(&self, feed: Address) -> Result<u64, SecurityError> {
        // Implementation to fetch last update timestamp from Chainlink feed
        let contract = self.get_chainlink_feed_contract(feed);
        let (_, timestamp, _, _, _) = contract
            .latest_round_data()
            .call()
            .await
            .map_err(|e| SecurityError::OracleError(format!("Failed to get round data: {}", e)))?;
        
        Ok(timestamp.as_u64())
    }

    async fn get_oracle_price(&self, oracle: Address) -> Result<f64, SecurityError> {
        // Implementation to fetch price from oracle
        let contract = self.get_chainlink_feed_contract(oracle);
        let (_, price, _, _, _) = contract
            .latest_round_data()
            .call()
            .await
            .map_err(|e| SecurityError::OracleError(format!("Failed to get price data: {}", e)))?;
        
        Ok(self.normalize_price(price))
    }

    fn calculate_weighted_average(&self, price_data: &[(f64, f64)]) -> f64 {
        let total_weight: f64 = price_data.iter().map(|(_, weight)| weight).sum();
        price_data.iter().map(|(price, weight)| price * weight).sum::<f64>() / total_weight
    }

    async fn get_recent_price_updates(&self, window: u64) -> Result<Vec<PriceUpdate>, SecurityError> {
        let mut updates = Vec::new();
        
        for (oracle_address, _) in &self.trusted_feeds {
            let contract = self.get_chainlink_feed_contract(*oracle_address);
            let latest_round = contract
                .latest_round()
                .call()
                .await
                .map_err(|e| SecurityError::OracleError(format!("Failed to get latest round: {}", e)))?;

            // Fetch recent rounds within the window
            for round_id in (latest_round.as_u64() - 10..=latest_round.as_u64()) {
                let (_, price, timestamp, _, _) = contract
                    .get_round_data(round_id.into())
                    .call()
                    .await
                    .map_err(|e| SecurityError::OracleError(format!("Failed to get round data: {}", e)))?;

                updates.push(PriceUpdate {
                    price: self.normalize_price(price),
                    timestamp: timestamp.as_u64(),
                    oracle: *oracle_address,
                });
            }
        }

        Ok(updates)
    }

    fn calculate_volatility_metrics(&self, updates: &[PriceUpdate]) -> Result<(f64, f64), SecurityError> {
        if updates.len() < 2 {
            return Ok((0.0, 0.0));
        }

        let prices: Vec<f64> = updates.iter().map(|u| u.price).collect();
        let volatility = self.calculate_price_volatility(&prices);
        let price_impact = (prices.last().unwrap() - prices.first().unwrap()).abs() / prices.first().unwrap();

        Ok((volatility, price_impact))
    }

    fn detect_price_reversal_pattern(&self, updates: &[PriceUpdate]) -> Option<f64> {
        if updates.len() < 3 {
            return None;
        }

        let prices: Vec<f64> = updates.iter().map(|u| u.price).collect();
        let initial_move = prices[1] - prices[0];
        let reversal_move = prices[2] - prices[1];

        if initial_move.signum() != reversal_move.signum() {
            Some((reversal_move / initial_move).abs())
        } else {
            None
        }
    }

    async fn detect_volume_spike(&self, updates: &[PriceUpdate]) -> Result<Option<f64>, SecurityError> {
        let mut volume_data = VolumeData {
            current_volume: 0.0,
            baseline_volume: 0.0,
            volume_multiplier: 0.0,
            dex_volumes: HashMap::new(),
        };

        // Collect volume data from multiple DEXes
        volume_data = self.collect_dex_volumes(updates).await?;
        
        // Calculate baseline volume (moving average)
        volume_data.baseline_volume = self.calculate_baseline_volume().await?;

        // Skip check if baseline volume is too low
        if volume_data.baseline_volume < MIN_VOLUME_THRESHOLD {
            return Ok(None);
        }

        // Calculate volume multiplier
        volume_data.volume_multiplier = volume_data.current_volume / volume_data.baseline_volume;

        // Check for suspicious volume patterns
        if let Some(spike_severity) = self.analyze_volume_patterns(&volume_data).await? {
            // Additional validation for extreme volume spikes
            if self.validate_volume_spike(&volume_data).await? {
                return Ok(Some(spike_severity));
            }
        }

        Ok(None)
    }

    async fn collect_dex_volumes(&self, updates: &[PriceUpdate]) -> Result<VolumeData, SecurityError> {
        let mut volume_data = VolumeData {
            current_volume: 0.0,
            baseline_volume: 0.0,
            volume_multiplier: 0.0,
            dex_volumes: HashMap::new(),
        };

        // Collect volumes from major DEXes
        let dexes = vec![
            "uniswap_v2",
            "uniswap_v3",
            "sushiswap",
            "curve",
            "balancer"
        ];

        for dex in dexes {
            let volume = match dex {
                "uniswap_v2" => self.get_uniswap_v2_volume().await?,
                "uniswap_v3" => self.get_uniswap_v3_volume().await?,
                "sushiswap" => self.get_sushiswap_volume().await?,
                "curve" => self.get_curve_volume().await?,
                "balancer" => self.get_balancer_volume().await?,
                _ => 0.0,
            };

            volume_data.dex_volumes.insert(dex.to_string(), volume);
            volume_data.current_volume += volume;
        }

        Ok(volume_data)
    }

    async fn calculate_baseline_volume(&self) -> Result<f64, SecurityError> {
        let mut total_volume = 0.0;
        let mut count = 0;

        // Get historical block data
        let current_block = self.provider
            .get_block_number()
            .await
            .map_err(|e| SecurityError::ProviderError(format!("Failed to get block number: {}", e)))?;

        // Calculate average volume over the window
        for block_number in (current_block.as_u64() - VOLUME_WINDOW_BLOCKS..current_block.as_u64()).rev() {
            let block_volume = self.get_block_volume(block_number).await?;
            total_volume += block_volume;
            count += 1;
        }

        if count == 0 {
            return Err(SecurityError::ValidationError("No historical volume data available".to_string()));
        }

        Ok(total_volume / count as f64)
    }

    async fn analyze_volume_patterns(&self, volume_data: &VolumeData) -> Result<Option<f64>, SecurityError> {
        // Basic volume spike check
        if volume_data.volume_multiplier > VOLUME_SPIKE_THRESHOLD {
            let severity = self.calculate_spike_severity(volume_data);
            
            // Check for suspicious patterns
            if self.check_suspicious_volume_patterns(volume_data).await? {
                return Ok(Some(severity));
            }
        }

        Ok(None)
    }

    async fn validate_volume_spike(&self, volume_data: &VolumeData) -> Result<bool, SecurityError> {
        // Reject extremely large volume spikes
        if volume_data.volume_multiplier > MAX_ACCEPTABLE_VOLUME_MULTIPLIER {
            return Ok(false);
        }

        // Check volume distribution across DEXes
        let is_volume_distributed = self.check_volume_distribution(&volume_data.dex_volumes)?;
        if !is_volume_distributed {
            return Ok(false);
        }

        // Verify transaction count correlation
        let tx_count_correlation = self.verify_transaction_count_correlation(volume_data).await?;
        if !tx_count_correlation {
            return Ok(false);
        }

        Ok(true)
    }

    fn check_volume_distribution(&self, dex_volumes: &HashMap<String, f64>) -> Result<bool, SecurityError> {
        let total_volume: f64 = dex_volumes.values().sum();
        
        // Check if volume is too concentrated in a single DEX
        for &volume in dex_volumes.values() {
            if volume > total_volume * 0.8 { // 80% concentration threshold
                return Ok(false);
            }
        }

        Ok(true)
    }

    async fn verify_transaction_count_correlation(&self, volume_data: &VolumeData) -> Result<bool, SecurityError> {
        let current_block = self.provider
            .get_block_number()
            .await
            .map_err(|e| SecurityError::ProviderError(format!("Failed to get block number: {}", e)))?;

        let tx_count = self.get_transaction_count(current_block.as_u64()).await?;
        let baseline_tx_count = self.get_baseline_transaction_count().await?;

        // Check if transaction count increase correlates with volume increase
        let tx_multiplier = tx_count as f64 / baseline_tx_count as f64;
        
        // Volume increase should be somewhat proportional to transaction count increase
        Ok(tx_multiplier * 2.0 > volume_data.volume_multiplier)
    }

    fn calculate_spike_severity(&self, volume_data: &VolumeData) -> f64 {
        let base_severity = (volume_data.volume_multiplier - VOLUME_SPIKE_THRESHOLD) / VOLUME_SPIKE_THRESHOLD;
        base_severity.min(1.0)
    }

    async fn check_suspicious_volume_patterns(&self, volume_data: &VolumeData) -> Result<bool, SecurityError> {
        // Check for wash trading patterns
        let wash_trading_detected = self.detect_wash_trading(volume_data).await?;
        if wash_trading_detected {
            return Ok(true);
        }

        // Check for coordinated trading patterns
        let coordinated_trading = self.detect_coordinated_trading(volume_data).await?;
        if coordinated_trading {
            return Ok(true);
        }

        Ok(false)
    }

    // Helper methods for specific DEX volume fetching
    async fn get_uniswap_v2_volume(&self) -> Result<f64, SecurityError> {
        let volume = match self.fetch_dex_volume("uniswap_v2").await {
            Ok(v) => v,
            Err(_) => {
                // Fallback to heuristic calculation
                let pair_reserves = self.get_pair_reserves().await?;
                let price = self.get_current_price().await?;
                let estimated_volume = pair_reserves * price * 0.003; // 0.3% fee heuristic
                estimated_volume
            }
        };
        Ok(volume)
    }

    async fn get_uniswap_v3_volume(&self) -> Result<f64, SecurityError> {
        let volume = match self.fetch_dex_volume("uniswap_v3").await {
            Ok(v) => v,
            Err(_) => {
                // Heuristic based on tick range and liquidity
                let (tick_lower, tick_upper) = self.get_tick_range().await?;
                let liquidity = self.get_pool_liquidity().await?;
                let price = self.get_current_price().await?;
                
                // Estimate volume based on tick range and liquidity
                let tick_range = (tick_upper - tick_lower) as f64;
                let estimated_volume = liquidity * price * (tick_range / 100.0) * 0.004;
                estimated_volume
            }
        };
        Ok(volume)
    }

    async fn get_sushiswap_volume(&self) -> Result<f64, SecurityError> {
        let volume = match self.fetch_dex_volume("sushiswap").await {
            Ok(v) => v,
            Err(_) => {
                // Similar to Uniswap V2 with adjustment factor
                let pair_reserves = self.get_pair_reserves().await?;
                let price = self.get_current_price().await?;
                let estimated_volume = pair_reserves * price * 0.0025; // 0.25% fee heuristic
                estimated_volume * 0.8 // Adjustment factor based on market share
            }
        };
        Ok(volume)
    }

    async fn get_curve_volume(&self) -> Result<f64, SecurityError> {
        let volume = match self.fetch_dex_volume("curve").await {
            Ok(v) => v,
            Err(_) => {
                // Heuristic based on pool balances and rates
                let pool_balances = self.get_curve_pool_balances().await?;
                let virtual_price = self.get_curve_virtual_price().await?;
                let base_volume = pool_balances * virtual_price;
                
                // Adjust based on typical Curve pool characteristics
                let daily_volume = base_volume * 0.15; // 15% daily turnover heuristic
                daily_volume
            }
        };
        Ok(volume)
    }

    async fn get_balancer_volume(&self) -> Result<f64, SecurityError> {
        let volume = match self.fetch_dex_volume("balancer").await {
            Ok(v) => v,
            Err(_) => {
                // Heuristic based on pool weights and balances
                let pool_data = self.get_balancer_pool_data().await?;
                let total_liquidity = self.calculate_weighted_liquidity(&pool_data).await?;
                let price = self.get_current_price().await?;
                
                // Estimate volume based on liquidity and weights
                let estimated_volume = total_liquidity * price * 0.002; // 0.2% fee heuristic
                estimated_volume
            }
        };
        Ok(volume)
    }

    // Helper methods for volume calculations
    async fn fetch_dex_volume(&self, dex: &str) -> Result<f64, SecurityError> {
        let endpoint = match dex {
            "uniswap_v2" => "https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v2",
            "uniswap_v3" => "https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v3",
            "sushiswap" => "https://api.thegraph.com/subgraphs/name/sushiswap/exchange",
            "curve" => "https://api.curve.fi/api/getVolume",
            "balancer" => "https://api.thegraph.com/subgraphs/name/balancer-labs/balancer-v2",
            _ => return Err(SecurityError::ValidationError("Unknown DEX".to_string())),
        };

        let client = reqwest::Client::new();
        let response = client.get(endpoint)
            .send()
            .await
            .map_err(|e| SecurityError::NetworkError(e.to_string()))?;

        let volume = response.json::<f64>()
            .await
            .map_err(|e| SecurityError::DataError(e.to_string()))?;

        Ok(volume)
    }

    async fn get_pair_reserves(&self) -> Result<f64, SecurityError> {
        // Simplified reserve calculation
        let reserve0 = 1000000.0; // Example fallback value
        let reserve1 = 1000000.0;
        Ok(reserve0.min(reserve1))
    }

    async fn get_current_price(&self) -> Result<f64, SecurityError> {
        // Simplified price fetch with fallback
        Ok(1500.0) // Example fallback price
    }

    async fn get_tick_range(&self) -> Result<(i32, i32), SecurityError> {
        // Example tick range for concentrated liquidity
        Ok((-887272, 887272))
    }

    async fn get_pool_liquidity(&self) -> Result<f64, SecurityError> {
        // Simplified liquidity calculation
        Ok(1000000.0)
    }

    async fn get_curve_pool_balances(&self) -> Result<f64, SecurityError> {
        // Simplified pool balance calculation
        Ok(2000000.0)
    }

    async fn get_curve_virtual_price(&self) -> Result<f64, SecurityError> {
        // Simplified virtual price calculation
        Ok(1.02)
    }

    async fn get_balancer_pool_data(&self) -> Result<BalancerPoolData, SecurityError> {
        Ok(BalancerPoolData {
            tokens: vec![
                ("TOKEN_A".to_string(), 0.5, 1000000.0),
                ("TOKEN_B".to_string(), 0.5, 1000000.0),
            ],
        })
    }

    async fn calculate_weighted_liquidity(&self, pool_data: &BalancerPoolData) -> Result<f64, SecurityError> {
        let mut weighted_liquidity = 0.0;
        for (_, weight, balance) in &pool_data.tokens {
            weighted_liquidity += balance * weight;
        }
        Ok(weighted_liquidity)
    }
}

#[derive(Debug)]
struct VolumeData {
    current_volume: f64,
    baseline_volume: f64,
    volume_multiplier: f64,
    dex_volumes: HashMap<String, f64>,
}

#[derive(Debug)]
struct BalancerPoolData {
    tokens: Vec<(String, f64, f64)>, // (token_address, weight, balance)
} 