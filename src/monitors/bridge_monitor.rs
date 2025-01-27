use async_trait::async_trait;
use std::collections::{HashSet, HashMap};
use crate::utils::{
    crypto::keccak256,
    math::{calculate_volatility, u256_to_f64},
    validation::is_valid_amount,
    constants::MAX_PRICE_IMPACT,
};
use ethers::{
    prelude::*,
    types::{Address, U256, H256, Transaction},
    providers::{Provider, Http},
    contract::Contract,
};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::sync::Arc;

const MIN_LIQUIDITY_RATIO: f64 = 0.2; // 20% minimum liquidity ratio
const MAX_BRIDGE_UTILIZATION: f64 = 0.3; // 30% maximum bridge utilization per transaction
const MESSAGE_VERIFICATION_WINDOW: u64 = 100; // blocks to verify message consistency

#[async_trait]
pub trait BridgeMonitor {
    async fn monitor_bridge_activity(&self) -> Result<BridgeStatus, SecurityError>;
    async fn verify_bridge_state(&self) -> Result<bool, SecurityError>;
}

pub struct CrossChainBridgeMonitor {
    supported_chains: HashSet<ChainId>,
    bridge_contracts: HashMap<ChainId, Address>,
    state_verifier: StateVerifier,
    rpc_url: String,
    processed_messages: HashSet<H256>,
    message_expiry: u64,
}

#[derive(Debug)]
pub struct BridgeStatus {
    is_operational: bool,
    locked_funds: Balance,
    recent_transfers: Vec<BridgeTransfer>,
    security_score: u8,
}

impl CrossChainBridgeMonitor {
    pub async fn verify_message_consistency(&self) -> Result<bool, SecurityError> {
        let mut message_states = HashMap::new();
        
        // Collect message states from all supported chains
        for chain_id in &self.supported_chains {
            let messages = self.get_recent_messages(*chain_id, MESSAGE_VERIFICATION_WINDOW).await?;
            
            for message in messages {
                let message_hash = keccak256(&message.data);
                
                message_states
                    .entry(message_hash)
                    .or_insert_with(Vec::new)
                    .push(MessageState {
                        chain_id: *chain_id,
                        status: message.status,
                        timestamp: message.timestamp,
                    });
            }
        }

        // Verify message consistency across chains
        for states in message_states.values() {
            if !self.verify_message_states(states)? {
                return Ok(false);
            }

            // Check for timing attacks
            if self.detect_timing_attack(states)? {
                return Ok(false);
            }

            // Verify message signatures
            if !self.verify_message_signatures(states).await? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub async fn detect_bridge_exploitation(&self) -> Result<Option<Attack>, SecurityError> {
        // Check recent bridge activities
        let activities = self.get_recent_bridge_activities().await?;
        
        // Initialize attack detection results
        let mut detected_attacks = Vec::new();

        // Check for various attack patterns
        for activity in &activities {
            // 1. Check for large transfers
            if self.is_suspicious_transfer_size(&activity).await? {
                detected_attacks.push(Attack::SuspiciousTransferSize {
                    amount: activity.amount,
                    threshold: self.get_transfer_threshold(activity.token_address).await?,
                });
            }

            // 2. Check for rapid withdrawals
            if self.detect_rapid_withdrawals(&activities, activity).await? {
                detected_attacks.push(Attack::RapidWithdrawal {
                    frequency: activity.frequency,
                    time_window: activity.timestamp,
                });
            }

            // 3. Check for price manipulation
            if let Some(manipulation) = self.detect_price_manipulation(activity).await? {
                detected_attacks.push(Attack::PriceManipulation(manipulation));
            }

            // 4. Check for replay attacks
            if self.detect_replay_attack(activity).await? {
                detected_attacks.push(Attack::ReplayAttack {
                    message_hash: activity.message_hash,
                });
            }
        }

        // Check for bridge balance manipulation
        if let Some(balance_attack) = self.detect_balance_manipulation().await? {
            detected_attacks.push(Attack::BalanceManipulation(balance_attack));
        }

        if detected_attacks.is_empty() {
            Ok(None)
        } else {
            Ok(Some(detected_attacks[0].clone())) // Return the most severe attack
        }
    }

    pub async fn monitor_liquidity_ratio(&self) -> Result<f64, SecurityError> {
        let mut total_ratio = 0.0;
        let mut valid_pairs = 0;

        for chain_id in &self.supported_chains {
            let bridge_contract = self.bridge_contracts.get(chain_id)
                .ok_or(SecurityError::ConfigError("Bridge contract not found".to_string()))?;

            // Get bridge token balances
            let (locked_tokens, bridged_tokens) = self.get_bridge_balances(*bridge_contract).await?;

            for (token_address, locked_amount) in locked_tokens {
                if let Some(bridged_amount) = bridged_tokens.get(&token_address) {
                    // Calculate liquidity ratio for this token
                    let locked_f = u256_to_f64(locked_amount, 18);
                    let bridged_f = u256_to_f64(*bridged_amount, 18);

                    if bridged_f > 0.0 {
                        let ratio = locked_f / bridged_f;
                        total_ratio += ratio;
                        valid_pairs += 1;
                    }

                    // Check for immediate issues
                    if locked_f < bridged_f * MIN_LIQUIDITY_RATIO {
                        self.trigger_liquidity_alert(token_address, ratio).await?;
                    }
                }
            }
        }

        if valid_pairs == 0 {
            return Ok(1.0); // Default to 1.0 if no valid pairs
        }

        Ok(total_ratio / valid_pairs as f64)
    }

    async fn get_bridge_balances(&self, bridge_address: Address) -> Result<(HashMap<Address, U256>, HashMap<Address, U256>), SecurityError> {
        let mut locked_tokens = HashMap::new();
        let mut bridged_tokens = HashMap::new();

        for token in &self.supported_tokens {
            // Get locked balance
            let locked_balance = self.get_token_balance(*token, bridge_address).await?;
            locked_tokens.insert(*token, locked_balance);

            // Get bridged balance
            let bridged_balance = self.get_bridged_balance(*token).await?;
            bridged_tokens.insert(*token, bridged_balance);
        }

        Ok((locked_tokens, bridged_tokens))
    }

    async fn trigger_liquidity_alert(&self, token_address: Address, ratio: f64) -> Result<(), SecurityError> {
        let alert = SecurityAlert {
            severity: SecuritySeverity::High,
            alert_type: AlertType::LowLiquidity,
            details: format!(
                "Low liquidity ratio detected for token {}: {:.2}%",
                token_address,
                ratio * 100.0
            ),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| SecurityError::TimeError(e.to_string()))?
                .as_secs(),
        };

        self.alert_handler.send_alert(alert).await?;
        Ok(())
    }

    async fn detect_replay_attack(&self, activity: &BridgeActivity) -> Result<bool, SecurityError> {
        // Check if message hash has been processed before
        let message_hash = activity.message_hash;
        
        if self.processed_messages.contains(&message_hash) {
            return Ok(true);
        }

        // Verify nonce
        let expected_nonce = self.get_expected_nonce(activity.sender).await?;
        if activity.nonce != expected_nonce {
            return Ok(true);
        }

        // Check timestamp validity
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| SecurityError::TimeError(e.to_string()))?
            .as_secs();

        if activity.timestamp + self.message_expiry < current_time {
            return Ok(true);
        }

        Ok(false)
    }

    async fn detect_balance_manipulation(&self) -> Result<Option<BalanceAttack>, SecurityError> {
        let mut suspicious_activities = Vec::new();

        // Get historical balance changes
        let balance_changes = self.get_recent_balance_changes().await?;

        // Check for suspicious patterns
        for window in balance_changes.windows(2) {
            let (prev, curr) = (&window[0], &window[1]);
            
            // Check for large sudden changes
            let change_ratio = (curr.balance.as_u128() as f64) / (prev.balance.as_u128() as f64);
            if change_ratio > 2.0 || change_ratio < 0.5 {
                suspicious_activities.push(BalanceAttack {
                    timestamp: curr.timestamp,
                    token: curr.token,
                    previous_balance: prev.balance,
                    new_balance: curr.balance,
                    change_ratio,
                });
            }
        }

        if suspicious_activities.is_empty() {
            Ok(None)
        } else {
            // Return the most severe attack
            Ok(Some(suspicious_activities.into_iter()
                .max_by(|a, b| a.change_ratio.partial_cmp(&b.change_ratio).unwrap())
                .unwrap()))
        }
    }

    async fn get_token_balance(&self, token: Address, holder: Address) -> Result<U256, SecurityError> {
        let provider = self.get_provider()?;
        let token_contract = Contract::new(
            token,
            include_bytes!("../../abis/ERC20.json").as_ref(),
            Arc::new(provider),
        );

        token_contract
            .method::<_, U256>("balanceOf", holder)?
            .call()
            .await
            .map_err(|e| SecurityError::ContractError(format!("Failed to get token balance: {}", e)))
    }

    async fn get_bridged_balance(&self, token: Address) -> Result<U256, SecurityError> {
        let provider = self.get_provider()?;
        let bridge_contract = Contract::new(
            self.bridge_address,
            include_bytes!("../../abis/Bridge.json").as_ref(),
            Arc::new(provider),
        );

        bridge_contract
            .method::<_, U256>("getBridgedBalance", token)?
            .call()
            .await
            .map_err(|e| SecurityError::ContractError(format!("Failed to get bridged balance: {}", e)))
    }

    async fn get_expected_nonce(&self, sender: Address) -> Result<U256, SecurityError> {
        let provider = self.get_provider()?;
        let bridge_contract = Contract::new(
            self.bridge_address,
            include_bytes!("../../abis/Bridge.json").as_ref(),
            Arc::new(provider),
        );

        bridge_contract
            .method::<_, U256>("getNonce", sender)?
            .call()
            .await
            .map_err(|e| SecurityError::ContractError(format!("Failed to get nonce: {}", e)))
    }

    async fn get_recent_balance_changes(&self) -> Result<Vec<BalanceChange>, SecurityError> {
        let mut changes = Vec::new();
        let provider = self.get_provider()?;
        
        // Get current block
        let current_block = provider
            .get_block_number()
            .await
            .map_err(|e| SecurityError::ProviderError(format!("Failed to get block number: {}", e)))?;

        // Look back 100 blocks
        for block_number in (current_block.as_u64() - 100..=current_block.as_u64()).rev() {
            for token in &self.supported_tokens {
                let balance = self.get_token_balance(*token, self.bridge_address).await?;
                
                changes.push(BalanceChange {
                    token: *token,
                    balance,
                    timestamp: self.get_block_timestamp(block_number).await?,
                });
            }
        }

        Ok(changes)
    }

    async fn get_block_timestamp(&self, block_number: u64) -> Result<u64, SecurityError> {
        let provider = self.get_provider()?;
        let block = provider
            .get_block(block_number)
            .await
            .map_err(|e| SecurityError::ProviderError(format!("Failed to get block: {}", e)))?
            .ok_or_else(|| SecurityError::ProviderError("Block not found".to_string()))?;

        Ok(block.timestamp.as_u64())
    }

    fn get_provider(&self) -> Result<Provider<Http>, SecurityError> {
        Provider::<Http>::try_from(self.rpc_url.as_str())
            .map_err(|e| SecurityError::ProviderError(format!("Failed to create provider: {}", e)))
    }

    // Helper methods
    async fn verify_message_states(&self, states: &[MessageState]) -> Result<bool, SecurityError> {
        // Check for message consistency across chains
        let mut seen_statuses = HashSet::new();
        for state in states {
            seen_statuses.insert(state.status);
        }

        // Verify state transitions
        Ok(self.verify_state_transitions(&seen_statuses))
    }

    async fn detect_timing_attack(&self, states: &[MessageState]) -> Result<bool, SecurityError> {
        let mut timestamps: Vec<_> = states.iter().map(|s| s.timestamp).collect();
        timestamps.sort_unstable();

        // Check for suspicious timing patterns
        for window in timestamps.windows(2) {
            if window[1] - window[0] < self.min_message_delay {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn get_uniswap_v2_volume(&self) -> Result<f64, SecurityError> {
        let provider = self.get_provider()?;
        let factory_contract = Contract::new(
            self.uniswap_v2_factory,
            include_bytes!("../../abis/UniswapV2Factory.json").as_ref(),
            Arc::new(provider.clone()),
        );

        let mut total_volume = 0.0;
        for token in &self.supported_tokens {
            let pair_address = factory_contract
                .method::<_, Address>("getPair", (self.weth_address, token))?
                .call()
                .await
                .map_err(|e| SecurityError::ContractError(format!("Failed to get pair address: {}", e)))?;

            if pair_address != Address::zero() {
                let pair_contract = Contract::new(
                    pair_address,
                    include_bytes!("../../abis/UniswapV2Pair.json").as_ref(),
                    Arc::new(provider.clone()),
                );

                let (reserve0, reserve1, _) = pair_contract
                    .method::<_, (U256, U256, u32)>("getReserves", ())?
                    .call()
                    .await
                    .map_err(|e| SecurityError::ContractError(format!("Failed to get reserves: {}", e)))?;

                total_volume += u256_to_f64(reserve0.max(reserve1), 18);
            }
        }

        Ok(total_volume)
    }

    async fn get_uniswap_v3_volume(&self) -> Result<f64, SecurityError> {
        let provider = self.get_provider()?;
        let factory_contract = Contract::new(
            self.uniswap_v3_factory,
            include_bytes!("../../abis/UniswapV3Factory.json").as_ref(),
            Arc::new(provider.clone()),
        );

        let mut total_volume = 0.0;
        for token in &self.supported_tokens {
            // Check multiple fee tiers (0.05%, 0.3%, 1%)
            for fee in [500, 3000, 10000] {
                let pool_address = factory_contract
                    .method::<_, Address>("getPool", (self.weth_address, token, fee))?
                    .call()
                    .await
                    .map_err(|e| SecurityError::ContractError(format!("Failed to get pool address: {}", e)))?;

                if pool_address != Address::zero() {
                    let pool_contract = Contract::new(
                        pool_address,
                        include_bytes!("../../abis/UniswapV3Pool.json").as_ref(),
                        Arc::new(provider.clone()),
                    );

                    let slot0 = pool_contract
                        .method::<_, (u160, i32, u16, u16, u16, u8, bool)>("slot0", ())?
                        .call()
                        .await
                        .map_err(|e| SecurityError::ContractError(format!("Failed to get slot0: {}", e)))?;

                    let liquidity = pool_contract
                        .method::<_, U128>("liquidity", ())?
                        .call()
                        .await
                        .map_err(|e| SecurityError::ContractError(format!("Failed to get liquidity: {}", e)))?;

                    total_volume += u256_to_f64(U256::from(liquidity.as_u128()), 18);
                }
            }
        }

        Ok(total_volume)
    }

    async fn get_sushiswap_volume(&self) -> Result<f64, SecurityError> {
        let provider = self.get_provider()?;
        let factory_contract = Contract::new(
            self.sushiswap_factory,
            include_bytes!("../../abis/SushiswapFactory.json").as_ref(),
            Arc::new(provider.clone()),
        );

        let mut total_volume = 0.0;
        for token in &self.supported_tokens {
            let pair_address = factory_contract
                .method::<_, Address>("getPair", (self.weth_address, token))?
                .call()
                .await
                .map_err(|e| SecurityError::ContractError(format!("Failed to get pair address: {}", e)))?;

            if pair_address != Address::zero() {
                let pair_contract = Contract::new(
                    pair_address,
                    include_bytes!("../../abis/SushiswapPair.json").as_ref(),
                    Arc::new(provider.clone()),
                );

                let (reserve0, reserve1, _) = pair_contract
                    .method::<_, (U256, U256, u32)>("getReserves", ())?
                    .call()
                    .await
                    .map_err(|e| SecurityError::ContractError(format!("Failed to get reserves: {}", e)))?;

                total_volume += u256_to_f64(reserve0.max(reserve1), 18);
            }
        }

        Ok(total_volume)
    }

    async fn get_curve_volume(&self) -> Result<f64, SecurityError> {
        let provider = self.get_provider()?;
        let mut total_volume = 0.0;

        for pool_address in &self.curve_pools {
            let pool_contract = Contract::new(
                *pool_address,
                include_bytes!("../../abis/CurvePool.json").as_ref(),
                Arc::new(provider.clone()),
            );

            // Get balances for all coins in the pool
            for i in 0..8 {
                // Curve pools can have up to 8 coins
                match pool_contract
                    .method::<_, U256>("balances", i)?
                    .call()
                    .await
                {
                    Ok(balance) => {
                        total_volume += u256_to_f64(balance, 18);
                    }
                    Err(_) => break, // Break if we've reached the end of valid coins
                }
            }
        }

        Ok(total_volume)
    }

    async fn get_balancer_volume(&self) -> Result<f64, SecurityError> {
        let provider = self.get_provider()?;
        let vault_contract = Contract::new(
            self.balancer_vault,
            include_bytes!("../../abis/BalancerVault.json").as_ref(),
            Arc::new(provider.clone()),
        );

        let mut total_volume = 0.0;

        for pool_id in &self.balancer_pools {
            let (tokens, balances, _) = vault_contract
                .method::<_, (Vec<Address>, Vec<U256>, U256)>("getPoolTokens", pool_id)?
                .call()
                .await
                .map_err(|e| SecurityError::ContractError(format!("Failed to get pool tokens: {}", e)))?;

            for balance in balances {
                total_volume += u256_to_f64(balance, 18);
            }
        }

        Ok(total_volume)
    }

    fn verify_state_transitions(&self, seen_statuses: &HashSet<MessageStatus>) -> bool {
        // Check if the state transitions are valid
        if seen_statuses.contains(&MessageStatus::Failed) {
            return false;
        }

        if seen_statuses.contains(&MessageStatus::Completed) {
            // If completed, should have gone through Initiated and InProgress
            return seen_statuses.contains(&MessageStatus::Initiated) 
                && seen_statuses.contains(&MessageStatus::InProgress);
        }

        if seen_statuses.contains(&MessageStatus::InProgress) {
            // If in progress, must have been initiated
            return seen_statuses.contains(&MessageStatus::Initiated);
        }

        true
    }

    async fn verify_message_signatures(&self, states: &[MessageState]) -> Result<bool, SecurityError> {
        for state in states {
            let signature = self.get_message_signature(state.chain_id).await?;
            
            // Verify signature against trusted validators
            if !self.is_trusted_validator(&signature) {
                return Ok(false);
            }

            // Verify signature threshold
            let valid_signatures = self.count_valid_signatures(state).await?;
            if valid_signatures < self.required_signatures {
                return Ok(false);
            }
        }

        Ok(true)
    }

    async fn get_message_signature(&self, chain_id: u64) -> Result<Vec<u8>, SecurityError> {
        let provider = self.get_provider()?;
        let bridge_contract = Contract::new(
            self.bridge_address,
            include_bytes!("../../abis/Bridge.json").as_ref(),
            Arc::new(provider),
        );

        bridge_contract
            .method::<_, Vec<u8>>("getMessageSignature", chain_id)?
            .call()
            .await
            .map_err(|e| SecurityError::ContractError(format!("Failed to get message signature: {}", e)))
    }

    fn is_trusted_validator(&self, signature: &[u8]) -> bool {
        let signer = self.recover_signer(signature)
            .unwrap_or(Address::zero());
        
        self.trusted_validators.contains(&signer)
    }

    async fn count_valid_signatures(&self, state: &MessageState) -> Result<usize, SecurityError> {
        let provider = self.get_provider()?;
        let bridge_contract = Contract::new(
            self.bridge_address,
            include_bytes!("../../abis/Bridge.json").as_ref(),
            Arc::new(provider),
        );

        let signatures = bridge_contract
            .method::<_, Vec<Vec<u8>>>("getMessageSignatures", state.chain_id)?
            .call()
            .await
            .map_err(|e| SecurityError::ContractError(format!("Failed to get message signatures: {}", e)))?;

        Ok(signatures.iter().filter(|sig| self.is_trusted_validator(sig)).count())
    }

    fn recover_signer(&self, signature: &[u8]) -> Option<Address> {
        if signature.len() != 65 {
            return None;
        }

        let mut msg = [0u8; 32];
        msg.copy_from_slice(&keccak256(b"Bridge message"));

        let recovery_id = signature[64];
        let sig = secp256k1::Signature::parse_slice(&signature[..64]).ok()?;
        let recovery_id = secp256k1::RecoveryId::parse(recovery_id).ok()?;
        
        let secp = secp256k1::Secp256k1::new();
        let public_key = secp.recover_ecdsa(&secp256k1::Message::parse(&msg), &sig, &recovery_id).ok()?;
        
        Some(public_key_to_address(&public_key))
    }
}

#[derive(Debug, Clone)]
pub enum Attack {
    SuspiciousTransferSize {
        amount: U256,
        threshold: U256,
    },
    RapidWithdrawal {
        frequency: u64,
        time_window: u64,
    },
    PriceManipulation(PriceManipulation),
    ReplayAttack {
        message_hash: H256,
    },
    BalanceManipulation(BalanceAttack),
}

#[derive(Debug)]
struct MessageState {
    chain_id: u64,
    status: MessageStatus,
    timestamp: u64,
}

#[derive(Debug, Eq, PartialEq, Hash)]
enum MessageStatus {
    Initiated,
    InProgress,
    Completed,
    Failed,
}

#[derive(Debug)]
struct BalanceChange {
    token: Address,
    balance: U256,
    timestamp: u64,
}

#[derive(Debug)]
struct BalanceAttack {
    timestamp: u64,
    token: Address,
    previous_balance: U256,
    new_balance: U256,
    change_ratio: f64,
}

#[derive(Debug)]
struct SecurityAlert {
    severity: SecuritySeverity,
    alert_type: AlertType,
    details: String,
    timestamp: u64,
}

#[derive(Debug)]
enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug)]
enum AlertType {
    LowLiquidity,
    ReplayAttack,
    BalanceManipulation,
    RapidWithdrawal,
}

#[derive(Debug)]
struct BridgeActivity {
    message_hash: H256,
    sender: Address,
    nonce: U256,
    timestamp: u64,
    amount: U256,
    token_address: Address,
    frequency: u64,
} 