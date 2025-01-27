use async_trait::async_trait;
use ethers::{
    prelude::*,
    types::{Address, U256, Transaction},
    providers::{Provider, Http},
    contract::Contract,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

const MIN_TIMELOCK_DURATION: Duration = Duration::from_secs(172800); // 48 hours
const MAX_VOTING_POWER_CONCENTRATION: f64 = 0.10; // 10% maximum concentration
const FLASH_LOAN_DETECTION_WINDOW: u64 = 1; // 1 block window
const MIN_PROPOSAL_THRESHOLD: U256 = U256([1000000000000000000u64, 0, 0, 0]); // 1 token

#[async_trait]
pub trait GovernanceAnalyzer {
    async fn analyze_proposal(&self, proposal_id: u64) -> Result<ProposalSecurity, SecurityError>;
    async fn check_voting_power(&self, address: Address) -> Result<VotingPowerAnalysis, SecurityError>;
}

pub struct GovernanceSecurity {
    timelock_monitor: TimelockMonitor,
    voting_analyzer: VotingPowerAnalyzer,
    governance_contract: Address,
    token_contract: Address,
    provider: Arc<Provider<Http>>,
    historical_votes: HashMap<Address, Vec<VoteHistory>>,
    proposal_cache: HashMap<u64, ProposalDetails>,
}

impl GovernanceSecurity {
    pub fn new(
        governance_address: Address,
        token_address: Address,
        rpc_url: &str,
    ) -> Result<Self, SecurityError> {
        let provider = Provider::<Http>::try_from(rpc_url)
            .map_err(|e| SecurityError::ProviderError(format!("Failed to create provider: {}", e)))?;

        Ok(Self {
            timelock_monitor: TimelockMonitor::new(Duration::from_secs(48 * 3600)),
            voting_analyzer: VotingPowerAnalyzer::new(),
            governance_contract: governance_address,
            token_contract: token_address,
            provider: Arc::new(provider),
            historical_votes: HashMap::new(),
            proposal_cache: HashMap::new(),
        })
    }

    pub async fn detect_governance_attack(&self) -> Result<bool, SecurityError> {
        // Get current block
        let current_block = self.provider
            .get_block_number()
            .await
            .map_err(|e| SecurityError::ProviderError(format!("Failed to get block number: {}", e)))?;

        // Check for flash loan attacks
        let flash_loan_detected = self.detect_flash_loan_voting(current_block.as_u64()).await?;
        if flash_loan_detected {
            return Ok(true);
        }

        // Check for voting power concentration
        let concentration = self.analyze_voting_concentration().await?;
        if concentration > MAX_VOTING_POWER_CONCENTRATION {
            return Ok(true);
        }

        // Check for suspicious proposal patterns
        let suspicious_proposals = self.detect_suspicious_proposals().await?;
        if !suspicious_proposals.is_empty() {
            return Ok(true);
        }

        Ok(false)
    }

    pub async fn verify_timelock(&self, duration: Duration) -> Result<bool, SecurityError> {
        // Check if timelock duration meets minimum requirement
        if duration < MIN_TIMELOCK_DURATION {
            return Ok(false);
        }

        // Get timelock contract
        let timelock_contract = self.get_timelock_contract().await?;
        
        // Verify timelock settings
        let min_delay = timelock_contract
            .method::<_, U256>("getMinDelay", ())?
            .call()
            .await
            .map_err(|e| SecurityError::ContractError(format!("Failed to get min delay: {}", e)))?;

        if min_delay < U256::from(MIN_TIMELOCK_DURATION.as_secs()) {
            return Ok(false);
        }

        // Check for bypass mechanisms
        let has_bypass = self.check_timelock_bypass(&timelock_contract).await?;
        if has_bypass {
            return Ok(false);
        }

        Ok(true)
    }

    pub async fn analyze_voting_concentration(&self) -> Result<f64, SecurityError> {
        let token_contract = Contract::new(
            self.token_contract,
            include_bytes!("../../abis/ERC20Votes.json").as_ref(),
            self.provider.clone(),
        );

        let total_supply = token_contract
            .method::<_, U256>("totalSupply", ())?
            .call()
            .await
            .map_err(|e| SecurityError::ContractError(format!("Failed to get total supply: {}", e)))?;

        let mut holder_balances = HashMap::new();
        let transfer_filter = token_contract.event::<TransferFilter>();
        let transfers = transfer_filter
            .query()
            .await
            .map_err(|e| SecurityError::ContractError(format!("Failed to query transfers: {}", e)))?;

        // Calculate current balances
        for transfer in transfers {
            *holder_balances.entry(transfer.from).or_insert(U256::zero()) -= transfer.value;
            *holder_balances.entry(transfer.to).or_insert(U256::zero()) += transfer.value;
        }

        // Calculate Gini coefficient
        let mut balances: Vec<f64> = holder_balances
            .values()
            .map(|&balance| u256_to_f64(balance))
            .collect();
        balances.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let n = balances.len() as f64;
        let mut gini = 0.0;
        for (i, balance) in balances.iter().enumerate() {
            gini += (2.0 * i as f64 - n + 1.0) * balance;
        }
        gini /= n * n * (balances.iter().sum::<f64>() / n);

        Ok(gini)
    }

    async fn detect_flash_loan_voting(&self, current_block: u64) -> Result<bool, SecurityError> {
        let governance_contract = Contract::new(
            self.governance_contract,
            include_bytes!("../../abis/Governance.json").as_ref(),
            self.provider.clone(),
        );

        // Get recent votes
        let vote_cast_filter = governance_contract.event::<VoteCastFilter>();
        let recent_votes = vote_cast_filter
            .from_block(current_block - FLASH_LOAN_DETECTION_WINDOW)
            .query()
            .await
            .map_err(|e| SecurityError::ContractError(format!("Failed to query votes: {}", e)))?;

        for vote in recent_votes {
            // Check if voting power was temporarily acquired
            let power_before = self.get_historical_voting_power(vote.voter, current_block - 1).await?;
            let power_after = self.get_historical_voting_power(vote.voter, current_block + 1).await?;

            if power_before < vote.weight && power_after < vote.weight {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn detect_suspicious_proposals(&self) -> Result<Vec<u64>, SecurityError> {
        let governance_contract = Contract::new(
            self.governance_contract,
            include_bytes!("../../abis/Governance.json").as_ref(),
            self.provider.clone(),
        );

        let proposal_created_filter = governance_contract.event::<ProposalCreatedFilter>();
        let recent_proposals = proposal_created_filter
            .query()
            .await
            .map_err(|e| SecurityError::ContractError(format!("Failed to query proposals: {}", e)))?;

        let mut suspicious_proposals = Vec::new();
        for proposal in recent_proposals {
            if self.is_suspicious_proposal(&proposal).await? {
                suspicious_proposals.push(proposal.proposal_id.as_u64());
            }
        }

        Ok(suspicious_proposals)
    }

    async fn is_suspicious_proposal(&self, proposal: &ProposalCreatedFilter) -> Result<bool, SecurityError> {
        // Check proposal threshold
        if proposal.start_block <= self.provider.get_block_number().await?.as_u64() + 1 {
            return Ok(true);
        }

        // Check for malicious calls
        for target in &proposal.targets {
            if self.is_malicious_target(*target).await? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn is_malicious_target(&self, target: Address) -> Result<bool, SecurityError> {
        // Check if target is a known malicious contract
        if self.is_blacklisted_contract(target).await? {
            return Ok(true);
        }

        // Check contract code for suspicious patterns
        let code = self.provider
            .get_code(target, None)
            .await
            .map_err(|e| SecurityError::ProviderError(format!("Failed to get code: {}", e)))?;

        if self.contains_suspicious_bytecode(&code) {
            return Ok(true);
        }

        Ok(false)
    }

    async fn get_historical_voting_power(&self, voter: Address, block: u64) -> Result<U256, SecurityError> {
        let token_contract = Contract::new(
            self.token_contract,
            include_bytes!("../../abis/ERC20Votes.json").as_ref(),
            self.provider.clone(),
        );

        token_contract
            .method::<_, U256>("getPastVotes", (voter, block))?
            .call()
            .await
            .map_err(|e| SecurityError::ContractError(format!("Failed to get past votes: {}", e)))
    }
}

#[derive(Debug)]
pub struct ProposalSecurity {
    risk_level: RiskLevel,
    timelock_sufficient: bool,
    centralization_risk: f64,
    malicious_indicators: Vec<String>,
}

#[derive(Debug)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

struct TimelockMonitor {
    min_delay: Duration,
}

impl TimelockMonitor {
    fn new(min_delay: Duration) -> Self {
        Self { min_delay }
    }
}

struct VotingPowerAnalyzer {
    historical_snapshots: HashMap<u64, HashMap<Address, U256>>,
}

impl VotingPowerAnalyzer {
    fn new() -> Self {
        Self {
            historical_snapshots: HashMap::new(),
        }
    }
}

#[derive(Debug)]
struct VoteHistory {
    block_number: u64,
    voting_power: U256,
    proposal_id: u64,
}

#[derive(Debug)]
struct ProposalDetails {
    creator: Address,
    start_block: u64,
    end_block: u64,
    targets: Vec<Address>,
    signatures: Vec<String>,
} 