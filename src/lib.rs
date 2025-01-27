use std::sync::Arc;
use thiserror::Error;

pub mod analyzers;
pub mod defenders;
pub mod types;
pub mod utils;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Smart contract vulnerability detected: {0}")]
    SmartContractVulnerability(String),
    #[error("Suspicious transaction detected: {0}")]
    SuspiciousTransaction(String),
    #[error("Price manipulation detected: {0}")]
    PriceManipulation(String),
    #[error("Liquidity risk detected: {0}")]
    LiquidityRisk(String),
}

pub struct SecurityFramework {
    analyzers: Arc<Analyzers>,
    auditors: Arc<Auditors>,
    monitors: Arc<Monitors>,
    defenders: Arc<Defenders>,
    oracle_validator: Arc<ChainlinkOracleValidator>,
    governance_security: Arc<GovernanceSecurity>,
    bridge_monitor: Arc<CrossChainBridgeMonitor>,
    mev_defender: Arc<MEVDefender>,
    protocol_validator: Arc<DeFiProtocolValidator>,
}

impl SecurityFramework {
    pub async fn new() -> Self {
        let framework = Self {
            analyzers: Arc::new(Analyzers::new()),
            auditors: Arc::new(Auditors::new()),
            monitors: Arc::new(Monitors::new()),
            defenders: Arc::new(Defenders::new()),
            oracle_validator: Arc::new(ChainlinkOracleValidator::new()),
            governance_security: Arc::new(GovernanceSecurity::new()),
            bridge_monitor: Arc::new(CrossChainBridgeMonitor::new()),
            mev_defender: Arc::new(MEVDefender::new()),
            protocol_validator: Arc::new(DeFiProtocolValidator::new()),
        };
        
        framework.initialize_security_components().await;
        framework
    }

    pub async fn analyze_contract(&self, contract_address: &str) -> Result<SecurityReport, SecurityError> {
        let mut vulnerabilities = Vec::new();
        let mut recommendations = Vec::new();
        
        // Validate contract address format
        if !utils::validation::is_contract_address(contract_address.parse().map_err(|e| 
            SecurityError::SmartContractVulnerability(format!("Invalid address format: {}", e)))?) {
            return Err(SecurityError::SmartContractVulnerability("Not a contract address".to_string()));
        }

        // Run security checks in parallel
        let (
            smart_contract_result,
            oracle_result,
            governance_result,
            bridge_result,
            protocol_result
        ) = tokio::join!(
            self.analyzers.check_smart_contract_vulnerabilities(contract_address),
            self.oracle_validator.validate(contract_address),
            self.governance_security.check_governance_risks(contract_address),
            self.bridge_monitor.analyze_bridge_risks(contract_address),
            self.protocol_validator.validate_protocol(contract_address)
        );

        // Collect vulnerabilities and recommendations
        if let Err(e) = smart_contract_result {
            vulnerabilities.push(Vulnerability {
                severity: SecuritySeverity::Critical,
                description: format!("Smart contract vulnerability: {}", e),
                mitigation: "Review and fix the identified smart contract issues".to_string(),
            });
        }

        if let Err(e) = oracle_result {
            vulnerabilities.push(Vulnerability {
                severity: SecuritySeverity::High,
                description: format!("Oracle security issue: {}", e),
                mitigation: "Implement proper oracle security measures".to_string(),
            });
        }

        if let Err(e) = governance_result {
            vulnerabilities.push(Vulnerability {
                severity: SecuritySeverity::High,
                description: format!("Governance risk: {}", e),
                mitigation: "Review governance mechanisms and implement safeguards".to_string(),
            });
        }

        if let Err(e) = bridge_result {
            vulnerabilities.push(Vulnerability {
                severity: SecuritySeverity::Critical,
                description: format!("Cross-chain bridge vulnerability: {}", e),
                mitigation: "Implement additional bridge security measures".to_string(),
            });
        }

        if let Err(e) = protocol_result {
            vulnerabilities.push(Vulnerability {
                severity: SecuritySeverity::High,
                description: format!("Protocol vulnerability: {}", e),
                mitigation: "Review and enhance protocol security measures".to_string(),
            });
        }

        // Calculate risk score (0-100)
        let risk_score = calculate_risk_score(&vulnerabilities);

        // Generate recommendations based on findings
        recommendations.extend(generate_recommendations(&vulnerabilities));

        Ok(SecurityReport {
            vulnerabilities,
            risk_score,
            recommendations,
        })
    }
}

#[derive(Debug)]
pub struct SecurityReport {
    vulnerabilities: Vec<Vulnerability>,
    risk_score: u8,
    recommendations: Vec<String>,
}

#[derive(Debug)]
pub struct Vulnerability {
    severity: SecuritySeverity,
    description: String,
    mitigation: String,
}

#[derive(Debug)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

#[derive(Debug, thiserror::Error)]
pub enum DeepShieldError {
    #[error("Transaction analysis failed: {0}")]
    TransactionAnalysisFailed(String),
    #[error("Smart contract vulnerability detected: {0}")]
    SmartContractVulnerability(String),
    #[error("Emergency shutdown triggered: {0}")]
    EmergencyShutdown(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("AI model error: {0}")]
    AIModelError(String),
}

pub type Result<T> = std::result::Result<T, DeepShieldError>;

#[derive(Clone)]
pub struct DeepShield {
    transaction_analyzer: Arc<analyzers::TransactionAnalyzer>,
    contract_analyzer: Arc<analyzers::SmartContractAnalyzer>,
    emergency_shutdown: Arc<defenders::EmergencyShutdown>,
}

impl DeepShield {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            transaction_analyzer: Arc::new(analyzers::TransactionAnalyzer::new()),
            contract_analyzer: Arc::new(analyzers::SmartContractAnalyzer::new()),
            emergency_shutdown: Arc::new(defenders::EmergencyShutdown::new()),
        })
    }

    pub async fn analyze_transaction(&self, tx_data: &[u8]) -> Result<bool> {
        let tx_safe = self.transaction_analyzer.analyze(tx_data).await?;
        if !tx_safe {
            self.emergency_shutdown.trigger("AI detected suspicious transaction pattern").await?;
            return Ok(false);
        }
        Ok(true)
    }

    pub async fn analyze_smart_contract(&self, contract_address: &str, bytecode: &[u8]) -> Result<bool> {
        let contract_safe = self.contract_analyzer.analyze(contract_address, bytecode).await?;
        if !contract_safe {
            self.emergency_shutdown.trigger("AI detected smart contract vulnerability").await?;
            return Ok(false);
        }
        Ok(true)
    }
}

fn calculate_risk_score(vulnerabilities: &[Vulnerability]) -> u8 {
    let base_score = match vulnerabilities.len() {
        0 => 0,
        1..=2 => 25,
        3..=4 => 50,
        5..=6 => 75,
        _ => 100,
    };

    // Adjust score based on severity
    let severity_modifier = vulnerabilities.iter().map(|v| match v.severity {
        SecuritySeverity::Critical => 25,
        SecuritySeverity::High => 15,
        SecuritySeverity::Medium => 10,
        SecuritySeverity::Low => 5,
        SecuritySeverity::Informational => 0,
    }).sum::<u8>();

    // Ensure we don't exceed 100
    std::cmp::min(base_score + severity_modifier, 100)
}

fn generate_recommendations(vulnerabilities: &[Vulnerability]) -> Vec<String> {
    let mut recommendations = Vec::new();
    
    if !vulnerabilities.is_empty() {
        recommendations.push("Conduct a thorough security audit".to_string());
    }

    // Add specific recommendations based on vulnerability types
    for vulnerability in vulnerabilities {
        recommendations.push(vulnerability.mitigation.clone());
    }

    // Add general recommendations
    recommendations.push("Implement continuous security monitoring".to_string());
    recommendations.push("Set up automated vulnerability scanning".to_string());
    
    recommendations
} 