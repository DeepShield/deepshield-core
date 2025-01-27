use tracing::{Level, Event, Subscriber};
use std::sync::Arc;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use crate::analyzers::protocol_validator::Vulnerability;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Serialize)]
pub struct SecurityEvent {
    pub timestamp: DateTime<Utc>,
    pub level: SecuritySeverity,
    pub message: String,
    pub metadata: HashMap<String, String>,
}

pub struct SecurityLogger {
    level: Level,
    output_path: String,
    file: Arc<parking_lot::RwLock<File>>,
}

impl SecurityLogger {
    pub fn new(level: Level, output_path: String) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&output_path)?;

        Ok(Self {
            level,
            output_path,
            file: Arc::new(parking_lot::RwLock::new(file)),
        })
    }

    pub fn log_security_event(&self, event: SecurityEvent) -> std::io::Result<()> {
        let log_entry = serde_json::to_string(&event)?;
        let mut file = self.file.write();
        writeln!(file, "{}", log_entry)?;
        
        // If critical or high severity, also print to stderr
        match event.level {
            SecuritySeverity::Critical | SecuritySeverity::High => {
                eprintln!("SECURITY ALERT [{}]: {}", event.level.as_str(), event.message);
                for (key, value) in event.metadata {
                    eprintln!("  {}: {}", key, value);
                }
            }
            _ => {}
        }
        
        Ok(())
    }

    pub fn log_vulnerability(&self, vulnerability: &Vulnerability) -> std::io::Result<()> {
        let event = SecurityEvent {
            timestamp: Utc::now(),
            level: convert_severity(&vulnerability.severity),
            message: vulnerability.description.clone(),
            metadata: HashMap::from([
                ("component".to_string(), vulnerability.affected_component.clone()),
                ("mitigation".to_string(), "Immediate action required".to_string()),
            ]),
        };
        
        self.log_security_event(event)
    }

    pub fn log_emergency_shutdown(&self, reason: &str) -> std::io::Result<()> {
        let event = SecurityEvent {
            timestamp: Utc::now(),
            level: SecuritySeverity::Critical,
            message: format!("EMERGENCY SHUTDOWN TRIGGERED: {}", reason),
            metadata: HashMap::from([
                ("action".to_string(), "emergency_shutdown".to_string()),
                ("timestamp".to_string(), Utc::now().to_rfc3339()),
            ]),
        };
        
        self.log_security_event(event)
    }

    pub fn log_mev_detection(&self, attack_type: &str, risk_level: &str, potential_loss: &str) -> std::io::Result<()> {
        let event = SecurityEvent {
            timestamp: Utc::now(),
            level: SecuritySeverity::High,
            message: format!("MEV Attack Detection: {}", attack_type),
            metadata: HashMap::from([
                ("risk_level".to_string(), risk_level.to_string()),
                ("potential_loss".to_string(), potential_loss.to_string()),
                ("detection_time".to_string(), Utc::now().to_rfc3339()),
            ]),
        };
        
        self.log_security_event(event)
    }

    pub fn log_oracle_manipulation(&self, oracle_address: &str, deviation: f64) -> std::io::Result<()> {
        let event = SecurityEvent {
            timestamp: Utc::now(),
            level: SecuritySeverity::Critical,
            message: format!("Oracle Price Manipulation Detected"),
            metadata: HashMap::from([
                ("oracle_address".to_string(), oracle_address.to_string()),
                ("price_deviation".to_string(), deviation.to_string()),
                ("detection_time".to_string(), Utc::now().to_rfc3339()),
            ]),
        };
        
        self.log_security_event(event)
    }
}

impl SecuritySeverity {
    fn as_str(&self) -> &'static str {
        match self {
            SecuritySeverity::Critical => "CRITICAL",
            SecuritySeverity::High => "HIGH",
            SecuritySeverity::Medium => "MEDIUM",
            SecuritySeverity::Low => "LOW",
            SecuritySeverity::Info => "INFO",
        }
    }
}

fn convert_severity(severity: &crate::analyzers::protocol_validator::ExploitSeverity) -> SecuritySeverity {
    match severity {
        crate::analyzers::protocol_validator::ExploitSeverity::Critical => SecuritySeverity::Critical,
        crate::analyzers::protocol_validator::ExploitSeverity::High => SecuritySeverity::High,
        crate::analyzers::protocol_validator::ExploitSeverity::Medium => SecuritySeverity::Medium,
        crate::analyzers::protocol_validator::ExploitSeverity::Low => SecuritySeverity::Low,
    }
} 