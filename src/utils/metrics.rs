use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct SecurityMetrics {
    total_transactions: AtomicU64,
    blocked_transactions: AtomicU64,
    alerts_triggered: AtomicU64,
    response_times: RwLock<Vec<Duration>>,
    vulnerability_counts: RwLock<HashMap<String, u64>>,
}

impl SecurityMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_transaction(&self, blocked: bool) {
        self.total_transactions.fetch_add(1, Ordering::SeqCst);
        if blocked {
            self.blocked_transactions.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub async fn record_vulnerability(&self, vulnerability_type: &str) {
        let mut counts = self.vulnerability_counts.write().await;
        *counts.entry(vulnerability_type.to_string()).or_default() += 1;
    }

    pub fn record_response_time(&self, duration: Duration) {
        tokio::spawn(async move {
            if let Ok(mut times) = self.response_times.write().await {
                times.push(duration);
            }
        });
    }
} 