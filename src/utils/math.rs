use ethers::types::U256;
use std::cmp::Ordering;

pub fn calculate_price_impact(amount_in: U256, amount_out: U256, decimals: u8) -> f64 {
    let amount_in_f = u256_to_f64(amount_in, decimals);
    let amount_out_f = u256_to_f64(amount_out, decimals);
    (amount_in_f - amount_out_f).abs() / amount_in_f
}

pub fn calculate_slippage(expected: U256, actual: U256) -> f64 {
    let expected_f = u256_to_f64(expected, 18);
    let actual_f = u256_to_f64(actual, 18);
    (expected_f - actual_f).abs() / expected_f
}

pub fn u256_to_f64(value: U256, decimals: u8) -> f64 {
    let divisor = U256::from(10).pow(U256::from(decimals));
    (value.as_u128() as f64) / (divisor.as_u128() as f64)
}

pub fn calculate_volatility(prices: &[f64]) -> f64 {
    if prices.is_empty() {
        return 0.0;
    }
    
    let mean = prices.iter().sum::<f64>() / prices.len() as f64;
    let variance = prices.iter()
        .map(|&x| (x - mean).powi(2))
        .sum::<f64>() / prices.len() as f64;
    
    variance.sqrt()
} 