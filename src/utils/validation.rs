use ethers::types::{Address, U256};
use std::str::FromStr;
use ethers::providers::{Provider, Http};
use std::sync::Arc;

pub fn is_valid_ethereum_address(address: &str) -> bool {
    if !address.starts_with("0x") || address.len() != 42 {
        return false;
    }
    
    Address::from_str(address).is_ok()
}

pub fn is_valid_amount(amount: U256, decimals: u8) -> bool {
    let max_amount = U256::from(10).pow(U256::from(decimals + 18));
    amount <= max_amount
}

pub fn validate_signature_length(signature: &[u8]) -> bool {
    signature.len() == 65
}

pub fn is_contract_address(address: Address) -> bool {
    // Get the default provider (you might want to make this configurable)
    let provider = Provider::<Http>::try_from(
        &std::env::var("ETHEREUM_RPC_URL")
            .unwrap_or_else(|_| "http://localhost:8545".to_string()) // Fallback to localhost if not set
    ).expect("could not instantiate HTTP Provider");
    let provider = Arc::new(provider);

    // Check if there's code at the address
    // This needs to be run in an async context
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async {
            let code = provider.get_code(address, None).await.unwrap_or_default();
            !code.is_empty()
        })
} 