use psy_common::args::{ContractCallArgs, ContractCallData, SignType};
use psy_config::{network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT, TOKEN_CONTRACT_ID};
use psy_prover::session::WalletSession;
use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;

use super::{args::WithdrawArgs, key_utils::load_wallet_key_info};

/// Parse a 32-byte hex string into 8 u32 words (big-endian word order).
fn parse_hash_hex_u32x8(hex_str: &str) -> anyhow::Result<[u32; 8]> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)?;
    anyhow::ensure!(bytes.len() == 32, "hash hex must be 32 bytes, got {}", bytes.len());
    let mut words = [0u32; 8];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        words[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    Ok(words)
}

pub async fn run(args: WithdrawArgs) -> anyhow::Result<()> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();

    // 1. Parse hex inputs → 8 u32 felts each
    let token_address = parse_hash_hex_u32x8(&args.token_address)?;
    let recipient = parse_hash_hex_u32x8(&args.recipient)?;

    // 2. Build contract call inputs withdraw(destination_chain_id,
    //    token_address[8], amount, recipient[8], nonce) = 19 felts total
    let mut inputs: Vec<u64> = Vec::with_capacity(19);
    inputs.push(args.destination_chain_id);
    inputs.extend(token_address.into_iter().map(|x| x as u64));
    inputs.push(args.amount);
    inputs.extend(recipient.into_iter().map(|x| x as u64));
    inputs.push(args.nonce);

    let contract_call = ContractCallArgs {
        contract_id: TOKEN_CONTRACT_ID as u64, // token contract
        method_name: "withdraw".to_string(),
        inputs,
    };
    let contract_call_data = ContractCallData::new(vec![contract_call]);

    // 3. Create wallet session and submit transaction
    let mut wallet_session = WalletSession::new(&rpc_config).await?;
    let info = load_wallet_key_info(&args.wallet, false)?;

    match args.wallet.sign_type {
        SignType::SoftwareDefinedPlonky2Sign => {
            let fingerprint = wallet_session
                .wallet
                .register_plonky2_software_defined_circuit(MAX_CONTRACT_STATE_TREE_HEIGHT, 0)
                .await?;
            assert_eq!(info.fingerprint, fingerprint, "software-defined-plonky2-sign key fingerprint mismatch");
        }
        SignType::SoftwareDefinedDPNSign => {
            let user_sdc: DPNFunctionCircuitDefinition = serde_json::from_str(&std::fs::read_to_string("sdc.json")?)?;
            let fingerprint = wallet_session.wallet.register_psy_software_defined_circuit(user_sdc, false).await?;
            assert_eq!(info.fingerprint, fingerprint, "software-defined-dpn-sign key fingerprint mismatch");
        }
        _ => {}
    };

    let user_pk_hash = wallet_session.add_user(info.private_key, info.fingerprint).await?;
    let tx_hash = wallet_session.exec_contract_call(user_pk_hash, contract_call_data).await?;

    tracing::info!(
        destination_chain_id = args.destination_chain_id,
        amount = args.amount,
        nonce = args.nonce,
        "withdraw tx submitted! hash: {}",
        tx_hash.to_string()
    );

    Ok(())
}
