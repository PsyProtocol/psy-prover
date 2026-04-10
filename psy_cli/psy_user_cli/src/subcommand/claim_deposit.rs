use k256::ecdsa::{signature::hazmat::{PrehashSigner, PrehashVerifier}, Signature, SigningKey, VerifyingKey};
use plonky2::field::types::PrimeField64;
use psy_common::{
    args::{ContractCallArgs, ContractCallData, SignType},
};
use psy_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
use psy_config::{network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT, TOKEN_CONTRACT_ID};
use psy_prover::session::WalletSession;
use psy_provider::provider::RpcProvider;
use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;
use serde::Deserialize;
use tiny_keccak::{Hasher, Keccak};

use super::{args::ClaimDepositArgs, key_utils::load_wallet_key_info};

/// Compute keccak256 over raw bytes, return 32-byte digest.
fn keccak_hash_bytes_inner(bytes: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);
    output
}

fn parse_hex32_bytes(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))?;
    anyhow::ensure!(bytes.len() == 32, "bytes32 hex must be 32 bytes, got {}", bytes.len());
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_evm_addr_or_bytes32_to_bytes32(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))?;
    match bytes.len() {
        20 => {
            // address -> bytes32(uint256(uint160(addr)))
            let mut out = [0u8; 32];
            out[12..32].copy_from_slice(&bytes);
            Ok(out)
        }
        32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(out)
        }
        n => anyhow::bail!("expected 20-byte address or 32-byte bytes32 hex, got {} bytes", n),
    }
}

fn parse_hex32_to_u32x8(hex_str: &str) -> anyhow::Result<[u32; 8]> {
    let bytes = parse_hex32_bytes(hex_str)?;
    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = u32::from_be_bytes(bytes[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    Ok(out)
}

/// bytes32 hash nodes (leaf/siblings/root) are mapped into [u32;8]
/// using big-endian 4-byte chunks.
fn parse_hex32_to_u32x8_internal(hex_str: &str) -> anyhow::Result<[u32; 8]> {
    let bytes = parse_hex32_bytes(hex_str)?;
    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = u32::from_be_bytes(bytes[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    Ok(out)
}

fn parse_evm_addr_or_bytes32_to_u32x8(hex_str: &str) -> anyhow::Result<[u32; 8]> {
    let bytes = parse_evm_addr_or_bytes32_to_bytes32(hex_str)?;
    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = u32::from_be_bytes(bytes[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    Ok(out)
}

fn user_id_to_u32x8_be(user_id: u64) -> [u32; 8] {
    [
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        (user_id >> 32) as u32,
        (user_id & 0xffff_ffff) as u32,
    ]
}

fn normalize_evm_addr_from_bytes32(hex32_or_addr: &str) -> anyhow::Result<String> {
    let b = parse_evm_addr_or_bytes32_to_bytes32(hex32_or_addr)?;
    Ok(format!("0x{}", hex::encode(&b[12..32])))
}

fn u32x8_to_bytes32_be(words: [u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

fn u64_to_u64_be_bytes(v: u64, _name: &str) -> anyhow::Result<[u8; 8]> {
    Ok(v.to_be_bytes())
}

fn u64_to_u32x2_be(v: u64) -> [u32; 2] {
    [(v >> 32) as u32, (v & 0xffff_ffff) as u32]
}

fn u32x8_to_hex(words: [u32; 8]) -> String {
    format!(
        "0x{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[7]
    )
}

fn keccak_two_to_one_u32x8(left: [u32; 8], right: [u32; 8]) -> [u32; 8] {
    let mut preimage = Vec::with_capacity(64);
    for w in left.iter().chain(right.iter()) {
        preimage.extend_from_slice(&w.to_be_bytes());
    }
    let digest = keccak_hash_bytes_inner(&preimage);
    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = u32::from_be_bytes(digest[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    out
}

fn fold_root_from_proof(leaf: [u32; 8], siblings: &[[u32; 8]], index: u64) -> [u32; 8] {
    let mut current = leaf;
    for (i, sibling) in siblings.iter().enumerate() {
        let bit = (index >> i) & 1;
        current = if bit == 0 {
            keccak_two_to_one_u32x8(current, *sibling)
        } else {
            keccak_two_to_one_u32x8(*sibling, current)
        };
    }
    current
}

fn compute_bridge_leaf_hash_hex(
    source_chain_index: u64,
    depositor: [u32; 8],
    recipient: [u32; 8],
    token: [u32; 8],
    l2_token_contract_id: [u32; 8],
    amount: u64,
    nonce: u64,
) -> anyhow::Result<String> {
    // Must match L1 Bridge leaf layout exactly:
    // keccak256(abi.encodePacked(depositor, l2Recipient, token, l2TokenContractId, uint64(amount), uint32(chainIndex), uint32(nonce)))
    let mut preimage = Vec::with_capacity(32 * 4 + 8 + 4 + 4);
    preimage.extend_from_slice(&u32x8_to_bytes32_be(depositor));
    preimage.extend_from_slice(&u32x8_to_bytes32_be(recipient));
    preimage.extend_from_slice(&u32x8_to_bytes32_be(token));
    preimage.extend_from_slice(&u32x8_to_bytes32_be(l2_token_contract_id));
    preimage.extend_from_slice(&u64_to_u64_be_bytes(amount, "amount")?);
    preimage.extend_from_slice(&(source_chain_index as u32).to_be_bytes());
    preimage.extend_from_slice(&(nonce as u32).to_be_bytes());
    let digest = keccak_hash_bytes_inner(&preimage);
    Ok(format!("0x{}", hex::encode(digest)))
}

#[derive(Debug, Deserialize)]
struct GraphqlResp<T> {
    data: Option<T>,
}

#[derive(Debug, Deserialize)]
struct DepositRowsData {
    #[serde(rename = "Deposit")]
    deposits: Vec<DepositRow>,
}

#[derive(Debug, Deserialize)]
struct DepositRow {
    depositor: String,
    l2_recipient: String,
    token: String,
    amount: String,
    nonce: String,
    chain_index: i64,
    deposit_index: i64,
    leaf_hash: String,
    new_root: String,
    siblings_json: String,
}

async fn fetch_deposit_proof_from_indexer(
    args: &ClaimDepositArgs,
) -> anyhow::Result<(Vec<u64>, Vec<Vec<u64>>, u64, String, String)> {
    let graphql_url = std::env::var("INDEXER_GRAPHQL_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8080/v1/graphql".to_string());

    let q = format!(
        "{{ Deposit(where: {{ deposit_index: {{_eq: {deposit_index}}}, chain_index: {{_eq: {chain_index}}} }}, order_by: {{block_number: desc}}, limit: 1) {{ depositor l2_recipient token amount nonce chain_index deposit_index leaf_hash new_root siblings_json }} }}",
        deposit_index = args.deposit_index,
        chain_index = args.source_chain_id
    );
    let body = serde_json::json!({ "query": q });
    let cli = reqwest::Client::new();
    let resp = cli
        .post(graphql_url)
        .json(&body)
        .send()
        .await?
        .error_for_status()?
        .json::<GraphqlResp<DepositRowsData>>()
        .await?;
    let row = resp
        .data
        .and_then(|d| d.deposits.into_iter().next())
        .ok_or_else(|| anyhow::anyhow!("deposit row not found in indexer for deposit_index={} chain_index={}", args.deposit_index, args.source_chain_id))?;

    // Sanity checks against CLI arguments.
    let expected_depositor = normalize_evm_addr_from_bytes32(&args.depositor)?;
    let expected_token = normalize_evm_addr_from_bytes32(&args.token_l1_address)?;
    anyhow::ensure!(row.depositor.eq_ignore_ascii_case(&expected_depositor), "depositor mismatch with indexer row");
    anyhow::ensure!(row.token.eq_ignore_ascii_case(&expected_token), "token mismatch with indexer row");
    anyhow::ensure!(row.amount == args.amount.to_string(), "amount mismatch with indexer row");
    anyhow::ensure!(row.nonce == args.nonce.to_string(), "nonce mismatch with indexer row");
    anyhow::ensure!(row.chain_index == args.source_chain_id as i64, "chain_index mismatch with indexer row");
    anyhow::ensure!(row.deposit_index == args.deposit_index as i64, "deposit_index mismatch with indexer row");

    let expected_l2_recipient_be = {
        let mut b = [0u8; 32];
        b[24..32].copy_from_slice(&args.user_id.to_be_bytes());
        format!("0x{}", hex::encode(b))
    };
    anyhow::ensure!(
        row.l2_recipient.eq_ignore_ascii_case(&expected_l2_recipient_be),
        "l2_recipient mismatch with user_id (expected bytes32 BE)"
    );

    // Proof nodes come from bytes32 hashes; convert into VM-internal limb layout.
    let leaf = parse_hex32_to_u32x8_internal(&row.leaf_hash)?
        .iter()
        .map(|&x| x as u64)
        .collect::<Vec<u64>>();
    let siblings_hex: Vec<String> = serde_json::from_str(&row.siblings_json)?;
    anyhow::ensure!(siblings_hex.len() == 32, "siblings_json length must be 32");
    let mut siblings_words: Vec<Vec<u64>> = Vec::with_capacity(32);
    for s in siblings_hex {
        siblings_words.push(
            parse_hex32_to_u32x8_internal(&s)?
                .iter()
                .map(|&x| x as u64)
                .collect::<Vec<u64>>(),
        );
    }
    Ok((leaf, siblings_words, args.deposit_index, row.leaf_hash, row.new_root))
}

pub async fn run(args: ClaimDepositArgs) -> anyhow::Result<()> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let provider = RpcProvider::new_with_config(&rpc_config)?;

    let checkpoint_id = provider.get_coordinator_latest_block_state().await?.checkpoint_id;

    // 1. Verify secp256k1 signature: message = keccak256(deposit_index || user_id
    //    || amount || "claim_deposit")
    let mut sig_preimage = Vec::with_capacity(8 * 3 + 13);
    sig_preimage.extend_from_slice(&args.deposit_index.to_le_bytes());
    sig_preimage.extend_from_slice(&args.user_id.to_le_bytes());
    sig_preimage.extend_from_slice(&args.amount.to_le_bytes());
    sig_preimage.extend_from_slice(b"claim_deposit");
    let message_hash = keccak_hash_bytes_inner(&sig_preimage);

    // 0. Resolve signature inputs.
    // Priority:
    //   a) explicit --public-key/--signature-proof (legacy/manual mode)
    //   b) auto-derive from wallet private key (default mode)
    let (public_key, signature): ([u8; 33], [u8; 64]) = if let (Some(public_key_hex), Some(signature_hex)) =
        (&args.public_key, &args.signature_proof)
    {
        let pk_bytes = hex::decode(public_key_hex)?;
        anyhow::ensure!(pk_bytes.len() == 33, "public_key must be 33 bytes compressed secp256k1");
        let mut public_key = [0u8; 33];
        public_key.copy_from_slice(&pk_bytes);

        let sig_bytes = hex::decode(signature_hex)?;
        anyhow::ensure!(sig_bytes.len() == 64, "signature_proof must be 64 bytes (r||s)");
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig_bytes);
        (public_key, signature)
    } else {
        anyhow::ensure!(
            args.public_key.is_none() && args.signature_proof.is_none(),
            "public_key and signature_proof must be provided together, or both omitted for auto-sign"
        );
        let info = load_wallet_key_info(&args.wallet, false)?;
        let sk_bytes = info.private_key.to_le_bytes();
        let signing_key = SigningKey::from_slice(&sk_bytes)?;
        let vk = signing_key.verifying_key();
        let encoded = vk.to_encoded_point(true);
        let pk_bytes = encoded.as_bytes();
        anyhow::ensure!(pk_bytes.len() == 33, "derived compressed secp256k1 public key must be 33 bytes");
        let mut public_key = [0u8; 33];
        public_key.copy_from_slice(pk_bytes);

        let sig: Signature = signing_key.sign_prehash(&message_hash)?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig.to_bytes());
        (public_key, signature)
    };

    let vk = VerifyingKey::from_sec1_bytes(&public_key)?;
    let sig = Signature::from_slice(&signature)?;
    vk.verify_prehash(&message_hash, &sig)?;
    tracing::info!("signature verified for deposit_id={}", args.deposit_index);

    // 2. Fetch deposit leaf/siblings from indexer (Envio/Hasura).
    let (leaf_hash, siblings, proof_index, indexer_leaf_hash_hex, indexer_new_root_hex) =
        fetch_deposit_proof_from_indexer(&args).await?;

    tracing::info!(
        "deposit leaf_hash(words): {:?}, proof index: {}, siblings: {}",
        leaf_hash,
        proof_index,
        siblings.len()
    );

    // 3. Encode inputs for latest claim_deposit signature:
    //    [source_chain_index(1), depositor(8), l2_token_contract_id(8), token_address(8),
    //     amount(1), recipient(8), nonce(1), siblings(32*8), index(1), checkpoint_id(1)]
    //    = 293 felts
    let depositor = parse_evm_addr_or_bytes32_to_u32x8(&args.depositor)?;
    let token_l1_address = parse_evm_addr_or_bytes32_to_u32x8(&args.token_l1_address)?;
    let recipient = user_id_to_u32x8_be(args.user_id);
    let mut l2_token_contract_id = [0u32; 8];
    l2_token_contract_id[0] = TOKEN_CONTRACT_ID as u32;
    let computed_leaf_hash_hex = compute_bridge_leaf_hash_hex(
        args.source_chain_id,
        depositor,
        recipient,
        token_l1_address,
        l2_token_contract_id,
        args.amount,
        args.nonce,
    )?;
    anyhow::ensure!(
        computed_leaf_hash_hex.eq_ignore_ascii_case(&indexer_leaf_hash_hex),
        "claim_deposit leaf mismatch: computed={} indexer={}",
        computed_leaf_hash_hex,
        indexer_leaf_hash_hex
    );

    // Diagnostics: compare proof-folded root vs expected chain root from deposit_tree storage.
    let mut leaf_u32 = [0u32; 8];
    for (i, v) in leaf_hash.iter().enumerate().take(8) {
        leaf_u32[i] = *v as u32;
    }
    let mut siblings_u32 = Vec::with_capacity(32);
    for s in &siblings {
        let mut t = [0u32; 8];
        for (i, v) in s.iter().enumerate().take(8) {
            t[i] = *v as u32;
        }
        siblings_u32.push(t);
    }
    let proof_root = fold_root_from_proof(leaf_u32, &siblings_u32, proof_index);
    let indexer_new_root = parse_hex32_to_u32x8_internal(&indexer_new_root_hex)?;
    anyhow::ensure!(
        proof_root == indexer_new_root,
        "claim_deposit proof mismatch with indexer new_root: folded={} indexer_new_root={}",
        u32x8_to_hex(proof_root),
        u32x8_to_hex(indexer_new_root)
    );

    tracing::info!(
        checkpoint_id,
        proof_index,
        source_chain_id = args.source_chain_id,
        leaf_hash = %indexer_leaf_hash_hex,
        indexer_new_root = %indexer_new_root_hex,
        proof_root = %u32x8_to_hex(proof_root),
        "claim_deposit root diagnostics"
    );

    let nonce_u32 = (args.nonce & 0xffff_ffff) as u32;
    if args.nonce > u32::MAX as u64 {
        tracing::warn!(
            original_nonce = args.nonce,
            truncated_nonce = nonce_u32,
            "claim_deposit nonce exceeds uint32; using low 32 bits to match bridge leaf encoding"
        );
    }

    let mut inputs: Vec<u64> = Vec::with_capacity(294);
    inputs.push(args.source_chain_id);
    for &v in &depositor {
        inputs.push(v as u64);
    }
    for &v in &l2_token_contract_id {
        inputs.push(v as u64);
    }
    for &v in &token_l1_address {
        inputs.push(v as u64);
    }
    let amount_u64 = u64_to_u32x2_be(args.amount);
    inputs.push(amount_u64[0] as u64);
    inputs.push(amount_u64[1] as u64);
    for &v in &recipient {
        inputs.push(v as u64);
    }
    inputs.push(nonce_u32 as u64);
    assert_eq!(siblings.len(), 32, "expected 32 siblings");
    for sibling in &siblings {
        anyhow::ensure!(sibling.len() == 8, "expected each sibling to be [u32;8]");
        for &e in sibling {
            inputs.push(e);
        }
    }
    inputs.push(proof_index);
    inputs.push(checkpoint_id);
    anyhow::ensure!(
        inputs.len() == 294,
        "claim_deposit inputs size mismatch, expected 294 got {}",
        inputs.len()
    );

    // 5. Submit L2 transaction
    let contract_call = ContractCallArgs {
        contract_id: TOKEN_CONTRACT_ID as u64,
        method_name: "claim_deposit".to_string(),
        inputs,
    };
    let contract_call_data = ContractCallData::new(vec![contract_call]);

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

    tracing::info!("claim_deposit tx submitted! hash: {}", tx_hash.to_string());

    // 6. Send QClaimDepositRPCRequest to Coordinator
    // let req = QClaimDepositRPCRequest {
    //     user_id: args.user_id,
    //     deposit_id: args.deposit_id,
    //     chain_id: args.source_chain_id,
    //     value: args.amount,
    //     txid: Hash256(txid),
    //     public_key,
    //     signature_proof: sig_bytes,
    // };

    // tracing::info!("sending claim_deposit RPC: user_id={}, deposit_id={},
    // value={}", req.user_id, req.deposit_id, req.value);
    // provider.claim_deposit::<GoldilocksField>(req).await?;
    // tracing::info!("claim_deposit completed successfully");

    Ok(())
}
