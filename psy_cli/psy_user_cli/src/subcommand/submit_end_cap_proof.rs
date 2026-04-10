use psy_common::args::{SignType, WalletSessionArgs};
use psy_common::data::qhashout::QHashOut;
use psy_data::config::store_config::PsyHasher;
use psy_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
use psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT;
use plonky2::field::goldilocks_field::GoldilocksField as F;
use psy_crypto::hash::traits::qhashable::QFieldHashable;
use psy_prover::session::WalletSession;
use psy_provider::provider::RpcProvider;
use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;
use std::str::FromStr;
use tokio::time::{sleep, Duration};

use crate::subcommand::key_utils::load_wallet_key_info;

pub async fn run(args: WalletSessionArgs) -> anyhow::Result<()> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let provider = RpcProvider::new_with_config(&rpc_config)?;
    let info = load_wallet_key_info(&args.wallet, false)?;
    let user_id = provider
        .get_user_ids_for_public_key(info.public_key_hash)
        .await?
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("No user id found for sender public key"))?;
    let checkpoint_before = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
    let baseline_leaf_hash = provider
        .get_user_leaf_data(checkpoint_before, user_id)
        .await
        .ok()
        .map(|leaf| leaf.qfhash::<PsyHasher>());

    let tx_hash = run_with_tx_hash(args).await?;
    tracing::info!("tx submitted! hash: {}", tx_hash.to_string());

    let mut next_checkpoint_to_check = checkpoint_before.saturating_add(1);
    for _ in 0..120 {
        let latest = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
        let latest_leaf_changed = provider
            .get_user_leaf_data(latest, user_id)
            .await
            .ok()
            .map(|leaf| leaf.qfhash::<PsyHasher>())
            .map(|h| baseline_leaf_hash.map(|b| h != b).unwrap_or(true))
            .unwrap_or(false);
        if latest_leaf_changed {
            tracing::info!(
                "tx confirmed (latest user leaf hash changed) at checkpoint={} user_id={} tx_hash={}",
                latest,
                user_id,
                tx_hash
            );
            return Ok(());
        }
        while next_checkpoint_to_check <= latest {
            let leaf_changed = provider
                .get_user_leaf_data(next_checkpoint_to_check, user_id)
                .await
                .ok()
                .map(|leaf| leaf.qfhash::<PsyHasher>())
                .map(|h| baseline_leaf_hash.map(|b| h != b).unwrap_or(true))
                .unwrap_or(false);
            if leaf_changed {
                tracing::info!(
                    "tx confirmed (user leaf hash changed) at checkpoint={} user_id={} tx_hash={}",
                    next_checkpoint_to_check,
                    user_id,
                    tx_hash
                );
                return Ok(());
            }
            next_checkpoint_to_check = next_checkpoint_to_check.saturating_add(1);
        }
        sleep(Duration::from_secs(1)).await;
    }
    anyhow::bail!(
        "tx submitted but not confirmed within timeout: start_checkpoint={}, user_id={}, tx_hash={}",
        checkpoint_before,
        user_id,
        tx_hash
    );
}

pub async fn run_with_tx_hash(args: WalletSessionArgs) -> anyhow::Result<QHashOut<F>> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();

    let mut wallet_session = WalletSession::new(&rpc_config).await?;
    let info = load_wallet_key_info(&args.wallet, false)?;

    match args.wallet.sign_type {
        SignType::SoftwareDefinedPlonky2Sign => {
            let fingerprint = wallet_session
                .wallet
                .register_plonky2_software_defined_circuit(MAX_CONTRACT_STATE_TREE_HEIGHT, 0)
                .await?;

            if let Some(mut _circuit) = wallet_session.wallet.get_plonky2_software_defined_circuit_mut(&fingerprint) {
                // add custom constraints here
                // state_reader must do the same thing while generating
                // witnesses
            }

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
    let contract_call_data = args.to_contract_call_data()?;
    let tx_hash = wallet_session.exec_contract_call(user_pk_hash, contract_call_data).await?;
    Ok(QHashOut::<F>::from_str(&tx_hash)?)
}
