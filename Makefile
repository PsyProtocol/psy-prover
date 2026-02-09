PROFILE := release
LOG_LEVEL := psy_ups_circuit=trace,psy_dpn_circuit=trace,psy_user_cli=debug,psy_common_circuit=trace,psy_network_circuit=trace,psy_prover=trace,plonky2=error

default: build

check:
	@cargo check --workspace --all-targets --tests --benches --examples --bins

fix:
	# @cargo machete --fix
	@cargo fix --all-targets --allow-dirty --allow-staged

build:
	@RUSTFLAGS="-A warnings" cargo build --profile ${PROFILE} --bin psy_user_cli

fmt:
	@cargo fmt

install:
	@cargo install --path psy_cli/psy_user_cli --locked

clean:
	@rm -rf target


.PHONY: check fix build fmt

################################################################################
#                                   TMP                                        #
################################################################################
USER0_PRIVATE_KEY        := c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359
USER0_PUBLIC_KEY         := cc92647d3a77819dec2f054a241d0863c9bd54cf5a1103ca560ed85ad59c460d
USER0_SECP_ZK_PUBLIC_KEY := 49deab842acf3d26236419d4fce1b2cb01081aef55d4ef0e566f980e3890cf2f
USER1_PRIVATE_KEY        := f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d
USER1_PUBLIC_KEY         := cf62ae15751624548ad897c22fa1598ab82b7a2ad7de6e42c921d433efa10c91
USER1_SECP_ZK_PUBLIC_KEY := ac85e11f5c8a53241502c4519567aa3f02d30b1639fc49bb94c1d61335197e1a
USER2_PRIVATE_KEY        := 73ae514d6f69510ad778a05128d980951d9d8c097beb022471b2f50f19c41268
USER2_PUBLIC_KEY         := 7fe4d043d0d6ac7383800233d503e6f94797ab6733f57c24f93a31a1cb242b21
USER2_SECP_ZK_PUBLIC_KEY := 2b280f7354a6648e1d37499d211876d4f68d703c4dbf4dd8ccee032a4da5f220
USER3_PRIVATE_KEY        := 88ebebcea0bdfbe88ff0ed470d44242c149343a9ec79244ff829042a62e8ad2d
USER3_PUBLIC_KEY         := f79b7a821bb0a4e027b212c5534338617013e171d54e1131ab5f0a9dabebba82
USER3_SECP_ZK_PUBLIC_KEY := 1e44a84db33d52243068ccfbf6519beb1e072d1128ee792fe62896a3338db2a4

CURRENT_USER_PRIVATE_KEY := ${USER0_PRIVATE_KEY}
CURRENT_USER_PUBLIC_KEY  := ${USER0_PUBLIC_KEY}

CHECKPOINT_ID            := 18446744073709551615
LEAF_CHECKPOINT_ID       := ${CHECKPOINT_ID}
USER_ID                  := 0
CONTRACT_ID              := 0
SLOT_ID                  := 0
CONTRACT_STATE_HEIGHT    := 32
REALM_ID                 := 0
REGISTRATION_ID          := 1
STRATEGY                 := 5
SIGN_TYPE                := zk

COORDINATOR_RPC_URL      := $(shell jq -r '.networks.localhost.coordinator_configs[].rpc_url[]' config.json)
REALM_RPC_URL            := $(shell jq -r '.networks.localhost.realm_configs[${REALM_ID}].rpc_url[]' config.json)

GLOBAL_USER_TREE_HEIGHT  := $(shell jq -r '.networks.localhost.global_user_tree_height' config.json)
REALM_USER_TREE_HEIGHT   := $(shell jq -r '.networks.localhost.realm_user_tree_height' config.json)
REALM_TREE_LEAF_LEVEL    := $(shell echo $$(($(GLOBAL_USER_TREE_HEIGHT) - $(REALM_USER_TREE_HEIGHT))))
USER1_ID                 := 1

SDC_PATH                 := "sdc.json"
SDC_FINGERPRINT          := "136ed39299c17a8cc4ea84e0b676e74c70d2a1668abaf346088d2df4087304c5"

run-prove-proxy:
	@RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli prove-proxy

get-public-key:
	@RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli wallet info --private-key=${CURRENT_USER_PRIVATE_KEY} --sign-type ${SIGN_TYPE}

wallet:
	@RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli wallet create

random-wallet:
	@RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli wallet random --sign-type ${SIGN_TYPE}

register-user:
	@echo "Registering all 4 users..."
	@RUST_LOG=error ./target/${PROFILE}/psy_user_cli register-user --private-key=${USER0_PRIVATE_KEY} --sign-type zk | tail -5 | jq .
	@sleep 0.5
	@RUST_LOG=error ./target/${PROFILE}/psy_user_cli register-user --private-key=${USER1_PRIVATE_KEY} --sign-type zk | tail -5 | jq .
	@sleep 0.5
	@RUST_LOG=error ./target/${PROFILE}/psy_user_cli register-user --private-key=${USER2_PRIVATE_KEY} --sign-type zk | tail -5 | jq .
	@sleep 0.5
	@RUST_LOG=error ./target/${PROFILE}/psy_user_cli register-user --private-key=${USER0_PRIVATE_KEY} --sign-type secp256k1 | tail -5 | jq .
	@sleep 0.5
	@RUST_LOG=error ./target/${PROFILE}/psy_user_cli register-user --private-key=${USER1_PRIVATE_KEY} --sign-type secp256k1 | tail -5 | jq .
	@sleep 0.5
	@RUST_LOG=error ./target/${PROFILE}/psy_user_cli register-user --private-key=${USER2_PRIVATE_KEY} --sign-type secp256k1 | tail -5 | jq .
	@echo "Waiting 6s for users to be registered..."
	@sleep 6
	# @RUST_LOG=error ./target/${PROFILE}/psy_user_cli register-user --private-key=${USER2_PRIVATE_KEY} | tail -5 | jq .
	# @sleep 0.5
	# @RUST_LOG=error ./target/${PROFILE}/psy_user_cli register-user --private-key=${USER3_PRIVATE_KEY} | tail -5 | jq .

register-random-user:
	@echo "Registering random users..."
	@RUST_LOG=error ./target/${PROFILE}/psy_user_cli register-user | tail -6 | jq .
	@sleep 0.5
	@RUST_LOG=error ./target/${PROFILE}/psy_user_cli register-user | tail -6 | jq .
	@sleep 0.5

deploy-contract:
	@echo "Deploying contracts..."
	@echo "USER0 deploying token contract..."
	@RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli deploy-contract --private-key=${USER0_PRIVATE_KEY} --contract-path ${PROJECT_DIR}/token/target/token.json --abi-path ${PROJECT_DIR}/token/target/token.abi.json --is-deploy
	@echo "USER1 deploying token contract..."
	@RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli deploy-contract --private-key=${USER1_PRIVATE_KEY} --contract-path ${PROJECT_DIR}/token/target/token.json --abi-path ${PROJECT_DIR}/token/target/token.abi.json --is-deploy

multi-contract-call:
	@RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli call -p ${USER0_PRIVATE_KEY} --contract-id ${CONTRACT_ID}

mint:
	@echo "All users minting 1000 tokens..."
	@RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli call -p ${USER0_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_mint --inputs "[1000000000000]"
	@RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli call -p ${USER1_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_mint --inputs "[1000000000000]"
	# @RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli call --keystore-path .wallets/treasury.json --contract-id ${CONTRACT_ID} --method-name simple_mint --inputs "[1000000000000]" --sign-type $(SIGN_TYPE)
	# @RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli call --keystore-path .wallets/treasury.json --contract-id ${CONTRACT_ID} --method-name simple_mint --inputs "[1000000000000]" --sign-type $(SIGN_TYPE)
	# @RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli call -p ${USER2_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_mint --inputs "[1000000000000]"
	# @RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli call -p ${USER3_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_mint --inputs "[1000000000000]"

transfer:
	@echo "USER0 transferring 250 to USER1..."
	@RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli call -p ${USER0_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_transfer --inputs "[1, 250000000000]" --sign-type $(SIGN_TYPE)
	@echo "USER1 transferring 250 to USER0..."
	@RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli call -p ${USER1_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_transfer --inputs "[0, 250000000000]" --sign-type $(SIGN_TYPE)

claim:
	@echo "USER1 claiming transfer..."
	@RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli call -p ${USER1_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_claim --inputs "[0]" --sign-type $(SIGN_TYPE)
	@echo "USER0 claiming transfer..."
	@RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli call -p ${USER0_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_claim --inputs "[1048576]" --sign-type $(SIGN_TYPE)

return-back:
	@echo "USER1 transferring back to USER0..."
	@RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli call -p ${USER1_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_transfer --inputs "[0, 250000000000]" --sign-type $(SIGN_TYPE)
	@echo "USER0 transferring back to USER1..."
	@RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli call -p ${USER0_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_transfer --inputs "[1048576, 250000000000]" --sign-type $(SIGN_TYPE)

claim-rewards-v2:
	@RUST_LOG=info ./target/${PROFILE}/psy_user_cli claim-reward-v2 --private-key ${USER0_PRIVATE_KEY} --jobs-file realm_worker_0.backup

# Unified RPC commands using psy_user_cli automatic routing
get-slot-value:
	@RUST_LOG=error ./target/${PROFILE}/psy_user_cli get-user-contract-state-tree-merkle-proof --checkpoint-id ${CHECKPOINT_ID} --user-id ${USER_ID} --contract-id ${CONTRACT_ID} --height ${CONTRACT_STATE_HEIGHT} --leaf-id ${SLOT_ID} | jq '.value' | tr -d '"'

# Metadata RPC commands
get-contract-leaf-data:
	@./target/${PROFILE}/psy_user_cli get-contract-leaf-data --contract-id ${CONTRACT_ID}

get-checkpoint-leaf-data:
	@./target/${PROFILE}/psy_user_cli get-checkpoint-leaf-data --checkpoint-id ${CHECKPOINT_ID}

get-contract-code-definition:
	@./target/${PROFILE}/psy_user_cli get-contract-code-definition --contract-id ${CONTRACT_ID}

get-latest-block-state:
	@./target/${PROFILE}/psy_user_cli get-latest-block-state

get-block-state:
	@./target/${PROFILE}/psy_user_cli get-block-state --checkpoint-id ${CHECKPOINT_ID}

# Tree structure RPC commands
get-checkpoint-tree-root:
	@./target/${PROFILE}/psy_user_cli get-checkpoint-tree-root --checkpoint-id ${CHECKPOINT_ID}

get-latest-checkpoint-tree-root:
	@./target/${PROFILE}/psy_user_cli get-latest-checkpoint-tree-root

get-checkpoint-tree-leaf-hash:
	@./target/${PROFILE}/psy_user_cli get-checkpoint-tree-leaf-hash --checkpoint-id ${CHECKPOINT_ID} --leaf-checkpoint-id ${LEAF_CHECKPOINT_ID}

get-checkpoint-tree-merkle-proof:
	@./target/${PROFILE}/psy_user_cli get-checkpoint-tree-merkle-proof --checkpoint-id ${CHECKPOINT_ID} --leaf-checkpoint-id ${LEAF_CHECKPOINT_ID}

# User tree RPC commands
get-user-leaf-data-by-pubkey:
	@./target/${PROFILE}/psy_user_cli get-user-leaf --checkpoint-id ${CHECKPOINT_ID} --pub-key ${CURRENT_USER_PUBLIC_KEY}

get-user-leaf-data-by-userid:
	@./target/${PROFILE}/psy_user_cli get-user-leaf --checkpoint-id ${CHECKPOINT_ID} --user-id ${USER_ID}

get-user-leaf-data: get-user-leaf-data-by-pubkey

get-user-tree-root:
	@./target/${PROFILE}/psy_user_cli get-user-tree-root --checkpoint-id ${CHECKPOINT_ID}

get-user-tree-leaf-hash:
	@./target/${PROFILE}/psy_user_cli get-user-tree-leaf-hash --checkpoint-id ${CHECKPOINT_ID} --user-id ${USER_ID}

get-user-tree-merkle-proof:
	@./target/${PROFILE}/psy_user_cli get-user-tree-merkle-proof --checkpoint-id ${CHECKPOINT_ID} --user-id ${USER_ID}

get-user-sub-tree-merkle-proof:
	@./target/${PROFILE}/psy_user_cli get-user-sub-tree-merkle-proof --checkpoint-id ${CHECKPOINT_ID} --root-level 0 --leaf-level ${REALM_TREE_LEAF_LEVEL} --leaf-index ${REALM_ID}

get-user-registration-tree-root:
	@./target/${PROFILE}/psy_user_cli get-user-registration-tree-root --checkpoint-id ${CHECKPOINT_ID}

get-user-registration-tree-leaf-hash:
	@./target/${PROFILE}/psy_user_cli get-user-registration-tree-leaf-hash --checkpoint-id ${CHECKPOINT_ID} --registration-id ${REGISTRATION_ID}

get-user-registration-tree-merkle-proof:
	@./target/${PROFILE}/psy_user_cli get-user-registration-tree-merkle-proof --checkpoint-id ${CHECKPOINT_ID} --registration-id ${REGISTRATION_ID}

# User contract tree RPC commands
get-user-contract-tree-root:
	@./target/${PROFILE}/psy_user_cli get-user-contract-tree-root --checkpoint-id ${CHECKPOINT_ID} --user-id ${USER_ID}

get-user-contract-state-tree-root:
	@./target/${PROFILE}/psy_user_cli get-user-contract-state-tree-root --checkpoint-id ${CHECKPOINT_ID} --user-id ${USER_ID} --contract-id ${CONTRACT_ID}

get-user-contract-tree-merkle-proof:
	@./target/${PROFILE}/psy_user_cli get-user-contract-tree-merkle-proof --checkpoint-id ${CHECKPOINT_ID} --user-id ${USER_ID} --contract-id ${CONTRACT_ID}

get-user-contract-state-tree-merkle-proof:
	@./target/${PROFILE}/psy_user_cli get-user-contract-state-tree-merkle-proof --checkpoint-id ${CHECKPOINT_ID} --user-id ${USER_ID} --contract-id ${CONTRACT_ID} --height ${CONTRACT_STATE_HEIGHT} --leaf-id ${SLOT_ID}

get-psy-sdc-fingerprint:
	@./target/${PROFILE}/psy_user_cli get-psy-sdc-fingerprint --sdc-path ${SDC_PATH}

register-sdc-user: 
	@./target/${PROFILE}/psy_user_cli register-user --private-key ${USER0_PRIVATE_KEY} --fingerprint ${SDC_FINGERPRINT} --sign-type "software-defined-dpn"

mint-sdc:
	@RUST_LOG=${LOG_LEVEL} ./target/${PROFILE}/psy_user_cli call -p ${USER0_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_mint --inputs "[1000000000000]" --sign-type "software-defined-dpn" --fingerprint ${SDC_FINGERPRINT}

get-endcap-common-data:
	@./target/${PROFILE}/psy_user_cli get-user-end-cap-common-data

help:
	@grep -E '^[a-zA-Z_-]+:.*?' Makefile | cut -d: -f1 | sort
