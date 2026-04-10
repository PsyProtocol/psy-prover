use std::collections::HashMap;

use indexmap::IndexMap;
use plonky2::hash::hash_types::RichField;
use psy_common::data::qhashout::QHashOut;
use psy_crypto::hash::merkle::core::DeltaMerkleProofCore;
use psy_crypto::hash::traits::qhashable::QFieldHashable;
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::{
    config::store_config::PsyHasher,
    guta::api::PsyContractStateUpdateHistory,
    qdata::{
        imt_contract_state::{compare_qhashout_keys, IMTContractStateLeaf},
        imt_proof::IMTContractStateUpdateHistory,
        user::PsyUserLeaf,
    },
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyUserSessionUpdateHistory<F: RichField> {
    pub start_user_leaf: PsyUserLeaf<F>,
    pub end_user_leaf: PsyUserLeaf<F>,
    pub total_slots_modified: u32,
    pub contract_updates: Vec<PsyContractStateUpdateHistory<F>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyStateTrackerContractResult<F: RichField> {
    pub contract_id: u64,
    pub slots: HashMap<u64, Vec<QHashOut<F>>>,
    pub ops: Vec<PsyStateOperation<F>>,
    pub total_slots_modified: u32,
    pub start_state_root: QHashOut<F>,
    pub end_state_root: QHashOut<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub enum PsyStateOperation<F: RichField> {
    PositionalWrite {
        op_seq: u64,
        contract_id: u64,
        slot: u64,
        from_version: u32,
        to_version: u32,
    },
    IMTUpdate {
        op_seq: u64,
        key: QHashOut<F>,
        state_slot_index: u64,
        from_version: u32,
        to_version: u32,
    },
    IMTInsert {
        op_seq: u64,
        key: QHashOut<F>,
        predecessor_state_slot_index: u64,
        predecessor_from_version: u32,
        predecessor_to_version: u32,
        new_leaf_state_slot_index: u64,
        new_leaf_from_version: u32,
        new_leaf_to_version: u32,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyContractStateTracker<F: RichField> {
    pub contract_id: u64,
    pub slots: HashMap<u64, Vec<QHashOut<F>>>,
    pub ops: Vec<PsyStateOperation<F>>,
    pub next_op_seq: u64,
    pub total_slots_modified: u32,
    pub start_state_root: QHashOut<F>,
    pub end_state_root: QHashOut<F>,
    pub imt_keys: IndexMap<QHashOut<F>, PsyIMTLocalStateSet<F>>,
    pub imt_preimages: HashMap<QHashOut<F>, IMTContractStateLeaf<F>>,
    pub imt_next_append_index: u64,
    pub total_keys_modified: u32,
}

impl<F: RichField> PsyContractStateTracker<F> {
    pub fn new(contract_id: u64) -> Self {
        Self {
            contract_id,
            slots: HashMap::new(),
            ops: Vec::new(),
            next_op_seq: 0,
            total_slots_modified: 0,
            start_state_root: QHashOut::ZERO,
            end_state_root: QHashOut::ZERO,
            imt_keys: IndexMap::new(),
            imt_preimages: HashMap::new(),
            imt_next_append_index: 1,
            total_keys_modified: 0,
        }
    }

    fn append_slot_version(&mut self, slot: u64, old_hash: QHashOut<F>, new_hash: QHashOut<F>) -> (u32, u32) {
        let versions = self.slots.entry(slot).or_insert_with(|| vec![old_hash]);
        if versions.last().copied() != Some(old_hash) {
            tracing::warn!(
                contract_id = self.contract_id,
                slot,
                expected_old_hash = %versions.last().copied().unwrap_or(QHashOut::ZERO),
                provided_old_hash = %old_hash,
                "state slot version old hash mismatch, continuing with append"
            );
        }
        let from_version = versions.len() as u32 - 1;
        versions.push(new_hash);
        let to_version = versions.len() as u32 - 1;
        (from_version, to_version)
    }

    fn bump_op_seq(&mut self) -> u64 {
        let op_seq = self.next_op_seq;
        self.next_op_seq = self.next_op_seq.saturating_add(1);
        op_seq
    }

    fn persist_imt_preimage(&mut self, preimage: IMTContractStateLeaf<F>) {
        self.imt_preimages.insert(preimage.qfhash::<PsyHasher>(), preimage);
    }

    fn advance_imt_next_append_index_for_insert(&mut self, inserted_leaf_index: u64) {
        if inserted_leaf_index >= self.imt_next_append_index {
            self.imt_next_append_index = inserted_leaf_index.saturating_add(1);
        } else {
            tracing::warn!(
                contract_id = self.contract_id,
                inserted_leaf_index,
                next_append_index = self.imt_next_append_index,
                "IMT insert index is behind local append cursor; keeping current cursor"
            );
        }
    }

    #[instrument(skip(self, dmp), fields(contract_id = self.contract_id, slot_index = dmp.index, total_slots_modified = self.total_slots_modified))]
    pub fn notify_update_slot_dmp(&mut self, dmp: &DeltaMerkleProofCore<QHashOut<F>>) -> i32 {
        tracing::debug!("State tracker DMP: {}", serde_json::to_string_pretty(&dmp).unwrap());
        let before_modified = self
            .slots
            .get(&dmp.index)
            .map(|v| !v.is_empty() && v.first() != v.last())
            .unwrap_or(false);
        let (from_version, to_version) = self.append_slot_version(dmp.index, dmp.old_value, dmp.new_value);
        let op_seq = self.bump_op_seq();
        self.ops.push(PsyStateOperation::PositionalWrite {
            op_seq,
            contract_id: self.contract_id,
            slot: dmp.index,
            from_version,
            to_version,
        });
        if self.ops.len() == 1 {
            self.start_state_root = dmp.old_root;
        }
        let after_modified = self
            .slots
            .get(&dmp.index)
            .map(|v| !v.is_empty() && v.first() != v.last())
            .unwrap_or(false);
        let inc = match (before_modified, after_modified) {
            (false, true) => 1,
            (true, false) => -1,
            _ => 0,
        };
        self.total_slots_modified = ((self.total_slots_modified as i32) + inc) as u32;
        self.end_state_root = dmp.new_root;
        inc
    }

    pub fn to_result(&self) -> PsyStateTrackerContractResult<F> {
        PsyStateTrackerContractResult {
            contract_id: self.contract_id,
            slots: self.slots.clone(),
            ops: self.ops.clone(),
            total_slots_modified: self.total_slots_modified,
            start_state_root: self.start_state_root,
            end_state_root: self.end_state_root,
        }
    }

    pub fn find_imt_predecessor(&self, key: &QHashOut<F>) -> Option<(u64, IMTContractStateLeaf<F>)> {
        self.imt_keys
            .values()
            .filter(|entry| compare_qhashout_keys(&entry.key, key) == std::cmp::Ordering::Less)
            .max_by(|a, b| compare_qhashout_keys(&a.key, &b.key))
            .map(|entry| (entry.leaf_index, entry.end_preimage))
    }

    pub fn get_imt_leaf_index_for_key(&self, key: &QHashOut<F>) -> Option<u64> {
        self.imt_keys.get(key).map(|entry| entry.leaf_index)
    }

    pub fn get_imt_leaf_preimage_by_leaf_index(&self, leaf_index: u64) -> Option<IMTContractStateLeaf<F>> {
        let latest_hash = self.imt_keys.values().find(|entry| entry.leaf_index == leaf_index).map(|entry| entry.end_preimage.qfhash::<PsyHasher>())?;
        self.imt_preimages.get(&latest_hash).copied()
    }

    pub fn get_imt_next_append_index(&self) -> u64 {
        self.imt_next_append_index
    }

    pub fn has_imt_insert_activity(&self) -> bool {
        self.imt_next_append_index > 1 || self.imt_keys.values().any(|entry| entry.is_insert)
    }

    pub fn notify_imt_update(
        &mut self,
        key: QHashOut<F>,
        leaf_index: u64,
        state_slot_index: u64,
        old_preimage: IMTContractStateLeaf<F>,
        new_preimage: IMTContractStateLeaf<F>,
    ) -> i32 {
        let old_hash = old_preimage.qfhash::<PsyHasher>();
        let new_hash = new_preimage.qfhash::<PsyHasher>();
        let (from_version, to_version) = self.append_slot_version(state_slot_index, old_hash, new_hash);
        self.persist_imt_preimage(old_preimage);
        self.persist_imt_preimage(new_preimage);

        let inc = match self.imt_keys.get_mut(&key) {
            Some(entry) => {
                entry.end_preimage = new_preimage;
                if !entry.is_insert && entry.end_preimage.value == entry.start_preimage.value {
                    -1
                } else {
                    0
                }
            }
            None => {
                self.imt_keys.insert(
                    key,
                    PsyIMTLocalStateSet {
                        key,
                        leaf_index,
                        state_slot_index,
                        start_preimage: old_preimage,
                        end_preimage: new_preimage,
                        is_insert: false,
                    },
                );
                1
            }
        };

        if inc == -1 {
            self.imt_keys.shift_remove(&key);
        }

        if inc > 0 {
            self.total_keys_modified += 1;
        } else if inc < 0 {
            self.total_keys_modified = self.total_keys_modified.saturating_sub(1);
        }

        let op_seq = self.bump_op_seq();
        self.ops.push(PsyStateOperation::IMTUpdate {
            op_seq,
            key,
            state_slot_index,
            from_version,
            to_version,
        });

        inc
    }

    pub fn notify_imt_insert(
        &mut self,
        predecessor_leaf_index: u64,
        predecessor_state_slot_index: u64,
        predecessor_old_preimage: IMTContractStateLeaf<F>,
        predecessor_new_preimage: IMTContractStateLeaf<F>,
        new_leaf_index: u64,
        new_leaf_state_slot_index: u64,
        new_leaf_preimage: IMTContractStateLeaf<F>,
        pred_dmp_old_value: QHashOut<F>,
        new_leaf_dmp_old_value: QHashOut<F>,
    ) -> i32 {
        self.advance_imt_next_append_index_for_insert(new_leaf_index);

        // Use the actual DMP old_values (from the Merkle tree) rather than qfhash() of the
        // preimage. For unwritten slots the tree stores ZERO, not hash(default_leaf), so using
        // qfhash() would record the wrong initial slot version and cause "Wire set twice" when
        // the state is reset and rebuilt during proving.
        let pred_new_hash = predecessor_new_preimage.qfhash::<PsyHasher>();
        let new_leaf_new_hash = new_leaf_preimage.qfhash::<PsyHasher>();

        let (predecessor_from_version, predecessor_to_version) =
            self.append_slot_version(predecessor_state_slot_index, pred_dmp_old_value, pred_new_hash);
        let (new_leaf_from_version, new_leaf_to_version) =
            self.append_slot_version(new_leaf_state_slot_index, new_leaf_dmp_old_value, new_leaf_new_hash);

        self.persist_imt_preimage(predecessor_old_preimage);
        self.persist_imt_preimage(predecessor_new_preimage);
        self.persist_imt_preimage(new_leaf_preimage);

        let pred_inc = match self.imt_keys.get_mut(&predecessor_old_preimage.key) {
            Some(entry) => {
                entry.end_preimage = predecessor_new_preimage;
                if !entry.is_insert && entry.end_preimage.value == entry.start_preimage.value {
                    -1
                } else {
                    0
                }
            }
            None => {
                self.imt_keys.insert(
                    predecessor_old_preimage.key,
                    PsyIMTLocalStateSet {
                        key: predecessor_old_preimage.key,
                        leaf_index: predecessor_leaf_index,
                        state_slot_index: predecessor_state_slot_index,
                        start_preimage: predecessor_old_preimage,
                        end_preimage: predecessor_new_preimage,
                        is_insert: false,
                    },
                );
                1
            }
        };

        if pred_inc == -1 {
            self.imt_keys.shift_remove(&predecessor_old_preimage.key);
        }

        let new_inc = match self.imt_keys.get_mut(&new_leaf_preimage.key) {
            Some(entry) => {
                entry.end_preimage = new_leaf_preimage;
                if !entry.is_insert && entry.end_preimage.value == entry.start_preimage.value {
                    -1
                } else {
                    0
                }
            }
            None => {
                self.imt_keys.insert(
                    new_leaf_preimage.key,
                    PsyIMTLocalStateSet {
                        key: new_leaf_preimage.key,
                        leaf_index: new_leaf_index,
                        state_slot_index: new_leaf_state_slot_index,
                        start_preimage: IMTContractStateLeaf::default(),
                        end_preimage: new_leaf_preimage,
                        is_insert: true,
                    },
                );
                1
            }
        };

        if new_inc == -1 {
            self.imt_keys.shift_remove(&new_leaf_preimage.key);
        }

        let total_inc = pred_inc + new_inc;
        if total_inc > 0 {
            self.total_keys_modified += total_inc as u32;
        } else if total_inc < 0 {
            self.total_keys_modified = self.total_keys_modified.saturating_sub((-total_inc) as u32);
        }

        let op_seq = self.bump_op_seq();
        self.ops.push(PsyStateOperation::IMTInsert {
            op_seq,
            key: new_leaf_preimage.key,
            predecessor_state_slot_index,
            predecessor_from_version,
            predecessor_to_version,
            new_leaf_state_slot_index,
            new_leaf_from_version,
            new_leaf_to_version,
        });
        total_inc
    }
}

#[derive(Clone, Debug)]
pub struct PsyLocalStateTracker<F: RichField> {
    pub contracts: IndexMap<u64, PsyContractStateTracker<F>>,
    pub total_slots_modified: u32,
    pub total_keys_modified: u32,
}

impl<F: RichField> PsyLocalStateTracker<F> {
    pub fn new() -> Self {
        Self {
            contracts: IndexMap::new(),
            total_slots_modified: 0,
            total_keys_modified: 0,
        }
    }
    pub fn notify_update_slot_dmp(&mut self, contract_id: u64, dmp: &DeltaMerkleProofCore<QHashOut<F>>) {
        let inc_modified_slots = match self.contracts.get_mut(&contract_id) {
            Some(c) => c.notify_update_slot_dmp(dmp),
            None => {
                let mut tracker = PsyContractStateTracker::new(contract_id);
                let result = tracker.notify_update_slot_dmp(dmp);
                self.contracts.insert(contract_id, tracker);
                result
            }
        };

        self.total_slots_modified = ((self.total_slots_modified as i32) + inc_modified_slots) as u32;
    }

    pub fn get_contract_result(&self, contract_id: u64) -> Option<PsyStateTrackerContractResult<F>> {
        self.contracts.get(&contract_id).map(|c| c.to_result())
    }

    pub fn get_total_keys_modified(&self) -> u32 {
        self.total_keys_modified
    }

    pub fn notify_imt_update(
        &mut self,
        contract_id: u64,
        key: QHashOut<F>,
        leaf_index: u64,
        state_slot_index: u64,
        old_preimage: IMTContractStateLeaf<F>,
        new_preimage: IMTContractStateLeaf<F>,
    ) {
        let inc = match self.contracts.get_mut(&contract_id) {
            Some(c) => c.notify_imt_update(key, leaf_index, state_slot_index, old_preimage, new_preimage),
            None => {
                let mut tracker = PsyContractStateTracker::new(contract_id);
                let result = tracker.notify_imt_update(key, leaf_index, state_slot_index, old_preimage, new_preimage);
                self.contracts.insert(contract_id, tracker);
                result
            }
        };
        if inc > 0 {
            self.total_keys_modified += 1;
        } else if inc < 0 {
            self.total_keys_modified = self.total_keys_modified.saturating_sub(1);
        }
    }

    pub fn notify_imt_insert(
        &mut self,
        contract_id: u64,
        predecessor_leaf_index: u64,
        predecessor_state_slot_index: u64,
        predecessor_old_preimage: IMTContractStateLeaf<F>,
        predecessor_new_preimage: IMTContractStateLeaf<F>,
        new_leaf_index: u64,
        new_leaf_state_slot_index: u64,
        new_leaf_preimage: IMTContractStateLeaf<F>,
        pred_dmp_old_value: QHashOut<F>,
        new_leaf_dmp_old_value: QHashOut<F>,
    ) {
        let inc = match self.contracts.get_mut(&contract_id) {
            Some(c) => c.notify_imt_insert(
                predecessor_leaf_index,
                predecessor_state_slot_index,
                predecessor_old_preimage,
                predecessor_new_preimage,
                new_leaf_index,
                new_leaf_state_slot_index,
                new_leaf_preimage,
                pred_dmp_old_value,
                new_leaf_dmp_old_value,
            ),
            None => {
                let mut tracker = PsyContractStateTracker::new(contract_id);
                let result = tracker.notify_imt_insert(
                    predecessor_leaf_index,
                    predecessor_state_slot_index,
                    predecessor_old_preimage,
                    predecessor_new_preimage,
                    new_leaf_index,
                    new_leaf_state_slot_index,
                    new_leaf_preimage,
                    pred_dmp_old_value,
                    new_leaf_dmp_old_value,
                );
                self.contracts.insert(contract_id, tracker);
                result
            }
        };
        if inc > 0 {
            self.total_keys_modified += inc as u32;
        } else if inc < 0 {
            self.total_keys_modified = self.total_keys_modified.saturating_sub((-inc) as u32);
        }
    }

    pub fn find_imt_predecessor(&self, contract_id: u64, key: &QHashOut<F>) -> Option<(u64, IMTContractStateLeaf<F>)> {
        self.contracts.get(&contract_id).and_then(|c| c.find_imt_predecessor(key))
    }

    pub fn get_imt_state_slot_index_for_key(&self, contract_id: u64, key: &QHashOut<F>) -> Option<u64> {
        self.contracts.get(&contract_id).and_then(|c| c.get_imt_leaf_index_for_key(key))
    }

    pub fn get_imt_leaf_preimage_by_state_slot_index(
        &self,
        contract_id: u64,
        leaf_index: u64,
    ) -> Option<IMTContractStateLeaf<F>> {
        self.contracts
            .get(&contract_id)
            .and_then(|c| c.get_imt_leaf_preimage_by_leaf_index(leaf_index))
    }

    pub fn get_imt_next_append_index(&self, contract_id: u64) -> Option<u64> {
        self.contracts.get(&contract_id).and_then(|c| {
            if c.has_imt_insert_activity() {
                Some(c.get_imt_next_append_index())
            } else {
                None
            }
        })
    }
}

// ===========================================================================
// IMT-based state tracking (256-bit keys)
// ===========================================================================

/// Tracks a single IMT key's state changes within a contract.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyIMTLocalStateSet<F: RichField> {
    pub key: QHashOut<F>,
    pub leaf_index: u64,
    pub state_slot_index: u64,
    pub start_preimage: IMTContractStateLeaf<F>,
    pub end_preimage: IMTContractStateLeaf<F>,
    pub is_insert: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qdata::imt_contract_state::IMTContractStateLeaf;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;

    type F = GoldilocksField;

    fn h(v: u64) -> QHashOut<F> {
        QHashOut::from_values(v, 0, 0, 0)
    }

    fn leaf(key: u64, value: u64, next_key: u64, next_index: u64) -> IMTContractStateLeaf<F> {
        IMTContractStateLeaf {
            key: h(key),
            value: h(value),
            next_key: h(next_key),
            next_index: F::from_canonical_u64(next_index),
        }
    }

    fn dmp(slot: u64, old_value: u64, new_value: u64, old_root: u64, new_root: u64) -> DeltaMerkleProofCore<QHashOut<F>> {
        DeltaMerkleProofCore {
            old_root: h(old_root),
            old_value: h(old_value),
            new_root: h(new_root),
            new_value: h(new_value),
            index: slot,
            siblings: vec![],
        }
    }

    #[test]
    fn slot_tracker_records_version_chain_and_ops() {
        let mut t = PsyContractStateTracker::<F>::new(7);
        let d1 = dmp(42, 1, 2, 100, 101);
        let d2 = dmp(42, 2, 3, 101, 102);
        t.notify_update_slot_dmp(&d1);
        t.notify_update_slot_dmp(&d2);

        assert_eq!(t.total_slots_modified, 1);
        assert_eq!(t.start_state_root, h(100));
        assert_eq!(t.end_state_root, h(102));

        let versions = t.slots.get(&42).expect("slot version chain must exist");
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0], h(1));
        assert_eq!(versions[1], h(2));
        assert_eq!(versions[2], h(3));

        assert_eq!(t.ops.len(), 2);
        match &t.ops[0] {
            PsyStateOperation::PositionalWrite {
                op_seq,
                from_version,
                to_version,
                ..
            } => {
                assert_eq!(*op_seq, 0);
                assert_eq!(*from_version, 0);
                assert_eq!(*to_version, 1);
            }
            v => panic!("expected positional op, got {:?}", v),
        }
        match &t.ops[1] {
            PsyStateOperation::PositionalWrite {
                op_seq,
                from_version,
                to_version,
                ..
            } => {
                assert_eq!(*op_seq, 1);
                assert_eq!(*from_version, 1);
                assert_eq!(*to_version, 2);
            }
            v => panic!("expected positional op, got {:?}", v),
        }
    }

    #[test]
    fn slot_tracker_net_zero_removes_active_slot_but_keeps_history() {
        let mut t = PsyContractStateTracker::<F>::new(1);
        t.notify_update_slot_dmp(&dmp(9, 5, 7, 10, 11));
        t.notify_update_slot_dmp(&dmp(9, 7, 5, 11, 12));

        assert_eq!(t.total_slots_modified, 0);
        let versions = t.slots.get(&9).expect("slot history must be kept");
        assert_eq!(versions.first(), versions.last());
        assert_eq!(t.end_state_root, h(12));

        let versions = t.slots.get(&9).expect("slot version chain must exist");
        assert_eq!(versions, &vec![h(5), h(7), h(5)]);
        assert_eq!(t.ops.len(), 2);
        match &t.ops[0] {
            PsyStateOperation::PositionalWrite {
                from_version,
                to_version,
                ..
            } => {
                assert_eq!(*from_version, 0);
                assert_eq!(*to_version, 1);
            }
            v => panic!("expected positional op, got {:?}", v),
        }
        match &t.ops[1] {
            PsyStateOperation::PositionalWrite {
                from_version,
                to_version,
                ..
            } => {
                assert_eq!(*from_version, 1);
                assert_eq!(*to_version, 2);
            }
            v => panic!("expected positional op, got {:?}", v),
        }
    }

    #[test]
    fn local_slot_tracker_aggregates_contract_results_with_ops() {
        let mut top = PsyLocalStateTracker::<F>::new();
        top.notify_update_slot_dmp(1, &dmp(1, 0, 10, 100, 101));
        top.notify_update_slot_dmp(2, &dmp(2, 0, 20, 200, 201));

        assert_eq!(top.total_slots_modified, 2);
        let r1 = top.get_contract_result(1).expect("contract 1 result");
        let r2 = top.get_contract_result(2).expect("contract 2 result");
        assert_eq!(r1.slots.len(), 1);
        assert_eq!(r2.slots.len(), 1);
        assert_eq!(r1.ops.len(), 1);
        assert_eq!(r2.ops.len(), 1);
        match &r1.ops[0] {
            PsyStateOperation::PositionalWrite { slot, .. } => assert_eq!(*slot, 1),
            v => panic!("expected positional op, got {:?}", v),
        }
        match &r2.ops[0] {
            PsyStateOperation::PositionalWrite { slot, .. } => assert_eq!(*slot, 2),
            v => panic!("expected positional op, got {:?}", v),
        }
    }

    #[test]
    fn local_slot_tracker_result_squashes_multi_writes_into_single_slot_update() {
        let mut top = PsyLocalStateTracker::<F>::new();
        top.notify_update_slot_dmp(1, &dmp(5, 10, 11, 100, 101));
        top.notify_update_slot_dmp(1, &dmp(5, 11, 12, 101, 102));
        top.notify_update_slot_dmp(1, &dmp(5, 12, 13, 102, 103));

        let r = top.get_contract_result(1).expect("contract 1 result");
        assert_eq!(r.slots.len(), 1);
        let versions = r.slots.get(&5).expect("slot 5 history exists");
        assert_eq!(versions.first().copied(), Some(h(10)));
        assert_eq!(versions.last().copied(), Some(h(13)));

        // Full history is still available from ops/version chain.
        assert_eq!(r.ops.len(), 3);
        let versions = top.contracts.get(&1).unwrap().slots.get(&5).unwrap();
        assert_eq!(versions, &vec![h(10), h(11), h(12), h(13)]);
    }

    #[test]
    fn find_predecessor_uses_key_order_not_insertion_order() {
        let mut t = PsyContractStateTracker::<F>::new(1);
        // Insert in non-sorted order on purpose.
        t.notify_imt_update(h(30), 1, 1, leaf(30, 1, 100, 0), leaf(30, 2, 100, 0));
        t.notify_imt_update(h(10), 2, 2, leaf(10, 1, 30, 1), leaf(10, 2, 30, 1));
        t.notify_imt_update(h(20), 3, 3, leaf(20, 1, 30, 1), leaf(20, 2, 30, 1));

        let (idx, pred) = t.find_imt_predecessor(&h(25)).expect("predecessor must exist");
        assert_eq!(idx, 3);
        assert_eq!(pred.key, h(20));
    }

    #[test]
    fn find_predecessor_returns_latest_local_preimage() {
        let mut t = PsyContractStateTracker::<F>::new(1);
        t.notify_imt_update(h(10), 1, 1, leaf(10, 1, 0, 0), leaf(10, 9, 0, 0));

        let (_idx, pred) = t.find_imt_predecessor(&h(11)).expect("predecessor must exist");
        assert_eq!(pred.value, h(9));
    }

    // --- notify_imt_update: basic insert ---

    #[test]
    fn insert_new_key_returns_inc_one_and_increments_count() {
        let mut t = PsyContractStateTracker::<F>::new(1);
        let inc = t.notify_imt_update(h(10), 1, 1, leaf(10, 0, 0, 0), leaf(10, 1, 0, 0));
        assert_eq!(inc, 1);
        assert_eq!(t.total_keys_modified, 1);
        assert_eq!(t.imt_next_append_index, 2);
    }

    #[test]
    fn insert_stores_start_and_end_preimage() {
        let mut t = PsyContractStateTracker::<F>::new(1);
        t.notify_imt_update(h(10), 1, 1, leaf(10, 0, 0, 0), leaf(10, 7, 0, 0));
        let entry = t.imt_keys.get(&h(10)).expect("entry must exist");
        assert_eq!(entry.start_preimage.value, h(0));
        assert_eq!(entry.end_preimage.value, h(7));
        assert!(entry.is_insert);
    }

    // --- notify_imt_update: update existing key ---

    #[test]
    fn update_existing_key_returns_inc_zero_and_keeps_count() {
        let mut t = PsyContractStateTracker::<F>::new(1);
        t.notify_imt_update(h(10), 1, 1, leaf(10, 0, 0, 0), leaf(10, 1, 0, 0));
        let inc = t.notify_imt_update(h(10), 1, 1, leaf(10, 1, 0, 0), leaf(10, 2, 0, 0));
        assert_eq!(inc, 0);
        assert_eq!(t.total_keys_modified, 1);
        let entry = t.imt_keys.get(&h(10)).expect("entry must exist");
        assert_eq!(entry.end_preimage.value, h(2));
        // start_preimage preserved from initial insert
        assert_eq!(entry.start_preimage.value, h(0));
    }

    // --- notify_imt_update: net-zero optimization ---

    #[test]
    fn net_zero_update_removes_key_and_decrements_count() {
        let mut t = PsyContractStateTracker::<F>::new(1);
        // Simulate a pre-existing key (not an insert) by using is_insert=false.
        let inc1 = t.notify_imt_update(h(10), 1, 1, leaf(10, 5, 0, 0), leaf(10, 7, 0, 0));
        assert_eq!(inc1, 1);
        assert_eq!(t.total_keys_modified, 1);
        // Revert to original value → net-zero
        let inc2 = t.notify_imt_update(h(10), 1, 1, leaf(10, 7, 0, 0), leaf(10, 5, 0, 0));
        assert_eq!(inc2, -1);
        assert_eq!(t.total_keys_modified, 0);
        assert!(t.imt_keys.get(&h(10)).is_none());
    }

    #[test]
    fn net_zero_does_not_apply_to_inserts() {
        // An insert that is "reverted" (value set back to start) should NOT be
        // removed — it is still a structural change to the IMT linked list.
        let mut t = PsyContractStateTracker::<F>::new(1);
        t.notify_imt_update(h(10), 1, 1, leaf(10, 5, 0, 0), leaf(10, 5, 0, 0));
        // Update back to same value as start
        let inc = t.notify_imt_update(h(10), 1, 1, leaf(10, 5, 0, 0), leaf(10, 5, 0, 0));
        // is_insert=true on the stored entry means net-zero check is skipped
        assert_eq!(inc, 0);
        assert!(t.imt_keys.get(&h(10)).is_some());
    }

    // --- next_append_index ---

    #[test]
    fn next_append_index_starts_at_one_and_increments_per_insert() {
        let mut t = PsyContractStateTracker::<F>::new(1);
        assert_eq!(t.imt_next_append_index, 1);
        t.notify_imt_update(h(10), 1, 1, leaf(10, 0, 0, 0), leaf(10, 1, 0, 0));
        assert_eq!(t.imt_next_append_index, 2);
        t.notify_imt_update(h(20), 2, 2, leaf(20, 0, 0, 0), leaf(20, 1, 0, 0));
        assert_eq!(t.imt_next_append_index, 3);
    }

    #[test]
    fn insert_with_large_leaf_index_advances_append_cursor() {
        let mut t = PsyContractStateTracker::<F>::new(1);
        t.notify_imt_update(h(10), 99, 99, leaf(10, 0, 0, 0), leaf(10, 1, 0, 0));
        assert_eq!(t.imt_next_append_index, 100);
    }

    // --- find_predecessor edge cases ---

    #[test]
    fn find_predecessor_returns_none_for_empty_tracker() {
        let t = PsyContractStateTracker::<F>::new(1);
        assert!(t.find_imt_predecessor(&h(5)).is_none());
    }

    #[test]
    fn find_predecessor_returns_none_when_target_smaller_than_all_keys() {
        let mut t = PsyContractStateTracker::<F>::new(1);
        t.notify_imt_update(h(10), 1, 1, leaf(10, 0, 0, 0), leaf(10, 1, 0, 0));
        t.notify_imt_update(h(20), 2, 2, leaf(20, 0, 0, 0), leaf(20, 1, 0, 0));
        // h(5) is less than all keys
        assert!(t.find_imt_predecessor(&h(5)).is_none());
    }

    #[test]
    fn find_predecessor_skips_equal_key() {
        let mut t = PsyContractStateTracker::<F>::new(1);
        t.notify_imt_update(h(10), 1, 1, leaf(10, 0, 0, 0), leaf(10, 1, 0, 0));
        // predecessor of h(10) itself is nothing (no key strictly less than 10)
        assert!(t.find_imt_predecessor(&h(10)).is_none());
    }

    // --- PsyLocalStateTracker IMT: cross-contract ---

    #[test]
    fn top_level_tracker_isolates_contracts() {
        let mut top = PsyLocalStateTracker::<F>::new();
        top.notify_imt_update(1, h(10), 1, 1, leaf(10, 0, 0, 0), leaf(10, 1, 0, 0));
        top.notify_imt_update(2, h(20), 1, 1, leaf(20, 0, 0, 0), leaf(20, 1, 0, 0));

        assert!(top.get_imt_state_slot_index_for_key(1, &h(10)).is_some());
        assert!(top.get_imt_state_slot_index_for_key(1, &h(20)).is_none()); // h(20) belongs to contract 2
        assert!(top.get_imt_state_slot_index_for_key(2, &h(20)).is_some());
    }

    #[test]
    fn top_level_total_keys_modified_aggregates_across_contracts() {
        let mut top = PsyLocalStateTracker::<F>::new();
        top.notify_imt_update(1, h(10), 1, 1, leaf(10, 0, 0, 0), leaf(10, 1, 0, 0));
        top.notify_imt_update(2, h(20), 1, 1, leaf(20, 0, 0, 0), leaf(20, 1, 0, 0));
        assert_eq!(top.total_keys_modified, 2);
    }

    #[test]
    fn top_level_net_zero_decrements_aggregate_count() {
        let mut top = PsyLocalStateTracker::<F>::new();
        top.notify_imt_update(1, h(10), 1, 1, leaf(10, 5, 0, 0), leaf(10, 7, 0, 0));
        assert_eq!(top.total_keys_modified, 1);
        top.notify_imt_update(1, h(10), 1, 1, leaf(10, 7, 0, 0), leaf(10, 5, 0, 0));
        assert_eq!(top.total_keys_modified, 0);
    }

    // --- get_state_slot_index_for_key / get_leaf_preimage_by_state_slot_index ---

    #[test]
    fn get_state_slot_index_for_key_returns_correct_index() {
        let mut t = PsyContractStateTracker::<F>::new(1);
        t.notify_imt_update(h(10), 1, 1, leaf(10, 0, 0, 0), leaf(10, 1, 0, 0));
        assert_eq!(t.get_imt_leaf_index_for_key(&h(10)), Some(1));
        assert_eq!(t.get_imt_leaf_index_for_key(&h(99)), None);
    }

    #[test]
    fn get_leaf_preimage_by_state_slot_index_returns_end_preimage() {
        let mut top = PsyLocalStateTracker::<F>::new();
        top.notify_imt_update(1, h(10), 1, 1, leaf(10, 0, 0, 0), leaf(10, 7, 0, 0));
        let preimage = top.get_imt_leaf_preimage_by_state_slot_index(1, 1).expect("must exist");
        assert_eq!(preimage.value, h(7));
        assert!(top.get_imt_leaf_preimage_by_state_slot_index(1, 99).is_none());
    }
}
