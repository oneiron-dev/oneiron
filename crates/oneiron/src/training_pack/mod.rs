//! OF-382: a consented corpus, pinned training job, checked checkpoint and
//! owner-approved role swap. Training and evaluation are host-supplied work;
//! this module never launches a trainer or deploys its result automatically.
mod connector;
mod custody;
mod export;
mod promotion;
mod types;

use serde::Serialize;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

pub use connector::{TrainOutput, TrainRequest, TrainingConnector, TrainingFuture};
pub use promotion::TrainingEvalInput;
pub use types::*;

const RUNS: SideTable<EntityId, TrainingRun, Named> =
    SideTable::new(&side_table::TRAINING_PACK_RUN);
const SWAPS: SideTable<EntityId, RoleSwapReceipt, Named> =
    SideTable::new(&side_table::TRAINING_PACK_SWAP);
const ROLES: SideTable<String, RoleSwapReceipt, Named> =
    SideTable::new(&side_table::TRAINING_PACK_ROLE);

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}

fn json_value(value: &impl Serialize) -> Result<serde_json::Value> {
    serde_json::to_value(value).map_err(|e| invalid(&format!("training receipt encoding: {e}")))
}

fn hash_json(value: &impl Serialize) -> Result<[u8; 32]> {
    let bytes = crate::llm::canonical_json_bytes(value)
        .map_err(|_| invalid("training pin encoding failed"))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn run_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<TrainingRun> {
    RUNS.get(&vault.store, txn, id)?
        .ok_or(Error::EntityNotFound)
}

impl TrainingRun {
    /// The admission must use this identity, not another run's meter or permits.
    pub fn admission_ref(&self) -> String {
        format!("training_pack:{}", self.id.to_hex())
    }

    /// Failed checks are evidence for the owner, never an automatic deployment.
    pub fn can_propose_swap(&self) -> bool {
        self.corpus.exact_hash_overlaps == 0
            && self
                .result
                .as_ref()
                .is_some_and(|result| result.checks.passed())
            && self
                .evaluation
                .as_ref()
                .is_some_and(|eval| eval.passed && eval.harness == self.plan.harness)
    }
}

impl ExportCheck {
    pub fn passed(&self) -> bool {
        self.hash_mismatches.is_empty()
            && self.probe_coverage_matches
            && self.probe_checkpoints_match
            && self.settings_match
            && self.harness_matches
            && self.argmax_flips == 0
            && self.max_logit_difference <= self.tolerance
    }
}

impl Vault {
    pub fn training_run(&self, id: &EntityId) -> Result<Option<TrainingRun>> {
        RUNS.get(&self.store, &self.store.env.read_txn()?, id)
    }

    pub fn training_runs(&self) -> Result<Vec<TrainingRun>> {
        let txn = self.store.env.read_txn()?;
        RUNS.iter_from(&self.store, &txn, &[])?
            .map(|row| row.map(|(_, run)| run))
            .collect()
    }

    pub fn training_swap_receipt(&self, id: &EntityId) -> Result<Option<RoleSwapReceipt>> {
        SWAPS.get(&self.store, &self.store.env.read_txn()?, id)
    }
}
