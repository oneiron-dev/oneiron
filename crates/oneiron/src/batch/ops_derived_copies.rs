//! The raw ops door with the derived-text step (FIX 10886): a door that
//! holds the vault and applies ops without a BatchBuilder runs the step
//! the two BatchBuilder terminals run after apply, so a caption or
//! transcript it writes from a marked repo blob gets its pending safe copy.

use std::collections::BTreeSet;

use heed::RwTxn;

use super::{ApplyOpsGateMode, BatchOp, apply_ops_with_gate_mode};
use crate::error::Result;
use crate::{EntityId, Vault};

impl Vault {
    /// [`apply_ops_with_gate_mode`], then the derived-text step: a text the
    /// ops birth, edge to a source, text or vector has its safe copy queued
    /// pending only when a mark covers one of its sources. Retained texts
    /// derived from `changed_sources` are included too. Any other write,
    /// a caption with no marked source included, keeps what the ops wrote.
    ///
    /// # Errors
    /// As [`apply_ops_with_gate_mode`], or a storage error of the step.
    pub(crate) fn apply_ops_with_derived_copies(
        &self,
        wtxn: &mut RwTxn<'_>,
        ops: Vec<BatchOp>,
        changed_sources: &BTreeSet<EntityId>,
        text_index_trusted: bool,
        gate_mode: ApplyOpsGateMode,
    ) -> Result<()> {
        let mut derived = crate::embed::repo_derived_batch(&ops);
        apply_ops_with_gate_mode(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            ops,
            text_index_trusted,
            gate_mode,
        )?;
        derived.include_source_dependents_in(&self.store, wtxn, changed_sources)?;
        crate::embed::finalize_repo_derived_index_copies_in_txn(self, wtxn, derived)
    }
}
