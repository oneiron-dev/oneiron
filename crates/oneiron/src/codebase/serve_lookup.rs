//! Transaction-composable lookup of the exact snapshot behind a served fork.

use heed::RoTxn;

use super::snapshot::{CodebaseForkHash, CodebaseSnapshot};
use super::store::{codebase_ids_by_fork_hash_in_txn, codebase_snapshot_in_txn};
use crate::{EntityId, Vault, error::Result};

impl Vault {
    pub(crate) fn get_codebase_snapshot_in_txn(
        &self,
        txn: &RoTxn<'_>,
        code_artifact_id: &EntityId,
    ) -> Result<Option<CodebaseSnapshot>> {
        codebase_snapshot_in_txn(&self.store, txn, code_artifact_id)
    }

    pub(crate) fn codebase_snapshots_by_fork_hash_in_txn(
        &self,
        txn: &RoTxn<'_>,
        fork_hash: &CodebaseForkHash,
    ) -> Result<Vec<EntityId>> {
        codebase_ids_by_fork_hash_in_txn(&self.store, txn, fork_hash)
    }
}
