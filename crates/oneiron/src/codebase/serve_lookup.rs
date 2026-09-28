//! Transaction-composable lookup of the exact snapshot behind a served fork.

use heed::RoTxn;

use super::snapshot::{CodebaseForkHash, CodebaseSnapshot, decode_codebase_snapshot};
use super::store::{
    codebase_fork_index_prefix, codebase_ids_by_index_prefix, codebase_snapshot_key,
};
use crate::{EntityId, Vault, error::Result};

impl Vault {
    pub(crate) fn get_codebase_snapshot_in_txn(
        &self,
        txn: &RoTxn<'_>,
        code_artifact_id: &EntityId,
    ) -> Result<Option<CodebaseSnapshot>> {
        let Some(raw) = self
            .store
            .vault_meta
            .get(txn, &codebase_snapshot_key(code_artifact_id))?
        else {
            return Ok(None);
        };
        decode_codebase_snapshot(&raw).map(Some)
    }

    pub(crate) fn codebase_snapshots_by_fork_hash_in_txn(
        &self,
        txn: &RoTxn<'_>,
        fork_hash: &CodebaseForkHash,
    ) -> Result<Vec<EntityId>> {
        let prefix = codebase_fork_index_prefix(fork_hash);
        codebase_ids_by_index_prefix(&self.store, txn, &prefix)
    }
}
