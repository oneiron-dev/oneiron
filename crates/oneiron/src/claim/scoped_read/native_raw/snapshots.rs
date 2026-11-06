//! CODE_ARTIFACT entitlement and snapshot metadata share the serving txn.

use super::*;
use crate::codebase::{CodebaseSnapshot, RepoRef};
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;

impl NativeRawRead<'_> {
    /// Reads metadata only after admitting that live CODE_ARTIFACT in the same txn.
    pub fn codebase_snapshot(&self, id: &EntityId) -> Result<Option<CodebaseSnapshot>> {
        Ok(self
            .lane
            .read_projected(&[PointRead::id(*id)], None, |txn, rows| {
                if rows.into_iter().next().flatten().is_some_and(|row| {
                    row.entity_type == ENTITY_TYPE_CODE_ARTIFACT && row.body.is_some()
                }) {
                    self.lane.vault.get_codebase_snapshot_in_txn(txn, id)
                } else {
                    Ok(None)
                }
            })?
            .value)
    }

    /// Selects actual indexed ids and admits them in the same serving txn.
    pub fn codebase_snapshots_by_repo_ref(&self, repo_ref: &RepoRef) -> Result<Vec<EntityId>> {
        self.snapshot_ids(|txn| {
            self.lane
                .vault
                .codebase_snapshots_by_repo_ref_in_txn(txn, repo_ref)
        })
    }

    /// Selects actual indexed ids and admits them in the same serving txn.
    pub fn codebase_snapshots_by_project_id(&self, project_id: &str) -> Result<Vec<EntityId>> {
        self.snapshot_ids(|txn| {
            self.lane
                .vault
                .codebase_snapshots_by_project_id_in_txn(txn, project_id)
        })
    }

    fn snapshot_ids(
        &self,
        select: impl FnOnce(&heed::RoTxn<'_>) -> Result<Vec<EntityId>>,
    ) -> Result<Vec<EntityId>> {
        let lane = &self.lane;
        let txn = lane.grant_read_txn()?;
        let (filter, policy) = lane.resolve_retrieval_filter_in(&txn, None)?;
        let authority = lane.held_for(None);
        let mut kept = Vec::new();
        let mut suppressed = 0;
        for id in select(&txn)? {
            let (row, withheld) = lane.id_row_in(
                &txn,
                &policy,
                &filter,
                id,
                crate::vault::ReadMode::Live,
                &authority,
            )?;
            suppressed += withheld;
            if row.is_some_and(|row| {
                row.entity_type == ENTITY_TYPE_CODE_ARTIFACT && row.body.is_some()
            }) {
                kept.push(id);
            }
        }
        let _receipt = lane.receipt_for(None, &policy, &filter, suppressed);
        Ok(kept)
    }
}
