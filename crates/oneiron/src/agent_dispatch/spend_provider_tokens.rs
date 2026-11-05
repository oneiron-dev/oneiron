//! Last recorded provider-token snapshots on each native guard generation.
//! These are observations, not a money ledger or proof of whole-scope coverage.

use super::{AgentDispatcher, SpendScopeId};
use crate::Result;
use crate::entity_id::bytes_to_hex_lower;
use crate::llm::ProviderTokenSnapshot;
use crate::side_table::{self, Named, SideTable};

const OBSERVATION: SideTable<String, ProviderTokenSnapshot, Named> =
    SideTable::new(&side_table::AGENT_DISPATCH_SPEND_PROVIDER_OBSERVATION);

impl AgentDispatcher<'_> {
    /// Records one actual guard capture without changing any charge or scope
    /// state. A late writer cannot replace a newer capture of that generation.
    /// A missing row is unknown; these rows do not enumerate every source.
    pub fn record_provider_token_snapshot(
        &self,
        scope: &SpendScopeId,
        snapshot: &ProviderTokenSnapshot,
    ) -> Result<()> {
        let key = snapshot_key(scope, &snapshot.generation);
        let mut txn = self.vault.store.env.write_txn()?;
        if let Some(previous) = OBSERVATION.get(&self.vault.store, &txn, &key)?
            && previous.observation_id >= snapshot.observation_id
        {
            return Ok(());
        }
        OBSERVATION.put(&self.vault.store, &mut txn, &key, snapshot)?;
        txn.commit()?;
        Ok(())
    }

    /// Present historical captures in the caller's snapshot. Even when every
    /// returned component is known, unrecorded generations remain uncovered.
    pub(crate) fn provider_token_snapshots_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScopeId,
    ) -> Result<Vec<ProviderTokenSnapshot>> {
        let prefix = scope_prefix(scope);
        Ok(OBSERVATION
            .scan_from(&self.vault.store, txn, prefix.as_bytes())?
            .into_iter()
            .map(|(_, snapshot)| snapshot)
            .collect())
    }
}

fn scope_prefix(scope: &SpendScopeId) -> String {
    format!("{}:{}\0", scope.as_str().len(), scope.as_str())
}

fn snapshot_key(scope: &SpendScopeId, generation: &[u8; 16]) -> String {
    let mut key = scope_prefix(scope);
    key.push_str(&bytes_to_hex_lower(generation));
    key
}
