//! Scoped, owner-bound counterparty commitment ledger.

use super::*;
use crate::commitment_ledger::CommitmentLedgerEntry;

#[derive(Debug, Clone, Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommitmentLedgerRequest {
    pub contact_ref: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct CommitmentLedgerItem {
    pub valid_from: u64,
    pub valid_to: u64,
    pub commitment: CommitmentView,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct CommitmentLedgerView {
    pub contact_ref: String,
    pub identity_ref: String,
    pub counterparty: String,
    pub channel: String,
    pub address_or_handle: String,
    pub owed_by_them: Vec<CommitmentLedgerItem>,
    pub owed_to_them: Vec<CommitmentLedgerItem>,
}

impl Memory<'_> {
    /// Reads both directions in due order, without acting on a reminder or grant.
    pub fn commitments_ledger_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CommitmentLedgerRequest,
    ) -> MemoryResult<CommitmentLedgerView> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let contact_ref = self.resolve_ref(&input.contact_ref)?;
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        owner_in(self, &txn, owner)?;
        let (ledger, label_heads) = self.vault.commitment_ledger_for_counterparty_in_txn(
            &lane.store_read(),
            &txn,
            &contact_ref,
            |id| Ok(lane.graph_ask_raw_in_txn(&txn, id)?.is_some()),
        )?;
        let owed_by_them = self.commitment_ledger_items_in(&lane, &txn, ledger.owed_by_them)?;
        let owed_to_them = self.commitment_ledger_items_in(&lane, &txn, ledger.owed_to_them)?;
        self.produced_from(label_heads);
        Ok(CommitmentLedgerView {
            contact_ref: contact_ref.to_hex(),
            identity_ref: ledger.counterparty.identity_ref.to_hex(),
            counterparty: ledger.counterparty.counterparty,
            channel: ledger.counterparty.channel,
            address_or_handle: ledger.counterparty.address_or_handle,
            owed_by_them,
            owed_to_them,
        })
    }

    fn commitment_ledger_items_in(
        &self,
        lane: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        entries: Vec<CommitmentLedgerEntry>,
    ) -> MemoryResult<Vec<CommitmentLedgerItem>> {
        let mut items = Vec::with_capacity(entries.len());
        for entry in entries {
            let view = match self.commitment_view_in(lane, txn, &entry.commitment_id) {
                Ok(view) => view,
                Err(error) if error.code == super::super::MEMORY_CODE_NOT_FOUND => continue,
                Err(error) => return Err(error),
            };
            if !matches!(view.status, CommitmentStatus::Open) {
                continue;
            }
            items.push(CommitmentLedgerItem {
                valid_from: entry.valid_time.start,
                valid_to: entry.valid_time.end,
                commitment: view,
            });
        }
        Ok(items)
    }
}
