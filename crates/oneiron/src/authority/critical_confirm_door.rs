//! Signed critical-claim answers, under the existing host-root owner ceremony.
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::{TimeRange, Vault};

use super::slip_vault::{next_entry, require_host};
use super::*;

impl Vault {
    /// Records an authenticated owner's exact answer and verifies its fold
    /// before the claim settlement runs in this same transaction.
    pub(crate) fn append_critical_write_confirm_as_owner_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        action: CriticalWriteConfirmAction,
        now: u64,
    ) -> Result<CriticalWriteConfirmState> {
        owner.owner_authored_write_in_txn(self, txn)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        require_host(&fold, issuer)?;
        // FIX 7908: join a frontier wider than one entry names, else today's path.
        let fold = self
            .prepare_authority_frontier_in_txn(
                txn,
                &fold,
                FrontierSigner::Host(issuer),
                MAX_PARENTS,
            )?
            .unwrap_or(fold);
        let entry = next_entry(
            issuer,
            &fold,
            AuthorityOp::CriticalWriteConfirm(action.clone()),
            now,
        )?;
        let hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        let after = self.authority_fold_readonly_in_txn(txn)?;
        after
            .critical_write_confirms
            .get(&action.confirm_id)
            .filter(|state| {
                state.authority_entry_hash == hash
                    && state.action == action
                    && !after
                        .conflicted_critical_write_confirms
                        .contains(&action.confirm_id)
            })
            .cloned()
            .ok_or_else(invalid_authority)
    }
}
