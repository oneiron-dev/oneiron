//! The owner's door to the Dreamer's own changes (OF-023, owner ruling
//! 10-18: "autoapply + revert rather than holdout"). The Dreamer applies its
//! work at once; the authenticated root owner lists what it changed and
//! takes any one change back, in one transaction with one Gate receipt. The
//! mechanics live beside the Dreamer, in
//! `crate::dreamer_consolidation::revert`.

use super::authorship::*;
use super::{Memory, MemoryResult};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_consolidation::{
    DreamerChanges, DreamerRevertReceipt, dreamer_changes_in_txn, revert_dreamer_change_in_txn,
};
use crate::edge::EdgeActorClass;
use crate::error::Error;
use crate::{EntityId, WriteActor};

const REVERT_KIND: &str = "dreamer_change_revert";
const REVERT_REASON: &str = "gate.memory.dreamer_change_revert";

impl Memory<'_> {
    /// The Dreamer's standing changes, newest first, at most `limit`, and
    /// each person whose newest `about` landing the owner may revert.
    pub fn dreamer_changes(
        &self,
        owner: &AuthenticatedOwner,
        limit: usize,
    ) -> MemoryResult<DreamerChanges> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        self.dreamer_change_owner(&txn, owner)?;
        Ok(dreamer_changes_in_txn(self.vault, &txn, limit)?)
    }

    /// The owner's revert of the Dreamer change `change` names: a claim, a
    /// settlement's answer, a summary, a NOTE, or a PERSON's `about` lines.
    /// The Gate receipt names the owner and the change.
    pub fn revert_dreamer_change(
        &self,
        owner: &AuthenticatedOwner,
        change: EntityId,
        now: u64,
    ) -> MemoryResult<DreamerRevertReceipt> {
        self.with_verified_actor_write_txn(|txn| {
            self.dreamer_change_owner(txn, owner)?;
            let actor = WriteActor::new(self.actor, self.actor_class);
            let reverted = revert_dreamer_change_in_txn(self.vault, txn, change, actor, now)?;
            let receipt = decision(
                actor,
                REVERT_KIND,
                "approved",
                REVERT_REASON,
                Some(change),
                change.as_bytes().to_vec(),
                now,
            );
            self.vault
                .store
                .append_gate_decision_in_txn(txn, &receipt)?;
            Ok(DreamerRevertReceipt {
                change,
                reverted,
                receipt_ref: format!("gate:{}", receipt.decision_id.to_hex()),
            })
        })
    }

    /// The owner proof must name this bound person, who owns the vault now.
    fn dreamer_change_owner(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
    ) -> Result<(), Error> {
        if self.actor != verify_owner(self.vault, txn, owner)?
            || self.actor_class != EdgeActorClass::Human
        {
            return Err(authority_denied("owner proof must name the bound caller"));
        }
        Ok(())
    }
}
