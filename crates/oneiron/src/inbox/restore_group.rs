//! The owner's whole-vault restores as inbox groups (RULING 02:26 13 Nov, NOTE
//! ARCHIVE-RESTORE-APPROVE-DESIGN R1-R4): one group per restore receipt, over the
//! claims that restore inserted as Proposed and that still wait for the owner's
//! word. Without the owner's answer a restored claim stays out of recall.
//!
//! The owner restore door alone records the members, in the restore's own
//! writer, so no agent can add one. The
//! owner answers a group through `vault.inbox.groups.resolve` under the owner's
//! proof; `Memory::resolve_restore_inbox_group` settles each member on the
//! `vault.claims.settle` path. `Vault::inbox_restore_groups` lists the groups for
//! the owner's one inbox page.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::GateDecisionRecord;

#[doc(hidden)]
pub use oneiron_verb_wire::inbox::restore_group::{
    RestoreInboxGroup, RestoreInboxResolution, RestoreMemberOutcome, RestoreMemberVerdict,
    RestoreMemberWait,
};

/// One restored claim still open for its restore group.
pub(crate) struct OpenRestoredMember {
    pub(crate) id: EntityId,
    /// The live head its approval would supersede.
    pub(crate) replaces: Option<EntityId>,
}

/// What settling one restore group member did, in its savepoint.
pub(crate) enum RestoredMemberSettle {
    /// It is no open proposal any more.
    Closed,
    /// It still waits, and why; nothing was written.
    Waiting {
        wait: RestoreMemberWait,
        replaces: Option<EntityId>,
        detail: Option<String>,
    },
    /// It settled: its Settlement receipt, the live gate decisions it recorded,
    /// and whether a Dreamer run proposed it.
    Settled {
        receipt: GateDecisionRecord,
        recorded: Vec<crate::gate::RecordedClaimGateDecision>,
        dreamer_run: bool,
    },
}

impl Vault {
    /// Every owner restore with a restored claim still open, one inbox group each,
    /// in receipt order. Each card counts its open members and those whose
    /// approval would supersede a live head: one claim read per member, and
    /// one read of the claims about each subject per group.
    ///
    /// # Errors
    ///
    /// A read failure.
    pub(crate) fn inbox_restore_groups(&self) -> Result<Vec<RestoreInboxGroup>> {
        let txn = self.store.env.read_txn()?;
        let mut groups = Vec::new();
        for (group_key, members) in crate::batch::export::owner_restore_groups_in_txn(self, &txn)? {
            let Some(receipt) =
                crate::batch::export::owner_restore_receipt_in_txn(&self.store, &txn, &group_key)?
            else {
                continue;
            };
            let open = self.open_restored_members_in_txn(&txn, &members)?;
            if open.is_empty() {
                continue;
            }
            let head =
                crate::batch::export::owner_restore_group_head_in_txn(self, &txn, &group_key)?;
            groups.push(RestoreInboxGroup {
                receipt_ref: format!("gate:{group_key}"),
                group_key,
                created_at: receipt.created_at,
                source_vault: head.and_then(|head| head.source_vault),
                open_members: open.len() as u64,
                replaces_live_head: open
                    .iter()
                    .filter(|member| member.replaces.is_some())
                    .count() as u64,
            });
        }
        Ok(groups)
    }
}
