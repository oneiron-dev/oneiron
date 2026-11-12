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

/// One owner restore's claims that still wait for the owner's word.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RestoreInboxGroup {
    /// The restore receipt's gate id (32 hex): the group's key.
    pub group_key: String,
    /// The restore receipt (`gate:<hex>`), readable through `vault.receipts`.
    pub receipt_ref: String,
    /// When the owner restored the archive.
    pub created_at: u64,
    /// The source vault id the restored archive names; absent when it names none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_vault: Option<String>,
    /// The restored claims still open: Proposed and Active.
    pub open_members: u64,
    /// The open members whose approval would supersede a live head. Accept-all
    /// leaves them waiting, for the owner to settle one by one.
    pub replaces_live_head: u64,
}

/// What became of one member of a restore group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RestoreMemberVerdict {
    /// The owner's approval landed: the claim reads as approved and is recalled.
    Landed,
    /// The owner rejected it: it is retracted, and its record is kept.
    Rejected,
    /// It still waits for the owner's word.
    Waiting,
}

/// Why a member of a restore group still waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RestoreMemberWait {
    /// Review-each: the owner settles it with `vault.claims.review` and
    /// `vault.claims.settle`.
    ReviewEach,
    /// Its approval would supersede the live head `replaces_ref` names, so the
    /// owner settles it alone: an archived value never replaces a newer one in
    /// one click.
    ReplacesLiveHead,
    /// The owner opened it, and the actor that opened a proposal never settles it.
    OpenedByOwner,
    /// The gate refused or held the owner's answer; `detail` says why.
    Refused,
}

/// One member of a restore group after the owner's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RestoreMemberOutcome {
    /// The restored claim (32 hex).
    pub claim_ref: String,
    pub verdict: RestoreMemberVerdict,
    /// Its own Settlement receipt (`gate:<hex>`), when it settled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_ref: Option<String>,
    /// Why it still waits, when it does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting: Option<RestoreMemberWait>,
    /// The live head its approval would supersede (32 hex), when one stands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces_ref: Option<String>,
    /// One human line on a refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The owner's answer to one restore group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RestoreInboxResolution {
    /// The restore receipt's gate id (32 hex).
    pub group_key: String,
    /// The act's one bundle receipt (`gate:<hex>`, a proposal outcome), when a
    /// member settled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_ref: Option<String>,
    /// Each member the answer read, newest first.
    pub members: Vec<RestoreMemberOutcome>,
    /// The `vault.runs.revert` handle (`run:restore:<hex>`), which takes back all
    /// of the settled members or any part of them, when a member settled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert_handle: Option<String>,
    /// The work still owed after the answer committed (FIX 7600); empty when
    /// none is.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<crate::memory::SettleWarning>,
}

/// Where one restored claim stands for its restore group.
pub(crate) enum RestoredMemberState {
    /// It is no open proposal: settled, closed, deleted or gone.
    Closed,
    /// It is open; `replaces` is the live head its approval would supersede.
    Open { replaces: Option<EntityId> },
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
    /// approval would supersede a live head: one claim read per member.
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
            let (mut open, mut replaces) = (0_u64, 0_u64);
            for member in &members {
                if let RestoredMemberState::Open { replaces: head } =
                    self.restored_member_state_in_txn(&txn, member)?
                {
                    open += 1;
                    replaces += u64::from(head.is_some());
                }
            }
            if open == 0 {
                continue;
            }
            let head =
                crate::batch::export::owner_restore_group_head_in_txn(self, &txn, &group_key)?;
            groups.push(RestoreInboxGroup {
                receipt_ref: format!("gate:{group_key}"),
                group_key,
                created_at: receipt.created_at,
                source_vault: head.and_then(|head| head.source_vault),
                open_members: open,
                replaces_live_head: replaces,
            });
        }
        Ok(groups)
    }
}
