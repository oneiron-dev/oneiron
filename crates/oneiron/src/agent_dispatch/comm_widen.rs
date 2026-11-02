//! FIX 1380 phase 2: the one widen signal a running child sends when the comm
//! dial refuses it, and the reach its parent approved. ARCH-0028 :611:
//! "Widening is one signal to the parent, approve-and-stop-asking."
//!
//! One row per child attempt: the grant lives as long as that attempt id, so
//! a retry of the same queue row keeps it and a new attempt does not (CALLS
//! W3). The row holds one request per needed reach (CALLS W5): a pending
//! request is reused, a decline is final for its reach, and a broader
//! approval covers every lesser reach. An approval widens the child's dial,
//! never past its parent's own live reach (CALLS W4).

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

use super::AgentDispatcher;
use super::comm::{CommReach, dispatch_parent_in_txn};
use super::types::AgentDispatchInput;
use super::widen_record::invalid;
use crate::genui::ConsentConfirmOutcome;

/// Child attempt → its comm widening.
const COMM_WIDEN: SideTable<AttemptId, CommWidenRecord, Named> =
    SideTable::new(&side_table::AGENT_DISPATCH_COMM_WIDEN);

/// Who answers a child's widen ask: its real dispatch parent's agent, or,
/// for a dispatch with no agent parent, the vault owner (CALLS W1); no one
/// once that actor was erased (FIX 3520).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CommWidenRecipient {
    Agent(EntityId),
    Owner(EntityId),
    Erased,
}

impl CommWidenRecipient {
    /// The actor, while it is not erased.
    pub(crate) const fn actor(self) -> Option<EntityId> {
        match self {
            Self::Agent(actor) | Self::Owner(actor) => Some(actor),
            Self::Erased => None,
        }
    }

    /// Names no one in place of `actor`; whether it named it.
    fn forget(&mut self, actor: EntityId) -> bool {
        let named = self.actor() == Some(actor);
        if named {
            *self = Self::Erased;
        }
        named
    }
}

/// Where one request stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CommWidenState {
    Pending,
    Approved,
    Declined,
}

/// The question one ask round carries: ids and time reserved before its
/// witness, so a retry lands the same question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommWidenQuestion {
    pub(crate) conversation: EntityId,
    pub(crate) turn: EntityId,
    pub(crate) message: EntityId,
    pub(crate) at: u64,
}

/// Who settled a request, when, and what they chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommWidenDecision {
    pub(crate) by: CommWidenRecipient,
    pub(crate) at: u64,
    /// The ask whose answer settled it.
    pub(crate) ask: EntityId,
    /// What the answer chose (FIX 10178): approve once covers the asking
    /// attempt, as an approval always has; approve and stop asking also
    /// answers its descendants' asks up to the approved reach, under the
    /// same clamps, for as long as that attempt's row lives; deny is final
    /// for the reach. An agent parent's approve is once, its decline a deny.
    pub(crate) choice: ConsentConfirmOutcome,
}

/// One request: the child needs `needed` to address someone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommWidenRequest {
    pub(crate) needed: CommReach,
    pub(crate) recipient: CommWidenRecipient,
    pub(crate) at: u64,
    /// The current round's question; `None` until one is reserved, and again
    /// after a round closed unanswered.
    pub(crate) question: Option<CommWidenQuestion>,
    /// The current round's admitted ask group.
    pub(crate) ask: Option<EntityId>,
    pub(crate) state: CommWidenState,
    pub(crate) decided: Option<CommWidenDecision>,
}

/// The reach the parent approved, and the answer that approved it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommApproval {
    pub(crate) reach: CommReach,
    pub(crate) decision: CommWidenDecision,
    /// When the owner revoked a stop-asking choice's standing (FIX 10695):
    /// from then its descendants inherit nothing from it and ask again. The
    /// choice stays as answered, and the asking run keeps its own reach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) standing_revoked_at: Option<u64>,
}

impl CommApproval {
    /// Whether descendants inherit this approval's reach: a stop-asking
    /// choice whose standing the owner has not revoked.
    fn stands(&self) -> bool {
        self.decision.choice == ConsentConfirmOutcome::ApproveAndStopAsking
            && self.standing_revoked_at.is_none()
    }
}

/// One child's comm widening.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommWidenRecord {
    pub(crate) approved: Option<CommApproval>,
    pub(crate) requests: Vec<CommWidenRequest>,
}

impl CommWidenRecord {
    /// Whether an approval already covers `needed`.
    pub(crate) fn covers(&self, needed: CommReach) -> bool {
        self.approved
            .is_some_and(|approval| approval.reach >= needed)
    }

    pub(crate) fn request_mut(&mut self, needed: CommReach) -> Option<&mut CommWidenRequest> {
        self.requests
            .iter_mut()
            .find(|request| request.needed == needed)
    }

    /// Settles the pending request whose current round is `ask`: approved
    /// widens the child to at least its reach, declined is final for it.
    /// Anything else (no such request, another round, already settled) is a
    /// no-op; returns whether it moved.
    pub(crate) fn settle(
        &mut self,
        ask: EntityId,
        approve: bool,
        decision: CommWidenDecision,
    ) -> bool {
        let Some(request) = self
            .requests
            .iter_mut()
            .find(|request| request.ask == Some(ask) && request.state == CommWidenState::Pending)
        else {
            return false;
        };
        let needed = request.needed;
        request.decided = Some(decision);
        if approve {
            request.state = CommWidenState::Approved;
            if !self.covers(needed) {
                self.approved = Some(CommApproval {
                    reach: needed,
                    decision,
                    standing_revoked_at: None,
                });
            }
        } else {
            request.state = CommWidenState::Declined;
        }
        true
    }

    /// Ends the standing of this record's stop-asking choice at `at` (FIX
    /// 10695): the choice stays as answered and the asking run keeps its own
    /// reach; only its descendants stop inheriting it. Answers the approval
    /// and whether this call ended it, or `None` when the record holds no
    /// stop-asking choice.
    pub(crate) fn revoke_standing(&mut self, at: u64) -> Option<(CommApproval, bool)> {
        let approval = self.approved.as_mut().filter(|approval| {
            approval.decision.choice == ConsentConfirmOutcome::ApproveAndStopAsking
        })?;
        let ended = approval.standing_revoked_at.is_none();
        if ended {
            approval.standing_revoked_at = Some(at);
        }
        Some((*approval, ended))
    }

    /// Takes `actor` out of the record (FIX 3520): a pending request it was
    /// to answer goes, so the next refused send asks its current parent
    /// afresh; a settled request and the approval keep their answer with no
    /// one named. Whether any did.
    fn forget(&mut self, actor: EntityId) -> bool {
        let before = self.requests.len();
        self.requests.retain(|request| {
            request.state != CommWidenState::Pending || request.recipient.actor() != Some(actor)
        });
        let mut named = self.requests.len() != before;
        for request in &mut self.requests {
            named |= request.recipient.forget(actor);
            if let Some(decided) = &mut request.decided {
                named |= decided.by.forget(actor);
            }
        }
        if let Some(approval) = &mut self.approved {
            named |= approval.decision.by.forget(actor);
        }
        named
    }

    /// Closes the pending round `ask` that ended unanswered (its deadline or a
    /// stale cut): the request stays pending with no question, so the next
    /// refused send asks a fresh round. Silence never approves. Returns
    /// whether it moved.
    pub(crate) fn close_round(&mut self, ask: EntityId) -> bool {
        let Some(request) = self
            .requests
            .iter_mut()
            .find(|request| request.ask == Some(ask) && request.state == CommWidenState::Pending)
        else {
            return false;
        };
        request.question = None;
        request.ask = None;
        true
    }
}

/// `child`'s comm widening, read in `txn`.
pub(crate) fn comm_widen_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    child: AttemptId,
) -> Result<Option<CommWidenRecord>> {
    COMM_WIDEN.get(&vault.store, txn, &child)
}

/// Every attempt that holds a comm widening, read in `txn`, so a reader of
/// the waiting asks reads those rows, not the whole ledger (FIX 11318).
pub(crate) fn comm_widen_children_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<AttemptId>> {
    COMM_WIDEN.scan_keys(&vault.store, txn, &[])
}

/// Stores `child`'s comm widening in `txn`.
pub(crate) fn put_comm_widen_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    child: AttemptId,
    record: &CommWidenRecord,
) -> Result<()> {
    COMM_WIDEN.put(&vault.store, txn, &child, record)
}

/// Forgets `actor` in every child's comm widening, in its erase's
/// transaction (FIX 3520).
pub(crate) fn erase_comm_widen_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let mut erased = Vec::new();
    for (child, mut record) in COMM_WIDEN.scan(&vault.store, txn)? {
        if record.forget(*actor) {
            erased.push((child, record));
        }
    }
    for (child, record) in &erased {
        COMM_WIDEN.put(&vault.store, txn, child, record)?;
    }
    Ok(())
}

/// Who answers `child`'s widen ask: the agent of its real dispatch parent;
/// for a dispatch with none, the vault owner, phase 1's root parent, and the
/// first owner by id when the vault has several (CALLS W1). Never a
/// grandparent.
pub(crate) fn comm_widen_recipient_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    child: &AttemptRecord,
) -> Result<CommWidenRecipient> {
    let dispatcher = AgentDispatcher::new(vault);
    let parent = decode_dreamer_attempt_payload(&child.payload)?.parent_attempt;
    if let Some((_, input)) = dispatch_parent_in_txn(&dispatcher, txn, parent)? {
        return Ok(CommWidenRecipient::Agent(
            super::agent_dispatch_actor(&input)?.entity_ref(),
        ));
    }
    crate::policy_model::owners_in_txn(vault, txn)?
        .into_iter()
        .min()
        .map(CommWidenRecipient::Owner)
        .ok_or_else(|| invalid("the vault has no owner to ask"))
}

fn approved_reach(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    child: AttemptId,
) -> Result<Option<CommReach>> {
    Ok(comm_widen_in(vault, txn, child)?
        .and_then(|record| record.approved)
        .map(|approval| approval.reach))
}

/// The reach `child` addresses with now (CALLS W4): its frozen dial or the
/// reach its parent approved, the wider, widened by any ancestor's approval
/// to stop asking (FIX 10178), then never wider than any ancestor's own live
/// reach. A spawn already froze the child within its parent's dial, so a
/// child with no approval reads its dial as frozen unless an ancestor
/// stopped asking; a walk that does not read leaves such a child at its
/// frozen dial.
pub(crate) fn effective_comm_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    child: AttemptId,
    input: &AgentDispatchInput,
) -> Result<CommReach> {
    let Some(approved) = approved_reach(vault, txn, child)? else {
        return Ok(match ancestry_in(vault, txn, child) {
            Ok(Ancestry {
                clamp,
                standing: Some(standing),
            }) => clamped(input.comm.max(standing), clamp),
            Ok(_) | Err(_) => input.comm,
        });
    };
    let ancestry = ancestry_in(vault, txn, child)?;
    let widened = input.comm.max(approved);
    let widened = ancestry
        .standing
        .map_or(widened, |standing| widened.max(standing));
    Ok(clamped(widened, ancestry.clamp))
}

/// What `child`'s real dispatch ancestors give its reach: the narrowest of
/// their own live reaches, and the widest reach any of them approved and
/// stopped asking for, while the owner has not revoked that standing (FIX
/// 10695).
struct Ancestry {
    clamp: Option<CommReach>,
    standing: Option<CommReach>,
}

/// `reach`, never wider than `clamp`.
fn clamped(reach: CommReach, clamp: Option<CommReach>) -> CommReach {
    clamp.map_or(reach, |clamp| reach.min(clamp))
}

/// Walks `child`'s real dispatch ancestors. A true cycle refuses; the walk's
/// length is observed against its scan row (FIX 10178), never refused.
fn ancestry_in(vault: &Vault, txn: &heed::RoTxn<'_>, child: AttemptId) -> Result<Ancestry> {
    let dispatcher = AgentDispatcher::new(vault);
    let queue = AttemptQueue::new(vault);
    let mut ancestry = Ancestry {
        clamp: None,
        standing: None,
    };
    let mut seen = std::collections::HashSet::from([child]);
    let mut cursor = child;
    while let Some(row) = queue.get_in_txn(txn, cursor)? {
        let parent = decode_dreamer_attempt_payload(&row.payload)?.parent_attempt;
        let Some((id, parent_input)) = dispatch_parent_in_txn(&dispatcher, txn, parent)? else {
            break;
        };
        if !seen.insert(id) {
            return Err(invalid("dispatch lineage cycle"));
        }
        let approval = comm_widen_in(vault, txn, id)?.and_then(|record| record.approved);
        let own = approval.map_or(parent_input.comm, |approval| {
            approval.reach.max(parent_input.comm)
        });
        ancestry.clamp = Some(clamped(own, ancestry.clamp));
        if let Some(approval) = approval.filter(CommApproval::stands) {
            ancestry.standing = Some(
                ancestry
                    .standing
                    .map_or(approval.reach, |standing| standing.max(approval.reach)),
            );
        }
        cursor = id;
    }
    if let Ok(mut count) = crate::scan_check::ScanCount::start(
        &vault.store,
        txn,
        crate::scan_check::EngineScan::CommWidenAncestorRows,
        child.as_bytes(),
    ) {
        count.rows(seen.len().saturating_sub(1));
        count.defer(&vault.store);
    }
    Ok(ancestry)
}
