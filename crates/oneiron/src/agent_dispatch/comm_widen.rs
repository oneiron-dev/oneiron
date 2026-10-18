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
use super::comm::{CommReach, MAX_LINEAGE_HOPS, dispatch_parent_in_txn};
use super::types::AgentDispatchInput;
use super::widen_record::invalid;

/// Child attempt → its comm widening.
const COMM_WIDEN: SideTable<AttemptId, CommWidenRecord, Named> =
    SideTable::new(&side_table::AGENT_DISPATCH_COMM_WIDEN);

/// Who answers a child's widen ask: its real dispatch parent's agent, or,
/// for a dispatch with no agent parent, the vault owner (CALLS W1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CommWidenRecipient {
    Agent(EntityId),
    Owner(EntityId),
}

impl CommWidenRecipient {
    pub(crate) const fn actor(self) -> EntityId {
        match self {
            Self::Agent(actor) | Self::Owner(actor) => actor,
        }
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

impl CommWidenState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Declined => "declined",
        }
    }
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

/// Who settled a request, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommWidenDecision {
    pub(crate) by: CommWidenRecipient,
    pub(crate) at: u64,
    /// The ask whose answer settled it.
    pub(crate) ask: EntityId,
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
    pub(crate) fn settle(&mut self, ask: EntityId, approve: bool, decision: CommWidenDecision) -> bool {
        let Some(request) = self.requests.iter_mut().find(|request| {
            request.ask == Some(ask) && request.state == CommWidenState::Pending
        }) else {
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
                });
            }
        } else {
            request.state = CommWidenState::Declined;
        }
        true
    }

    /// Closes the pending round `ask` that ended unanswered (its deadline or a
    /// stale cut): the request stays pending with no question, so the next
    /// refused send asks a fresh round. Silence never approves. Returns
    /// whether it moved.
    pub(crate) fn close_round(&mut self, ask: EntityId) -> bool {
        let Some(request) = self.requests.iter_mut().find(|request| {
            request.ask == Some(ask) && request.state == CommWidenState::Pending
        }) else {
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

/// Stores `child`'s comm widening in `txn`.
pub(crate) fn put_comm_widen_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    child: AttemptId,
    record: &CommWidenRecord,
) -> Result<()> {
    COMM_WIDEN.put(&vault.store, txn, &child, record)
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

fn approved_reach(vault: &Vault, txn: &heed::RoTxn<'_>, child: AttemptId) -> Result<Option<CommReach>> {
    Ok(comm_widen_in(vault, txn, child)?
        .and_then(|record| record.approved)
        .map(|approval| approval.reach))
}

/// The reach `child` addresses with now (CALLS W4): its frozen dial or the
/// reach its parent approved, the wider, then never wider than any
/// ancestor's own live reach. A spawn already froze the child within its
/// parent's dial, so a child with no approval reads its dial as frozen.
pub(crate) fn effective_comm_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    child: AttemptId,
    input: &AgentDispatchInput,
) -> Result<CommReach> {
    let Some(approved) = approved_reach(vault, txn, child)? else {
        return Ok(input.comm);
    };
    let dispatcher = AgentDispatcher::new(vault);
    let queue = AttemptQueue::new(vault);
    let mut reach = input.comm.max(approved);
    let mut cursor = child;
    let mut hops = 0;
    while let Some(row) = queue.get_in_txn(txn, cursor)? {
        let parent = decode_dreamer_attempt_payload(&row.payload)?.parent_attempt;
        let Some((id, parent_input)) = dispatch_parent_in_txn(&dispatcher, txn, parent)? else {
            break;
        };
        hops += 1;
        if hops > MAX_LINEAGE_HOPS || id == child {
            return Err(invalid("dispatch lineage bound or cycle"));
        }
        let own = approved_reach(vault, txn, id)?
            .map_or(parent_input.comm, |approved| approved.max(parent_input.comm));
        reach = reach.min(own);
        cursor = id;
    }
    Ok(reach)
}
