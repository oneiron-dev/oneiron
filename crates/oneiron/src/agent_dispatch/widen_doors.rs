//! The owner's doors over context-widen proposals (OF-568): list them, and
//! approve or decline one as the board above. The owner routes
//! (`/v1/owner/widen-proposals`), the host verbs `vault.widen_proposals`,
//! `.approve` and `.decline`, and the `oneiron widen-proposals` command all
//! call these. A proposal is named by its id, the digest of its stored
//! request, so the one acted on is the one listed. Approval and decline keep
//! their own proof ([`AgentDispatcher::approve_context_widen`],
//! [`AgentDispatcher::decline_context_widen`]): the owner of the board's
//! TASK, a live human, and the immediate board above.

use serde::{Deserialize, Serialize};

use super::AgentDispatcher;
use super::widen_record::{
    PROPOSAL_INDEX, WIDEN, WidenLanding, WidenRecord, WidenTarget, invalid, validate_proposal_id,
};
use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::context_projection::ContextSpec;
use crate::{Result, Vault};

/// Where a proposal stands: waiting on the board, approved (its child
/// enqueued), or declined (final).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WidenProposalState {
    Pending,
    Approved,
    Declined,
}

/// `vault.widen_proposals`'s input.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WidenProposalsRequest {
    /// Only proposals in this state; every state when absent.
    #[serde(default)]
    pub state: Option<WidenProposalState>,
}

/// `vault.widen_proposals.approve` and `.decline`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WidenProposalAnswer {
    /// The proposal's id (64 hex), as the list and the spawn's
    /// `proposal_ref` name it.
    pub proposal_id: String,
}

/// One proposal as the owner sees it. Contexts are descriptors, never the
/// content they name.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WidenProposalView {
    pub proposal_id: String,
    pub state: WidenProposalState,
    /// The attempt that asked for the wider context (32 hex).
    pub parent_attempt: String,
    /// The board above, which answers; absent when it cannot be proven, and
    /// then approval fails closed.
    pub board_attempt: Option<String>,
    /// What the child runs: `agent` or `workflow`.
    pub target_kind: String,
    /// The agent or workflow id the child runs.
    pub target: String,
    /// The parent's context as it is.
    pub parent_context: serde_json::Value,
    /// The context the child asked for.
    pub requested_context: serde_json::Value,
    /// The parent's context once widened, as approval would set it.
    pub widened_parent_context: serde_json::Value,
    /// When it was raised, on the vault clock (seconds).
    pub recorded_at: u64,
    /// The child attempt an approval enqueued (32 hex).
    pub landed_attempt: Option<String>,
    /// Who declined it (actor hex), and when.
    pub declined_by: Option<String>,
    pub declined_at: Option<u64>,
}

/// `vault.widen_proposals`'s answer, newest first.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WidenProposalsView {
    pub proposals: Vec<WidenProposalView>,
}

/// Every stored proposal, or those in one state, newest first.
pub fn widen_proposals_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: &WidenProposalsRequest,
) -> Result<WidenProposalsView> {
    owner.revalidate(vault)?;
    let rtxn = vault.store.env.read_txn()?;
    let mut proposals = Vec::new();
    for (_, record) in WIDEN.scan(&vault.store, &rtxn)? {
        let row = view(&record)?;
        if request.state.is_none_or(|state| state == row.state) {
            proposals.push(row);
        }
    }
    proposals.sort_by(|a, b| {
        b.recorded_at
            .cmp(&a.recorded_at)
            .then_with(|| a.proposal_id.cmp(&b.proposal_id))
    });
    Ok(WidenProposalsView { proposals })
}

/// The board above approves one proposal: the parent's slice widens and the
/// child is enqueued, under the approve-once consent. An approved proposal
/// answers as it landed; a declined one is refused.
pub fn approve_widen_proposal_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    answer: &WidenProposalAnswer,
) -> Result<WidenProposalView> {
    let proposal = stored(vault, &answer.proposal_id)?.request.proposal()?;
    AgentDispatcher::new(vault).approve_context_widen(
        owner,
        &proposal,
        crate::unix_seconds_now(),
    )?;
    view(&stored(vault, &answer.proposal_id)?)
}

/// The board above declines one proposal. The decline is final and stays on
/// record as the Coach's widen-denial evidence; declining again is a no-op,
/// and an approved proposal cannot be declined.
pub fn decline_widen_proposal_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    answer: &WidenProposalAnswer,
) -> Result<WidenProposalView> {
    let proposal = stored(vault, &answer.proposal_id)?.request.proposal()?;
    AgentDispatcher::new(vault).decline_context_widen(owner, &proposal)?;
    view(&stored(vault, &answer.proposal_id)?)
}

/// The stored record a proposal id names, in its own snapshot. The doors it
/// feeds check the record again in their own write.
fn stored(vault: &Vault, id: &str) -> Result<WidenRecord> {
    validate_proposal_id(id)?;
    let rtxn = vault.store.env.read_txn()?;
    let full_key = PROPOSAL_INDEX
        .get(&vault.store, &rtxn, &id.to_owned())?
        .ok_or_else(|| invalid("widen proposal was not issued by this vault"))?;
    let prefix = WIDEN.decl().prefix;
    let key_hash: [u8; 32] = full_key
        .strip_prefix(prefix)
        .and_then(|hash| hash.try_into().ok())
        .ok_or_else(|| invalid("invalid widen intent index"))?;
    let record = WIDEN
        .get(&vault.store, &rtxn, &key_hash)?
        .ok_or_else(|| invalid("widen proposal intent is missing"))?;
    if record.request.id()? != id {
        return Err(invalid("widen proposal index does not match its request"));
    }
    Ok(record)
}

fn view(record: &WidenRecord) -> Result<WidenProposalView> {
    let proposal = record.request.proposal()?;
    let hex = |id: &AttemptId| crate::entity_id::bytes_to_hex_lower(id.as_bytes());
    let spec = |spec: &ContextSpec| {
        serde_json::to_value(spec).map_err(|_| invalid("widen context does not encode"))
    };
    let (target_kind, target) = match &record.request.intent.target {
        WidenTarget::Agent(id) => ("agent", id.clone()),
        WidenTarget::Workflow(id) => ("workflow", id.clone()),
    };
    let state = match (&record.landed, &record.declined) {
        (Some(_), _) => WidenProposalState::Approved,
        (None, Some(_)) => WidenProposalState::Declined,
        (None, None) => WidenProposalState::Pending,
    };
    Ok(WidenProposalView {
        state,
        parent_attempt: hex(&proposal.parent_attempt),
        board_attempt: proposal.board_attempt.as_ref().map(hex),
        target_kind: target_kind.to_owned(),
        target,
        parent_context: spec(&proposal.parent_context)?,
        requested_context: spec(&proposal.requested_context)?,
        widened_parent_context: spec(&proposal.widened_parent_context)?,
        recorded_at: record.recorded_at,
        landed_attempt: record.landed.map(|landing| match landing {
            WidenLanding::Agent(id) | WidenLanding::Workflow(id) => hex(&id),
        }),
        declined_by: record.declined.as_ref().map(|decline| decline.by.clone()),
        declined_at: record.declined.as_ref().map(|decline| decline.at),
        proposal_id: proposal.proposal_id,
    })
}
