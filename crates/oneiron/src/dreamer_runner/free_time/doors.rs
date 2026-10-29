//! The owner's free-time doors (FIX 4453): one agent's policy with its
//! revision, or Disabled; its cycles, a page at a time; and one cycle's
//! sheet. The human sees the agent's short note and the spending records;
//! the agent's diary, its prompts and every stored response stay out of
//! each answer. Each read revalidates the owner in its one read transaction
//! and reads everything in that snapshot: a read resumes no job and changes
//! no note, receipt or floor. A set or a clear is the policy's own
//! owner-revalidated write. No door marks an item done.
//!
//! A cycle's spend is in the host's usage ledger, which this crate does not
//! read: the sheet's spend says so ([`FreeTimeSpendView::unmetered`]), and a
//! server joins its trusted spend records in ([`FreeTimeSpendView::metered`]).

use std::collections::BTreeMap;
use std::ops::Bound;

use serde::{Deserialize, Serialize};

use super::cycle::{FreeTimeCycle, FreeTimeCycleState};
use super::policy::{
    FREE_TIME_WHEN_UNSET, FreeTimeAuthority, FreeTimePolicy, FreeTimePolicyInput, FreeTimeSchedule,
    FreeTimeSplit, UnsetFreeTimePolicy, effective_policy,
};
use super::receipt::{
    FreeTimeFloor, FreeTimeItemOutcome, FreeTimeItemReceipt, free_time_floor, receipts_in_txn,
};
use super::{CYCLE, FreeTimeKind, POLICY};
use crate::agent_dispatch::SpendScopeId;
use crate::agent_dispatch::budget_doors::RunRungSettlement;
use crate::attempt_queue::AttemptId;
use crate::authority::ActAuthority;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::owner_read_page_limit;
use crate::entity_id::bytes_to_hex_lower;
use crate::llm::run_admission::LeaseUnit;
use crate::{EntityId, Error, Result, Vault};

/// One agent's free-time policy.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FreeTimePolicyRequest {
    /// The agent definition, 32 hex.
    pub agent: String,
}

/// The owner sets or clears one agent's free-time policy.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FreeTimePolicySetRequest {
    /// The agent definition, 32 hex.
    pub agent: String,
    /// The revision the owner's surface showed: 0 while none is set.
    pub expected_revision: u64,
    /// The policy to set; absent or null clears it.
    #[serde(default)]
    pub policy: Option<FreeTimePolicyInput>,
}

/// Whether an agent has a free-time policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FreeTimePolicyState {
    /// The owner set one: a cycle opens at each of its boundaries.
    Set,
    /// None is set: no cycle, no floor and no free-time spend, and the agent
    /// keeps its nightly dreaming.
    Disabled,
}

/// The owner's policy as the engine keeps it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreeTimePolicyRow {
    /// The most one cycle may spend, in `unit`.
    pub total_units: u64,
    pub unit: String,
    pub schedule: FreeTimeSchedule,
    pub pinned_split: Option<FreeTimeSplit>,
    /// When the owner was shown the recurring cap and accepted it, in host
    /// milliseconds.
    pub cap_shown_at_ms: u64,
    /// The owner who set it, as the vault revalidated them, 32 hex; `None`
    /// once that owner was erased.
    pub set_by: Option<String>,
    /// Vault clock seconds.
    pub set_at: u64,
}

/// One agent's free-time policy and the revision a set or clear names.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreeTimePolicyView {
    pub agent: String,
    pub state: FreeTimePolicyState,
    /// The revision a set or clear names as `expected_revision`: 0 while
    /// none is set.
    pub revision: u64,
    /// `None` while Disabled.
    pub policy: Option<FreeTimePolicyRow>,
}

/// One page of an agent's free-time cycles, newest first.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FreeTimeCyclesRequest {
    /// The agent definition, 32 hex.
    pub agent: String,
    /// The `next` a previous page answered; absent for the newest page.
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One cycle as a list shows it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreeTimeCycleSummary {
    pub cycle: String,
    pub state: FreeTimeCycleState,
    pub policy_revision: u64,
    pub total_units: u64,
    /// Unix seconds: the boundary before this one, 0 when none was found.
    pub period_start: u64,
    /// Unix seconds: the owner-set boundary it opened at.
    pub boundary: u64,
    /// Unix seconds: the next boundary, at which it ends at the latest.
    pub next_boundary: Option<u64>,
    pub opened_at: u64,
    pub closed_at: Option<u64>,
    /// The floor, from the item receipts alone.
    pub floor: FreeTimeFloor,
    /// Whether every item receipt read; when not, the floor is Unknown.
    pub items_complete: bool,
    /// Whether the agent left its human a note.
    pub has_note: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreeTimeCyclesPage {
    pub agent: String,
    pub cycles: Vec<FreeTimeCycleSummary>,
    /// The cursor of the next, older page; `None` when this page holds the
    /// agent's oldest cycle.
    pub next: Option<String>,
}

/// One cycle of one agent.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FreeTimeCycleRequest {
    /// The agent definition, 32 hex.
    pub agent: String,
    /// The cycle, 32 hex.
    pub cycle: String,
}

/// An item's terminal receipt: how it ended, never what it said.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreeTimeItemReceiptView {
    pub outcome: FreeTimeItemOutcome,
    pub policy_revision: u64,
    /// The attempt that ran it, 32 hex; `None` for rest chosen with no
    /// attempt.
    pub attempt: Option<String>,
    /// The Proposed claim a for-human item landed, 32 hex.
    pub proposal: Option<String>,
    /// The code of a for-human item's read of its human's context that
    /// failed: the item ran on its own records. `None` when that context
    /// read, or there was none to read.
    pub context_unread: Option<String>,
    /// Vault clock seconds.
    pub at: u64,
}

/// One item a cycle opened with.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreeTimeItemView {
    pub item: String,
    pub kind: FreeTimeKind,
    /// The label its calls carry: `autonomy.for_human` or
    /// `autonomy.own_time`.
    pub purpose: String,
    /// The attempt that runs it, 32 hex; `None` for an own-time item of a
    /// resident whose dreaming is off, which only rest ends.
    pub attempt: Option<String>,
    /// The spend scope its calls draw on under the cycle's root, as the
    /// spend records name it.
    pub spend_scope: Option<String>,
    /// `None` while it has no receipt.
    pub receipt: Option<FreeTimeItemReceiptView>,
}

/// The agent's own short note to its human, never its diary.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreeTimeNoteView {
    pub author: String,
    /// Vault clock seconds.
    pub at: u64,
    pub text: String,
}

/// One label's spend records.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreeTimeLabelSpend {
    /// The label its calls carried; `None` for a record that named none.
    pub purpose: Option<String>,
    /// Each settled physical call, oldest first, with its run, item and
    /// scope refs, its reserved and settled quantities and unit, its
    /// stamped provider cost when it was priced, and its `source`: `engine`
    /// or `posted`, the path that wrote its record. An unpriced call has no
    /// cost; it is never zero.
    pub settlements: Vec<RunRungSettlement>,
}

/// A cycle's spending records, by label. No total: an unpriced call would
/// make one a floor, never the bill.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreeTimeSpendView {
    /// False when no usage ledger answered (an embedded vault, or a server
    /// that has not bound its usage ledger to an account): the spend is not
    /// known, and none of it reads as zero.
    pub metering_enabled: bool,
    /// Whether every stored spend record read. Always false while metering
    /// is off.
    pub complete: bool,
    pub by_label: Vec<FreeTimeLabelSpend>,
}

impl FreeTimeSpendView {
    /// The spend of a read no usage ledger answered.
    #[must_use]
    pub fn unmetered() -> Self {
        Self {
            metering_enabled: false,
            complete: false,
            by_label: Vec::new(),
        }
    }

    /// A cycle's spend from its settled calls, as a usage ledger read them;
    /// `complete` says every stored record read.
    #[must_use]
    pub fn metered(settlements: Vec<RunRungSettlement>, complete: bool) -> Self {
        let mut labels: BTreeMap<Option<String>, Vec<RunRungSettlement>> = BTreeMap::new();
        for settlement in settlements {
            labels
                .entry(settlement.purpose.clone())
                .or_default()
                .push(settlement);
        }
        Self {
            metering_enabled: true,
            complete,
            by_label: labels
                .into_iter()
                .map(|(purpose, settlements)| FreeTimeLabelSpend {
                    purpose,
                    settlements,
                })
                .collect(),
        }
    }
}

/// One cycle's sheet.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreeTimeCycleView {
    pub agent: String,
    pub cycle: String,
    pub state: FreeTimeCycleState,
    /// The policy revision it opened under, with that policy's total and
    /// split as they stood.
    pub policy_revision: u64,
    pub total_units: u64,
    pub unit: String,
    pub pinned_split: Option<FreeTimeSplit>,
    /// Unix seconds: the boundary before this one, 0 when none was found.
    pub period_start: u64,
    /// Unix seconds: the owner-set boundary it opened at.
    pub boundary: u64,
    /// Unix seconds: the next boundary, at which it ends at the latest.
    pub next_boundary: Option<u64>,
    pub opened_at: u64,
    pub closed_at: Option<u64>,
    /// The root spend scope holding the owner's total.
    pub root_scope: String,
    /// The floor, from the item receipts alone: a for-human item that
    /// landed a proposal and an own-time item that reflected or rested.
    pub floor: FreeTimeFloor,
    /// Whether every item receipt read in this snapshot; when not, the floor
    /// is Unknown. Apart from the spend's own `complete`.
    pub items_complete: bool,
    pub items: Vec<FreeTimeItemView>,
    /// The agent's short note to its human; `None` when it wrote none.
    pub note: Option<FreeTimeNoteView>,
    pub spend: FreeTimeSpendView,
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("free-time door: {reason}"))
}

fn entity(field: &str, value: &str) -> Result<EntityId> {
    EntityId::from_hex(value.trim()).map_err(|_| invalid(&format!("{field} is 32 hex")))
}

/// The label a kind's calls carry, as spend records name it.
fn label(kind: FreeTimeKind) -> String {
    crate::llm::routing::purpose_key(&kind.purpose())
}

fn policy_view(agent: EntityId, row: Option<FreeTimePolicy>) -> FreeTimePolicyView {
    let revision = row.as_ref().map_or(0, |policy| policy.revision);
    let policy = effective_policy(row);
    let state = match (&policy, FREE_TIME_WHEN_UNSET) {
        (Some(_), _) => FreeTimePolicyState::Set,
        (None, UnsetFreeTimePolicy::Disabled) => FreeTimePolicyState::Disabled,
    };
    FreeTimePolicyView {
        agent: agent.to_hex(),
        state,
        revision,
        policy: policy.map(|policy| FreeTimePolicyRow {
            total_units: policy.total_units,
            unit: LeaseUnit::tokens().as_str().to_owned(),
            schedule: policy.schedule,
            pinned_split: policy.pinned_split,
            cap_shown_at_ms: policy.cap_shown_at_ms,
            set_by: policy.set_by.as_ref().map(EntityId::to_hex),
            set_at: policy.set_at,
        }),
    }
}

/// Reads one agent's free-time policy as the owner.
///
/// # Errors
/// A malformed agent id, a stale owner proof, and storage errors.
pub fn free_time_policy_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &FreeTimePolicyRequest,
) -> Result<FreeTimePolicyView> {
    let agent = entity("agent", &input.agent)?;
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    // A cleared policy's row is only its witness (FIX 5661): it reads as
    // none, revision 0 and Disabled, as before.
    let row = POLICY
        .get(&vault.store, &txn, &agent)?
        .and_then(|record| record.policy);
    Ok(policy_view(agent, row))
}

/// Sets, or with no policy clears, one agent's free-time policy as the owner,
/// at the revision the owner read. A clear ends the agent's open cycle and
/// it goes back to its nightly dreaming.
///
/// # Errors
/// A malformed agent id or policy, a proof that does not hold here, an
/// unknown agent, [`Error::ConcurrentWrite`] for a stale revision, and
/// storage errors.
pub fn free_time_policy_set_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &FreeTimePolicySetRequest,
) -> Result<FreeTimePolicyView> {
    set_policy_as(vault, FreeTimeAuthority::Owner(owner, None), input)
}

/// Sets, or with no policy clears, one agent's free-time policy as
/// `authority` (FIX 5660): the owner's own proof, or an agent's act its live
/// Grant names (the `free_time_policy_set` verb), any set or clear of any
/// agent's policy, its Grant checked again in the write. Either is signed as
/// the act it is, an agent's naming its Grant.
///
/// # Errors
/// As [`free_time_policy_set_as_owner`]; an authority refusal when the
/// agent's Grant no longer names the act.
pub fn free_time_policy_set_as(
    vault: &Vault,
    authority: &ActAuthority,
    input: &FreeTimePolicySetRequest,
) -> Result<FreeTimePolicyView> {
    set_policy_as(vault, authority.into(), input)
}

fn set_policy_as(
    vault: &Vault,
    authority: FreeTimeAuthority<'_>,
    input: &FreeTimePolicySetRequest,
) -> Result<FreeTimePolicyView> {
    let agent = entity("agent", &input.agent)?;
    let row = match &input.policy {
        Some(policy) => Some(vault.set_free_time_policy_as(
            authority,
            agent,
            input.expected_revision,
            policy.clone(),
        )?),
        None => {
            vault.clear_free_time_policy_as(authority, agent, input.expected_revision)?;
            None
        }
    };
    Ok(policy_view(agent, row))
}

fn summary_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cycle: &FreeTimeCycle,
) -> Result<FreeTimeCycleSummary> {
    let (receipts, complete) = receipts_in_txn(vault, txn, cycle.agent, cycle.cycle)?;
    Ok(FreeTimeCycleSummary {
        cycle: cycle.cycle.to_hex(),
        state: cycle.state,
        policy_revision: cycle.policy_revision,
        total_units: cycle.total_units,
        period_start: cycle.period_start,
        boundary: cycle.boundary,
        next_boundary: cycle.next_boundary,
        opened_at: cycle.opened_at,
        closed_at: cycle.closed_at,
        floor: free_time_floor(cycle.agent, cycle.cycle, &receipts, complete),
        items_complete: complete,
        has_note: cycle.owner_note.is_some(),
    })
}

/// Reads one page of an agent's free-time cycles as the owner, newest
/// first, in one snapshot.
///
/// # Errors
/// A malformed agent id or cursor, a zero limit, a stale owner proof, a
/// cycle row that does not decode, and storage errors.
pub fn free_time_cycles_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &FreeTimeCyclesRequest,
) -> Result<FreeTimeCyclesPage> {
    let agent = entity("agent", &input.agent)?;
    let limit =
        owner_read_page_limit(input.limit).ok_or_else(|| invalid("limit must be positive"))?;
    let before = input
        .cursor
        .as_deref()
        .map(|cursor| {
            cursor
                .trim()
                .parse::<u64>()
                .map_err(|_| invalid("cursor is the next a previous page answered"))
        })
        .transpose()?;
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    let first = (agent, 0);
    let last = (agent, before.unwrap_or(u64::MAX));
    let end = if before.is_some() {
        Bound::Excluded(&last)
    } else {
        Bound::Included(&last)
    };
    let mut cycles: Vec<FreeTimeCycleSummary> = Vec::new();
    let mut next = None;
    for row in CYCLE.iter_rev_range(&vault.store, &txn, Bound::Included(&first), end)? {
        let (_, cycle) = row?;
        if cycles.len() >= limit {
            next = cycles.last().map(|summary| summary.boundary.to_string());
            break;
        }
        cycles.push(summary_in_txn(vault, &txn, &cycle)?);
    }
    Ok(FreeTimeCyclesPage {
        agent: agent.to_hex(),
        cycles,
        next,
    })
}

fn receipt_view(receipt: &FreeTimeItemReceipt) -> FreeTimeItemReceiptView {
    FreeTimeItemReceiptView {
        outcome: receipt.outcome,
        policy_revision: receipt.policy_revision,
        attempt: receipt.attempt.map(|attempt| bytes_to_hex_lower(&attempt)),
        proposal: receipt.proposal.map(|proposal| proposal.to_hex()),
        context_unread: receipt.context_unread.clone(),
        at: receipt.at,
    }
}

fn cycle_view_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cycle: FreeTimeCycle,
) -> Result<FreeTimeCycleView> {
    let (receipts, complete) = receipts_in_txn(vault, txn, cycle.agent, cycle.cycle)?;
    let mut items = Vec::with_capacity(cycle.items.len());
    for item in &cycle.items {
        let spend_scope = item
            .attempt
            .map(|attempt| {
                AttemptId::from_bytes(&attempt)
                    .map(|attempt| SpendScopeId::for_attempt(&attempt).to_string())
            })
            .transpose()?;
        items.push(FreeTimeItemView {
            item: item.item.to_hex(),
            kind: item.kind,
            purpose: label(item.kind),
            attempt: item.attempt.map(|attempt| bytes_to_hex_lower(&attempt)),
            spend_scope,
            receipt: receipts
                .iter()
                .find(|receipt| receipt.item == item.item)
                .map(receipt_view),
        });
    }
    Ok(FreeTimeCycleView {
        agent: cycle.agent.to_hex(),
        cycle: cycle.cycle.to_hex(),
        state: cycle.state,
        policy_revision: cycle.policy_revision,
        total_units: cycle.total_units,
        unit: LeaseUnit::tokens().as_str().to_owned(),
        pinned_split: cycle.pinned_split,
        period_start: cycle.period_start,
        boundary: cycle.boundary,
        next_boundary: cycle.next_boundary,
        opened_at: cycle.opened_at,
        closed_at: cycle.closed_at,
        root_scope: cycle.root_scope.to_string(),
        floor: free_time_floor(cycle.agent, cycle.cycle, &receipts, complete),
        items_complete: complete,
        items,
        note: cycle.owner_note.map(|note| FreeTimeNoteView {
            author: note.author.to_hex(),
            at: note.at,
            text: note.text,
        }),
        spend: FreeTimeSpendView::unmetered(),
    })
}

/// Reads one free-time cycle's sheet as the owner, in one snapshot; `None`
/// when the agent has no such cycle. Its spend is unmetered here: a server
/// joins its usage ledger's records in.
///
/// # Errors
/// A malformed agent or cycle id, a stale owner proof, a cycle row that does
/// not decode, and storage errors.
pub fn free_time_cycle_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &FreeTimeCycleRequest,
) -> Result<Option<FreeTimeCycleView>> {
    let agent = entity("agent", &input.agent)?;
    let wanted = entity("cycle", &input.cycle)?;
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    for row in CYCLE.iter_from(&vault.store, &txn, agent.as_bytes())? {
        let (_, cycle) = row?;
        if cycle.cycle == wanted {
            return cycle_view_in_txn(vault, &txn, cycle).map(Some);
        }
    }
    Ok(None)
}
