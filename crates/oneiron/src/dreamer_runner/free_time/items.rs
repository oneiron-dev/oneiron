//! A free-time cycle's items (FIX 4453): the binding each item's attempt
//! runs under, what it lands, and how it ends.
//!
//! The cycle stamps each item's binding in the commit that queues it; the
//! binding, never the model's words or the run's name, says which agent,
//! cycle, item and spend scope the work is. The for-human item lands its
//! suggestion as a Proposed claim of the agent's own, about its human when it
//! read its human's context (FIX 5663), and its note to its human; the
//! own-time item is the resident's dreaming, or rest when the agent chose
//! rest. Its real spend lands on its own scope under the cycle's root in the
//! commit that settles its wake reservation, and its terminal settles that
//! scope in the commit that ends it. An erase of the agent since the item
//! read lands none of its copies (FIX 5664): each writer rechecks the erase
//! in its own commit.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::cycle::{
    FreeTimeCycle, FreeTimeCycleState, FreeTimeItemRef, FreeTimeNote, FreeTimeOwnTimeChoice,
    enqueue_item_in_txn, round_item_id,
};
use super::receipt::{
    FreeTimeItemOutcome, FreeTimeItemReceipt, close_cycle_if_done_in_txn, record_receipt_in_txn,
};
use super::{CYCLE, FreeTimeKind, ITEM, LONG_RETRY_LINEAGE, RECEIPT};
use crate::agent_dispatch::{AgentDispatcher, SpendScopeId};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::{ClaimInput, ClaimSource, EdgeActorClass, EntityId, Error, Result, Vault};

/// The predicate an agent's free-time suggestion for its human lands under.
const SUGGESTION_PREDICATE: &str = "autonomy.suggestion";

/// What one item's attempt runs under, stamped by its cycle when it queued
/// the attempt. A retry reads the binding of the try it retries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreeTimeItemBinding {
    pub agent: EntityId,
    pub cycle: EntityId,
    /// Its cycle's boundary, which keys the cycle's row.
    pub boundary: u64,
    /// Where its cycle's period starts (Unix seconds): the records the item
    /// reads begin here.
    pub period_start: u64,
    pub item: EntityId,
    pub kind: FreeTimeKind,
    pub policy_revision: u64,
    /// The attempt its cycle queued.
    pub attempt: [u8; 16],
    /// The scope its spend lands on, under its cycle's root.
    pub spend_scope: SpendScopeId,
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("free-time item: {reason}"))
}

/// The payload input of an item its cycle queues: the resident, and the
/// cycle it belongs to.
pub(crate) fn free_time_item_input(resident: EntityId, cycle: EntityId) -> rmpv::Value {
    rmpv::Value::Map(vec![
        (
            rmpv::Value::from("resident"),
            rmpv::Value::Binary(resident.as_bytes().to_vec()),
        ),
        (
            rmpv::Value::from("cycle"),
            rmpv::Value::Binary(cycle.as_bytes().to_vec()),
        ),
    ])
}

/// Whether a payload input names a free-time cycle.
fn names_cycle(input: &rmpv::Value) -> bool {
    matches!(input, rmpv::Value::Map(entries)
        if entries.iter().any(|(key, _)| key.as_str() == Some("cycle")))
}

/// The runner line a free-time item reserves and settles on: its resident's
/// free-time line, never the pass's. Accounting only; the money meter is its
/// cycle's spend scope. `None` for any attempt no cycle queued.
pub(crate) fn free_time_line(record: &AttemptRecord) -> Option<String> {
    let payload = crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload).ok()?;
    if !names_cycle(&payload.input) {
        return None;
    }
    let resident = crate::dreamer_consolidation::resident_of_dream_input(&payload.input).ok()?;
    Some(format!("free_time/{}", resident.to_hex()))
}

/// Whether `record` is a free-time item's try, of either kind (FIX 6576):
/// the host timer arms one only when this node's admission takes it.
pub fn is_free_time_try(record: &AttemptRecord) -> bool {
    free_time_line(record).is_some()
}

/// `attempt`'s binding: its own, else the binding of the try it retries,
/// followed back to the chain's first try. A visited set stops a cycle,
/// never a count (FIX 7057): a chain of any length is walked to its end.
fn binding_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<Option<FreeTimeItemBinding>> {
    let queue = AttemptQueue::new(vault);
    let mut visited = BTreeSet::new();
    let mut cursor = attempt;
    loop {
        if !visited.insert(cursor) {
            return Err(invalid("the retry chain runs in a cycle"));
        }
        if visited.len() == LONG_RETRY_LINEAGE + 1 {
            tracing::warn!(
                kind = "retry_lineage_long",
                past = LONG_RETRY_LINEAGE,
                "free-time binding lookup walks an unusually long retry lineage"
            );
        }
        if let Some(binding) = ITEM.get(&vault.store, txn, &cursor)? {
            return Ok(Some(binding));
        }
        match queue.get_in_txn(txn, cursor)?.and_then(|row| row.retry_of) {
            Some(previous) => cursor = previous,
            None => return Ok(None),
        }
    }
}

impl Vault {
    /// The free-time binding `attempt` runs under (FIX 4453); `None` for an
    /// attempt no free-time cycle queued.
    ///
    /// # Errors
    /// A store read that fails, or a retry chain that runs in a cycle.
    pub fn free_time_item_binding(
        &self,
        attempt: AttemptId,
    ) -> Result<Option<FreeTimeItemBinding>> {
        let txn = self.store.env.read_txn()?;
        binding_in_txn(self, &txn, attempt)
    }
}

/// Whether `record` is a free-time item's try that was queued and never
/// started (FIX 5661): the one kind of free-time work a home move carries,
/// and the one a draining home holds back. A retry, or a try whose lease
/// was handed back, already started: it runs and settles where it is.
pub(crate) fn free_time_item_waits_unstarted(record: &AttemptRecord) -> bool {
    record.state == crate::attempt_queue::AttemptState::Queued
        && record.attempt_count == 0
        && record.retry_of.is_none()
        && free_time_line(record).is_some()
}

/// FIX 5661: whether `queue_kind`'s free-time items wait on this node. While
/// it drains its free-time rows toward a home move, or after it froze them
/// for one, C1's guard takes no new admission here: an item whose try never
/// started ([`free_time_item_waits_unstarted`]) stays queued and inert,
/// never cancelled, for the move to carry it to the new home, which queues
/// it again as itself. A try that already started, and other work of its
/// queue (a resident's nightly dreaming), are admitted as before.
#[cfg(feature = "sync")]
pub(crate) fn free_time_items_fenced_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    queue_kind: &str,
) -> Result<bool> {
    if queue_kind != crate::dreamer_runner::DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND
        && queue_kind != crate::dreamer_runner::DREAMER_RESIDENT_DREAM_ATTEMPT_KIND
    {
        return Ok(false);
    }
    let admits = crate::sync::home_handoff::takes_home_write_in_txn(
        vault,
        txn,
        crate::sync::home_handoff::HomeWrite::Admit,
    )?;
    Ok(!admits)
}

/// FIX 5661: whether this node still settles its free-time rows. An item
/// admitted before a move settles while its home drains; a home that froze
/// its rows for the move keeps them as history, and C1's guard takes no
/// settlement there.
#[cfg(feature = "sync")]
pub(super) fn settles_here_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    crate::sync::home_handoff::takes_home_write_in_txn(
        vault,
        txn,
        crate::sync::home_handoff::HomeWrite::Settle,
    )
}

/// Whether a resident's attempt runs as a free-time item.
pub(crate) enum FreeTimeItemRun {
    /// No cycle queued it: it runs as it always has.
    Unbound,
    /// Its cycle ended, or its item already has its receipt: it runs nothing.
    Done,
    /// It runs under this binding.
    Run(FreeTimeItemBinding),
}

/// What `resident`'s `attempt` runs as. Its binding must name `resident`.
pub(crate) fn free_time_item_to_run(
    vault: &Vault,
    attempt: AttemptId,
    resident: EntityId,
) -> Result<FreeTimeItemRun> {
    let txn = vault.store.env.read_txn()?;
    let Some(binding) = binding_in_txn(vault, &txn, attempt)? else {
        return Ok(FreeTimeItemRun::Unbound);
    };
    if binding.agent != resident {
        return Err(invalid("the binding names another agent"));
    }
    let open = CYCLE
        .get(&vault.store, &txn, &(binding.agent, binding.boundary))?
        .is_some_and(|cycle| cycle.state == FreeTimeCycleState::Open);
    if !open
        || RECEIPT.contains(
            &vault.store,
            &txn,
            &(binding.agent, binding.cycle, binding.item),
        )?
    {
        return Ok(FreeTimeItemRun::Done);
    }
    Ok(FreeTimeItemRun::Run(binding))
}

/// Records an own-time item's reflection in the commit that lands its diary
/// entry. The entry stays private; the receipt says only that it landed.
/// When the reply asked for another round, that round queues before the
/// cycle's close check runs, so the cycle stays open for it (FIX 7763).
pub(crate) fn record_own_time_landed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    binding: &FreeTimeItemBinding,
    another_round: bool,
    at: u64,
) -> Result<()> {
    let receipt = FreeTimeItemReceipt::of(binding, FreeTimeItemOutcome::Completed, None, at);
    if !record_receipt_in_txn(vault, txn, &receipt)? {
        return Ok(());
    }
    enqueue_round_if_asked_in_txn(vault, txn, binding, another_round, at)?;
    close_cycle_if_done_in_txn(vault, txn, binding.agent, binding.boundary, at)
}

/// Queues the dreaming's asked-for round of its own time (FIX 7763): one
/// more own-time item on what the allowance has left. Only while its cycle
/// is still open; what the root no longer covers queues nothing, and the
/// cycle closes as it did.
fn enqueue_round_if_asked_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    binding: &FreeTimeItemBinding,
    another_round: bool,
    now: u64,
) -> Result<()> {
    if !another_round {
        return Ok(());
    }
    let key = (binding.agent, binding.boundary);
    let Some(mut cycle) = CYCLE.get(&vault.store, txn, &key)? else {
        return Ok(());
    };
    if cycle.state != FreeTimeCycleState::Open {
        return Ok(());
    }
    // The round spends from what the root has left: a pinned share carves
    // again, so it queues only when the root still covers it.
    let available = AgentDispatcher::new(vault).available_units_in_txn(txn, &cycle.root_scope)?;
    let affords = match cycle.pinned_split {
        Some(split) => available >= split.own_time_units,
        None => available > 0,
    };
    if !affords {
        return Ok(());
    }
    cycle.own_time_rounds += 1;
    let item = round_item_id(cycle.cycle, cycle.own_time_rounds)?;
    let attempt = enqueue_item_in_txn(vault, txn, &cycle, FreeTimeKind::OwnTime, item, now)?;
    cycle.items.push(FreeTimeItemRef {
        item,
        kind: FreeTimeKind::OwnTime,
        attempt: Some(*attempt.as_bytes()),
    });
    CYCLE.put(&vault.store, txn, &key, &cycle)
}

/// What an agent's free time for its human came back with, from its reply's
/// block.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FreeTimeForHumanReply {
    /// One suggestion for its human. It lands as a proposal; nothing is
    /// applied.
    #[serde(default)]
    pub(crate) suggestion: Option<String>,
    /// Its short note to its human on what it got up to.
    #[serde(default)]
    pub(crate) note: Option<String>,
    /// What it chose for its own time.
    #[serde(default)]
    pub(crate) own_time: Option<FreeTimeOwnTimeChoice>,
}

/// What a for-human item read of its human's context (FIX 5663), for what
/// it lands: the human its suggestion is about when that context read, and
/// the code of a read that failed, noted on its receipt. The default is the
/// item as it ran before: about the agent, nothing noted.
#[derive(Debug, Clone, Default)]
pub(crate) struct FreeTimeForHumanContext {
    pub(crate) human: Option<EntityId>,
    pub(crate) unread: Option<String>,
}

/// Lands what an agent's free time for its human came back with (FIX 4453):
/// its suggestion as a Proposed claim of its own, then in one commit the
/// item's receipt (Completed only with a landed proposal, else Failed), its
/// note to its human and its choice for its own time. A choice of rest ends
/// the own-time item with no call, no spend and no text. `reply` is `None`
/// when the reply held no block. A replay lands nothing twice. `context` is
/// what the item read of its human's context: a read that failed is noted on
/// the receipt and fails nothing (FIX 5663).
///
/// # Errors
/// A store read or write that fails.
pub(crate) fn land_free_time_for_human(
    vault: &Vault,
    binding: &FreeTimeItemBinding,
    reply: Option<&FreeTimeForHumanReply>,
    context: &FreeTimeForHumanContext,
) -> Result<()> {
    let suggestion = reply
        .and_then(|reply| reply.suggestion.as_deref())
        .map(str::trim)
        .filter(|suggestion| !suggestion.is_empty());
    let proposal = match suggestion {
        Some(suggestion) => propose_suggestion(vault, binding, suggestion, context.human)?,
        None => None,
    };
    vault.with_write_txn_grouped(|txn| {
        let at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        let outcome = if proposal.is_some() {
            FreeTimeItemOutcome::Completed
        } else {
            FreeTimeItemOutcome::Failed
        };
        let mut receipt = FreeTimeItemReceipt::of(binding, outcome, proposal, at);
        receipt.context_unread.clone_from(&context.unread);
        // The receipt's writer rechecks the agent's erase (FIX 5664): an
        // erased agent records no receipt here, so no note or choice lands.
        if !record_receipt_in_txn(vault, txn, &receipt)? {
            return Ok(());
        }
        let key = (binding.agent, binding.boundary);
        let Some(mut cycle) = CYCLE.get(&vault.store, txn, &key)? else {
            return Ok(());
        };
        if let Some(reply) = reply {
            if cycle.owner_note.is_none()
                && let Some(text) = reply
                    .note
                    .as_deref()
                    .map(str::trim)
                    .filter(|text| !text.is_empty())
            {
                cycle.owner_note = Some(FreeTimeNote {
                    author: binding.agent,
                    at,
                    text: text.to_owned(),
                });
            }
            if cycle.own_time_choice.is_none() {
                cycle.own_time_choice = reply.own_time;
            }
        }
        // The note is the agent's own words, admitted at the side-row wall.
        // A note the wall refuses is dropped; the receipt and choice stand.
        let mut savepoint = vault.store.env.nested_write_txn(txn)?;
        match CYCLE.put(&vault.store, &mut savepoint, &key, &cycle) {
            Ok(()) => savepoint.commit()?,
            Err(error) => {
                drop(savepoint);
                tracing::warn!(
                    kind = ?error.kind(),
                    agent = %binding.agent.to_hex(),
                    "a free-time note was not admitted"
                );
                cycle.owner_note = None;
                CYCLE.put(&vault.store, txn, &key, &cycle)?;
            }
        }
        if cycle.own_time_choice == Some(FreeTimeOwnTimeChoice::Rest) {
            rest_in_txn(vault, txn, &cycle, at)?;
        }
        close_cycle_if_done_in_txn(vault, txn, binding.agent, binding.boundary, at)
    })
}

/// Proposes `suggestion` as the agent's own Generated claim, Proposed and
/// never applied, under one id per item so a replay proposes nothing twice.
/// It is about `human` when the item read its human's context (FIX 5663); a
/// proposal about its human that does not land is proposed about the agent,
/// as it was before. A refusal is logged and lands nothing: the item then has
/// no proposal.
fn propose_suggestion(
    vault: &Vault,
    binding: &FreeTimeItemBinding,
    suggestion: &str,
    human: Option<EntityId>,
) -> Result<Option<EntityId>> {
    let id = crate::codebase::entity_id_from_hash_material(
        b"oneiron:free_time:suggestion:v1",
        &[binding.item.as_bytes().as_slice()],
    )?;
    if vault.get_claim(&id)?.is_some() {
        return Ok(Some(id));
    }
    for subject in human.into_iter().chain(std::iter::once(binding.agent)) {
        if propose_about(vault, binding, id, suggestion, subject) {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

/// One proposal of the suggestion `id` about `subject`; whether it landed.
/// In the claim's own writer the agent must not be erased (FIX 5664): an
/// erase that removed it since the item read keeps no copy, and a call
/// already made settles as it did.
fn propose_about(
    vault: &Vault,
    binding: &FreeTimeItemBinding,
    id: EntityId,
    suggestion: &str,
    subject: EntityId,
) -> bool {
    let input = ClaimInput {
        id: Some(id.to_hex()),
        predicate: SUGGESTION_PREDICATE.to_owned(),
        subject_ref: subject.to_hex(),
        value: serde_json::Value::String(suggestion.to_owned()),
        confidence: 1.0,
        source: ClaimSource::Generated.as_str().to_owned(),
        world_ref: None,
        relationship_ref: None,
        scope: None,
        valid_from: None,
        valid_to: None,
        occurred_at: None,
        learned_at: None,
        salience: None,
        confidence_details: None,
    };
    let agent = binding.agent;
    let about_agent = subject == agent;
    match vault
        .memory(agent, EdgeActorClass::Agent)
        .claim_propose_guarded(&input, &|txn: &heed::RoTxn<'_>| {
            if crate::ports::removed_in_txn(&vault.store, txn, &agent)? {
                return Err(Error::EntityNotFound);
            }
            Ok(())
        }) {
        Ok(_) => true,
        Err(error) => {
            tracing::warn!(
                code = %error.code,
                agent = %agent.to_hex(),
                about_agent,
                "a free-time suggestion was not proposed"
            );
            false
        }
    }
}

/// Ends `cycle`'s own-time item Rested: the agent chose rest. Rest makes no
/// call and spends nothing, so an own-time item that already spent keeps
/// running to its own receipt.
fn rest_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    cycle: &FreeTimeCycle,
    at: u64,
) -> Result<()> {
    let Some(item) = cycle
        .items
        .iter()
        .find(|item| item.kind == FreeTimeKind::OwnTime)
    else {
        return Ok(());
    };
    if let Some(attempt) = item.attempt
        && AgentDispatcher::new(vault)
            .attempt_spend_scope_in_txn(txn, AttemptId::from_bytes(&attempt)?)?
            .is_some_and(|scope| scope.spent_units > 0)
    {
        return Ok(());
    }
    record_receipt_in_txn(
        vault,
        txn,
        &FreeTimeItemReceipt {
            agent: cycle.agent,
            cycle: cycle.cycle,
            item: item.item,
            kind: FreeTimeKind::OwnTime,
            policy_revision: cycle.policy_revision,
            outcome: FreeTimeItemOutcome::Rested,
            attempt: item.attempt,
            proposal: None,
            context_unread: None,
            at,
        },
    )?;
    Ok(())
}

/// Lands a free-time item's real spend on its own scope under its cycle's
/// root (FIX 4453), in the commit that settles its wake reservation: that
/// reservation is the key, so a replay that finds it gone records nothing
/// twice. Spend already made is recorded whole. A no-op for any attempt no
/// cycle queued.
pub(crate) fn charge_free_time_item_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    units: u64,
) -> Result<()> {
    if units == 0 {
        return Ok(());
    }
    let Some(binding) = binding_in_txn(vault, txn, attempt)? else {
        return Ok(());
    };
    #[cfg(feature = "sync")]
    if !settles_here_in_txn(vault, txn)? {
        tracing::warn!(
            agent = %binding.agent.to_hex(),
            units,
            "a free-time item's spend landed after its home froze its rows for a move"
        );
        return Ok(());
    }
    AgentDispatcher::new(vault).record_guard_spend_in_txn(txn, &binding.spend_scope, units)?;
    Ok(())
}

/// Ends a free-time item at its attempt's terminal (FIX 4453), in the commit
/// that ends it: its scope settles into its cycle's root and gives back what
/// it held, and an item that ended without its receipt takes `outcome`,
/// never a success. A no-op for any attempt no cycle queued.
pub(crate) fn end_free_time_item_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
    outcome: FreeTimeItemOutcome,
    now: u64,
) -> Result<()> {
    if record.kind != crate::dreamer_runner::DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND
        && record.kind != crate::dreamer_runner::DREAMER_RESIDENT_DREAM_ATTEMPT_KIND
    {
        return Ok(());
    }
    let Some(binding) = binding_in_txn(vault, txn, record.id)? else {
        return Ok(());
    };
    // A home that froze its free-time rows for a move keeps them, and the
    // scope its item spends under, as history (FIX 5661).
    #[cfg(feature = "sync")]
    if !settles_here_in_txn(vault, txn)? {
        tracing::warn!(
            agent = %binding.agent.to_hex(),
            "a free-time item ended after its home froze its rows for a move"
        );
        return Ok(());
    }
    AgentDispatcher::new(vault).settle_child_in_txn(txn, &record.id, now)?;
    let receipt = FreeTimeItemReceipt::of(&binding, outcome, None, now);
    if record_receipt_in_txn(vault, txn, &receipt)? {
        close_cycle_if_done_in_txn(vault, txn, binding.agent, binding.boundary, now)?;
    }
    Ok(())
}
