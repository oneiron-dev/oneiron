//! Effects of a handed-over run's replayed steps (FIX 4747 slice 7; canon
//! ARCH-0023b "pending outbound send", owner RULING A with the fence-first
//! amendment: "Uncertain: check by an engine-stamped id on every outbound
//! send ... Still unknown: ask the owner before any retry. Effect-free
//! steps: rerun. Never a blind retry.").
//!
//! A run handed over reruns from its frozen payload under the same try id
//! (`super::run_handover`), so a replayed step's outbound call derives the
//! same engine-stamped intent id on the taker
//! (`outbound_intent_ledger::derive_intent_id`). The intent ledger is
//! device-local, so the taker holds no row of an effect the old machine
//! started. The run TASK carries what the taker needs instead: one
//! [`AgentRunEffectMark`] per effect the run started, its intent id, the
//! lease generation that started it, whether its provider dedupes it, and
//! whether its ledger row settled. Ids and flags only, never a body.
//!
//! - **Marks are written** in the admission writer that commits an effect's
//!   Pending ledger row for a run that has a run TASK
//!   ([`record_agent_run_effect_mark_in_txn`], from
//!   `outbound_chokepoint::execute_outbound_effect`), at the generation that
//!   writer read this machine holding. Past [`AGENT_RUN_EFFECT_MARKS_MAX`]
//!   the run mints no mark and its next effect is refused with
//!   [`AGENT_RUN_EFFECT_MARKS_FULL`], so nothing goes unrecorded.
//! - **Marks settle** in the writer that settles that ledger row
//!   ([`settle_agent_run_effect_mark_in_txn`], from the ledger's
//!   transitions), while this machine holds the run.
//! - **The taker meets a mark** at the same admission, for an effect with no
//!   local ledger row ([`admit_agent_run_effect_in_txn`]): one an earlier
//!   generation marked goes again only when both its call and its mark are
//!   idempotent (the frozen key reaches the provider, which dedupes it);
//!   otherwise it does not go and the owner is asked once, in the same
//!   writer. His resend releases it once; his leave makes the call answer
//!   [`AGENT_RUN_EFFECT_ELSEWHERE`] to the step, which goes on without it.
//! - **Effect-free steps rerun**: model calls never reach the chokepoint,
//!   and a read-only tool call is never marked or asked about.
//!
//! The owner answers through `vault.agent.run_effect.answer`
//! ([`Vault::answer_agent_run_effect`]). A run that never moved meets only
//! its own marks, at its own generation, and runs as before.
//! Entry: `admit_agent_run_effect_in_txn`, `Vault::answer_agent_run_effect`.

use std::collections::HashMap;
use std::sync::PoisonError;

use serde::{Deserialize, Serialize};

use super::run_task::{
    AGENT_RUN_EXECUTOR_MOVED, AgentRunExecutorLease, AgentRunTaskBody,
    agent_run_fence_permits_effect, agent_run_task_body_in, agent_run_task_of_attempt_in,
    update_agent_run_task_body_in_txn,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::derived_domains::AGENT_RUN_SEND_TASK;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::outbound_intent_ledger::{
    IntentId, IntentLedgerRecord, IntentState, RecordedOutboundOutcome,
};
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::store::verb_invocation::InvocationId;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The most effect marks one run TASK carries (FIX 4747 slice 7). Engine
/// call (CALLS, FIX 4747): 512, under 60 KB of ids on the synced TASK. Past
/// it the run mints no mark, and the admission of its next effect refuses
/// it with [`AGENT_RUN_EFFECT_MARKS_FULL`], so no effect goes unrecorded.
pub(crate) const AGENT_RUN_EFFECT_MARKS_MAX: usize = 512;

/// The reason a call a replayed step makes holds with while it waits for the
/// owner's answer: an earlier executor of its run may have made it.
pub(crate) const AGENT_RUN_EFFECT_UNCONFIRMED: &str = "agent_run_effect_unconfirmed";

/// The typed result a replayed step's call answers once the owner left it:
/// the effect may have happened on the machine that ran the run before, and
/// it is not made again. It names no body.
pub(crate) const AGENT_RUN_EFFECT_ELSEWHERE: &str = "effect_may_have_happened_elsewhere";

/// The refusal an effect gets when its run's TASK carries
/// [`AGENT_RUN_EFFECT_MARKS_MAX`] marks.
pub(crate) const AGENT_RUN_EFFECT_MARKS_FULL: &str = "agent_run_effect_marks_full";

/// Producer name of a replayed effect's owner ask.
pub(crate) const AGENT_RUN_EFFECT_NOTIFICATION_PRODUCER: &str = "agent.run_effect";

/// The verb the ask's taps call.
pub(crate) const AGENT_RUN_EFFECT_ANSWER_VERB: &str = "vault.agent.run_effect.answer";

/// One outbound effect an agent run's step started, as its run TASK records
/// it for every machine (FIX 4747 slice 7).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct AgentRunEffectMark {
    /// The effect's engine-stamped intent id, 64 lower hex: replay-stable
    /// for the same try, call, server, tool and frozen bytes.
    pub(super) intent_id: String,
    /// The executor lease generation whose admission marked it last.
    pub(super) generation: u64,
    /// Whether that call's frozen idempotency key reaches its provider, which
    /// then dedupes a resend under it.
    pub(super) idempotent: bool,
    /// Whether the marking machine's ledger row of it settled: delivered,
    /// failed for certain, or stopped.
    pub(super) settled: bool,
    /// The owner's ask a taker raised on it, and his answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) owner_ask: Option<AgentRunEffectAsk>,
}

/// The owner's ask on one marked effect a replayed step meets (FIX 4747
/// slice 7).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct AgentRunEffectAsk {
    /// When the ask was raised, vault clock seconds: part of its identity.
    pub(super) asked_at: u64,
    /// The owner's answer; `None` while it waits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) answer: Option<AgentRunEffectChoice>,
}

/// The owner's answer on one marked effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentRunEffectChoice {
    /// The effect goes once more, under the same intent id.
    Resend,
    /// The effect is not made again; the step reads that it may have
    /// happened elsewhere.
    Leave,
}

/// What the owner's answer to a replayed effect's ask came to (FIX 4747
/// slice 7).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentRunEffectAnswerOutcome {
    /// The effect goes once more, at the run's next pass over it.
    ResendReleased,
    /// The effect is not made again: the step reads that it may have
    /// happened elsewhere.
    Left,
    /// An earlier answer settled the ask, or no ask waits on that effect:
    /// this answer changed nothing.
    AlreadySettled,
}

/// One outbound call an agent run's step makes, as the chokepoint meets it
/// (FIX 4747 slice 7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AgentRunEffectCall {
    /// The run's try, the attempt the agent pump leased.
    pub(crate) run: AttemptId,
    /// The call's tool declares itself read-only: an effect-free step.
    pub(crate) read_only: bool,
    /// The call's frozen idempotency key reaches its provider.
    pub(crate) idempotent: bool,
}

/// This machine's holding of an effect's run, as the admission writer read
/// it: what the Pending insert in that writer marks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AgentRunEffectHolding {
    task_ref: EntityId,
    run: AttemptId,
    generation: u64,
    idempotent: bool,
}

/// Why an agent run's effect did not go (FIX 4747 slice 7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AgentRunEffectStop {
    /// Another machine holds the run, or its run TASK does not read: this
    /// machine starts nothing.
    StoodDown,
    /// An earlier executor of the run may have made this effect; it waits
    /// for the owner's answer.
    AwaitsOwner,
    /// The owner left it: the step reads that it may have happened
    /// elsewhere.
    LeftByOwner,
    /// The run's TASK carries [`AGENT_RUN_EFFECT_MARKS_MAX`] marks.
    MarksFull,
}

impl AgentRunEffectStop {
    /// The reason the call names.
    #[must_use]
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::StoodDown => super::run_task::AGENT_RUN_STOOD_DOWN,
            Self::AwaitsOwner => AGENT_RUN_EFFECT_UNCONFIRMED,
            Self::LeftByOwner => AGENT_RUN_EFFECT_ELSEWHERE,
            Self::MarksFull => AGENT_RUN_EFFECT_MARKS_FULL,
        }
    }
}

/// What the admission of one agent run's effect came to (FIX 4747 slice 7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AgentRunEffectAdmission {
    /// The run has no run TASK, the call is read-only, or the run settled:
    /// the effect goes as before, unmarked.
    Unmarked,
    /// The effect goes, marked at this holding in the writer that commits
    /// its Pending row.
    Marked(AgentRunEffectHolding),
    /// The effect does not go. `commit` when the writer raised the owner's
    /// ask and owes its commit.
    Stopped {
        stop: AgentRunEffectStop,
        commit: bool,
    },
}

/// The run TASK and try of one effect this process marked, until its ledger
/// row settles for good.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AgentRunEffectSite {
    task_ref: EntityId,
    run: AttemptId,
}

/// The effects this process marked, by intent id: what the ledger's settling
/// writer reads to find the run TASK it sets settled on. In memory only.
pub(crate) type AgentRunEffectSites = HashMap<IntentId, AgentRunEffectSite>;

/// What a replayed step's effect does at its admission when its run TASK
/// already marks its intent id and this machine holds no ledger row of it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplayedEffect {
    /// It goes, marked again at this generation.
    Goes,
    /// It does not go; the owner is asked now.
    AsksOwner,
    /// It does not go; the owner's ask waits.
    AwaitsOwner,
    /// It does not go; the owner left it.
    Left,
}

/// What a replayed step's effect does when its run TASK marks its intent id
/// (FIX 4747 slice 7; canon ARCH-0023b "never a blind retry"). Engine call
/// (CALLS, FIX 4747):
///
/// - a mark of this generation or a later one is not an earlier executor's:
///   the effect goes, and the ledger decides as before;
/// - the owner's answer decides once given: resend goes once, leave never;
/// - with no answer, the effect goes again only when its call and its mark
///   are both idempotent, so the provider dedupes it under the same frozen
///   key, settled or not;
/// - any other effect, a settled one included, waits for the owner: asked
///   once, the first time it is met.
fn replayed_effect_step(
    mark: &AgentRunEffectMark,
    generation: u64,
    idempotent: bool,
) -> ReplayedEffect {
    if mark.generation >= generation {
        return ReplayedEffect::Goes;
    }
    match mark.owner_ask {
        Some(AgentRunEffectAsk {
            answer: Some(AgentRunEffectChoice::Resend),
            ..
        }) => ReplayedEffect::Goes,
        Some(AgentRunEffectAsk {
            answer: Some(AgentRunEffectChoice::Leave),
            ..
        }) => ReplayedEffect::Left,
        _ if idempotent && mark.idempotent => ReplayedEffect::Goes,
        Some(AgentRunEffectAsk { answer: None, .. }) => ReplayedEffect::AwaitsOwner,
        None => ReplayedEffect::AsksOwner,
    }
}

/// The generation at which this machine holds the run of the try `run`,
/// whose run TASK reads as `body`, in `txn`: the fence its claim took while
/// the run is on this host, else the TASK's own lease while it names this
/// machine. `None` while another machine holds it. Engine call (CALLS, FIX
/// 4747): a run parked off the host (a held call the connector settler
/// resumes) holds by its TASK's lease, expired or not, as no other machine
/// took it; only a claim takes a new generation.
fn holding_generation_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    run: AttemptId,
    body: &AgentRunTaskBody,
) -> Result<Option<u64>> {
    if let Some(fence) = vault.agent_run_fence(run) {
        return Ok(fence.holds(body.executor).then_some(fence.generation));
    }
    let Some(node_id) = crate::identity::read_client_id_in_txn(vault, txn)? else {
        return Ok(None);
    };
    Ok((body.executor.node_id == node_id).then_some(body.executor.generation))
}

/// The one local log line an effect's stand-down writes: the run TASK and
/// the lease it holds now, `None` when it does not read. It names no body.
fn log_effect_stand_down(task_ref: EntityId, held: Option<AgentRunExecutorLease>) {
    tracing::warn!(
        reason = AGENT_RUN_EXECUTOR_MOVED,
        task = %task_ref.to_hex(),
        held_node_id = ?held.map(|lease| lease.node_id),
        held_generation = ?held.map(|lease| lease.generation),
        "an agent run's effect stood down: this machine does not hold its run TASK"
    );
}

/// Admits one outbound effect of an agent run in the writer that would
/// commit its Pending ledger row, `wtxn`, for an effect this machine holds
/// no ledger row of (FIX 4747 slice 7). `intent_id` is its engine-stamped
/// id; `server` and `tool` name it in the owner's ask, never its body.
///
/// A run with no run TASK, a read-only call and a settled run go unmarked,
/// as before. A run this machine does not hold, or whose run TASK does not
/// read, starts nothing. A new effect goes and is marked by the Pending
/// insert ([`record_agent_run_effect_mark_in_txn`]), unless the run carries
/// [`AGENT_RUN_EFFECT_MARKS_MAX`] marks. An effect an earlier generation
/// marked goes as [`replayed_effect_step`] rules; one that waits for the
/// owner raises his ask once, in this writer.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn admit_agent_run_effect_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    call: AgentRunEffectCall,
    intent_id: &IntentId,
    server: &str,
    tool: &str,
) -> Result<AgentRunEffectAdmission> {
    let stopped = |stop| AgentRunEffectAdmission::Stopped {
        stop,
        commit: false,
    };
    let Some(task_ref) = agent_run_task_of_attempt_in(vault, &*wtxn, call.run)? else {
        return Ok(AgentRunEffectAdmission::Unmarked);
    };
    let body = match agent_run_task_body_in(vault, &*wtxn, task_ref) {
        Ok(Some(body)) => body,
        Ok(None) => return Ok(AgentRunEffectAdmission::Unmarked),
        Err(Error::Record(_)) => {
            log_effect_stand_down(task_ref, None);
            return Ok(stopped(AgentRunEffectStop::StoodDown));
        }
        Err(error) => return Err(error),
    };
    let Some(generation) = holding_generation_in(vault, &*wtxn, call.run, &body)? else {
        log_effect_stand_down(task_ref, Some(body.executor));
        return Ok(stopped(AgentRunEffectStop::StoodDown));
    };
    if call.read_only || body.outcome.is_some() {
        return Ok(AgentRunEffectAdmission::Unmarked);
    }
    let holding = AgentRunEffectHolding {
        task_ref,
        run: call.run,
        generation,
        idempotent: call.idempotent,
    };
    let intent = bytes_to_hex_lower(intent_id);
    let Some(mark) = body.effects.iter().find(|mark| mark.intent_id == intent) else {
        if body.effects.len() >= AGENT_RUN_EFFECT_MARKS_MAX {
            tracing::warn!(
                reason = AGENT_RUN_EFFECT_MARKS_FULL,
                task = %task_ref.to_hex(),
                marks = body.effects.len(),
                "an agent run's effect was refused: its run TASK carries the most effect marks"
            );
            return Ok(stopped(AgentRunEffectStop::MarksFull));
        }
        return Ok(AgentRunEffectAdmission::Marked(holding));
    };
    Ok(
        match replayed_effect_step(mark, generation, call.idempotent) {
            ReplayedEffect::Goes => AgentRunEffectAdmission::Marked(holding),
            ReplayedEffect::Left => stopped(AgentRunEffectStop::LeftByOwner),
            ReplayedEffect::AwaitsOwner => stopped(AgentRunEffectStop::AwaitsOwner),
            ReplayedEffect::AsksOwner => {
                let settled = mark.settled;
                ask_owner_in_txn(vault, wtxn, task_ref, &intent, settled, server, tool)?;
                AgentRunEffectAdmission::Stopped {
                    stop: AgentRunEffectStop::AwaitsOwner,
                    commit: true,
                }
            }
        },
    )
}

/// Marks the effect `intent_id` on its run's TASK at `holding`, in the
/// admission writer that commits its Pending ledger row (FIX 4747 slice 7):
/// a new effect is appended; one an earlier generation marked is marked
/// again at this generation, unsettled, and the owner's resend it spends,
/// or an ask its idempotent call no longer needs, goes. The run TASK and
/// try are kept in memory for the writer that settles the row.
///
/// # Errors
///
/// Storage errors; a run TASK that no longer reads in this writer.
pub(crate) fn record_agent_run_effect_mark_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    holding: AgentRunEffectHolding,
    intent_id: &IntentId,
) -> Result<()> {
    let now = vault.store.clock.now_recorded_at();
    let intent = bytes_to_hex_lower(intent_id);
    let mut spent_ask = None;
    update_agent_run_task_body_in_txn(vault, wtxn, holding.task_ref, now, |body| {
        match body
            .effects
            .iter_mut()
            .find(|mark| mark.intent_id == intent)
        {
            Some(mark) if mark.generation < holding.generation => {
                spent_ask = mark
                    .owner_ask
                    .filter(|ask| ask.answer.is_none())
                    .map(|ask| ask.asked_at);
                mark.generation = holding.generation;
                mark.idempotent = holding.idempotent;
                mark.settled = false;
                mark.owner_ask = None;
            }
            Some(_) => {}
            None if body.effects.len() >= AGENT_RUN_EFFECT_MARKS_MAX => {
                return Err(Error::InvariantViolation(
                    "agent run effect marks filled inside the admission writer",
                ));
            }
            None => body.effects.push(AgentRunEffectMark {
                intent_id: intent.clone(),
                generation: holding.generation,
                idempotent: holding.idempotent,
                settled: false,
                owner_ask: None,
            }),
        }
        Ok(())
    })?;
    if let Some(asked_at) = spent_ask {
        clear_agent_run_effect_ask_in_txn(vault, wtxn, holding.task_ref, &intent, asked_at)?;
    }
    vault.keep_agent_run_effect_site(
        *intent_id,
        AgentRunEffectSite {
            task_ref: holding.task_ref,
            run: holding.run,
        },
    );
    Ok(())
}

/// Whether the ledger row `record` settled its effect, for the run TASK's
/// mark (FIX 4747 slice 7). Engine call (CALLS, FIX 4747): delivered (Done),
/// stopped (Abandoned), or a definite non-delivery recorded on its Pending
/// row; a Deferred row's outcome is still out, and a row a retry reopened
/// is unsettled again.
fn agent_run_effect_settled(record: &IntentLedgerRecord) -> bool {
    matches!(record.state, IntentState::Done | IntentState::Abandoned)
        || record.recorded_outcome == Some(RecordedOutboundOutcome::DefiniteNonDelivery)
}

/// Sets the mark of the effect `record` settles on its run's TASK, in the
/// ledger writer that settles the row, `wtxn` (FIX 4747 slice 7): only for
/// an effect this process marked, and only while this machine holds the
/// run, in a savepoint. It never fails the ledger's write: a mark that does
/// not write is logged, and the mark stays as it was.
pub(crate) fn settle_agent_run_effect_mark_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &IntentLedgerRecord,
) {
    let Some(site) = vault.agent_run_effect_site(&record.id) else {
        return;
    };
    if let Err(error) = settle_mark_in_txn(
        vault,
        wtxn,
        site,
        &record.id,
        agent_run_effect_settled(record),
    ) {
        tracing::warn!(
            task = %site.task_ref.to_hex(),
            kind = ?error.kind(),
            "an agent run's effect mark was not settled; the mark stays as it was"
        );
    }
    if matches!(record.state, IntentState::Done | IntentState::Abandoned) {
        vault.forget_agent_run_effect_site(&record.id);
    }
}

/// [`settle_agent_run_effect_mark_in_txn`]'s write, in a savepoint of `wtxn`.
fn settle_mark_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    site: AgentRunEffectSite,
    intent_id: &IntentId,
    settled: bool,
) -> Result<()> {
    let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
    let Some(body) = agent_run_task_body_in(vault, &savepoint, site.task_ref)? else {
        return Ok(());
    };
    // Only the run's holder writes its TASK, so an old executor's settle
    // never writes back a lease another machine took since.
    if holding_generation_in(vault, &savepoint, site.run, &body)?.is_none() {
        return Ok(());
    }
    let intent = bytes_to_hex_lower(intent_id);
    if !body
        .effects
        .iter()
        .any(|mark| mark.intent_id == intent && mark.settled != settled)
    {
        return Ok(());
    }
    let now = vault.store.clock.now_recorded_at();
    update_agent_run_task_body_in_txn(vault, &mut savepoint, site.task_ref, now, |body| {
        for mark in body
            .effects
            .iter_mut()
            .filter(|mark| mark.intent_id == intent)
        {
            mark.settled = settled;
        }
        Ok(())
    })?;
    savepoint.commit()?;
    Ok(())
}

/// What a fresh read of an effect's run says of this machine, for
/// [`agent_run_effect_permitted`].
enum EffectStanding {
    /// No run TASK stands: the effect goes as before.
    NoRunTask,
    /// This machine holds the run.
    Holds,
    /// Another machine holds it (the lease it holds), or its run TASK does
    /// not read (`None`).
    StandsDown(EntityId, Option<AgentRunExecutorLease>),
}

/// Whether the transport call of an effect the agent run try `run` makes
/// may start (FIX 4747 slices 5, 7), read in a fresh read right before it:
/// the fence its claim took while the run is on this host, else the run
/// TASK's own lease while it names this machine (a held call the connector
/// settler resumes while its run is parked). A try with no run TASK goes as
/// before; a run TASK that does not read, or another machine's lease,
/// stands the call down, logged.
#[must_use]
pub(crate) fn agent_run_effect_permitted(vault: &Vault, run: AttemptId) -> bool {
    if let Some(fence) = vault.agent_run_fence(run) {
        return agent_run_fence_permits_effect(vault, &fence);
    }
    match effect_standing(vault, run) {
        Ok(EffectStanding::NoRunTask | EffectStanding::Holds) => true,
        Ok(EffectStanding::StandsDown(task_ref, held)) => {
            log_effect_stand_down(task_ref, held);
            false
        }
        Err(error) => {
            tracing::warn!(
                reason = AGENT_RUN_EXECUTOR_MOVED,
                kind = ?error.kind(),
                "an agent run's effect stood down: its run TASK could not be read"
            );
            false
        }
    }
}

/// [`agent_run_effect_permitted`]'s fresh read, for a run with no fence on
/// this host.
fn effect_standing(vault: &Vault, run: AttemptId) -> Result<EffectStanding> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(task_ref) = agent_run_task_of_attempt_in(vault, &rtxn, run)? else {
        return Ok(EffectStanding::NoRunTask);
    };
    match agent_run_task_body_in(vault, &rtxn, task_ref) {
        Ok(Some(body)) => Ok(
            if holding_generation_in(vault, &rtxn, run, &body)?.is_some() {
                EffectStanding::Holds
            } else {
                EffectStanding::StandsDown(task_ref, Some(body.executor))
            },
        ),
        Ok(None) => Ok(EffectStanding::NoRunTask),
        Err(Error::Record(_)) => Ok(EffectStanding::StandsDown(task_ref, None)),
        Err(error) => Err(error),
    }
}

/// The connector-send TASK id a schedule made by the agent run try `run`
/// takes (FIX 4747 slice 7), read in `txn`: derived from the try's id, the
/// verb call's invocation (its run step and place, the same when a taker
/// replays the step under the same try id), and the send's channel, verb
/// and target, so a replay on another machine finds the TASK the old
/// machine created, synced, instead of minting a second. Engine call (CALLS,
/// FIX 4747): the content ref is not part of it, as a rerun step drafts its
/// body anew. `None` for a try with no run TASK, which cannot move, and for
/// a call that carries no invocation: such a schedule mints a fresh id as
/// before.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn agent_run_send_task_id_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    run: AttemptId,
    invocation: Option<InvocationId>,
    channel: &str,
    verb: &str,
    target: &str,
) -> Result<Option<EntityId>> {
    let Some(invocation) = invocation else {
        return Ok(None);
    };
    if agent_run_task_of_attempt_in(vault, txn, run)?.is_none() {
        return Ok(None);
    }
    EntityId::derive(
        AGENT_RUN_SEND_TASK,
        &[
            run.as_bytes(),
            &invocation.0,
            channel.as_bytes(),
            verb.as_bytes(),
            target.as_bytes(),
        ],
    )
    .map(Some)
}

/// The ask's identity for `owner`: the run TASK, the effect, when it was
/// asked, the owner.
fn agent_run_effect_ask_source(
    task_ref: EntityId,
    intent: &str,
    asked_at: u64,
    owner: EntityId,
) -> NotificationSource {
    NotificationSource {
        producer: AGENT_RUN_EFFECT_NOTIFICATION_PRODUCER.to_owned(),
        event: format!(
            "{}:{intent}:{asked_at}:{}",
            task_ref.to_hex(),
            owner.to_hex()
        ),
        result: Some(task_ref.to_hex()),
        ..NotificationSource::default()
    }
}

/// The run TASK and effect intent id an ask of this producer names, read
/// from its `result` and `event`; `None` for any other shape.
pub(crate) fn agent_run_effect_ask_target(
    source: &NotificationSource,
) -> Option<(EntityId, String)> {
    let task_ref = EntityId::from_hex(source.result.as_deref()?).ok()?;
    let mut parts = source.event.split(':');
    if parts.next()? != task_ref.to_hex() {
        return None;
    }
    let intent = parts.next()?;
    (intent.len() == 64 && intent.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| (task_ref, intent.to_owned()))
}

/// The ask's words: the server and tool the call names and what is known
/// of the earlier executor's try, never the call's body. Engine call (CALLS,
/// FIX 4747): `settled` says that machine recorded how it ended, which this
/// machine cannot read.
fn agent_run_effect_ask_detail(server: &str, tool: &str, settled: bool) -> String {
    let known = if settled {
        "That machine recorded how the call ended, but this machine cannot read it."
    } else {
        "How that call ended is not known here."
    };
    format!(
        "An agent run moved to this machine and replays a step that calls \"{tool}\" on \"{server}\". The machine that ran it before may already have made this call. {known} Make the call again, or leave it?"
    )
}

/// Raises the owner's ask on the marked effect `intent` of the run TASK
/// `task_ref`, in the admission writer (FIX 4747 slice 7): the mark records
/// the ask, and one inbox Ask per live owner names the server and tool,
/// never the body.
fn ask_owner_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    intent: &str,
    settled: bool,
    server: &str,
    tool: &str,
) -> Result<()> {
    let asked_at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    update_agent_run_task_body_in_txn(vault, wtxn, task_ref, asked_at, |body| {
        if let Some(mark) = body
            .effects
            .iter_mut()
            .find(|mark| mark.intent_id == intent)
        {
            mark.owner_ask = Some(AgentRunEffectAsk {
                asked_at,
                answer: None,
            });
        }
        Ok(())
    })?;
    let detail = agent_run_effect_ask_detail(server, tool, settled);
    for owner in crate::policy_model::owners_in_txn(vault, &*wtxn)? {
        vault.record_notification_in_txn(
            wtxn,
            &NotificationEvent {
                kind: NotificationKind::Ask,
                source: NotificationSource {
                    detail: Some(detail.clone()),
                    ..agent_run_effect_ask_source(task_ref, intent, asked_at, owner)
                },
                subject_refs: vec![task_ref],
                recipient: Some(owner),
                created_at: asked_at,
                origin_conversation: None,
            },
        )?;
    }
    Ok(())
}

/// Marks the ask raised at `asked_at` on the effect `intent` seen and acked
/// for each live owner, in the caller's write: an answered or spent ask
/// offers no tap any more.
fn clear_agent_run_effect_ask_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    intent: &str,
    asked_at: u64,
) -> Result<()> {
    for owner in crate::policy_model::owners_in_txn(vault, &*wtxn)? {
        let ask = crate::inbox::notification_id(&agent_run_effect_ask_source(
            task_ref, intent, asked_at, owner,
        ))?;
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(&vault.store, &*wtxn, &ask)?
        else {
            continue;
        };
        if entity_type != ENTITY_TYPE_NOTIFICATION {
            continue;
        }
        let mut body = crate::inbox::decode_notification_body(&body)?;
        let Some(recipient) = body.recipient.clone() else {
            continue;
        };
        if body.acked_by.get(&recipient) == Some(&true) {
            continue;
        }
        body.seen_by.insert(recipient.clone(), true);
        body.acked_by.insert(recipient, true);
        vault.put_notification_in_txn(wtxn, &ask, &body)?;
    }
    Ok(())
}

impl Vault {
    /// The owner's answer to the ask a replayed step's effect raised (FIX
    /// 4747 slice 7): `resend` releases the effect `intent_id` of the run
    /// TASK `task_ref` for one more call under the same intent id, which the
    /// run makes at its next pass over the held call; no resend leaves it,
    /// and the call answers the step that it may have happened elsewhere.
    /// The proof is the vault owner's, rechecked in the writer; the first
    /// answer settles the ask and clears its rows, and a later one finds it
    /// settled. A committed answer wakes the connector-call settler.
    ///
    /// # Errors
    ///
    /// A proof that is not a live owner's; a run TASK that does not read.
    pub fn answer_agent_run_effect(
        &self,
        owner: &AuthenticatedOwner,
        task_ref: EntityId,
        intent_id: IntentId,
        resend: bool,
    ) -> Result<AgentRunEffectAnswerOutcome> {
        let intent = bytes_to_hex_lower(&intent_id);
        let outcome = self.with_write_txn_grouped(|wtxn| {
            owner.revalidate_in_txn(self, &*wtxn)?;
            let now = crate::ports::recorded_at_in_txn(&self.store, wtxn)?;
            let Some(body) = agent_run_task_body_in(self, &*wtxn, task_ref)? else {
                return Ok(AgentRunEffectAnswerOutcome::AlreadySettled);
            };
            let Some(ask) = body
                .effects
                .iter()
                .find(|mark| mark.intent_id == intent)
                .and_then(|mark| mark.owner_ask)
                .filter(|ask| ask.answer.is_none())
            else {
                return Ok(AgentRunEffectAnswerOutcome::AlreadySettled);
            };
            let answer = if resend {
                AgentRunEffectChoice::Resend
            } else {
                AgentRunEffectChoice::Leave
            };
            update_agent_run_task_body_in_txn(self, wtxn, task_ref, now, |body| {
                if let Some(ask) = body
                    .effects
                    .iter_mut()
                    .find(|mark| mark.intent_id == intent)
                    .and_then(|mark| mark.owner_ask.as_mut())
                {
                    ask.answer = Some(answer);
                }
                Ok(())
            })?;
            clear_agent_run_effect_ask_in_txn(self, wtxn, task_ref, &intent, ask.asked_at)?;
            Ok(if resend {
                AgentRunEffectAnswerOutcome::ResendReleased
            } else {
                AgentRunEffectAnswerOutcome::Left
            })
        })?;
        // The held call the effect waits in goes again at the settler's next
        // pass, without waiting for its backoff.
        if outcome != AgentRunEffectAnswerOutcome::AlreadySettled {
            self.notify_consent_answer();
        }
        Ok(outcome)
    }

    /// Whether the effect `intent` of the run TASK `task_ref` waits for the
    /// owner's answer now, read in `txn`: the inbox offers the ask's taps
    /// only then.
    pub(crate) fn agent_run_effect_awaits_owner_in(
        &self,
        txn: &heed::RoTxn<'_>,
        task_ref: EntityId,
        intent: &str,
    ) -> Result<bool> {
        Ok(match agent_run_task_body_in(self, txn, task_ref) {
            Ok(Some(body)) => body.effects.iter().any(|mark| {
                mark.intent_id == intent && mark.owner_ask.is_some_and(|ask| ask.answer.is_none())
            }),
            Ok(None) | Err(Error::Record(_)) => false,
            Err(error) => return Err(error),
        })
    }

    /// Keeps `site` for the effect `intent_id` this process marked, until
    /// its ledger row settles for good.
    fn keep_agent_run_effect_site(&self, intent_id: IntentId, site: AgentRunEffectSite) {
        self.agent_run_effect_sites
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(intent_id, site);
    }

    /// The run TASK and try of the effect `intent_id`, while this process
    /// keeps them.
    fn agent_run_effect_site(&self, intent_id: &IntentId) -> Option<AgentRunEffectSite> {
        self.agent_run_effect_sites
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(intent_id)
            .copied()
    }

    /// Drops the effect `intent_id` once its ledger row settled for good.
    fn forget_agent_run_effect_site(&self, intent_id: &IntentId) {
        self.agent_run_effect_sites
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(intent_id);
    }
}
