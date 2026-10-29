//! The host-facing enqueue doors; the engine owns no timer.

use rmpv::Value;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::{
    PreparedPartitionPlans, WatermarkAdvance, apply_partition_plans_in_txn,
    apply_watermark_advance_in_txn, collect_dirty_turn_ids_until, prepare_partition_plans_in_txn,
    read_partition_turns_in_txn, read_watermark_advance_in_txn, read_watermark_in_txn,
};
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerConsolidationScope, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
    EnqueueDreamerVaultCleanupAttempt,
};
use crate::entity_id::EntityId;
use crate::error::Result;

use super::policy::AgentWakeSignals;
use super::projector::ProjectionPlan;
use super::read_phase::{OnStale, ReadWrite, WakeStop, read_then_write};

use super::types::WakeTrigger;

/// Wake scheduling entry: enqueues one consolidation attempt on the advisory
/// attempt-table floor. The engine owns NO timer/cron — hosts call this.
///
/// `trigger` carries host intent; the scope is the caller's (typically
/// `trigger.default_scope()`, which an Event payload may override).
/// Timer/Macro also enqueues vault cleanup in the SAME transaction. Other
/// triggers and narrower scopes enqueue consolidation only. The returned
/// outcome remains the consolidation outcome; cleanup has its own queue kind.
/// A Timer/Macro wake whose payload input is Nil names no partition: its
/// outcome is the typed plan parent its Nightly spending is planned under.
pub fn request_wake(
    store: &DreamerRunnerStore<'_>,
    trigger: WakeTrigger,
    scope: DreamerConsolidationScope,
    payload: DreamerAttemptPayload,
    dedupe_key: Option<String>,
    run_id: Option<String>,
    now: u64,
) -> Result<EnqueueDreamerAttemptOutcome> {
    if trigger == WakeTrigger::Timer && scope == DreamerConsolidationScope::Macro {
        return store.enqueue_timer_wake(payload, dedupe_key, run_id, now);
    }
    store.enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
        scope,
        input: payload.input,
        parent_attempt: payload.parent_attempt,
        dedupe_key,
        run_id,
        now,
    })
}

/// [`request_wake`] inside a CALLER-OWNED write transaction (CMT-3, ONE-1540).
///
/// The transactional twin, not a second scheduler: same trigger/scope
/// semantics, same store verb, same queue keys, run-tree logic, and admission —
/// only the transaction boundary moves outward. It exists because a wake that
/// must be atomic with the durable fact that PROVOKED it (a commitment due
/// phase being consumed) cannot open a transaction of its own; the public
/// [`request_wake`] stays source-compatible for every host that does not need
/// that composition.
///
/// The trigger is nominal here, not decorative: it IS the scope, derived
/// through [`WakeTrigger::default_scope`] exactly as [`request_wake`] documents
/// its own scope argument. The public entry point takes that scope separately
/// because a host's Event payload may override it; this crate-private door has
/// no such host, so deriving keeps trigger and scope from ever disagreeing.
pub(crate) fn request_wake_in_txn(
    store: &DreamerRunnerStore<'_>,
    txn: &mut heed::RwTxn<'_>,
    trigger: WakeTrigger,
    payload: DreamerAttemptPayload,
    dedupe_key: Option<String>,
    run_id: Option<String>,
    now: u64,
) -> Result<EnqueueDreamerAttemptOutcome> {
    if trigger == WakeTrigger::Event
        && payload.attempt_type == crate::dreamer_runner::connector_event::CONNECTOR_EVENT_FACET
    {
        return store.enqueue_connector_event_in_txn(txn, payload, dedupe_key, run_id, now);
    }
    let scope = trigger.default_scope();
    if trigger == WakeTrigger::Timer {
        request_timer_maintenance_in_txn(
            store,
            txn,
            payload.parent_attempt,
            dedupe_key.as_deref(),
            run_id.as_deref(),
            now,
        )?;
        // A Timer wake that names no partition plans the existing Nightly
        // spending under one typed parent in this commit (FIX 336), never a
        // consolidation with nothing to read; an explicit partition keeps
        // its own consolidation below.
        if payload.input.is_nil() {
            return super::nightly::enqueue_timer_plan_in_txn(
                store,
                txn,
                payload.parent_attempt,
                dedupe_key,
                run_id,
                now,
            );
        }
    }
    store.enqueue_consolidation_in_txn(
        txn,
        EnqueueDreamerConsolidationAttempt {
            scope,
            input: payload.input,
            parent_attempt: payload.parent_attempt,
            dedupe_key,
            run_id,
            now,
        },
    )
}

/// Every maintenance lane a Timer wake asks for, in its one order, each
/// under `parent_attempt` and `run_id`: cleanup, skill optimize, the Coach's
/// retrieval tune and honesty audits, the Coach's nightly jobs, then the
/// Dreamer's. A resident Timer wake asks before its plan, under its own
/// parent and run; a night step asks after its plan, beneath it (FIX
/// 6903).
pub(super) fn request_timer_maintenance_in_txn(
    store: &DreamerRunnerStore<'_>,
    txn: &mut heed::RwTxn<'_>,
    parent_attempt: Option<AttemptId>,
    dedupe_key: Option<&str>,
    run_id: Option<&str>,
    now: u64,
) -> Result<()> {
    // The queue dedupe domain includes the kind, so sharing the wake key
    // coalesces each lane without one lane swallowing the other.
    store.enqueue_vault_cleanup_in_txn(
        txn,
        EnqueueDreamerVaultCleanupAttempt {
            trigger: WakeTrigger::Timer,
            input: Value::Nil,
            parent_attempt,
            dedupe_key: dedupe_key.map(str::to_owned),
            run_id: run_id.map(str::to_owned),
            now,
        },
    )?;
    store.enqueue_skill_optimize_in_txn(
        txn,
        crate::dreamer_runner::EnqueueDreamerSkillOptimizeAttempt {
            input: Value::Nil,
            parent_attempt,
            dedupe_key: dedupe_key.map(str::to_owned),
            run_id: run_id.map(str::to_owned),
            now,
        },
    )?;
    store.enqueue_coach_retrieval_tune_in_txn(
        txn,
        parent_attempt,
        dedupe_key,
        run_id.map(str::to_owned),
        now,
    )?;
    store.enqueue_honesty_audits_in_txn(
        txn,
        parent_attempt,
        dedupe_key,
        run_id.map(str::to_owned),
        now,
    )?;
    store.enqueue_coach_nightly_in_txn(
        txn,
        parent_attempt,
        dedupe_key,
        run_id.map(str::to_owned),
        now,
    )?;
    store.enqueue_dreamer_nightly_in_txn(
        txn,
        parent_attempt,
        dedupe_key,
        run_id.map(str::to_owned),
        now,
    )
}

/// [`request_wake`] for a Compaction wake that CARRIES a forked-compaction
/// packet (DREAM-008, ONE-1250).
///
/// The only door: taking [`crate::compaction::ValidatedCompactionPacket`]
/// by reference makes admission structural. That witness has no public
/// constructor, so this entry point cannot be reached with a packet whose
/// schema, turn set, session membership, snapshot ref, or payload shape was
/// never checked — a host cannot assert compaction provenance the vault
/// never recorded.
///
/// This is the packet-carrying path ONLY. Packet-less Compaction wakes call
/// [`request_wake`] with [`WakeTrigger::Compaction`] exactly as before; that
/// path is untouched, and this wrapper enqueues the same attempt through the
/// same store verb, changing no runner behavior.
///
/// The admitted packet's contents are not read here: consuming a handoff's
/// turns and snapshot is the compaction backend's job, not the wake
/// scheduler's. Its role at this seam is to bind the wake to admitted
/// evidence, mirroring how `trigger` binds intent in [`request_wake`].
pub fn request_compaction_wake_with_packet(
    store: &DreamerRunnerStore<'_>,
    packet: &crate::compaction::ValidatedCompactionPacket,
    scope: DreamerConsolidationScope,
    payload: DreamerAttemptPayload,
    dedupe_key: Option<String>,
    run_id: Option<String>,
    now: u64,
) -> Result<EnqueueDreamerAttemptOutcome> {
    let _ = packet;
    request_wake(
        store,
        WakeTrigger::Compaction,
        scope,
        payload,
        dedupe_key,
        run_id,
        now,
    )
}

/// Whose turn is being scheduled. The agent variant resolves the STORED
/// definition in the same transaction as the policy and enqueue, so a caller
/// cannot substitute a stale or invented cadence dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeTurnSubject {
    Vault,
    Agent {
        id: EntityId,
        signals: AgentWakeSignals,
    },
}

/// Schedule the projector's turn wake through the one engine enqueue door.
///
/// `projection_digest` is the SHA-256 of the projector's proposed image, not
/// a hash of the turn or of the queue payload. The projector supplies it only
/// after computing the candidate image. `None` is no new material. Equal images mean no change:
/// no attempt, cursor, or receipt is written. The image participates in the
/// enqueue dedupe key, so a new image for the same turn cannot be swallowed
/// by an existing attempt. The projection cursor and the
/// queued attempt land in the same transaction; a failed enqueue cannot lose
/// a changed image. Other triggers (consent, connector, session end) bypass
/// the cadence gate and retain their existing event semantics.
#[allow(
    clippy::too_many_arguments,
    reason = "the arguments mirror the existing enqueue door plus turn and projection"
)]
pub fn request_turn_wake(
    store: &DreamerRunnerStore<'_>,
    subject: WakeTurnSubject,
    turn_ordinal: u64,
    projection_digest: Option<[u8; 32]>,
    payload: DreamerAttemptPayload,
    dedupe_key: Option<String>,
    run_id: Option<String>,
    now: u64,
) -> Result<Option<EnqueueDreamerAttemptOutcome>> {
    let Some(projection_digest) = projection_digest else {
        return Ok(None);
    };
    let vault = store.vault();
    let mut txn = vault.store.env.write_txn()?;
    if !turn_wake_due_in_txn(vault, &txn, subject, turn_ordinal..=turn_ordinal)? {
        return Ok(None);
    }
    if vault.queued_wake_projection_in_txn(&txn)? == Some(projection_digest) {
        return Ok(None);
    }
    // Caller dedupe keys may name a turn, not an image. Bind the image into
    // the effective key so a second, changed projection on the SAME turn
    // cannot return Existing and advance the cursor without new work.
    let mut key_hash = blake3::Hasher::new();
    key_hash.update(b"dreamer:turn-projection:v1");
    key_hash.update(&turn_ordinal.to_be_bytes());
    key_hash.update(&projection_digest);
    if let Some(key) = dedupe_key {
        key_hash.update(&(key.len() as u64).to_be_bytes());
        key_hash.update(key.as_bytes());
    }
    let image_key = format!("turn-projection:{}", key_hash.finalize().to_hex());
    let outcome = store.enqueue_consolidation_in_txn(
        &mut txn,
        EnqueueDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            input: payload.input,
            parent_attempt: payload.parent_attempt,
            dedupe_key: Some(image_key),
            run_id,
            now,
        },
    )?;
    vault.set_queued_wake_projection_in_txn(&mut txn, &projection_digest)?;
    txn.commit()?;
    vault.store.notify_attempt_observers();
    // FIX 6941: a raw commit has no owner to drain the enqueue's marker.
    vault.store.notify_proactivity_changes();
    Ok(Some(outcome))
}

/// Which test a turn wake's window is due on.
#[derive(Clone, Copy)]
enum TurnWakeTest {
    /// A landed turn's: each window ordinal on the grain or the agent's cadence
    /// dial, and the agent's signals.
    Turn,
    /// A surprising save's: the agent's signals alone, at no ordinal.
    Surprise,
}

/// Whether any of `ordinals` is due on the per-vault wake grain, or on the
/// agent's stored cadence dial on top of it, read in the caller's transaction.
fn turn_wake_due_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: WakeTurnSubject,
    mut ordinals: std::ops::RangeInclusive<u64>,
) -> Result<bool> {
    let policy = super::policy::policy_in_txn(vault, txn)?;
    Ok(match subject {
        WakeTurnSubject::Vault => {
            let grain = super::grain::WakeGrain::new(policy.wake_grain_turns)?;
            ordinals.any(|ordinal| grain.due(ordinal))
        }
        WakeTurnSubject::Agent { id, signals } => {
            let definition = vault.read_agent_definition_in_txn(txn, &id)?;
            ordinals.any(|ordinal| definition.dream_wake_due(&policy, ordinal, signals))
        }
    })
}

/// The wake policy's surprise floor (OF-138): how far a re-tag must move its
/// turn beside the set it replaced to be a surprise.
pub(crate) fn surprise_floor_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<f32> {
    Ok(f32::from(super::policy::policy_in_txn(vault, txn)?.surprise_permille) / 1000.0)
}

/// Whether a re-tag's measured `surprise` is a surprise at `floor`.
pub(crate) fn surprises(surprise: f32, floor: f32) -> bool {
    surprise > 0.0 && surprise >= floor
}

/// An agent's surprise signal, read from the window's saved tags (OF-138).
/// A turn whose re-tag moved at least the policy's surprise floor beside the
/// set it replaced sets it; a first tag set measures nothing. The caller's
/// own signal stands either way, and the vault's wake takes no signals. A
/// surprising re-tag of a turn a window already read puts the turn back in
/// the next window (FIX 901, [`crate::tagging`]'s save).
fn measured_surprise_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: WakeTurnSubject,
    turns: impl Iterator<Item = EntityId>,
) -> Result<WakeTurnSubject> {
    let WakeTurnSubject::Agent { id, mut signals } = subject else {
        return Ok(subject);
    };
    if !signals.surprise {
        let floor = surprise_floor_in_txn(vault, txn)?;
        for turn in turns {
            let measured = crate::tagging::readable_view_in_txn(&vault.store, txn, &turn)?
                .and_then(|tags| tags.surprise);
            if measured.is_some_and(|surprise| surprises(surprise, floor)) {
                signals.surprise = true;
                break;
            }
        }
    }
    Ok(WakeTurnSubject::Agent { id, signals })
}

/// Whether a TURN carries an import stamp, read as its import's review reads
/// it (ARCH-0027).
fn turn_imported_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, turn: &EntityId) -> Result<bool> {
    Ok(vault.get_raw_in(txn, turn)?.is_some_and(|raw| {
        crate::dreamer_consolidation::decode_turn_body(
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN.min(raw.len())..],
        )
        .imported
    }))
}

/// What a turn wake's read phase decided.
struct TurnWakeReads {
    queue: Option<(ProjectionPlan, Option<PreparedPartitionPlans>)>,
    advance: Option<WatermarkAdvance>,
}

/// The turn wake's read phase: today's reads in today's order, in the
/// caller's snapshot. `None` when `stop` stopped the read; nothing is
/// written then.
fn read_turn_wake_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: WakeTurnSubject,
    stop: WakeStop<'_>,
    test: TurnWakeTest,
) -> Result<Option<TurnWakeReads>> {
    let scope = DreamerConsolidationScope::Micro;
    let watermark = read_watermark_in_txn(vault, txn, scope)?;
    let Some(ids) =
        collect_dirty_turn_ids_until(vault, txn, scope, watermark.last_learned_at, u64::MAX, stop)?
    else {
        return Ok(None);
    };
    let mut window = Vec::with_capacity(ids.len());
    let mut stepped = Vec::new();
    for turn in read_partition_turns_in_txn(vault, txn, scope, &ids)? {
        if turn.conversation.is_none() || turn_imported_in_txn(vault, txn, &turn.turn_id)? {
            stepped.push(turn.learned_at);
        } else {
            window.push(turn);
        }
    }
    let subject = measured_surprise_in_txn(vault, txn, subject, window.iter().map(|t| t.turn_id))?;
    // A surprise test reads ordinal 0 alone, which no cadence dial is due on.
    let ordinals = match test {
        TurnWakeTest::Turn => 1..=window.len() as u64,
        TurnWakeTest::Surprise => 0..=0,
    };
    let due = !window.is_empty() && turn_wake_due_in_txn(vault, txn, subject, ordinals)?;
    // The watermark settles every turn up to where it moves, so an
    // undue wake stops it before the first live turn it leaves.
    let first_live = window.iter().map(|turn| turn.learned_at).min();
    let through = if due {
        window
            .iter()
            .map(|turn| turn.learned_at)
            .chain(stepped.iter().copied())
            .max()
    } else {
        stepped
            .iter()
            .copied()
            .filter(|at| first_live.is_none_or(|live| *at < live))
            .max()
    };
    let mut queue = None;
    if due {
        let Some(plan) = super::projector::plan_in_txn(vault, txn, &window, &watermark, stop)?
        else {
            return Ok(None);
        };
        let prepared = prepare_partition_plans_in_txn(vault, txn, scope, &plan.turns, &watermark)?;
        queue = Some((plan, prepared));
    }
    let mut advance = None;
    if let Some(through) = through {
        let Some(read) = read_watermark_advance_in_txn(vault, txn, scope, through, stop)? else {
            return Ok(None);
        };
        advance = Some(read);
    }
    Ok(Some(TurnWakeReads { queue, advance }))
}

/// The turn wake's write phase: today's writes in today's order. Returns
/// whether a wake was queued.
fn apply_turn_wake_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    reads: TurnWakeReads,
    now: u64,
) -> Result<bool> {
    let scope = DreamerConsolidationScope::Micro;
    let mut held = None;
    if let Some((plan, prepared)) = reads.queue {
        // A plan that queues nothing still runs the hold, as today, with an
        // empty `enqueued`.
        let enqueued = match &prepared {
            Some(prepared) => apply_partition_plans_in_txn(vault, txn, scope, prepared, None, now)?,
            None => Vec::new(),
        };
        held = Some((plan, enqueued));
    }
    if let Some(advance) = &reads.advance {
        apply_watermark_advance_in_txn(vault, txn, scope, advance)?;
    }
    // After the settlement, which consumes every carrier up to where
    // it moves: a rider the projector puts back waits for a later wake.
    let Some((plan, enqueued)) = held else {
        return Ok(false);
    };
    super::projector::hold_in_txn(vault, txn, &plan, &enqueued)?;
    Ok(!enqueued.is_empty())
}

impl Vault {
    /// The turn producer (ARCH-0026 RD-26): a landed turn counts against the
    /// wake grain, and a due turn offers the Micro rounds for every turn no
    /// Micro round has read yet to the projector.
    ///
    /// The continuous sieve reads what landed first, in its own commit. A
    /// turn's ordinal is its place in the unread window, so the Nth new turn
    /// closes an N-turn grain; turns that landed together are due when any of
    /// their ordinals is. A due window goes to the projector's surprise check:
    /// a window that only repeats the turn the projection holds writes
    /// nothing, its repeats riding that turn's round, and any other window is
    /// queued whole. Either way the window is read: the watermark passes it.
    /// The enqueue, the projector rows and the Micro watermark land in one
    /// transaction, so a crash cannot queue a window twice or lose one; the
    /// scans and history reads run in a read snapshot before that
    /// transaction, which writes only if no commit landed in between (FIX
    /// 11568). A pause or stop before the write writes nothing.
    ///
    /// An imported TURN belongs to its import's one review (ARCH-0027): it is
    /// never planned here and never counts. A TURN without its conversation
    /// edge is never planned or counted either; the settlement parks it on
    /// its carrier until the edge lands, so it stops no later turn. The
    /// watermark steps over both up to the first live turn left unplanned.
    /// Returns the write the read phase decided, or that it stopped or
    /// deferred and wrote nothing.
    pub(crate) fn wake_dreamer_on_turn_until(
        &self,
        subject: WakeTurnSubject,
        now: u64,
        stop: WakeStop<'_>,
        on_stale: OnStale,
    ) -> Result<ReadWrite<bool>> {
        self.wake_dreamer_tested_until(subject, now, stop, on_stale, TurnWakeTest::Turn)
    }

    /// [`Self::wake_dreamer_on_turn`] for `agent` at a save whose surprise
    /// reached the wake policy's floor (FIX 11410): the window is due on the
    /// surprise test alone, the agent's role admitting a surprise wake, so no
    /// cadence ordinal fires at a save.
    pub(crate) fn wake_dreamer_on_surprise(&self, agent: EntityId, now: u64) -> Result<bool> {
        let subject = WakeTurnSubject::Agent {
            id: agent,
            signals: AgentWakeSignals {
                surprise: true,
                ..AgentWakeSignals::default()
            },
        };
        let outcome = self.wake_dreamer_tested_until(
            subject,
            now,
            WakeStop::NEVER,
            OnStale::OneWriter,
            TurnWakeTest::Surprise,
        )?;
        Ok(matches!(outcome, ReadWrite::Written(true)))
    }

    fn wake_dreamer_tested_until(
        &self,
        subject: WakeTurnSubject,
        now: u64,
        stop: WakeStop<'_>,
        on_stale: OnStale,
        test: TurnWakeTest,
    ) -> Result<ReadWrite<bool>> {
        let commit = match self.sieve_pass_until(now, stop, on_stale, true)? {
            ReadWrite::Written(commit) => commit,
            ReadWrite::Stopped => return Ok(ReadWrite::Stopped),
            ReadWrite::Deferred => return Ok(ReadWrite::Deferred),
        };
        let outcome = read_then_write(
            self,
            "turn wake",
            on_stale,
            |txn| read_turn_wake_in_txn(self, txn, subject, stop, test),
            |txn, reads| apply_turn_wake_in_txn(self, txn, reads, now),
        )?;
        if commit.followed || matches!(outcome, ReadWrite::Written(true)) {
            self.store.notify_attempt_observers();
        }
        Ok(outcome)
    }

    /// The turn producer with nothing stopping it: a stale read retries in
    /// its writer, so the wake always lands. Returns whether a wake was
    /// queued.
    pub fn wake_dreamer_on_turn(&self, subject: WakeTurnSubject, now: u64) -> Result<bool> {
        Ok(matches!(
            self.wake_dreamer_on_turn_until(subject, now, WakeStop::NEVER, OnStale::OneWriter)?,
            ReadWrite::Written(true)
        ))
    }

    /// The authority-bearing turn producer (DOOR-141), beside the Micro one:
    /// each wake a landed turn's own commit owed one of its actor's armed
    /// programs is admitted as one Dreamer program attempt under that actor's
    /// authority, never the Dreamer's, through the same dedupe after a turn
    /// as at boot. It reads no partition and moves no consolidation grain.
    /// One batch per call; [`crate::dreamer_runner::TurnProgramDrain::more`]
    /// asks for the next.
    pub fn wake_turn_programs(&self, now: u64) -> Result<crate::dreamer_runner::TurnProgramDrain> {
        crate::dreamer_runner::drain_turn_program_wakes(self, now)
    }
}
