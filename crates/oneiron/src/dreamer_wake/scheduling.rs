//! The host-facing enqueue doors; the engine owns no timer.

use rmpv::Value;

use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerConsolidationScope, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
    EnqueueDreamerVaultCleanupAttempt,
};
use crate::error::Result;

use super::types::WakeTrigger;

/// Wake scheduling entry: enqueues one consolidation attempt on the advisory
/// attempt-table floor. The engine owns NO timer/cron — hosts call this.
///
/// `trigger` carries host intent; the scope is the caller's (typically
/// `trigger.default_scope()`, which an Event payload may override).
/// Timer/Macro also enqueues vault cleanup in the SAME transaction. Other
/// triggers and narrower scopes enqueue consolidation only. The returned
/// outcome remains the consolidation outcome; cleanup has its own queue kind.
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
    let scope = trigger.default_scope();
    if trigger == WakeTrigger::Timer {
        // The queue dedupe domain includes the kind, so sharing the wake key
        // coalesces each lane without one lane swallowing the other.
        store.enqueue_vault_cleanup_in_txn(
            txn,
            EnqueueDreamerVaultCleanupAttempt {
                trigger,
                input: Value::Nil,
                parent_attempt: payload.parent_attempt,
                dedupe_key: dedupe_key.clone(),
                run_id: run_id.clone(),
                now,
            },
        )?;
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
