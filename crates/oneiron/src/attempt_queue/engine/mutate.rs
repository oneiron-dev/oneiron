//! Retry/intervene/manifest append mutation doors. Lease cleanup lives in
//! the sibling `reclaim` module.

use crate::attempt_queue::annotation_hold::{
    ANNOTATION_HOLD_ACTOR, AnnotationHold, ERR_ANNOTATION_HOLD_ACTOR_RESERVED,
};
use crate::attempt_queue::budget_hold::{BUDGET_HOLD_ACTOR, ERR_BUDGET_HOLD_ACTOR_RESERVED};
use crate::attempt_queue::cancel::{AttemptCancelState, AttemptLandingReserve};
use crate::attempt_queue::encoding::{DedupeIndexKeys, decode_record, ready_at, ready_key};
use crate::attempt_queue::fanout_hold::{ERR_FANOUT_HOLD_ACTOR_RESERVED, FANOUT_HOLD_ACTOR};
use crate::attempt_queue::hold_override::override_note;
use crate::attempt_queue::lifecycle::{HoldSignal, RunEvent, RunLifecycle, RunRow, RunStep};
use crate::attempt_queue::telemetry::invalid_transition;
use crate::attempt_queue::types::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptPause, AttemptRecord,
    AttemptState, InterveneAttempt, InterveneOutcome, ManifestEntry, RetryAttempt, RetryOutcome,
};
use crate::attempt_queue::validate::{
    append_attempt_event, validate_intervention_actor, validate_lease_owner,
    validate_manifest_entry, validate_optional_failure_reason, validate_optional_intervention_note,
    validate_transition_lease,
};
use crate::error::{Error, Result};
use crate::limit_ask::EngineLimit;

use super::AttemptQueue;
use crate::error::ArtifactError;
/// Stable reason stamped on a retried source row when the caller supplied none.
pub(in crate::attempt_queue) const RETRY_REASON_UNSPECIFIED: &str = "retry";
impl AttemptQueue<'_> {
    /// Retries a leased attempt by finalizing it and minting a fresh try.
    ///
    /// The leased source row becomes terminally [`AttemptState::Failed`] and is
    /// never claimable again; it stays point-readable for per-try receipts and
    /// forensics. A new row copies the immutable payload/provenance, links back
    /// through `retry_of`, and waits in [`AttemptState::Scheduled`] until
    /// `scheduled_at`. Both rows plus every index move commit as one LMDB
    /// transaction, so a fault before commit leaves neither a half-finalized
    /// source nor an orphan retry.
    pub fn retry(&self, input: RetryAttempt) -> Result<RetryOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.retry_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        self.store.notify_attempt_observers();
        Ok(outcome)
    }

    /// Retries inside a caller-owned transaction, including both rows and all
    /// index moves. The caller must abort the transaction on error.
    pub(crate) fn retry_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        mut input: RetryAttempt,
    ) -> Result<RetryOutcome> {
        input.now = crate::ports::recorded_at_in_txn(self.store, wtxn)?;
        let outcome = self.retry_storage_in_txn(wtxn, input, None)?;
        // The minted successor's id joins the persisted id floor.
        crate::ports::recorded_at_in_txn(self.store, wtxn)?;
        Ok(outcome)
    }

    /// [`Self::retry_in_txn`] under a successor id the caller derived from the
    /// work's own identity, stamped at the caller's `input.now`.
    ///
    /// It draws nothing from the vault's id source and persists no clock
    /// floor, so the retry writes nothing outside the job tables and a write
    /// after it allocates exactly the entity ids it would allocate without
    /// it. The source's lease is fenced and every index moves as for a minted
    /// successor; a taken id is refused as a collision, never overwritten.
    pub(crate) fn retry_with_id_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: RetryAttempt,
        id: AttemptId,
    ) -> Result<RetryOutcome> {
        self.retry_storage_in_txn(wtxn, input, Some(id))
    }

    fn retry_storage_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: RetryAttempt,
        id: Option<AttemptId>,
    ) -> Result<RetryOutcome> {
        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("retry", "missing"));
        };
        let mut source = decode_record(&raw_record, input.id)?;
        if source.state != AttemptState::Leased {
            return Err(invalid_transition("retry", source.state.as_str()));
        }
        validate_lease_owner(&input.lease_owner)?;
        validate_transition_lease(&source, &input.lease_owner, input.attempt_count, "retry")?;
        validate_optional_failure_reason(input.last_error.as_deref())?;

        let mut next = AttemptRecord {
            id: match id {
                Some(id) => id,
                None => AttemptId::from_bytes(&self.store.clock.ulid()?)?,
            },
            kind: source.kind.clone(),
            payload: source.payload.clone(),
            state: AttemptState::Scheduled,
            lease_owner: None,
            attempt_count: 0,
            lease_expirations: Vec::new(),
            claimed_at: None,
            scheduled_at: Some(input.backoff_until),
            retry_of: Some(source.id),
            folded_retries: 0,
            backoff_until: None,
            last_error: None,
            task_ref: source.task_ref.clone(),
            run_id: source.run_id.clone(),
            dedupe_key: source.dedupe_key.clone(),
            // The scope travels WITH the key it scopes, so the index move below
            // derives the child's entry from the row itself — never from a
            // caller's state or a decoded TASK payload.
            dedupe_actor_ref: source.dedupe_actor_ref.clone(),
            created_at: input.now,
            updated_at: input.now,
            settled_at: None,
            events: Vec::new(),
            // A retry is a NEW attempt: its attribution manifest starts empty,
            // the finalized source keeps the prior try's.
            manifest: Vec::new(),
            executor_model: None,
            executor_seat: None,
            executor_role: None,
            planned_binding: None,
            read_set: None,
            // Likewise its cancel lifecycle: the new try inherits neither the
            // source's refusal history nor its spent landing reserve. It DOES
            // inherit the dial's VALUES, so a retried try lands on the same
            // terms — but not its one-shot mark, because the new row's own
            // admission dials it against the new row's own lease generation.
            cancel_state: AttemptCancelState {
                reserve: AttemptLandingReserve {
                    spent_units: 0,
                    dial_generation: None,
                    ..source.cancel_state.reserve
                },
                ..AttemptCancelState::default()
            },
            // A retry is a NEW attempt: it has produced nothing yet, and the
            // finalized source keeps sole ownership of the artifact its own
            // try left behind.
            signals: Vec::new(),
            asks: Vec::new(),
            placement: source.placement.as_ref().map(|placement| {
                crate::attempt_queue::AttemptPlacement {
                    worker: placement.worker.clone(),
                    // Keep the new try below its predecessor, not beside it. A later
                    // explicit redirect can still select another effective parent.
                    parent: Some(source.id),
                }
            }),
            result_ref: None,
            history: Vec::new(),
            active_pause: None,
            terminal_exhaust: None,
            signal_intents: Vec::new(),
        };

        // A `Failed` row must carry a reason, so an omitted retry cause
        // normalizes to a stable non-empty token rather than failing the call.
        source.state = AttemptState::Failed;
        source.lease_owner = None;
        source.scheduled_at = None;
        source.backoff_until = None;
        source.last_error = Some(
            input
                .last_error
                .unwrap_or_else(|| RETRY_REASON_UNSPECIFIED.to_owned()),
        );
        source.updated_at = input.now;
        source.settled_at = Some(input.now);

        crate::attempt_queue::check_owner_retained_range(&next.kind, &next.id)?;
        if self
            .store
            .attempt_records
            .get(wtxn, next.id.as_bytes())?
            .is_some()
        {
            return Err(Error::InvariantViolation("attempt id collision"));
        }
        let encoded_source = self.encode_in_txn(wtxn, &mut source)?;
        self.store
            .attempt_records
            .put(wtxn, source.id.as_bytes(), &encoded_source)?;
        // A retry finalizes the source attempt. Its manifest and resident
        // binding have the same terminal receipt promise as fail/complete.
        crate::receipt::stamp_attempt_pack_receipt_in_txn(
            self.store,
            wtxn,
            &source,
            &input.lease_owner,
        )?;
        let encoded_next = self.encode_in_txn(wtxn, &mut next)?;
        self.store
            .attempt_records
            .put(wtxn, next.id.as_bytes(), &encoded_next)?;

        // The source was leased, so it holds no ready entry to retire; only the
        // new row enters the ready index, at its own scheduled instant.
        let ready_key = ready_key(ready_at(&next), next.id);
        self.store
            .attempt_ready
            .put(wtxn, &ready_key, next.id.as_bytes())?;
        self.store.put_attempt_run_index_in_txn(
            wtxn,
            next.run_id.as_deref(),
            next.id.as_bytes(),
        )?;
        crate::attempt_queue::index::put_created_in_txn(self.store, wtxn, &next)?;

        // Only the newest pending member of a dedupe chain owns the advisory
        // index, so the entry moves off the now-terminal source. The chain
        // stays in ONE key family: an actor-scoped chain keeps its v2 entry, a
        // pre-1876 actorless chain keeps its v1 entry until it drains.
        self.delete_dedupe_entry_for_record(wtxn, &source)?;
        if let Some(dedupe_key) = next.dedupe_key.as_deref() {
            let keys =
                DedupeIndexKeys::new(&next.kind, next.dedupe_actor_ref.as_deref(), dedupe_key);
            self.store
                .attempt_dedupe
                .put(wtxn, &keys.primary[..], next.id.as_bytes())?;
        }

        Ok(RetryOutcome::Retried(next))
    }

    /// Applies a durable operator intervention to an attempt row. Pause removes a
    /// queued row from the ready index, resume restores it, cancel makes a
    /// queued or paused row terminal, and interrupt records an event without
    /// changing claimability.
    pub fn intervene(&self, input: InterveneAttempt) -> Result<InterveneOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.intervene_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        self.store.notify_attempt_observers();
        // FIX 11482: a cancelled row's job notice commits here, outside
        // any owner scope, so this door sends the signal itself.
        if outcome.effect == AttemptInterventionEffect::Cancelled {
            self.store.notify_notification_updates();
        }
        Ok(outcome)
    }

    pub(crate) fn intervene_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: InterveneAttempt,
    ) -> Result<InterveneOutcome> {
        self.intervene_releasing_in_txn(wtxn, input, HoldRelease::Override)
    }

    /// [`Self::intervene_in_txn`] for a caller that is not the vault owner (a
    /// TASK's owner, the host, an agent): its Pause or Resume of a held row
    /// passes the table's caller-class column first
    /// ([`RunLifecycle::caller_hold`]). `Ok(Err(signal))` refuses it, names
    /// what the row waits on, and writes nothing. Every other intervention,
    /// and an admitted one, runs as [`Self::intervene_in_txn`] does.
    ///
    /// # Errors
    ///
    /// As [`Self::intervene_in_txn`].
    pub(crate) fn intervene_as_caller_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: InterveneAttempt,
    ) -> Result<std::result::Result<InterveneOutcome, HoldSignal>> {
        let event = match input.kind {
            AttemptInterventionKind::Resume => Some(RunEvent::Resume),
            AttemptInterventionKind::Pause => Some(RunEvent::Pause {
                pause: AttemptPause::Person,
                by_hold_actor: false,
            }),
            _ => None,
        };
        if let Some(event) = event
            && let Some(row) = self.get_in_write_txn(wtxn, input.id)?
            && let Some(signal) =
                RunLifecycle::caller_hold(RunRow::of(&row), event, placed_pause(&row, &input.actor))
        {
            return Ok(Err(signal));
        }
        Ok(Ok(self.intervene_in_txn(wtxn, input)?))
    }

    /// [`Self::intervene_in_txn`] for an engine hold's own release door
    /// (budget resume, fan-out approval, hook answer): the door writes its
    /// hold's record itself, so the Resume is no override (RUN-HOLD).
    pub(crate) fn release_hold_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: InterveneAttempt,
    ) -> Result<InterveneOutcome> {
        self.intervene_releasing_in_txn(wtxn, input, HoldRelease::Own)
    }

    fn intervene_releasing_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        mut input: InterveneAttempt,
        release: HoldRelease,
    ) -> Result<InterveneOutcome> {
        // The annotation hold's actor is the engine's own: a pause under it
        // would read as a hold, and a reattach would resume it.
        if input.actor == ANNOTATION_HOLD_ACTOR {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_ANNOTATION_HOLD_ACTOR_RESERVED,
            )));
        }
        // OF-541: the budget hold's actor is the engine's own too; only the
        // lease-fenced hold door writes it.
        if input.actor == BUDGET_HOLD_ACTOR {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_BUDGET_HOLD_ACTOR_RESERVED,
            )));
        }
        // OF-393: so is the fan-out launch hold's; only its lease-fenced
        // hold door writes it, and only its approval releases it.
        if input.actor == FANOUT_HOLD_ACTOR {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_FANOUT_HOLD_ACTOR_RESERVED,
            )));
        }
        // RUN-HOLD: a Resume of an engine hold by anyone but that hold's own
        // door is an override. The hold follows it: its record moves in this
        // transaction, and the Resume event's note names it.
        let overridden = match (input.kind, release) {
            (AttemptInterventionKind::Resume, HoldRelease::Override) => self
                .get_in_write_txn(wtxn, input.id)?
                .and_then(|row| match row.active_pause {
                    Some(pause) if row.state == AttemptState::Paused && pause.is_engine_hold() => {
                        Some((pause, row))
                    }
                    _ => None,
                }),
            _ => None,
        };
        if let Some((pause, _)) = &overridden {
            input.note = override_note(*pause, input.note.take());
        }
        let now = input.now;
        let actor = input.actor.clone();
        let outcome = self.apply_intervention_in_txn(wtxn, input)?;
        if outcome.effect == AttemptInterventionEffect::Resumed
            && let Some((pause, before)) = &overridden
        {
            self.follow_hold_override_in_txn(wtxn, *pause, before, &actor, now)?;
        }
        // FIX 900: a cancelled child settles its spend lease in the same
        // write (OF-532), as `kill_spawn` does; idempotent, unmetered no-op.
        if outcome.effect == AttemptInterventionEffect::Cancelled
            && let Some(vault) = self.vault
        {
            crate::agent_dispatch::AgentDispatcher::new(vault).settle_child_in_txn(
                wtxn,
                &outcome.record.id,
                now,
            )?;
        }
        Ok(outcome)
    }

    /// [`Self::intervene_in_txn`] for any actor, the annotation hold's
    /// included (OF-368).
    pub(in crate::attempt_queue) fn apply_intervention_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: InterveneAttempt,
    ) -> Result<InterveneOutcome> {
        validate_intervention_actor(&input.actor)?;
        validate_optional_intervention_note(input.note.as_deref())?;

        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition(input.kind.as_str(), "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;

        // RunLifecycle (slice 5.0c) answers what the intervention does in the
        // row's state; this writer keeps the guards and the side writes.
        let row = RunRow::of(&record);
        let effect = match input.kind {
            AttemptInterventionKind::Redirect => {
                return Err(invalid_transition("redirect", "missing placement"));
            }
            AttemptInterventionKind::Interrupt => {
                match RunLifecycle::step(row, RunEvent::Interrupt) {
                    RunStep::Note { clock } => {
                        append_attempt_event(
                            &mut record,
                            input.kind,
                            input.actor,
                            input.note,
                            input.now,
                        )?;
                        // A landing's note moves no clock: only accepting the
                        // landing starts its one bounded lease window.
                        if clock {
                            record.updated_at = input.now;
                        }
                        AttemptInterventionEffect::Interrupted
                    }
                    RunStep::Move { .. } | RunStep::Replay | RunStep::Keep | RunStep::Refuse => {
                        return Err(invalid_transition(input.kind.as_str(), row.state.as_str()));
                    }
                }
            }
            AttemptInterventionKind::Pause => {
                let pause = held_pause(&input.actor, input.note.as_deref());
                let by_hold_actor = input.actor == ANNOTATION_HOLD_ACTOR;
                match RunLifecycle::step(
                    row,
                    RunEvent::Pause {
                        pause,
                        by_hold_actor,
                    },
                ) {
                    // A person's pause takes over an engine hold (FIX 9579):
                    // the row is already paused and out of the ready index.
                    RunStep::Move { to, pause } if row.state == AttemptState::Paused => {
                        append_attempt_event(
                            &mut record,
                            input.kind,
                            input.actor,
                            input.note,
                            input.now,
                        )?;
                        record.state = to;
                        record.active_pause = pause;
                        record.updated_at = input.now;
                        crate::attempt_queue::index::delete_annotation_hold_in_txn(
                            self.store, wtxn, record.id,
                        )?;
                        AttemptInterventionEffect::Paused
                    }
                    // A paused row keeps its readiness instant so resume can
                    // restore the exact schedule instead of pulling the try
                    // forward.
                    RunStep::Move { to, pause } => {
                        self.delete_ready_entry_for_record(wtxn, &record)?;
                        append_attempt_event(
                            &mut record,
                            input.kind,
                            input.actor,
                            input.note,
                            input.now,
                        )?;
                        record.state = to;
                        record.active_pause = pause;
                        record.lease_owner = None;
                        record.updated_at = input.now;
                        if matches!(pause, Some(AttemptPause::Annotation { .. })) {
                            crate::attempt_queue::index::put_annotation_hold_in_txn(
                                self.store, wtxn, record.id,
                            )?;
                        }
                        AttemptInterventionEffect::Paused
                    }
                    RunStep::Replay => AttemptInterventionEffect::AlreadyPaused,
                    RunStep::Note { .. } | RunStep::Keep | RunStep::Refuse => {
                        return Err(invalid_transition(input.kind.as_str(), row.state.as_str()));
                    }
                }
            }
            AttemptInterventionKind::Resume => match RunLifecycle::step(row, RunEvent::Resume) {
                RunStep::Move { to, pause } => {
                    self.delete_ready_entry_for_record(wtxn, &record)?;
                    append_attempt_event(
                        &mut record,
                        input.kind,
                        input.actor,
                        input.note,
                        input.now,
                    )?;
                    // The table restores Scheduled while the row keeps its
                    // scheduled instant, so no read surface renders a
                    // still-deferred row as runnable now.
                    record.state = to;
                    record.active_pause = pause;
                    record.lease_owner = None;
                    record.updated_at = input.now;
                    crate::attempt_queue::index::delete_annotation_hold_in_txn(
                        self.store, wtxn, record.id,
                    )?;
                    let ready_key = ready_key(ready_at(&record), record.id);
                    self.store
                        .attempt_ready
                        .put(wtxn, &ready_key, record.id.as_bytes())?;
                    AttemptInterventionEffect::Resumed
                }
                RunStep::Replay => AttemptInterventionEffect::AlreadyResumed,
                RunStep::Note { .. } | RunStep::Keep | RunStep::Refuse => {
                    return Err(invalid_transition(input.kind.as_str(), row.state.as_str()));
                }
            },
            AttemptInterventionKind::Cancel => match RunLifecycle::step(row, RunEvent::Cancel) {
                RunStep::Replay => AttemptInterventionEffect::AlreadyCancelled,
                RunStep::Move { to, pause } => {
                    self.delete_ready_entry_for_record(wtxn, &record)?;
                    let actor = input.actor.clone();
                    append_attempt_event(
                        &mut record,
                        input.kind,
                        input.actor,
                        input.note,
                        input.now,
                    )?;
                    record.state = to;
                    record.active_pause = pause;
                    record.lease_owner = None;
                    record.scheduled_at = None;
                    record.backoff_until = None;
                    record.last_error = None;
                    record.updated_at = input.now;
                    record.settled_at = Some(input.now);
                    crate::attempt_queue::index::delete_annotation_hold_in_txn(
                        self.store, wtxn, record.id,
                    )?;
                    self.delete_dedupe_entry_for_record(wtxn, &record)?;
                    // A queued/paused cancel can follow a pack load or resident
                    // binding; stamp while the cancellation is still atomic.
                    crate::receipt::stamp_attempt_pack_receipt_in_txn(
                        self.store, wtxn, &record, &actor,
                    )?;
                    AttemptInterventionEffect::Cancelled
                }
                RunStep::Note { .. } | RunStep::Keep | RunStep::Refuse => {
                    return Err(invalid_transition(input.kind.as_str(), row.state.as_str()));
                }
            },
        };

        let encoded = self.encode_in_txn(wtxn, &mut record)?;
        self.store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        // A cancelled row is settled: its owner hears it as any other
        // terminal one does.
        if matches!(effect, AttemptInterventionEffect::Cancelled) {
            self.notify_settled_in_txn(wtxn, &record)?;
        }

        Ok(InterveneOutcome { effect, record })
    }

    /// Appends one row to a live attempt's PACK MANIFEST (ARCH-0053 §3).
    ///
    /// The pack is alive for the whole attempt, so this door accepts every
    /// pending state (queued, leased, paused) and refuses the terminal ones:
    /// a completed/failed/cancelled attempt's manifest is the evidence the
    /// terminal receipt already projected, and appending to it after the fact
    /// would rewrite history.
    ///
    /// Never drains and never refuses on a count: every row is kept, so
    /// append-only holds. Past the `[limits]` `attempt_manifest_entries` row
    /// the append asks whether everything is okay and lands (OF-520, Rule 5);
    /// only storage capacity (LMDB's value ceiling, a full map) refuses one.
    ///
    /// `updated_at` is deliberately NOT bumped: it is the lease-expiry clock
    /// ([`Self::cleanup_leases`]), and turning a pack load into a lease
    /// heartbeat would silently change reclaim timing for every attempt that
    /// pulls a skill. Manifest rows carry their own `at`.
    pub fn append_manifest_entry(
        &self,
        id: AttemptId,
        entry: ManifestEntry,
    ) -> Result<AttemptRecord> {
        let mut txn = self.store.env.write_txn()?;
        let record = self.append_manifest_entry_in_txn(&mut txn, id, entry)?;
        txn.commit()?;
        self.store.notify_attempt_observers();
        Ok(record)
    }

    /// Joins a load or dispatch transaction, so returned pack data and its receipt cannot diverge.
    pub(crate) fn append_manifest_entry_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        entry: ManifestEntry,
    ) -> Result<AttemptRecord> {
        validate_manifest_entry(&entry)?;
        let Some(raw_record) = self.store.attempt_records.get(txn, id.as_bytes())? else {
            return Err(invalid_transition("append_manifest_entry", "missing"));
        };
        let mut record = decode_record(&raw_record, id)?;
        if !record.state.is_pending() {
            return Err(invalid_transition(
                "append_manifest_entry",
                record.state.as_str(),
            ));
        }
        record.manifest.push(entry);
        // Past its `[limits]` row the append asks whether everything is okay
        // and lands (OF-520, Rule 5). A vault-opened handle's store is its
        // vault's, so this one watch also serves a store-only handle.
        self.store.limit_watch.measure(
            EngineLimit::AttemptManifestEntries,
            record.manifest.len() as u64,
        );
        let encoded = self.encode_in_txn(txn, &mut record)?;
        self.store
            .attempt_records
            .put(txn, record.id.as_bytes(), &encoded)?;
        Ok(record)
    }

    /// Returns one leased try to the ready index as the SAME try: the lease
    /// clears and the row queues again under its own id, so whatever is keyed
    /// by that id (a Dreamer step memo, say) still holds. A parked attempt
    /// whose signal arrived resumes this way. `false` when `lease_owner` no
    /// longer holds the row's lease; nothing changes then.
    pub(crate) fn release_lease_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        lease_owner: &str,
        now: u64,
    ) -> Result<bool> {
        let Some(raw_record) = self.store.attempt_records.get(wtxn, id.as_bytes())? else {
            return Err(invalid_transition("release", "missing"));
        };
        let mut record = decode_record(&raw_record, id)?;
        let lease_holder = record.lease_owner.as_deref() == Some(lease_owner);
        let RunStep::Move { to, pause } =
            RunLifecycle::step(RunRow::of(&record), RunEvent::Release { lease_holder })
        else {
            return Ok(false);
        };
        record.state = to;
        record.active_pause = pause;
        record.lease_owner = None;
        record.scheduled_at = None;
        record.backoff_until = None;
        record.updated_at = now;
        let encoded = self.encode_in_txn(wtxn, &mut record)?;
        self.store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        let ready_key = ready_key(ready_at(&record), record.id);
        self.store
            .attempt_ready
            .put(wtxn, &ready_key, record.id.as_bytes())?;
        Ok(true)
    }
}

/// Whether `actor` placed `record`'s pause: the row's newest Pause event names
/// it.
fn placed_pause(record: &AttemptRecord, actor: &str) -> bool {
    record
        .events
        .iter()
        .rev()
        .find(|event| event.kind == AttemptInterventionKind::Pause)
        .is_some_and(|event| event.actor == actor)
}

/// Who resumes an engine hold (RUN-HOLD): its own release door, which writes
/// the hold's record itself, or anyone else, whose Resume the hold follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HoldRelease {
    Own,
    Override,
}

/// The pause an intervention's `Pause` holds a row under (FIX 9579): the
/// annotation hold its reserved actor names in its note, else a person's.
fn held_pause(actor: &str, note: Option<&str>) -> AttemptPause {
    if actor == ANNOTATION_HOLD_ACTOR
        && let Some(hold) = note.and_then(AnnotationHold::from_note)
    {
        return AttemptPause::Annotation {
            artifact_id: hold.artifact_id,
            thread_id: hold.thread_id,
        };
    }
    AttemptPause::Person
}
