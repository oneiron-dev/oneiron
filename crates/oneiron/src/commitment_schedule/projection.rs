//! The durable projection layer: series indexing, occurrence minting, and the
//! close hook.
//!
//! This is where the pure evaluator meets LMDB. Three doors, and the split
//! between them is the whole design:
//!
//! * [`Vault::put_commitment_series`] is the ONLY door that indexes a series.
//!   A typed payload written through CMT-1's generic
//!   [`Vault::put_commitment_claim`] is stored-but-unindexed, which is a legal
//!   state every reader here tolerates rather than treats as corruption.
//! * [`Vault::reconcile_commitment_schedule`] is the ONLY production projector.
//!   It consumes `Project` rows that have come due and materializes the
//!   occurrences they name. Nothing polls it; the driver calls it inside a
//!   deadline read (ARCH-0026).
//! * [`Vault::on_instance_closed`] is a hook, not a verb. It never writes the
//!   terminal status — the caller already did that — so it is safe to call
//!   twice, and a second call reports the same successor instead of minting a
//!   new one.
//!
//! Every write in this module is all-or-none inside ONE caller-visible write
//! transaction. A rejected schedule, a refused claim, or a failed row write
//! rolls the whole attempt back, because a series that is half-indexed is
//! worse than one that was never written: the index would promise occurrences
//! the claim cannot describe.

use heed::{RoTxn, RwTxn};

use super::{
    CAL_RRULE_ROUTE, CommitmentDueEntry, CommitmentDuePhase, CommitmentInstanceOutcome,
    CommitmentOccurrence, CommitmentSchedulePayload, QuotaWindow, Schedule, ScheduleError,
    ScheduleHistoryEntry, ScheduleResult, commitment_instance_id, commitment_projection_envelope,
    iso_week_window, next_due, validate_quota_count,
};
use crate::claim::ClaimLifecycleStatus;
use crate::commitment::{
    CommitmentRecord, CommitmentStatus, commitment_claim_candidate, decode_commitment_claim,
};
use crate::entity_id::EntityId;
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::WriteEnvelope;

/// What one [`Vault::reconcile_commitment_schedule`] pass did.
///
/// Minted and already-present instances are reported separately so a retry is
/// legible: a crash-resumed pass that mints nothing and reports the same ids as
/// already present did its job exactly once, which is not the same story as a
/// pass that found no work at all.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CommitmentProjectionReport {
    /// How many `Project` rows this pass consumed.
    pub projected_series: usize,
    /// Instances this pass wrote for the first time.
    pub minted_instances: Vec<EntityId>,
    /// Instances whose deterministic id already carried the identical identity.
    pub already_present_instances: Vec<EntityId>,
}

/// What a series write did to the due index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommitmentSeriesWriteOutcome {
    /// The series is indexed: a `Project` row sits at `project_at` and names
    /// the occurrence owed at `next_due`.
    Indexed {
        /// When the projector will materialize the next occurrence.
        project_at: u64,
        /// The instant that occurrence is owed.
        next_due: u64,
    },
    /// The series is an rrule: the claim is stored verbatim and NO due row was
    /// written. Expansion belongs to `route`.
    StoredRrule {
        /// The calendar entry point that owns expansion.
        route: &'static str,
    },
}

/// The series-side facts one mint needs, bundled so the minting helpers stay
/// under the argument-count bar and cannot be called with a series record and
/// somebody else's payload.
struct SeriesMint<'a> {
    series_ref: EntityId,
    record: &'a CommitmentRecord,
    payload: &'a CommitmentSchedulePayload,
    envelope: &'a WriteEnvelope,
    learned_at: u64,
}

impl Vault {
    /// Writes a commitment SERIES and indexes it in one transaction.
    ///
    /// This is the only door that creates a `Project` row. CMT-1's
    /// [`Vault::put_commitment_claim`] still accepts a typed payload and still
    /// stores it faithfully — it simply does not index it, and every reader in
    /// this module treats that stored-but-unindexed claim as ordinary data.
    ///
    /// An rrule series is committed as a claim and nothing else: no due row, no
    /// deadline, and the outcome names [`CAL_RRULE_ROUTE`] rather than
    /// pretending v1 can expand it.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Invalid`] for a non-open record or a payload that is
    /// not a SERIES, [`ScheduleError::InvalidPayload`] for schedule bytes that
    /// are not a CMT-2 payload, and the evaluator's own refusals for a schedule
    /// that cannot name an occurrence. Every one of them rolls the claim write
    /// back with the index write.
    pub fn put_commitment_series(
        &self,
        id: &EntityId,
        record: &CommitmentRecord,
        envelope: &WriteEnvelope,
        valid_time: TimeRange,
        learned_at: u64,
    ) -> ScheduleResult<CommitmentSeriesWriteOutcome> {
        let payload = series_payload(record)?;
        let candidate = commitment_claim_candidate(record)?
            .with_validity(Some(valid_time.start), Some(valid_time.end));
        self.try_with_write_txn(|wtxn| {
            self.batch_in()
                .claim_candidate(id, candidate, envelope, valid_time, learned_at)
                .apply(wtxn)?;
            self.index_commitment_series_in_txn(wtxn, id, &payload, learned_at)
        })
    }

    /// Replaces an indexed series with an edited one.
    ///
    /// A series EDIT is not a mutation: it is a replacement claim plus the
    /// canonical `Supersedes` edge, which is lifecycle machinery that already
    /// exists. CMT-1's same-row [`Vault::supersede_commitment`] is deliberately
    /// NOT used — it would rewrite the old series in place and leave the edit
    /// with no head to point at.
    ///
    /// All four steps (replacement claim, supersession, removal of the old
    /// series' pending `Project` row, indexing of the replacement) share ONE
    /// write transaction, so a refused supersession never leaves two live heads
    /// or an orphaned `Project` row behind.
    ///
    /// # Errors
    ///
    /// Everything [`Vault::put_commitment_series`] can refuse, plus the
    /// lifecycle layer's own guards (self-supersession, already-closed claims,
    /// reserved predicates) surfaced through [`ScheduleError::Engine`].
    pub fn supersede_commitment_series(
        &self,
        new_id: &EntityId,
        old_id: &EntityId,
        new_record: &CommitmentRecord,
        envelope: &WriteEnvelope,
        valid_time: TimeRange,
        learned_at: u64,
    ) -> ScheduleResult<CommitmentSeriesWriteOutcome> {
        let payload = series_payload(new_record)?;
        let candidate = commitment_claim_candidate(new_record)?
            .with_validity(Some(valid_time.start), Some(valid_time.end));
        self.try_with_write_txn(|wtxn| {
            self.batch_in()
                .claim_candidate(new_id, candidate, envelope, valid_time, learned_at)
                .apply(wtxn)?;
            self.supersede_claim_in_txn(wtxn, new_id, old_id, learned_at)?;
            // The old series' pending projection dies with the old head. Left
            // behind it would mint occurrences of a schedule nobody holds.
            self.store
                .commitment_due_clear_series_project_in_txn(wtxn, old_id)?;
            self.index_commitment_series_in_txn(wtxn, new_id, &payload, learned_at)
        })
    }

    /// Materializes every occurrence whose `Project` row has come due.
    ///
    /// The SOLE production projector. It reads only `Project` rows at or before
    /// `now`: `Lead`, `Due`, and `LifecycleDue` are consumer phases and this
    /// pass never touches them.
    ///
    /// Idempotent by construction rather than by bookkeeping. Instance ids are
    /// derived from the series and the occurrence, so a pass that repeats work
    /// after a crash re-derives the SAME id, finds the claim already there,
    /// verifies its copied identity, and reports it as already-present. A
    /// mismatch at that id is [`ScheduleError::InstanceIdentityCollision`],
    /// never a silent overwrite.
    ///
    /// # Errors
    ///
    /// Storage and index corruption surface as typed errors. A commitment
    /// engine that answered "nothing to do" on an unreadable index would drop
    /// obligations, so this pass fails loudly instead.
    pub fn reconcile_commitment_schedule(
        &self,
        now: u64,
    ) -> ScheduleResult<CommitmentProjectionReport> {
        self.try_with_write_txn(|wtxn| {
            let due = self.store.commitment_due_entries_through_in_txn(
                &*wtxn,
                now,
                &[CommitmentDuePhase::Project],
            )?;
            let mut report = CommitmentProjectionReport::default();
            for entry in due {
                self.project_commitment_series_in_txn(wtxn, &entry, now, &mut report)?;
            }
            Ok(report)
        })
    }

    /// Reacts to an instance that has ALREADY been closed.
    ///
    /// The hook does not perform the status write and never second-guesses it;
    /// it reads the terminal status back and refuses if the caller's `outcome`
    /// disagrees with what is on disk. That ordering is what makes it
    /// retry-safe: a crash between the status write and this call is repaired
    /// by calling it again.
    ///
    /// Returns the successor instances this close produced — one for an
    /// interval, a whole window for a quota that rolled over past its window
    /// end, none for anything else.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Invalid`] when the named claim is a SERIES or is still
    /// open, or when its terminal status does not match `outcome`.
    /// [`ScheduleError::RruleNotImplemented`] for an rrule instance.
    /// [`ScheduleError::ArithmeticOverflow`] when the interval successor would
    /// leave the `u64` time model.
    pub fn on_instance_closed(
        &self,
        instance_ref: &EntityId,
        outcome: CommitmentInstanceOutcome,
        envelope: &WriteEnvelope,
        closed_at: u64,
    ) -> ScheduleResult<Vec<EntityId>> {
        self.try_with_write_txn(|wtxn| {
            let Some(closed) = self.closed_instance_in_txn(&*wtxn, instance_ref, outcome)? else {
                // Either the claim is gone (rows outliving it is exactly the
                // crash this repairs) or it is not a CMT-2 instance at all.
                self.store
                    .commitment_due_clear_instance_phases_in_txn(wtxn, instance_ref)?;
                return Ok(Vec::new());
            };
            // The occurrence is over: its timed rows go, its series membership
            // stays. A closed occurrence is still an occurrence, and the
            // evaluator reads membership as history.
            self.store
                .commitment_due_clear_instance_phases_in_txn(wtxn, instance_ref)?;
            self.commitment_successors_in_txn(wtxn, &closed, envelope, closed_at)
        })
    }

    /// Writes the `Project` row for a series, in the caller's transaction.
    fn index_commitment_series_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        series_ref: &EntityId,
        payload: &CommitmentSchedulePayload,
        now: u64,
    ) -> ScheduleResult<CommitmentSeriesWriteOutcome> {
        if matches!(payload.schedule, Schedule::Rrule { .. }) {
            return Ok(CommitmentSeriesWriteOutcome::StoredRrule {
                route: CAL_RRULE_ROUTE,
            });
        }
        let history = self.commitment_series_history_in_txn(&*wtxn, series_ref)?;
        let due_at = next_due(&payload.schedule, now, &history)?.ok_or(ScheduleError::Invalid(
            "commitment series schedule owes no occurrence",
        ))?;
        let entry = project_row(series_ref, payload, due_at)?;
        self.store.commitment_due_put_in_txn(wtxn, &entry)?;
        Ok(CommitmentSeriesWriteOutcome::Indexed {
            project_at: entry.at,
            next_due: entry.occurrence.due_at,
        })
    }

    /// Consumes one due `Project` row and mints whatever it owes.
    fn project_commitment_series_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        entry: &CommitmentDueEntry,
        now: u64,
        report: &mut CommitmentProjectionReport,
    ) -> ScheduleResult<()> {
        report.projected_series = report.projected_series.saturating_add(1);
        // The row is spent either way. Its successor, if the schedule has one,
        // is a row the CLOSE hook writes; leaving this one behind would re-mint
        // the same occurrence on every pass forever.
        self.store.commitment_due_delete_in_txn(wtxn, entry)?;

        let Some((record, payload)) = self.live_series_in_txn(&*wtxn, &entry.series_ref)? else {
            return Ok(());
        };
        let history = self.commitment_series_history_in_txn(&*wtxn, &entry.series_ref)?;
        let occurrences = occurrences_owed(&payload, now, &history)?;
        let mint = SeriesMint {
            series_ref: entry.series_ref,
            record: &record,
            payload: &payload,
            envelope: &commitment_projection_envelope()?,
            learned_at: now,
        };
        self.mint_commitment_instances_in_txn(wtxn, &mint, &occurrences, report)?;
        Ok(())
    }

    /// The successor policy, per schedule kind, for one closed occurrence.
    fn commitment_successors_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        closed: &ClosedInstance,
        envelope: &WriteEnvelope,
        closed_at: u64,
    ) -> ScheduleResult<Vec<EntityId>> {
        // Closing an old instance never revives an edited or dead series.
        let Some((record, payload)) = self.live_series_in_txn(&*wtxn, &closed.series_ref)? else {
            return Ok(Vec::new());
        };
        let mint = SeriesMint {
            series_ref: closed.series_ref,
            record: &record,
            payload: &payload,
            envelope,
            learned_at: closed_at,
        };
        let occurrences = match &payload.schedule {
            // A single promise kept (or not) is finished.
            Schedule::Once { .. } => Vec::new(),
            Schedule::Interval { period, .. } => {
                // Grid-derived from the occurrence that just closed, NEVER from
                // the close instant: anchoring on close time would let a
                // fortnightly retainer drift a little later every cycle.
                let due_at = closed
                    .occurrence
                    .due_at
                    .checked_add(*period)
                    .ok_or(ScheduleError::ArithmeticOverflow)?;
                vec![point_occurrence(due_at)?]
            }
            Schedule::Quota { count, window } => {
                let QuotaWindow::IsoWeek { tz } = window;
                let history = self.commitment_series_history_in_txn(&*wtxn, &closed.series_ref)?;
                self.quota_rollover_in_txn(wtxn, &mint, closed, &history, (*count, tz, closed_at))?
            }
            Schedule::Rrule { .. } => {
                return Err(ScheduleError::RruleNotImplemented {
                    route: CAL_RRULE_ROUTE,
                });
            }
        };
        let mut report = CommitmentProjectionReport::default();
        self.mint_commitment_instances_in_txn(wtxn, &mint, &occurrences, &mut report)
    }

    /// A quota never rolls per completion. The window rolls as a whole, once,
    /// and only when every slot in it is terminal.
    fn quota_rollover_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        mint: &SeriesMint<'_>,
        closed: &ClosedInstance,
        history: &[ScheduleHistoryEntry],
        (count, tz, closed_at): (u32, &str, u64),
    ) -> ScheduleResult<Vec<CommitmentOccurrence>> {
        validate_quota_count(count)?;
        let window_start = closed.occurrence.window.start;
        let slots = history
            .iter()
            .filter(|entry| entry.window.start == window_start)
            .count();
        let open = history
            .iter()
            .any(|entry| entry.window.start == window_start && entry.is_open());
        if open || u32::try_from(slots).unwrap_or(u32::MAX) < count {
            // The window still owes something. Released and superseded slots
            // close without counting as completions, and none of them earns a
            // replacement inside this window.
            return Ok(Vec::new());
        }
        if closed_at > closed.occurrence.window.end {
            // The last slot closed after the local rollover instant: skip
            // forward to the week the close actually happened in, exactly as
            // the evaluator would from `now`. Missed weeks are never
            // back-filled.
            let window = iso_week_window(closed_at, tz)?;
            return quota_window_occurrences(count, window);
        }
        // Closed inside the window: the next week is projected, not minted, so
        // its slots appear when that week opens rather than early.
        let next = iso_week_window(closed.occurrence.window.end.saturating_add(1), tz)?;
        self.store.commitment_due_put_in_txn(
            wtxn,
            &CommitmentDueEntry {
                at: next.start,
                phase: CommitmentDuePhase::Project,
                series_ref: mint.series_ref,
                instance_ref: None,
                occurrence: CommitmentOccurrence::new(next.end, next, 0)?,
            },
        )?;
        Ok(Vec::new())
    }

    /// Mints (or recognizes) one occurrence per entry, with its phase rows.
    fn mint_commitment_instances_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        mint: &SeriesMint<'_>,
        occurrences: &[CommitmentOccurrence],
        report: &mut CommitmentProjectionReport,
    ) -> ScheduleResult<Vec<EntityId>> {
        let mut ids = Vec::with_capacity(occurrences.len());
        for occurrence in occurrences {
            ids.push(self.mint_commitment_instance_in_txn(wtxn, mint, occurrence, report)?);
        }
        Ok(ids)
    }

    fn mint_commitment_instance_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        mint: &SeriesMint<'_>,
        occurrence: &CommitmentOccurrence,
        report: &mut CommitmentProjectionReport,
    ) -> ScheduleResult<EntityId> {
        let instance_ref = commitment_instance_id(&mint.series_ref, occurrence);
        let payload = CommitmentSchedulePayload::instance(
            mint.payload.schedule.clone(),
            mint.payload.lead_seconds,
            mint.series_ref,
            *occurrence,
        );
        let mut record = mint.record.clone();
        record.schedule = payload.encode()?;
        record.status = CommitmentStatus::Open;

        if let Some(existing) = self.instance_occupant_in_txn(&*wtxn, &instance_ref)? {
            if !same_copied_identity(&existing, &record, &payload) {
                return Err(ScheduleError::InstanceIdentityCollision);
            }
            // A matching retry is idempotent and writes nothing: the phase rows
            // this instance already lived through are not resurrected by
            // looking at it again.
            report.already_present_instances.push(instance_ref);
            return Ok(instance_ref);
        }

        let candidate = commitment_claim_candidate(&record)?
            .with_validity(Some(occurrence.window.start), Some(occurrence.window.end));
        self.batch_in()
            .claim_candidate(
                &instance_ref,
                candidate,
                mint.envelope,
                occurrence.window,
                mint.learned_at,
            )
            .apply(wtxn)?;
        self.write_instance_phases_in_txn(wtxn, mint, &instance_ref, occurrence)?;
        report.minted_instances.push(instance_ref);
        Ok(instance_ref)
    }

    /// One row per (instance, phase) plus the durable membership row, all in
    /// the transaction that wrote the instance claim.
    fn write_instance_phases_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        mint: &SeriesMint<'_>,
        instance_ref: &EntityId,
        occurrence: &CommitmentOccurrence,
    ) -> ScheduleResult<()> {
        let due_at = occurrence.due_at;
        // Saturating, not checked: a lead longer than the due instant's
        // distance from the epoch means "visible immediately", which is a
        // sensible answer, unlike a refusal.
        let lead_at = due_at.saturating_sub(mint.payload.lead_seconds());
        for (phase, at) in [
            (CommitmentDuePhase::Lead, lead_at),
            (CommitmentDuePhase::Due, due_at),
            (CommitmentDuePhase::LifecycleDue, due_at),
        ] {
            self.store.commitment_due_put_in_txn(
                wtxn,
                &CommitmentDueEntry {
                    at,
                    phase,
                    series_ref: mint.series_ref,
                    instance_ref: Some(*instance_ref),
                    occurrence: *occurrence,
                },
            )?;
        }
        self.store.commitment_due_put_membership_in_txn(
            wtxn,
            &mint.series_ref,
            occurrence,
            instance_ref,
        )?;
        Ok(())
    }

    /// The series' already-materialized occurrences, as the evaluator sees
    /// them.
    ///
    /// Read from the durable membership rows, not from a scan of live phase
    /// rows: a completed series whose rows have all been consumed must still
    /// look started, or `Once` would re-fire forever and a quota would re-mint
    /// a window it already served.
    fn commitment_series_history_in_txn(
        &self,
        txn: &RoTxn<'_>,
        series_ref: &EntityId,
    ) -> ScheduleResult<Vec<ScheduleHistoryEntry>> {
        let members = self
            .store
            .commitment_due_series_members_in_txn(txn, series_ref)?;
        let mut history = Vec::with_capacity(members.len());
        for (occurrence, instance_ref) in members {
            let mut entry = ScheduleHistoryEntry {
                instance_ref,
                due_at: occurrence.due_at,
                window: occurrence.window,
                ordinal: occurrence.ordinal,
                // A membership row whose claim has gone missing still occupies
                // its slot. Assuming it open is the conservative reading: it
                // keeps the occurrence from being minted twice.
                status: CommitmentStatus::Open,
            };
            if let Some(record) = self.instance_occupant_in_txn(txn, &instance_ref)? {
                entry.status = record.status;
                // The membership key carries no window end; the claim does.
                if let Ok(payload) = CommitmentSchedulePayload::decode(&record.schedule)
                    && let Some(stored) = payload.occurrence
                {
                    entry.window = stored.window;
                }
            }
            history.push(entry);
        }
        Ok(history)
    }

    /// The series claim behind a `series_ref`, when it is still a live, open,
    /// CMT-2 series.
    ///
    /// `Ok(None)` covers every legitimate reason there is nothing to project:
    /// the claim is gone, it was superseded by an edit, it is no longer open,
    /// it is not a commitment at all, or it carries a plain CMT-1 opaque
    /// schedule. None of those is corruption.
    fn live_series_in_txn(
        &self,
        txn: &RoTxn<'_>,
        series_ref: &EntityId,
    ) -> ScheduleResult<Option<(CommitmentRecord, CommitmentSchedulePayload)>> {
        let Some(body) = self.get_claim_in_txn(txn, series_ref)? else {
            return Ok(None);
        };
        if body.lifecycle != ClaimLifecycleStatus::Active {
            return Ok(None);
        }
        let Some(record) = decode_commitment_claim(&body)? else {
            return Ok(None);
        };
        if record.status != CommitmentStatus::Open {
            return Ok(None);
        }
        let Ok(payload) = CommitmentSchedulePayload::decode(&record.schedule) else {
            return Ok(None);
        };
        Ok(payload.is_series().then_some((record, payload)))
    }

    /// Whatever commitment claim already sits on a deterministic instance id.
    ///
    /// An id that is occupied by something which does not read back as a
    /// commitment record is not "absent" — it is a different identity wearing
    /// this id, which is exactly what
    /// [`ScheduleError::InstanceIdentityCollision`] names.
    fn instance_occupant_in_txn(
        &self,
        txn: &RoTxn<'_>,
        instance_ref: &EntityId,
    ) -> ScheduleResult<Option<CommitmentRecord>> {
        if self.get_raw_in(txn, instance_ref)?.is_none() {
            return Ok(None);
        }
        let body = self
            .get_claim_in_txn(txn, instance_ref)
            .map_err(|_| ScheduleError::InstanceIdentityCollision)?
            .ok_or(ScheduleError::InstanceIdentityCollision)?;
        decode_commitment_claim(&body)
            .map_err(|_| ScheduleError::InstanceIdentityCollision)?
            .ok_or(ScheduleError::InstanceIdentityCollision)
            .map(Some)
    }

    /// Grounds the close hook's subject: a CMT-2 INSTANCE whose stored terminal
    /// status agrees with the caller's `outcome`.
    ///
    /// `Ok(None)` means "nothing to react to, but there may be rows to sweep":
    /// the claim is absent, is not a commitment, or carries a plain CMT-1
    /// opaque schedule.
    fn closed_instance_in_txn(
        &self,
        txn: &RoTxn<'_>,
        instance_ref: &EntityId,
        outcome: CommitmentInstanceOutcome,
    ) -> ScheduleResult<Option<ClosedInstance>> {
        let Some(body) = self.get_claim_in_txn(txn, instance_ref)? else {
            return Ok(None);
        };
        let Some(record) = decode_commitment_claim(&body)? else {
            return Ok(None);
        };
        let Ok(payload) = CommitmentSchedulePayload::decode(&record.schedule) else {
            return Ok(None);
        };
        let (Some(series_ref), Some(occurrence)) = (payload.series_ref, payload.occurrence) else {
            return Err(ScheduleError::Invalid(
                "close hook requires commitment instance",
            ));
        };
        if record.status == CommitmentStatus::Open || record.status != outcome.status() {
            // The hook does NOT write the status. A still-open instance, or one
            // whose terminal status contradicts the caller, means the write
            // this hook is supposed to be reacting to never landed.
            return Err(ScheduleError::Invalid(
                "close hook requires terminal instance status",
            ));
        }
        Ok(Some(ClosedInstance {
            series_ref,
            occurrence,
        }))
    }
}

/// The grounded subject of one close hook call.
struct ClosedInstance {
    series_ref: EntityId,
    occurrence: CommitmentOccurrence,
}

/// Decodes a record's schedule as a SERIES payload, refusing a non-open record.
fn series_payload(record: &CommitmentRecord) -> ScheduleResult<CommitmentSchedulePayload> {
    if record.status != CommitmentStatus::Open {
        return Err(ScheduleError::Invalid("commitment series must be open"));
    }
    let payload = CommitmentSchedulePayload::decode(&record.schedule)?;
    if !payload.is_series() {
        return Err(ScheduleError::Invalid(
            "commitment series payload must not name an occurrence",
        ));
    }
    Ok(payload)
}

/// The `Project` row for one series and one computed due instant.
///
/// A quota projects at the START of its window and is owed at the window's
/// inclusive end; everything else projects one lead ahead of its due instant.
fn project_row(
    series_ref: &EntityId,
    payload: &CommitmentSchedulePayload,
    due_at: u64,
) -> ScheduleResult<CommitmentDueEntry> {
    let (at, occurrence) = match &payload.schedule {
        Schedule::Quota { window, .. } => {
            let QuotaWindow::IsoWeek { tz } = window;
            let window = iso_week_window(due_at, tz)?;
            (
                window.start,
                CommitmentOccurrence::new(window.end, window, 0)?,
            )
        }
        _ => (
            due_at.saturating_sub(payload.lead_seconds()),
            point_occurrence(due_at)?,
        ),
    };
    Ok(CommitmentDueEntry {
        at,
        phase: CommitmentDuePhase::Project,
        series_ref: *series_ref,
        instance_ref: None,
        occurrence,
    })
}

/// The occurrences a due `Project` row owes right now.
///
/// A quota owes its whole window at once — one transaction, `count` slots,
/// ordinals `0..count` — because a promise of "three times this week" is one
/// commitment with three openings, not three commitments discovered one at a
/// time. Everything else owes exactly the next grid point.
fn occurrences_owed(
    payload: &CommitmentSchedulePayload,
    now: u64,
    history: &[ScheduleHistoryEntry],
) -> ScheduleResult<Vec<CommitmentOccurrence>> {
    if matches!(payload.schedule, Schedule::Rrule { .. }) {
        // Unreachable through this module's own doors (an rrule series is never
        // indexed), and a stray row must not wedge the projector.
        return Ok(Vec::new());
    }
    let Some(due_at) = next_due(&payload.schedule, now, history)? else {
        return Ok(Vec::new());
    };
    match &payload.schedule {
        Schedule::Quota { count, window } => {
            let QuotaWindow::IsoWeek { tz } = window;
            quota_window_occurrences(*count, iso_week_window(due_at, tz)?)
        }
        _ => Ok(vec![point_occurrence(due_at)?]),
    }
}

fn quota_window_occurrences(
    count: u32,
    window: TimeRange,
) -> ScheduleResult<Vec<CommitmentOccurrence>> {
    validate_quota_count(count)?;
    (0..count)
        .map(|ordinal| CommitmentOccurrence::new(window.end, window, ordinal))
        .collect()
}

/// A non-quota occurrence covers exactly its due instant: the window is the
/// point, so the membership key round-trips it without loss.
fn point_occurrence(due_at: u64) -> ScheduleResult<CommitmentOccurrence> {
    CommitmentOccurrence::new(
        due_at,
        TimeRange {
            start: due_at,
            end: due_at,
        },
        0,
    )
}

/// Whether an existing claim at a deterministic id is the SAME occurrence of
/// the SAME series carrying the SAME copied identity.
///
/// Status is deliberately excluded: an already-closed instance is still the
/// same instance, and a retry that found one must report it rather than accuse
/// it of collision.
fn same_copied_identity(
    existing: &CommitmentRecord,
    minted: &CommitmentRecord,
    payload: &CommitmentSchedulePayload,
) -> bool {
    let Ok(stored) = CommitmentSchedulePayload::decode(&existing.schedule) else {
        return false;
    };
    stored.series_ref == payload.series_ref
        && stored.occurrence == payload.occurrence
        && existing.obligor == minted.obligor
        && existing.beneficiary == minted.beneficiary
        && existing.content == minted.content
        && existing.strength == minted.strength
        && existing.birth_provenance == minted.birth_provenance
}
