//! The durable projection layer: series indexing, occurrence minting, and the
//! close hook.
//!
//! This is where the pure evaluator meets LMDB. Three doors, and the split
//! between them is the whole design:
//!
//! * [`Vault::put_commitment_series`] is the typed door that indexes a series,
//!   and the generic claim commit indexes a series it lands through the same
//!   row writer (OF-187). A typed payload written through CMT-1's
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
use crate::claim::{ClaimBody, ClaimLifecycleStatus};
use crate::commitment::{
    CommitmentRecord, CommitmentStatus, commitment_claim_candidate, decode_commitment_claim,
};
use crate::entity_id::EntityId;
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};

mod doors;
mod occurrences;

use occurrences::{
    next_rrule_due, occurrences_named, point_occurrence, project_row, quota_window_slots,
    rrule_dtstart, rrule_search_from,
};

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
    /// The series is an rrule whose rule names no start from now on (its
    /// `COUNT` or `UNTIL` is spent): the claim is stored verbatim and NO due
    /// row was written. `route` expanded it.
    StoredRrule {
        /// The calendar entry point that owns expansion.
        route: &'static str,
    },
    /// The series is stored, but it is Proposed or stale, so NO due row was
    /// written; it projects once approved (FIX 5993).
    StoredAwaitingApproval,
}

/// FIX 5993: only an approved (or Auto) series that is not stale projects; a
/// Proposed or stale one is stored and owes nothing yet. `false` projects
/// every unrejected series, as before.
const PROJECT_ONLY_CONSENTED_SERIES: bool = true;

/// A live, open CMT-2 series: its stored claim, its record and its schedule.
struct LiveSeries {
    body: ClaimBody,
    record: CommitmentRecord,
    payload: CommitmentSchedulePayload,
}

/// The series-side facts one mint needs, bundled so the minting helpers stay
/// under the argument-count bar and cannot be called with a series record and
/// somebody else's payload.
struct SeriesMint<'a> {
    series_ref: EntityId,
    series: &'a LiveSeries,
    envelope: &'a WriteEnvelope,
    learned_at: u64,
}

impl Vault {
    /// Indexes a commitment SERIES that a generic claim write has just landed,
    /// inside that write's transaction (OF-187).
    ///
    /// [`Vault::put_commitment_series`] is the typed door, but a promise is
    /// mostly recorded through the generic claim doors (`vault.remember`,
    /// `vault.claims.upsert`, MCP), which store the schedule faithfully and
    /// index nothing. The generic commit calls this after its own write, so a
    /// promise born there owes its reminders too. Everything that is not a
    /// live, unrejected CMT-2 series passes: a CMT-1 opaque schedule stays
    /// ordinary data, an rrule whose rule has ended stays stored, and a
    /// schedule that already owes nothing (a `Once` in the past) or that the
    /// evaluator refuses indexes nothing and leaves the write alone. Only a
    /// storage failure fails it.
    pub(crate) fn index_landed_commitment_series_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        series_ref: &EntityId,
        now: u64,
    ) -> crate::Result<()> {
        let payload = match self.live_series_in_txn(&*wtxn, series_ref) {
            Ok(Some(series)) => series.payload,
            Ok(None) => return Ok(()),
            Err(ScheduleError::Engine(error)) => return Err(error),
            Err(_) => return Ok(()),
        };
        match self.index_commitment_series_in_txn(wtxn, series_ref, &payload, now) {
            Ok(_) => Ok(()),
            Err(ScheduleError::Engine(error)) => Err(error),
            Err(error) => {
                tracing::info!(
                    series = %series_ref.to_hex(),
                    %error,
                    "commitment series stored without a due index"
                );
                Ok(())
            }
        }
    }

    /// FIX 5993: a series approved, or granted Auto, after it landed projects
    /// from that approval's transaction, through the landed hook above.
    pub(crate) fn index_consented_commitment_series_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim: &ClaimBody,
        series_ref: &EntityId,
        now: u64,
    ) -> crate::Result<()> {
        if !PROJECT_ONLY_CONSENTED_SERIES
            || claim.predicate != crate::commitment::PREDICATE_COMMITMENT_RECORD
        {
            return Ok(());
        }
        self.index_landed_commitment_series_in_txn(wtxn, series_ref, now)
    }

    /// Writes the `Project` row for a series, in the caller's transaction.
    fn index_commitment_series_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        series_ref: &EntityId,
        payload: &CommitmentSchedulePayload,
        now: u64,
    ) -> ScheduleResult<CommitmentSeriesWriteOutcome> {
        let body = self.get_claim_in_txn(&*wtxn, series_ref)?;
        if PROJECT_ONLY_CONSENTED_SERIES
            && let Some(body) = &body
            && !series_projects(body)
        {
            return Ok(CommitmentSeriesWriteOutcome::StoredAwaitingApproval);
        }
        let history = self.commitment_series_history_in_txn(&*wtxn, series_ref)?;
        let due_at = match &payload.schedule {
            // The rule's DTSTART is the series claim's own start, and its next
            // start comes from the calendar layer's one expander (FIX 7848).
            Schedule::Rrule { rrule_string, tz } => {
                let series = body.as_ref().ok_or(ScheduleError::Invalid(
                    "commitment rrule series is not stored",
                ))?;
                let from = rrule_search_from(now, &history)?;
                match next_rrule_due(rrule_string, tz, rrule_dtstart(series)?, from)? {
                    Some(due_at) => due_at,
                    None => {
                        return Ok(CommitmentSeriesWriteOutcome::StoredRrule {
                            route: CAL_RRULE_ROUTE,
                        });
                    }
                }
            }
            schedule => next_due(schedule, now, &history)?.ok_or(ScheduleError::Invalid(
                "commitment series schedule owes no occurrence",
            ))?,
        };
        let entry = project_row(series_ref, payload, due_at)?;
        self.store.commitment_due_put_in_txn(wtxn, &entry)?;
        Ok(CommitmentSeriesWriteOutcome::Indexed {
            project_at: entry.at,
            next_due: entry.occurrence.due_at,
        })
    }

    /// Consumes one due `Project` row and mints the occurrence it names.
    fn project_commitment_series_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        entry: &CommitmentDueEntry,
        now: u64,
        report: &mut CommitmentProjectionReport,
    ) -> ScheduleResult<()> {
        report.projected_series = report.projected_series.saturating_add(1);
        // The row is spent either way. Its successor, if the schedule has one,
        // is a row the CLOSE hook writes (or, for a quota window this pass did
        // not finish, the row below); leaving this one behind would re-mint
        // the same occurrence on every pass forever.
        self.store.commitment_due_delete_in_txn(wtxn, entry)?;

        let Some(series) = self.live_series_in_txn(&*wtxn, &entry.series_ref)? else {
            return Ok(());
        };
        let history = self.commitment_series_history_in_txn(&*wtxn, &entry.series_ref)?;
        let occurrences = occurrences_named(&series.payload, &entry.occurrence, &history)?;
        let mint = SeriesMint {
            series_ref: entry.series_ref,
            series: &series,
            envelope: &commitment_projection_envelope()?,
            learned_at: now,
        };
        self.mint_commitment_instances_in_txn(wtxn, &mint, &occurrences, report)?;
        self.queue_quota_remainder_in_txn(wtxn, &mint, &occurrences, now)
    }

    /// Writes the `Project` row for the rest of a quota window one pass did
    /// not finish, naming the first slot still unminted, due at `at`. Nothing
    /// for any other schedule or a finished window.
    fn queue_quota_remainder_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        mint: &SeriesMint<'_>,
        minted: &[CommitmentOccurrence],
        at: u64,
    ) -> ScheduleResult<()> {
        let Schedule::Quota { count, .. } = &mint.series.payload.schedule else {
            return Ok(());
        };
        let Some(last) = minted.last() else {
            return Ok(());
        };
        let next = last.ordinal.saturating_add(1);
        if next >= *count {
            return Ok(());
        }
        self.store.commitment_due_put_in_txn(
            wtxn,
            &CommitmentDueEntry {
                at,
                phase: CommitmentDuePhase::Project,
                series_ref: mint.series_ref,
                instance_ref: None,
                occurrence: CommitmentOccurrence::new(last.due_at, last.window, next)?,
            },
        )?;
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
        let Some(series) = self.live_series_in_txn(&*wtxn, &closed.series_ref)? else {
            return Ok(Vec::new());
        };
        let mint = SeriesMint {
            series_ref: closed.series_ref,
            series: &series,
            envelope,
            learned_at: closed_at,
        };
        let occurrences = match &series.payload.schedule {
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
            Schedule::Rrule { rrule_string, tz } => {
                // The rule's next start after the occurrence that closed, as
                // an interval steps from it; none once the rule has ended.
                let from = closed
                    .occurrence
                    .due_at
                    .checked_add(1)
                    .ok_or(ScheduleError::ArithmeticOverflow)?;
                let dtstart = rrule_dtstart(&series.body)?;
                match next_rrule_due(rrule_string, tz, dtstart, from)? {
                    Some(due_at) => vec![point_occurrence(due_at)?],
                    None => Vec::new(),
                }
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
            // back-filled. A window larger than one pass mints its first
            // slots here and queues the rest.
            let window = iso_week_window(closed_at, tz)?;
            let slots = quota_window_slots(count, window, 0)?;
            self.queue_quota_remainder_in_txn(wtxn, mint, &slots, closed_at)?;
            return Ok(slots);
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
        let instance_ref = commitment_instance_id(&mint.series_ref, occurrence)?;
        let payload = CommitmentSchedulePayload::instance(
            mint.series.payload.schedule.clone(),
            mint.series.payload.lead_seconds,
            mint.series_ref,
            *occurrence,
        );
        let mut record = mint.series.record.clone();
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

        let candidate = series_scoped(commitment_claim_candidate(&record)?, &mint.series.body)
            .with_validity(Some(occurrence.window.start), Some(occurrence.window.end));
        let mut envelope = mint.envelope.clone();
        self.sign_retained_machine_claim_in_txn(&*wtxn, &instance_ref, &candidate, &mut envelope)?;
        self.batch_in()
            .claim_candidate(
                &instance_ref,
                candidate,
                &envelope,
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
        let lead_at = due_at.saturating_sub(mint.series.payload.lead_seconds());
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
    pub(crate) fn commitment_series_history_in_txn(
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
                entry.status = self.instance_status_in_txn(txn, &instance_ref, record.status)?;
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
    ) -> ScheduleResult<Option<LiveSeries>> {
        let Some(body) = self.get_claim_in_txn(txn, series_ref)? else {
            return Ok(None);
        };
        // A promise the owner rejected, or has not yet approved, owes none.
        if !series_projects(&body) {
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
        Ok(payload.is_series().then_some(LiveSeries {
            body,
            record,
            payload,
        }))
    }

    /// The status an instance holds now: its head's, once a status change
    /// has minted a successor for it (FIX 9726), else the one it stores.
    fn instance_status_in_txn(
        &self,
        txn: &RoTxn<'_>,
        instance_ref: &EntityId,
        stored: CommitmentStatus,
    ) -> ScheduleResult<CommitmentStatus> {
        let head = self.commitment_head_in_txn(txn, instance_ref)?;
        if head == *instance_ref {
            return Ok(stored);
        }
        Ok(self
            .get_claim_in_txn(txn, &head)?
            .as_ref()
            .map(decode_commitment_claim)
            .transpose()?
            .flatten()
            .map_or(stored, |record| record.status))
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
        // The terminal status sits at the head of the instance's status chain.
        let head = self.commitment_head_in_txn(txn, instance_ref)?;
        let Some(body) = self.get_claim_in_txn(txn, &head)? else {
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
        // A successor learned its status when the instance closed; the
        // predecessor's own header still names its birth.
        let learned_at = if head == *instance_ref {
            None
        } else {
            self.entity_header_in_txn(txn, &head)?
                .map(|header| header.learned_at)
        };
        Ok(Some(ClosedInstance {
            series_ref,
            occurrence,
            learned_at,
        }))
    }
}

/// The grounded subject of one close hook call.
struct ClosedInstance {
    series_ref: EntityId,
    occurrence: CommitmentOccurrence,
    /// When the status successor that closed it was learned, if one did.
    learned_at: Option<u64>,
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

/// Whether a series claim may project: active and unrejected, and with
/// [`PROJECT_ONLY_CONSENTED_SERIES`] also Auto or Approved and not stale.
fn series_projects(body: &ClaimBody) -> bool {
    use crate::claim::ClaimApprovalStatus::{Approved, Auto, Rejected};
    body.lifecycle == ClaimLifecycleStatus::Active
        && body.approval != Rejected
        && (!PROJECT_ONLY_CONSENTED_SERIES
            || (matches!(body.approval, Auto | Approved) && !body.stale))
}

/// The series' boundaries on one of its occurrences (FIX 9727): the world,
/// relationship, opaque scope, facet and project the promise was made in, so
/// an instance is never readable wider than the series that owes it.
fn series_scoped(candidate: ClaimCandidate, series: &ClaimBody) -> ClaimCandidate {
    let mut candidate = candidate.with_scope_stamps(series.scope_facet, series.scope_project);
    if let Some(world) = series.world {
        candidate = candidate.with_world(world);
    }
    if let Some(relationship) = series.rel {
        candidate = candidate.with_relationship(relationship);
    }
    if let Some(scope) = &series.scope {
        candidate = candidate.with_scope(scope.clone());
    }
    candidate
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
