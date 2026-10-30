//! Commitment series doors: put, supersede, reconcile and instance close.
//! Entry: `Vault::reconcile_commitment_schedule`. The indexing, minting and close
//! implementation they call stays in `projection`.

use super::*;

impl Vault {
    /// Writes a commitment SERIES and indexes it in one transaction.
    ///
    /// This is the typed door that creates a `Project` row; the generic claim
    /// commit reaches the same row writer for a series it lands. CMT-1's
    /// [`Vault::put_commitment_claim`] still accepts a typed payload and still
    /// stores it faithfully — it simply does not index it, and every reader in
    /// this module treats that stored-but-unindexed claim as ordinary data.
    ///
    /// An rrule series is expanded through [`CAL_RRULE_ROUTE`] from its own
    /// valid-time start; one whose rule names no start from now on is
    /// committed as a claim and nothing else.
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
        self.try_with_write_txn_grouped(|wtxn| {
            self.put_commitment_series_in_txn(
                wtxn, id, record, envelope, valid_time, learned_at, None,
            )
        })
    }

    /// Indexed birth inside a credential door's guarded write transaction.
    pub(crate) fn put_commitment_series_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
        record: &CommitmentRecord,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
        evidence: Option<rmpv::Value>,
    ) -> ScheduleResult<CommitmentSeriesWriteOutcome> {
        let payload = series_payload(record)?;
        if self.get_raw_in(wtxn, id)?.is_some() {
            return Err(ScheduleError::Invalid("commitment claim id already exists"));
        }
        let mut candidate = commitment_claim_candidate(record)?
            .with_validity(Some(occurred.start), Some(occurred.end));
        if let Some(evidence) = evidence {
            candidate = candidate.with_evidence(evidence);
        }
        self.batch_in()
            .claim_candidate(id, candidate, envelope, occurred, learned_at)
            .apply_recording_gate_decisions(wtxn)?;
        self.index_commitment_series_in_txn(wtxn, id, &payload, learned_at)
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
        self.try_with_write_txn_grouped(|wtxn| {
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
        self.try_with_write_txn_grouped(|wtxn| {
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
    /// interval or an rrule that has a next start, a quota's window (its
    /// first pass of slots) for a quota that rolled over past its window end,
    /// none for anything else.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Invalid`] when the named claim is a SERIES or is still
    /// open, or when its terminal status does not match `outcome`.
    /// [`ScheduleError::Calendar`] when an rrule series' rule cannot be
    /// expanded.
    /// [`ScheduleError::ArithmeticOverflow`] when the interval successor would
    /// leave the `u64` time model.
    pub fn on_instance_closed(
        &self,
        instance_ref: &EntityId,
        outcome: CommitmentInstanceOutcome,
        envelope: &WriteEnvelope,
        closed_at: u64,
    ) -> ScheduleResult<Vec<EntityId>> {
        self.try_with_write_txn_grouped(|wtxn| {
            self.on_instance_closed_in_txn(wtxn, instance_ref, outcome, envelope, closed_at)
        })
    }

    /// The same close hook in the transaction that closes the obligation.
    pub(crate) fn on_instance_closed_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        instance_ref: &EntityId,
        outcome: CommitmentInstanceOutcome,
        envelope: &WriteEnvelope,
        closed_at: u64,
    ) -> ScheduleResult<Vec<EntityId>> {
        let Some(closed) = self.closed_instance_in_txn(wtxn, instance_ref, outcome)? else {
            self.store
                .commitment_due_clear_instance_phases_in_txn(wtxn, instance_ref)?;
            return Ok(Vec::new());
        };
        self.store
            .commitment_due_clear_instance_phases_in_txn(wtxn, instance_ref)?;
        // A caller holding a status successor's id still closes the rows the
        // deterministic instance id carries.
        let minted = commitment_instance_id(&closed.series_ref, &closed.occurrence)?;
        if minted != *instance_ref {
            self.store
                .commitment_due_clear_instance_phases_in_txn(wtxn, &minted)?;
        }
        let closed_at = closed
            .learned_at
            .map_or(closed_at, |learned| learned.max(closed_at));
        self.commitment_successors_in_txn(wtxn, &closed, envelope, closed_at)
    }
}
