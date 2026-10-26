//! The two cancel rungs' effects in the writer that applies them, once the
//! gate allowed the cancel: the soft cancel of a TASK's or a spawn's live
//! realizations and the owner's force of a TASK's (ONE-1896).
//! Entry: `Memory::soft_cancel_in`, `Memory::force_cancel_task_in`.

use super::*;

impl Memory<'_> {
    /// The owner's force of every live realization of `task_ref`, in `wtxn`,
    /// once the gate allowed it and the TASK's owner was verified there:
    /// answers how many it stopped.
    pub(in crate::task_verb) fn force_cancel_task_in(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task_ref: EntityId,
        reason: Option<String>,
        now: u64,
    ) -> MemoryResult<usize> {
        let authority = ForceCancelAuthority::owner(self.actor().to_hex().as_str())
            .map_err(MemoryError::from)?;

        let queue = AttemptQueue::new(self.vault());
        let records = queue.list_task_in_write_txn(&*wtxn, task_ref.to_hex().as_str())?;
        let superseded = superseded_attempt_ids(&records);
        let mut forced_count = 0usize;
        for record in &records {
            if superseded.contains(&record.id) || record.state.is_terminal() {
                continue;
            }
            let outcome = queue.force_cancel_in_txn(
                wtxn,
                ForceAttemptCancel {
                    id: record.id,
                    authority: authority.clone(),
                    reason: reason.clone(),
                    now,
                },
            )?;
            if matches!(outcome, ForceCancelOutcome::Cancelled(_)) {
                forced_count += 1;
            }
        }
        // Only a force that really stopped something records one: the
        // Cancelled fact is a cancellation that happened, never an
        // attempt to cancel.
        if forced_count > 0 {
            cancel_task_in_txn(self.vault(), wtxn, task_ref, self.actor(), now)?;
        }
        Ok(forced_count)
    }

    /// The soft cancel of `state`'s target, in `wtxn`, once the gate allowed
    /// it: whether it stopped anything, the status it leaves, and whether a
    /// running realization was asked to land.
    pub(in crate::task_verb) fn soft_cancel_in(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        state: &CancelTargetState,
        now: u64,
    ) -> MemoryResult<(bool, Option<RunTreeStatus>, bool)> {
        // P1-b (TOCTOU): decide on transaction-current attempt state,
        // not the pre-txn snapshot. A `Leased`→`Queued` requeue (lease
        // cleanup / timeout) between the snapshot and this write txn
        // must be acted on as its live state; otherwise the now-Queued
        // attempt survives a "successful" cancel and stays claimable.
        let queue = AttemptQueue::new(self.vault());
        let live_attempts: Vec<(AttemptId, AttemptState)> = match state.task_ref {
            // Membership TOCTOU: a retry mints a NEW row under the same
            // `task_ref` and finalizes its source as `Failed`, so
            // re-reading only the snapshotted IDS would see the dead
            // source, report the task terminally failed, cancel
            // nothing, and leave the live successor to run and send. A
            // TASK target therefore re-derives its realizing SET here,
            // reduced to retry-chain heads.
            Some(task_ref) => {
                let records = queue.list_task_in_write_txn(&*wtxn, task_ref.to_hex().as_str())?;
                let superseded = superseded_attempt_ids(&records);
                records
                    .iter()
                    .filter(|record| !superseded.contains(&record.id))
                    .map(|record| (record.id, record.state))
                    .collect()
            }
            // A spawn realization carries no TASK backlink to re-derive
            // membership from, so its single row is re-read by id.
            None => {
                let mut attempts = Vec::with_capacity(state.attempts.len());
                for (attempt_id, snapshot_state) in &state.attempts {
                    match queue.get_in_write_txn(&*wtxn, *attempt_id)? {
                        Some(record) => attempts.push((*attempt_id, record.state)),
                        // Preserve an already-terminal spawn snapshot
                        // when the in-txn lookup cannot surface its
                        // row; terminal states cannot transition again.
                        None if matches!(
                            snapshot_state,
                            AttemptState::Completed
                                | AttemptState::Failed
                                | AttemptState::Cancelled
                        ) =>
                        {
                            attempts.push((*attempt_id, *snapshot_state));
                        }
                        None => {}
                    }
                }
                attempts
            }
        };

        // P1-a (leased-cancel honesty): a running realization cannot be
        // stopped in this txn and its local/outbound work keeps running.
        // Report the honest partial — do NOT hide the task and do NOT
        // claim effect while a live lease remains; the task stays
        // VISIBLE (it folds to Running under its live lease) until the
        // lease releases. A Queued+Leased mix is uneffected too: nothing
        // is intervened and nothing is hidden, so the receipt never
        // conceals live work.
        //
        // ONE-1896: it is no longer a dead end. The gate has already
        // ALLOWED an owner-scoped cancel, which is standing to ASK, so
        // the running worker gets a durable soft `cancel.request` and
        // must answer it by landing or by refusing with a reason.
        // `effected` stays false — nothing stopped yet — and the receipt
        // says a request was made rather than pretending the attempt was
        // synchronously killed.
        let running: Vec<AttemptId> = live_attempts
            .iter()
            .filter(|(_, attempt_state)| is_running_attempt_state(*attempt_state))
            .map(|(attempt_id, _)| *attempt_id)
            .collect();
        let has_running = !running.is_empty();
        let mut cancel_requested = false;
        for attempt_id in running {
            let outcome = queue.request_cancel_in_txn(
                wtxn,
                RequestAttemptCancel {
                    id: attempt_id,
                    actor: self.actor().to_hex(),
                    standing: CancelStanding::Authority,
                    trigger: LandingTrigger::CancelRequest,
                    reason: None,
                    now,
                },
            )?;
            if matches!(
                outcome,
                CancelRequestOutcome::Requested { .. } | CancelRequestOutcome::AlreadyLanding(_)
            ) {
                cancel_requested = true;
            }
        }

        // A `Scheduled` retry is live work waiting on its instant: it
        // cancels exactly like a queued one. Omitting it would report
        // the task terminal off its failed source row while the next
        // try still ran and sent.
        //
        // ONE-1896: this walk runs even when a sibling is RUNNING or
        // LANDING. Returning early there left every queued, paused and
        // scheduled sibling of a landing parent alive and claimable —
        // an owner-approved cancel that stopped nothing while the
        // receipt said the target was handled. The running sibling is
        // still only ASKED (it holds the lease), so the two rungs
        // compose: ask what can answer, stop what cannot.
        let terminal_status = terminal_attempt_status(&live_attempts);
        let mut cancelled_count = 0usize;
        for (attempt_id, attempt_state) in &live_attempts {
            if !is_cancelable_attempt_state(*attempt_state) {
                continue;
            }
            let outcome = queue.intervene_in_txn(
                wtxn,
                InterveneAttempt {
                    id: *attempt_id,
                    kind: AttemptInterventionKind::Cancel,
                    actor: self.actor().to_hex(),
                    note: None,
                    now,
                },
            )?;
            match outcome.effect {
                AttemptInterventionEffect::Cancelled => cancelled_count += 1,
                AttemptInterventionEffect::AlreadyCancelled => {}
                _ => {
                    return Err(MemoryError::from(Error::InvariantViolation(
                        "cancel.effect",
                    )));
                }
            }
        }
        if has_running {
            // A live lease remains, so the TASK stays VISIBLE and folds
            // to Running: it is not hidden and the whole target is not
            // claimed cancelled. `effected` is still honest — it names
            // the siblings this call really did stop.
            return Ok((
                cancelled_count > 0,
                Some(RunTreeStatus::Running),
                cancel_requested,
            ));
        }
        if cancelled_count == 0 {
            // An allowed cancel of an open TASK with no local attempt
            // (a human, peer or child addressed one) cancels the TASK
            // itself (FIX 10185): its Cancelled fact is the effect. A
            // settled or already cancelled TASK answers as before.
            if live_attempts.is_empty()
                && let Some(task_ref) = state.task_ref
                && !self
                    .vault()
                    .task_authority_facts_in(&*wtxn, task_ref)?
                    .cancelled
                && super::wire_decode::task_verb_body_in(self.vault(), &*wtxn, task_ref)?
                    .is_some_and(|body| body.terminal().is_none())
            {
                cancel_task_in_txn(self.vault(), wtxn, task_ref, self.actor(), now)?;
                return Ok((true, Some(RunTreeStatus::Cancelled), false));
            }
            return Ok((false, terminal_status, false));
        }
        // A Completed/Failed sibling remains real terminal work. Keep
        // its TASK intent visible so the unchanged job stays folded
        // exactly once, and surface that aggregate terminal status
        // instead of claiming the whole target was cancelled.
        let preserved_terminal_status = terminal_status
            .filter(|status| matches!(status, RunTreeStatus::Completed | RunTreeStatus::Failed));
        // The Cancelled fact rides the SAME transaction as the
        // interventions that made it true, and is reached only after
        // `cancelled_count > 0`: the fact records a cancellation that
        // really happened, never an intent to cancel.
        if preserved_terminal_status.is_none()
            && let Some(task_ref) = state.task_ref
        {
            cancel_task_in_txn(self.vault(), wtxn, task_ref, self.actor(), now)?;
        }
        Ok((
            true,
            preserved_terminal_status.or(Some(RunTreeStatus::Cancelled)),
            false,
        ))
    }
}
