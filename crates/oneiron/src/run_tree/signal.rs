//! Durable, branch-addressed Signal inbox. The executor explicitly calls `breakpoint`;
//! admission never runs a step or cancels a leased worker.

use crate::attempt_queue::{
    AttemptId, AttemptState, CancelRequestOutcome, CancelStanding, LandingTrigger, PauseAtBoundary,
    RequestAttemptCancel,
};
use crate::batch::secret_scan::{admitted_from, named_tree};
use crate::error::{Error, Result};
use crate::limit_ask::{EngineLimit, LimitWatch};

use super::RunTreeAdapter;

mod intent;
pub(crate) use intent::SignalIntent;

pub use crate::attempt_queue::run_signal::{
    RunAsk, RunAskAnswer, RunAskAnswerKind, RunAskQuestion, RunAskState, RunBranchSignal,
    RunSignalInput, RunSignalKind, RunSignalState,
};
use crate::attempt_queue::run_signal::{field, validate_questions};

/// A run ask's rows, as `tasks.ask` measures its own: its recipients (one
/// per question), each question's options and its longest option text. A
/// crossing asks whether everything is okay; the ask is kept either way.
fn measure_questions(watch: &LimitWatch, questions: &[RunAskQuestion]) {
    let measured = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    watch.measure(EngineLimit::AskRecipients, measured(questions.len()));
    for question in questions {
        watch.measure(EngineLimit::AskOptions, measured(question.options.len()));
        if let Some(longest) = question.options.iter().map(String::len).max() {
            watch.measure(EngineLimit::AskOptionTextBytes, measured(longest));
        }
    }
}

fn live(state: AttemptState) -> bool {
    matches!(state, AttemptState::Leased | AttemptState::Landing)
}

/// Whether a Pause no step has taken yet stands on `record`'s branch.
pub(crate) fn pause_pending(record: &crate::attempt_queue::AttemptRecord) -> bool {
    record.signals.iter().any(|signal| {
        signal.state == RunSignalState::Pending
            && matches!(signal.kind, RunSignalKind::Pause { .. })
    })
}

impl RunTreeAdapter<'_> {
    /// Subscribe before taking a handle snapshot; on lag, read a fresh snapshot.
    /// An answer commits before this invalidation fires. Foreign hosts without
    /// a local receiver fall back to `peek_ask` on the durable handle.
    #[cfg(feature = "sync")]
    pub fn subscribe_signals(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.queue.subscribe()
    }

    /// Creates an ask under the worker's lease. It is a durable handle: hosts
    /// unable to receive an observer invalidation may read it via `peek_ask`.
    pub fn open_ask(
        &self,
        branch: AttemptId,
        run_id: &str,
        lease_owner: &str,
        attempt_count: u32,
        handle: &str,
        questions: Vec<RunAskQuestion>,
    ) -> Result<RunAsk> {
        field(run_id)?;
        field(handle)?;
        validate_questions(&questions)?;
        let mut txn = self.vault.store.env.write_txn()?;
        let mut record = self
            .queue
            .get_in_txn(&txn, branch)?
            .ok_or_else(|| Error::InvalidConfig("missing Signal branch".into()))?;
        if record.run_id.as_deref() != Some(run_id)
            || !live(record.state)
            || record.lease_owner.as_deref() != Some(lease_owner)
            || record.attempt_count != attempt_count
        {
            return Err(Error::InvalidConfig("ask branch lease mismatch".into()));
        }
        if let Some(existing) = record.asks.iter().find(|ask| ask.handle == handle) {
            // The held questions are as the side-row wall stored them: a
            // secret it lifted reads as its handle there (OF-067).
            if existing.questions != questions
                && !admitted_from(&named_tree(&existing.questions)?, &named_tree(&questions)?)?
            {
                return Err(Error::InvalidConfig("ask handle reused".into()));
            }
            return Ok(existing.clone());
        }
        measure_questions(&self.vault.store.limit_watch, &questions);
        let ask = RunAsk {
            handle: handle.into(),
            questions,
            answers: Vec::new(),
        };
        record.asks.push(ask.clone());
        self.save(&mut txn, &mut record)?;
        txn.commit()?;
        self.vault.store.notify_attempt_observers();
        Ok(ask)
    }

    /// Non-blocking Signal admission. Reusing a key with identical input
    /// returns its original pending/settled receipt, as stored; conflicting
    /// reuse fails. A signal the side-row wall masked matches its identical
    /// retry by the keyed fingerprint kept beside it (FIX 10066).
    ///
    /// A Pause is refused here: only the engine's pause doors post it, in
    /// their own writer ([`Self::signal_in_txn`]).
    pub fn signal(&self, input: RunSignalInput) -> Result<RunBranchSignal> {
        if matches!(input.kind, RunSignalKind::Pause { .. }) {
            return Err(Error::InvalidConfig(
                "a Pause signal is posted only by a pause door".into(),
            ));
        }
        let mut txn = self.vault.store.env.write_txn()?;
        let (stored, landed) = self.signal_in_txn(&mut txn, input)?;
        if landed {
            txn.commit()?;
            // In sync builds this wakes a subscribed local caller; foreign hosts
            // without that path use the durable peek handle instead.
            self.vault.store.notify_attempt_observers();
        }
        Ok(stored)
    }

    /// [`Self::signal`] in the caller's writer (FIX 8533), so a caller can
    /// commit its own record with the signal. Answers the receipt and whether
    /// this call landed it; `false` is a replay of the receipt the key
    /// already holds, which wrote nothing. A caller that commits a landed
    /// signal then wakes the attempt observers.
    pub(crate) fn signal_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: RunSignalInput,
    ) -> Result<(RunBranchSignal, bool)> {
        field(&input.run_id)?;
        field(&input.key)?;
        field(&input.actor)?;
        match &input.kind {
            RunSignalKind::Steer { instruction } => field(instruction)?,
            RunSignalKind::Interject { content } => field(content)?,
            RunSignalKind::Cancel { standing, reason } => {
                if !standing.may_request() {
                    return Err(Error::InvalidConfig("cancel standing required".into()));
                }
                if let Some(reason) = reason {
                    field(reason)?;
                }
                crate::attempt_queue::validate_signal_cancel(&input.actor, reason.as_deref())?;
            }
            RunSignalKind::AskAnswer {
                handle,
                who,
                answer,
                kind: _,
            } => {
                field(handle)?;
                field(who)?;
                field(answer)?;
            }
            RunSignalKind::Pause { note } => {
                if let Some(note) = note {
                    field(note)?;
                }
            }
        }
        let mut record = self
            .queue
            .get_in_txn(txn, input.branch)?
            .ok_or_else(|| Error::InvalidConfig("missing Signal branch".into()))?;
        if record.run_id.as_deref() != Some(&input.run_id) {
            return Err(Error::InvalidConfig("Signal run mismatch".into()));
        }
        if let Some(prior) = record.signals.iter().find(|s| s.key == input.key) {
            if (prior.actor != input.actor || prior.kind != input.kind)
                && !intent::retry_matches(self.vault, txn, &record, &input)
            {
                return Err(Error::InvalidConfig(
                    "Signal key reused with different intent".into(),
                ));
            }
            return Ok((prior.clone(), false));
        }
        if !live(record.state) {
            return Err(Error::InvalidConfig("Signal branch not live".into()));
        }
        if matches!(input.kind, RunSignalKind::Pause { .. }) {
            // A landing run takes no more steps: no boundary would take it.
            if record.state != AttemptState::Leased {
                return Err(Error::InvalidConfig("Pause branch is landing".into()));
            }
            // One boundary takes one pause: a second would pause the run
            // again after its resume.
            if pause_pending(&record) {
                return Err(Error::InvalidConfig(
                    "a Pause is already pending on this branch".into(),
                ));
            }
        }
        if let RunSignalKind::AskAnswer {
            handle,
            who,
            answer,
            kind,
        } = &input.kind
        {
            let ask = record
                .asks
                .iter_mut()
                .find(|a| &a.handle == handle)
                .ok_or_else(|| Error::InvalidConfig("unknown ask handle".into()))?;
            if !ask.questions.iter().any(|q| &q.who == who) {
                return Err(Error::InvalidConfig("unaddressed ask answer".into()));
            }
            if let Some(prior) = ask.answers.iter().find(|a| &a.who == who) {
                if &prior.answer != answer || prior.kind != *kind {
                    return Err(Error::InvalidConfig("ask already answered".into()));
                }
            } else {
                let at = crate::ports::recorded_at_in_txn(&self.vault.store, txn)?;
                ask.answers.push(RunAskAnswer {
                    who: who.clone(),
                    answer: answer.clone(),
                    kind: *kind,
                    at,
                });
                super::ask_wait::signal_waiters_in_txn(
                    self.vault,
                    txn,
                    input.branch,
                    handle,
                    at.saturating_mul(1000),
                )?;
            }
        }
        let intent_bytes = intent::intent_bytes(&input);
        let signal = RunBranchSignal {
            key: input.key,
            actor: input.actor,
            kind: input.kind,
            state: RunSignalState::Pending,
        };
        record.signals.push(signal.clone());
        self.save(txn, &mut record)?;
        // The receipt as the side-row wall stored it, which a retry replays.
        let stored = record
            .signals
            .iter()
            .find(|s| s.key == signal.key)
            .cloned()
            .unwrap_or_else(|| signal.clone());
        if stored != signal
            && let Some(bytes) = intent_bytes
        {
            self.keep_intent_in(txn, &mut record, &stored.key, &bytes);
        }
        Ok((stored, true))
    }

    /// Keeps the keyed fingerprint of a masked signal's exact intent beside
    /// it (FIX 10066), in a savepoint of the admitting writer: a fingerprint
    /// that does not read or a row that does not save again is logged, and
    /// the admission stands without it, so its retries are judged by plain
    /// equality as before.
    fn keep_intent_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &mut crate::attempt_queue::AttemptRecord,
        key: &str,
        bytes: &[u8],
    ) {
        let Some(fingerprint) = intent::fingerprint_in(self.vault, txn, bytes) else {
            return;
        };
        let mut kept = record.clone();
        kept.signal_intents.push(SignalIntent {
            key: key.to_owned(),
            fingerprint,
        });
        let saved = (|| -> Result<()> {
            let mut savepoint = self.vault.store.env.nested_write_txn(txn)?;
            self.save(&mut savepoint, &mut kept)?;
            savepoint.commit()?;
            Ok(())
        })();
        match saved {
            Ok(()) => *record = kept,
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "a masked Signal's intent fingerprint was not kept; plain equality decides"
            ),
        }
    }

    /// Returns partial answers without blocking or consuming them. The caller
    /// parks only its own waiting step when this returns Pending.
    pub fn peek_ask(
        &self,
        branch: AttemptId,
        run_id: &str,
        handle: &str,
    ) -> Result<Option<RunAskState>> {
        let Some(record) = self.queue.get(branch)? else {
            return Ok(None);
        };
        if record.run_id.as_deref() != Some(run_id) {
            return Ok(None);
        }
        Ok(record
            .asks
            .into_iter()
            .find(|ask| ask.handle == handle)
            .map(|ask| {
                if ask.answers.len() == ask.questions.len() {
                    RunAskState::Ready(ask)
                } else {
                    RunAskState::Pending(ask)
                }
            }))
    }

    /// Reads the branch inbox, including settled retry receipts. A run id
    /// mismatch is invisible instead of exposing another run's intent data.
    pub fn read_branch_signals(
        &self,
        branch: AttemptId,
        run_id: &str,
    ) -> Result<Option<Vec<RunBranchSignal>>> {
        let Some(record) = self.queue.get(branch)? else {
            return Ok(None);
        };
        Ok((record.run_id.as_deref() == Some(run_id)).then_some(record.signals))
    }

    /// Withdraws the pending interjections `actor` landed on `branch`, a
    /// branch of run `run_id` that runs no step: one paused, or parked on a
    /// durable wait (or on an outage or its payer). No step of it takes them
    /// while it waits, so each leaves the branch untaken, with its kept
    /// intent, and its actor keeps it where it came from. The branch's state
    /// and park are read in this same writer, so a branch that has resumed
    /// keeps them for its next step, and one that resumes later never takes
    /// them. Answers the keys withdrawn.
    pub(crate) fn withdraw_idle_interjections(
        &self,
        branch: AttemptId,
        run_id: &str,
        actor: &str,
    ) -> Result<Vec<String>> {
        let mut txn = self.vault.store.env.write_txn()?;
        let Some(mut record) = self.queue.get_in_txn(&txn, branch)? else {
            return Ok(Vec::new());
        };
        if record.run_id.as_deref() != Some(run_id) || record.state.is_terminal() {
            return Ok(Vec::new());
        }
        if record.state != AttemptState::Paused
            && crate::dreamer_runner::DreamerRunnerStore::new(self.vault)
                .parked_attempt_in_txn(&txn, branch)?
                .is_none()
        {
            return Ok(Vec::new());
        }
        let mut withdrawn = Vec::new();
        record.signals.retain(|signal| {
            let idle = signal.state == RunSignalState::Pending
                && signal.actor == actor
                && matches!(signal.kind, RunSignalKind::Interject { .. });
            if idle {
                withdrawn.push(signal.key.clone());
            }
            !idle
        });
        if withdrawn.is_empty() {
            return Ok(withdrawn);
        }
        record
            .signal_intents
            .retain(|intent| !withdrawn.contains(&intent.key));
        self.save(&mut txn, &mut record)?;
        txn.commit()?;
        self.vault.store.notify_attempt_observers();
        Ok(withdrawn)
    }

    /// Worker-owned safe breakpoint. A stale lease consumes nothing. Cancel
    /// co-commits the existing soft request receipt; it never force-cancels.
    /// The returned intents are the only instructions this branch should apply.
    /// Steer/interject remain pending until the worker acknowledges their key
    /// AFTER applying it at this breakpoint. A crash before acknowledgment
    /// redelivers the same key, rather than silently losing an instruction.
    pub fn breakpoint(
        &self,
        branch: AttemptId,
        run_id: &str,
        lease_owner: &str,
        attempt_count: u32,
    ) -> Result<Vec<RunBranchSignal>> {
        let mut txn = self.vault.store.env.write_txn()?;
        let mut record = self
            .queue
            .get_in_txn(&txn, branch)?
            .ok_or_else(|| Error::InvalidConfig("missing Signal branch".into()))?;
        if record.run_id.as_deref() != Some(run_id)
            || !live(record.state)
            || record.lease_owner.as_deref() != Some(lease_owner)
            || record.attempt_count != attempt_count
        {
            return Err(Error::InvalidConfig(
                "Signal breakpoint lease mismatch".into(),
            ));
        }
        let pending: Vec<_> = record
            .signals
            .iter()
            .filter(|s| s.state == RunSignalState::Pending)
            .cloned()
            .collect();
        // Each cancel has its own outcome. An unavailable target cannot roll
        // back earlier accepted requests or starve later instructions.
        let mut cancel_results = Vec::new();
        for signal in &pending {
            if let RunSignalKind::Cancel { standing, reason } = &signal.kind {
                let now = crate::ports::recorded_at_in_txn(&self.vault.store, &mut txn)?;
                let state = match self.queue.request_cancel_in_txn(
                    &mut txn,
                    RequestAttemptCancel {
                        id: branch,
                        actor: signal.actor.clone(),
                        standing: *standing,
                        trigger: LandingTrigger::CancelRequest,
                        reason: reason.clone(),
                        now,
                    },
                ) {
                    Ok(
                        CancelRequestOutcome::Requested { .. }
                        | CancelRequestOutcome::AlreadyLanding(_),
                    ) => RunSignalState::Settled,
                    Ok(
                        CancelRequestOutcome::NoStanding(_)
                        | CancelRequestOutcome::NotRunning(_)
                        | CancelRequestOutcome::AlreadySettled(_),
                    ) => RunSignalState::RefusedCancelUnavailable,
                    Err(error) => return Err(error),
                };
                cancel_results.push((signal.key.clone(), state));
            }
        }
        // The cancel rail may have rewritten this same row. Never overwrite
        // its receipts with the pre-request snapshot.
        record = self
            .queue
            .get_in_txn(&txn, branch)?
            .expect("branch existed in transaction");
        for signal in &mut record.signals {
            if signal.state != RunSignalState::Pending {
                continue;
            }
            if matches!(signal.kind, RunSignalKind::AskAnswer { .. }) {
                signal.state = RunSignalState::Settled;
            } else if let Some((_, state)) =
                cancel_results.iter().find(|(key, _)| key == &signal.key)
            {
                signal.state = *state;
            }
        }
        let resolved: Vec<_> = pending
            .into_iter()
            .map(|mut signal| {
                if let Some(row) = record.signals.iter().find(|row| row.key == signal.key) {
                    signal.state = row.state;
                }
                signal
            })
            .collect();
        if resolved
            .iter()
            .any(|signal| signal.state != RunSignalState::Pending)
        {
            self.save(&mut txn, &mut record)?;
            txn.commit()?;
            self.vault.store.notify_attempt_observers();
        }
        Ok(resolved)
    }

    /// Takes the Pause signal `key` a step of the run took, once that
    /// step's checkpoint has committed: in one writer, fenced by the run's
    /// lease, the row moves to `Paused` under a person's pause, its event
    /// naming the signal's actor and note, and the signal settles. A signal
    /// no longer pending (withdrawn by a resume, or settled before) pauses
    /// nothing and answers `false`.
    ///
    /// # Errors
    ///
    /// A missing branch, a run or lease that does not match, a key that is
    /// no Pause; the queue's refusal; storage errors. Each writes nothing.
    pub(crate) fn pause_at_boundary(
        &self,
        branch: AttemptId,
        run_id: &str,
        lease_owner: &str,
        attempt_count: u32,
        key: &str,
    ) -> Result<bool> {
        field(key)?;
        let mut txn = self.vault.store.env.write_txn()?;
        let record = self
            .queue
            .get_in_txn(&txn, branch)?
            .ok_or_else(|| Error::InvalidConfig("missing Signal branch".into()))?;
        if record.run_id.as_deref() != Some(run_id)
            || !live(record.state)
            || record.lease_owner.as_deref() != Some(lease_owner)
            || record.attempt_count != attempt_count
        {
            return Err(Error::InvalidConfig(
                "Signal boundary pause lease mismatch".into(),
            ));
        }
        let Some(signal) = record.signals.iter().find(|s| s.key == key) else {
            return Ok(false);
        };
        let RunSignalKind::Pause { note } = &signal.kind else {
            return Err(Error::InvalidConfig("Signal is no Pause".into()));
        };
        if signal.state != RunSignalState::Pending {
            return Ok(false);
        }
        let now = crate::ports::recorded_at_in_txn(&self.vault.store, &mut txn)?;
        self.queue.pause_at_boundary_in_txn(
            &mut txn,
            PauseAtBoundary {
                id: branch,
                lease_owner: lease_owner.to_owned(),
                attempt_count,
                actor: signal.actor.clone(),
                note: note.clone(),
                now,
            },
        )?;
        // The queue rewrote this same row: settle the signal on its write.
        let mut record = self
            .queue
            .get_in_txn(&txn, branch)?
            .ok_or_else(|| Error::InvalidConfig("missing Signal branch".into()))?;
        for signal in &mut record.signals {
            if signal.key == key {
                signal.state = RunSignalState::Settled;
            }
        }
        self.save(&mut txn, &mut record)?;
        txn.commit()?;
        self.vault.store.notify_attempt_observers();
        Ok(true)
    }

    /// Withdraws the Pause signal `key` from `branch` in the caller's
    /// writer while it is still pending: no step has taken it, and none
    /// will. Its kept intent goes with it. Answers whether it was pending;
    /// one a step took, or one never posted, is left as it is.
    pub(crate) fn withdraw_pause_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        branch: AttemptId,
        key: &str,
    ) -> Result<bool> {
        let Some(mut record) = self.queue.get_in_txn(txn, branch)? else {
            return Ok(false);
        };
        // An ended branch keeps its signals as they were.
        if record.state.is_terminal() {
            return Ok(false);
        }
        let pending = record.signals.iter().any(|signal| {
            signal.key == key
                && signal.state == RunSignalState::Pending
                && matches!(signal.kind, RunSignalKind::Pause { .. })
        });
        if !pending {
            return Ok(false);
        }
        record.signals.retain(|signal| signal.key != key);
        record.signal_intents.retain(|intent| intent.key != key);
        self.save(txn, &mut record)?;
        Ok(true)
    }

    /// Confirms one steer/interject only after the worker has applied it.
    /// Calling this twice returns the same settled receipt. The lease fence
    /// prevents a stale worker from acknowledging a successor's breakpoint.
    pub fn acknowledge_signal(
        &self,
        branch: AttemptId,
        run_id: &str,
        lease_owner: &str,
        attempt_count: u32,
        key: &str,
    ) -> Result<RunBranchSignal> {
        field(key)?;
        let mut txn = self.vault.store.env.write_txn()?;
        let mut record = self
            .queue
            .get_in_txn(&txn, branch)?
            .ok_or_else(|| Error::InvalidConfig("missing Signal branch".into()))?;
        if record.run_id.as_deref() != Some(run_id)
            || !live(record.state)
            || record.lease_owner.as_deref() != Some(lease_owner)
            || record.attempt_count != attempt_count
        {
            return Err(Error::InvalidConfig(
                "Signal acknowledgment lease mismatch".into(),
            ));
        }
        let signal = record
            .signals
            .iter_mut()
            .find(|s| s.key == key)
            .ok_or_else(|| Error::InvalidConfig("unknown Signal key".into()))?;
        if !matches!(
            signal.kind,
            RunSignalKind::Steer { .. } | RunSignalKind::Interject { .. }
        ) {
            return Err(Error::InvalidConfig(
                "Signal does not need acknowledgment".into(),
            ));
        }
        let changed = signal.state == RunSignalState::Pending;
        signal.state = RunSignalState::Settled;
        let receipt = signal.clone();
        if changed {
            self.save(&mut txn, &mut record)?;
            txn.commit()?;
            self.vault.store.notify_attempt_observers();
        }
        Ok(receipt)
    }

    fn save(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &mut crate::attempt_queue::AttemptRecord,
    ) -> Result<()> {
        let raw = crate::attempt_queue::encode_admitted_signal_record(self.vault, txn, record)?;
        self.vault
            .store
            .attempt_records
            .put(txn, record.id.as_bytes(), &raw)?;
        Ok(())
    }
}

pub(crate) use crate::attempt_queue::run_signal::validate_signal_rows;
