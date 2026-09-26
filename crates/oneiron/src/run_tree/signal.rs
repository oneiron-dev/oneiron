//! Durable, branch-addressed Signal inbox. The executor explicitly calls `breakpoint`;
//! admission never runs a step or cancels a leased worker.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{
    AttemptId, AttemptState, CancelRequestOutcome, CancelStanding, LandingTrigger,
    RequestAttemptCancel,
};
use crate::error::{Error, Result};

use super::RunTreeAdapter;

const MAX_SIGNALS: usize = 1024;
const MAX_ASKS: usize = 128;
const MAX_FIELD: usize = 4096;

/// Caller-authenticated control intent; the adapter must resolve the actor and
/// cancel standing before calling this storage door.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSignalInput {
    pub branch: AttemptId,
    pub run_id: String,
    pub key: String,
    pub actor: String,
    pub kind: RunSignalKind,
}

/// No answer variant grants effect confirmation: that remains at the
/// authenticated effect/consent door, not at this message transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunSignalKind {
    Steer {
        instruction: String,
    },
    Interject {
        content: String,
    },
    Cancel {
        standing: CancelStanding,
        reason: Option<String>,
    },
    AskAnswer {
        handle: String,
        who: String,
        answer: String,
        kind: RunAskAnswerKind,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunSignalState {
    Pending,
    Settled,
}

/// A per-branch idempotency receipt, kept after consumption for retry replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunBranchSignal {
    pub key: String,
    pub actor: String,
    pub kind: RunSignalKind,
    pub state: RunSignalState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunAskAnswerKind {
    Word,
    Companion,
    Default,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunAskAnswer {
    pub who: String,
    pub answer: String,
    pub kind: RunAskAnswerKind,
    pub at: u64,
}

/// One question on a durable needs_input handle. The host can display the
/// exact prompt and choices without a live round trip to the worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunAskQuestion {
    pub who: String,
    pub prompt: String,
    pub options: Vec<String>,
    pub deadline: Option<u64>,
}

/// Durable needs_input handle; `answers` may be partial and is readable even
/// after every question was answered. Silence is never treated as consent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunAsk {
    pub handle: String,
    pub questions: Vec<RunAskQuestion>,
    pub answers: Vec<RunAskAnswer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunAskState {
    Pending(RunAsk),
    Ready(RunAsk),
}

fn field(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_FIELD || value.chars().any(char::is_control) {
        return Err(Error::InvalidConfig("invalid run Signal field".into()));
    }
    Ok(())
}

fn validate_questions(questions: &[RunAskQuestion]) -> Result<()> {
    if questions.is_empty() || questions.len() > MAX_ASKS {
        return Err(Error::InvalidConfig("invalid ask questions".into()));
    }
    let mut recipients = std::collections::HashSet::new();
    for question in questions {
        field(&question.who)?;
        field(&question.prompt)?;
        if !recipients.insert(&question.who) || question.options.len() > 16 {
            return Err(Error::InvalidConfig("invalid ask question".into()));
        }
        for option in &question.options {
            field(option)?;
        }
    }
    Ok(())
}

fn live(state: AttemptState) -> bool {
    matches!(state, AttemptState::Leased | AttemptState::Landing)
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
            if existing.questions != questions {
                return Err(Error::InvalidConfig("ask handle reused".into()));
            }
            return Ok(existing.clone());
        }
        if record.asks.len() >= MAX_ASKS {
            return Err(Error::InvalidConfig("ask inbox full".into()));
        }
        let ask = RunAsk {
            handle: handle.into(),
            questions,
            answers: Vec::new(),
        };
        record.asks.push(ask.clone());
        self.save(&mut txn, &record)?;
        txn.commit()?;
        self.vault.store.notify_attempt_observers();
        Ok(ask)
    }

    /// Non-blocking Signal admission. Reusing a key with identical input
    /// returns its original pending/settled receipt; conflicting reuse fails.
    pub fn signal(&self, input: RunSignalInput) -> Result<RunBranchSignal> {
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
        }
        let mut txn = self.vault.store.env.write_txn()?;
        let mut record = self
            .queue
            .get_in_txn(&txn, input.branch)?
            .ok_or_else(|| Error::InvalidConfig("missing Signal branch".into()))?;
        if record.run_id.as_deref() != Some(&input.run_id) {
            return Err(Error::InvalidConfig("Signal run mismatch".into()));
        }
        if let Some(prior) = record.signals.iter().find(|s| s.key == input.key) {
            if prior.actor != input.actor || prior.kind != input.kind {
                return Err(Error::InvalidConfig(
                    "Signal key reused with different intent".into(),
                ));
            }
            return Ok(prior.clone());
        }
        if !live(record.state) {
            return Err(Error::InvalidConfig("Signal branch not live".into()));
        }
        if record.signals.len() >= MAX_SIGNALS {
            return Err(Error::InvalidConfig("Signal inbox full".into()));
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
                let at = crate::ports::recorded_at_in_txn(&self.vault.store, &mut txn)?;
                ask.answers.push(RunAskAnswer {
                    who: who.clone(),
                    answer: answer.clone(),
                    kind: *kind,
                    at,
                });
            }
        }
        let signal = RunBranchSignal {
            key: input.key,
            actor: input.actor,
            kind: input.kind,
            state: RunSignalState::Pending,
        };
        record.signals.push(signal.clone());
        self.save(&mut txn, &record)?;
        txn.commit()?;
        // In sync builds this wakes a subscribed local caller; foreign hosts
        // without that path use the durable peek handle instead.
        self.vault.store.notify_attempt_observers();
        Ok(signal)
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
        for signal in &pending {
            if let RunSignalKind::Cancel { standing, reason } = &signal.kind {
                let now = crate::ports::recorded_at_in_txn(&self.vault.store, &mut txn)?;
                let outcome = self.queue.request_cancel_in_txn(
                    &mut txn,
                    RequestAttemptCancel {
                        id: branch,
                        actor: signal.actor.clone(),
                        standing: *standing,
                        trigger: LandingTrigger::CancelRequest,
                        reason: reason.clone(),
                        now,
                    },
                )?;
                if !matches!(
                    outcome,
                    CancelRequestOutcome::Requested { .. }
                        | CancelRequestOutcome::AlreadyLanding(_)
                ) {
                    return Err(Error::InvalidConfig(
                        "Signal cancel request not accepted".into(),
                    ));
                }
            }
        }
        // request_cancel_in_txn rewrites the same row: reload before settling.
        record = self
            .queue
            .get_in_txn(&txn, branch)?
            .expect("branch existed in transaction");
        for signal in &mut record.signals {
            if signal.state == RunSignalState::Pending
                && matches!(
                    signal.kind,
                    RunSignalKind::Cancel { .. } | RunSignalKind::AskAnswer { .. }
                )
            {
                // Both effects already committed in this transaction (ask at
                // admission, cancel above). Instructions need worker ack.
                signal.state = RunSignalState::Settled;
            }
        }
        if pending.iter().any(|signal| {
            matches!(
                signal.kind,
                RunSignalKind::Cancel { .. } | RunSignalKind::AskAnswer { .. }
            )
        }) {
            self.save(&mut txn, &record)?;
            txn.commit()?;
            self.vault.store.notify_attempt_observers();
        }
        Ok(pending
            .into_iter()
            .map(|mut signal| {
                if matches!(
                    signal.kind,
                    RunSignalKind::Cancel { .. } | RunSignalKind::AskAnswer { .. }
                ) {
                    signal.state = RunSignalState::Settled;
                }
                signal
            })
            .collect())
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
            self.save(&mut txn, &record)?;
            txn.commit()?;
            self.vault.store.notify_attempt_observers();
        }
        Ok(receipt)
    }

    fn save(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &crate::attempt_queue::AttemptRecord,
    ) -> Result<()> {
        let raw = crate::attempt_queue::encode_signal_record(record)?;
        self.vault
            .store
            .attempt_records
            .put(txn, record.id.as_bytes(), &raw)?;
        Ok(())
    }
}

/// Corrupted persisted intent data fails at the read door, not just admission.
pub(crate) fn validate_signal_rows(record: &crate::attempt_queue::AttemptRecord) -> Result<()> {
    if record.signals.len() > MAX_SIGNALS || record.asks.len() > MAX_ASKS {
        return Err(Error::InvalidConfig("invalid Signal inbox size".into()));
    }
    let mut keys = std::collections::HashSet::new();
    for signal in &record.signals {
        field(&signal.key)?;
        field(&signal.actor)?;
        if !keys.insert(&signal.key) {
            return Err(Error::InvalidConfig("duplicate Signal key".into()));
        }
        match &signal.kind {
            RunSignalKind::Steer { instruction } => field(instruction)?,
            RunSignalKind::Interject { content } => field(content)?,
            RunSignalKind::Cancel { standing, reason } => {
                if !standing.may_request() {
                    return Err(Error::InvalidConfig(
                        "invalid Signal cancel standing".into(),
                    ));
                }
                if let Some(reason) = reason {
                    field(reason)?;
                }
            }
            RunSignalKind::AskAnswer {
                handle,
                who,
                answer,
                kind,
            } => {
                field(handle)?;
                field(who)?;
                field(answer)?;
                if !record.asks.iter().any(|ask| {
                    ask.handle == *handle
                        && ask
                            .answers
                            .iter()
                            .any(|a| a.who == *who && a.answer == *answer && a.kind == *kind)
                }) {
                    return Err(Error::InvalidConfig("orphan Signal ask answer".into()));
                }
            }
        }
    }
    let mut handles = std::collections::HashSet::new();
    for ask in &record.asks {
        field(&ask.handle)?;
        if !handles.insert(&ask.handle) {
            return Err(Error::InvalidConfig("duplicate ask handle".into()));
        }
        validate_questions(&ask.questions)?;
        if ask.answers.len() > ask.questions.len() {
            return Err(Error::InvalidConfig("invalid ask answer count".into()));
        }
        let recipients: std::collections::HashSet<_> =
            ask.questions.iter().map(|q| &q.who).collect();
        let mut answered = std::collections::HashSet::new();
        for answer in &ask.answers {
            field(&answer.who)?;
            field(&answer.answer)?;
            if !recipients.contains(&answer.who) || !answered.insert(&answer.who) {
                return Err(Error::InvalidConfig("invalid ask answer recipient".into()));
            }
        }
    }
    Ok(())
}
