//! The owner's feedback triage doors: run the sweep now, read a sweep's
//! status, and read or set the skill binding. Each revalidates the owner's
//! proof in the transaction it reads or writes in; none supplies a plan, a
//! lease or a Coach stamp.
use serde::{Deserialize, Serialize};

use super::{
    BINDING, COACH_FEEDBACK_SWEEP_FACET, FeedbackTriageBinding, FeedbackTriageContinuation,
    FeedbackTriageResult, FeedbackTriageSourceRef, HANDOFFS, SOURCES, STALE_BINDING, attempt_id,
    attempt_ref, binding_in_txn, erased, handoff_key,
};
use crate::attempt_queue::{AttemptQueue, AttemptState};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::maintenance::coach::COACH_HOST_QUEUE_KIND;
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::{EntityId, Error, Result, Vault};

/// The owner's change of the binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageBindingRequest {
    /// The SKILL entity to bind; `None` unbinds.
    #[serde(default)]
    pub skill: Option<EntityId>,
    /// The `revision` the owner's surface read: a binding that moved since
    /// is refused, and nothing changes.
    pub seen: u64,
}

/// The owner's run-now ask. It carries no plan, lease or stamp: the
/// production sweep runs.
#[derive(Clone, Debug, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageRunRequest {}

/// The sweep a run-now ask queued, or the queued one it joined.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageRun {
    /// 32 hex: the sweep's attempt.
    pub attempt: EntityId,
}

/// Which sweep's status to read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageStatusRequest {
    /// 32 hex: the sweep's attempt, as the run answered it.
    pub attempt: EntityId,
}

/// One sweep's status, as the owner reads it. The sweep completing is not
/// every triage job finishing: each child names its own state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageStatus {
    /// The sweep's attempt.
    pub attempt: EntityId,
    /// The sweep's queue state.
    pub state: AttemptState,
    /// Whether the sweep settled.
    pub terminal: bool,
    /// The sweep's last error, if any.
    pub last_error: Option<String>,
    /// The binding now.
    pub binding: FeedbackTriageBinding,
    /// Each source's state: its continuation, the walk that last reached
    /// its end, and what stopped it last, with any retry time it named.
    /// Empty before the first sweep.
    pub continuations: Vec<FeedbackTriageContinuation>,
    /// Every GitHub repository `[feedback.triage]` binds now, as
    /// `github:<owner>/<repo>`, in its configured order: one with no entry in
    /// `continuations` was never swept (FIX 7632). Empty when the host does
    /// not name its binding.
    pub bound_sources: Vec<String>,
    /// Each revision the sweep handed off or queued again.
    pub children: Vec<FeedbackTriageChild>,
    /// What holds triage back now, across every sweep.
    pub holds: Vec<FeedbackTriageHold>,
    /// Each unacknowledged revision whose evidence the owner erased, across
    /// every sweep, and each of this sweep's acknowledged ones, in erased
    /// form; none of them is a child or a hold (FIX 8305).
    pub erased: Vec<FeedbackTriageErased>,
}

/// A revision whose evidence ASSET the owner erased, in erased form: its
/// name and any result committed before the erase, with no content,
/// revision digest or evidence id. No sweep queues it again, and its
/// evidence is never retained again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageErased {
    /// The source, as [`FeedbackTriageSourceRef::source`] names it.
    pub source: String,
    /// The item's id in its source, in decimal.
    pub id: String,
    /// Vault seconds a sweep settled it erased; `None` until one does.
    pub erased_at: Option<u64>,
    /// The result committed before the erase; `None` when it was erased
    /// unacknowledged.
    pub result: Option<FeedbackTriageResult>,
}

/// One revision a sweep handed off or queued again, and its triage job.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageChild {
    /// The item and revision.
    pub source_ref: FeedbackTriageSourceRef,
    /// Its evidence ASSET.
    pub evidence: EntityId,
    /// Its current triage job.
    pub attempt: EntityId,
    /// That job's queue state; `None` when the queue holds no such row.
    pub state: Option<AttemptState>,
    /// That job's last error, if any.
    pub last_error: Option<String>,
    /// The committed result; `None` while unacknowledged.
    pub result: Option<FeedbackTriageResult>,
}

/// What holds triage back.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "hold", rename_all = "snake_case")]
pub enum FeedbackTriageHold {
    /// No skill is bound: every sweep and every triage job already queued
    /// completes doing nothing, until the owner binds one.
    SkillUnbound,
    /// A revision handed off with no committed result. A job that failed
    /// is queued again by the next sweep, unless its evidence was erased.
    Unacknowledged {
        /// The item and revision.
        source_ref: FeedbackTriageSourceRef,
        /// Its current triage job.
        attempt: EntityId,
        /// That job's queue state; `None` when the queue holds no such row.
        state: Option<AttemptState>,
        /// That job's last error, if any.
        last_error: Option<String>,
    },
}

/// A stable order for a source's items: an inbox's arrival numbers in
/// numeric order.
fn source_order(source_ref: &FeedbackTriageSourceRef) -> (&str, usize, &str, &str) {
    (
        source_ref.source.as_str(),
        source_ref.id.len(),
        source_ref.id.as_str(),
        source_ref.revision.as_str(),
    )
}

impl Vault {
    /// Queues the Coach's feedback sweep now, coalescing with a sweep
    /// already queued, and answers its attempt. The sweep runs on the bound
    /// skill; with none bound it completes doing nothing, and its status
    /// shows `skill_unbound`.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds; storage errors.
    pub fn queue_feedback_triage(
        &self,
        owner: &AuthenticatedOwner,
        _input: FeedbackTriageRunRequest,
    ) -> Result<FeedbackTriageRun> {
        let now = self.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let outcome = DreamerRunnerStore::new(self).enqueue_kind_in_txn(
                txn,
                COACH_HOST_QUEUE_KIND,
                DreamerAttemptPayload {
                    attempt_type: COACH_FEEDBACK_SWEEP_FACET.into(),
                    input: rmpv::Value::Nil,
                    parent_attempt: None,
                },
                Some(COACH_FEEDBACK_SWEEP_FACET.into()),
                None,
                now,
            )?;
            let status = match outcome {
                EnqueueDreamerAttemptOutcome::Enqueued(status)
                | EnqueueDreamerAttemptOutcome::Existing(status) => status,
            };
            Ok(FeedbackTriageRun {
                attempt: attempt_ref(status.attempt.id)?,
            })
        })
    }

    /// The skill binding the feedback triage runs on.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds; storage errors.
    pub fn feedback_triage_binding(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<FeedbackTriageBinding> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        binding_in_txn(self, &txn)
    }

    /// Binds the SKILL the feedback triage runs, or unbinds it, at the
    /// revision the owner read. Naming the skill bound already changes
    /// nothing and keeps the revision. The skill must be a live SKILL; the
    /// triage job's load checks that it is active and approved.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds; [`Error::ConcurrentWrite`] when `seen`
    /// is not the current revision; a skill that is not a live SKILL;
    /// storage errors.
    pub fn set_feedback_triage_binding(
        &self,
        owner: &AuthenticatedOwner,
        input: &FeedbackTriageBindingRequest,
    ) -> Result<FeedbackTriageBinding> {
        let now = self.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let current = binding_in_txn(self, txn)?;
            if input.seen != current.revision {
                return Err(Error::ConcurrentWrite(STALE_BINDING));
            }
            if current.skill == input.skill {
                return Ok(current);
            }
            if let Some(skill) = &input.skill {
                if !crate::vault::live_entity_row_in_txn(&self.store, txn, skill)?.is_live() {
                    return Err(Error::EntityNotFound);
                }
                self.read_skill_record_in_txn(txn, skill)?;
            }
            let next = FeedbackTriageBinding {
                skill: input.skill,
                revision: current
                    .revision
                    .checked_add(1)
                    .ok_or(Error::IndexOverflow("feedback triage binding revision"))?,
                set_at: Some(now),
            };
            BINDING.put(&self.store, txn, &(), &next)?;
            Ok(next)
        })
    }

    /// One sweep's status: its queue state, the binding, each source's
    /// continuation, each revision it handed off or queued again with its
    /// job's state and committed result, what holds triage back across
    /// every sweep, and each unacknowledged revision whose evidence the
    /// owner erased, by name only. `None` when the queue holds no such
    /// attempt.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds; an attempt that is not a feedback
    /// sweep; storage errors.
    pub fn feedback_triage_status(
        &self,
        owner: &AuthenticatedOwner,
        input: &FeedbackTriageStatusRequest,
    ) -> Result<Option<FeedbackTriageStatus>> {
        owner.revalidate(self)?;
        let Some(sweep) = DreamerRunnerStore::new(self).status(attempt_id(&input.attempt)?)? else {
            return Ok(None);
        };
        if sweep.attempt.kind != COACH_HOST_QUEUE_KIND
            || sweep.payload.attempt_type != COACH_FEEDBACK_SWEEP_FACET
        {
            return Err(Error::InvalidConfig(
                "the attempt is not a feedback triage sweep".into(),
            ));
        }
        let txn = self.store.env.read_txn()?;
        let binding = binding_in_txn(self, &txn)?;
        let continuations = SOURCES
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, continuation)| continuation)
            .collect();
        let queue = AttemptQueue::new(self);
        let mut children = Vec::new();
        let mut holds = Vec::new();
        let mut erased = Vec::new();
        if binding.skill.is_none() {
            holds.push(FeedbackTriageHold::SkillUnbound);
        }
        let mut handoffs = HANDOFFS.scan(&self.store, &txn)?;
        handoffs.sort_by(|(_, a), (_, b)| {
            source_order(&a.source_ref).cmp(&source_order(&b.source_ref))
        });
        for (key, handoff) in handoffs {
            if handoff_key(&handoff.source_ref) != key {
                return Err(Error::CorruptedIndex("feedback triage handoff identity"));
            }
            let mine = handoff.sweep == input.attempt || handoff.queued_by == input.attempt;
            if !mine && handoff.result.is_some() {
                continue;
            }
            // A revision acknowledged before its evidence was erased keeps
            // its result, never its digest or evidence id (FIX 8305).
            if erased::evidence_erased_in_txn(self, &txn, &handoff)? {
                erased.push(FeedbackTriageErased {
                    source: handoff.source_ref.source,
                    id: handoff.source_ref.id,
                    erased_at: handoff.erased_at,
                    result: handoff.result,
                });
                continue;
            }
            let record = queue.get_in_txn(&txn, attempt_id(&handoff.attempt)?)?;
            let state = record.as_ref().map(|record| record.state);
            let last_error = record.and_then(|record| record.last_error);
            if handoff.result.is_none() {
                holds.push(FeedbackTriageHold::Unacknowledged {
                    source_ref: handoff.source_ref.clone(),
                    attempt: handoff.attempt,
                    state,
                    last_error: last_error.clone(),
                });
            }
            if mine {
                children.push(FeedbackTriageChild {
                    source_ref: handoff.source_ref,
                    evidence: handoff.evidence,
                    attempt: handoff.attempt,
                    state,
                    last_error,
                    result: handoff.result,
                });
            }
        }
        Ok(Some(FeedbackTriageStatus {
            attempt: input.attempt,
            state: sweep.attempt.state,
            terminal: sweep.attempt.state.is_terminal(),
            last_error: sweep.attempt.last_error,
            binding,
            continuations,
            bound_sources: Vec::new(),
            children,
            holds,
            erased,
        }))
    }
}
