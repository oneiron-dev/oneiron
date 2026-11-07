//! The owner's feedback triage doors: run the sweep now, read a sweep's
//! status, and read or set the skill binding. Each revalidates the owner's
//! proof in the transaction it reads or writes in; none supplies a plan, a
//! lease or a Coach stamp.
use serde::{Deserialize, Serialize};

use super::{
    BINDING, COACH_FEEDBACK_SWEEP_FACET, FeedbackTriageBinding, FeedbackTriageContinuation,
    FeedbackTriageHandoffSource, FeedbackTriageResult, FeedbackTriageSourceRef, SOURCES,
    STALE_BINDING, attempt_id, attempt_ref, binding_in_txn, erased, handoff_key,
};
use crate::attempt_queue::{AttemptQueue, AttemptState};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::dreamer_runner::maintenance::coach::COACH_HOST_QUEUE_KIND;
use crate::{EntityId, Error, Result, Vault};

/// The owner's change of the binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageBindingRequest {
    /// The SKILL entity to bind; `None` unbinds.
    #[serde(default)]
    pub skill: Option<EntityId>,
    /// Queue the ordinary sweep on new inbox notes; false keeps batching.
    pub enqueue_on_intake: bool,
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
    /// Each in-flight revision across every sweep: handed off with no
    /// committed result, its job neither failed nor settled (FIX 7553).
    pub pending: Vec<FeedbackTriagePending>,
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
    /// Its part/synthesis progress; `None` for an item triaged whole
    /// (FIX 10307).
    pub progress: Option<FeedbackTriageProgress>,
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

/// One revision handed off with no committed result, its job neither
/// failed nor settled: in flight across every sweep (FIX 7553).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriagePending {
    /// The item and revision.
    pub source_ref: FeedbackTriageSourceRef,
    /// Its current triage job.
    pub attempt: EntityId,
    /// That job's queue state; `None` when the queue holds no such row.
    pub state: Option<AttemptState>,
    /// That job's last error, if any.
    pub last_error: Option<String>,
}

/// One long note's part/synthesis progress, over its current generation's
/// nodes (FIX 10307).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageProgress {
    /// Answered parts.
    pub parts_answered: u32,
    /// Parts in the current generation.
    pub parts_total: u32,
    /// Answered synthesis nodes.
    pub synthesis_answered: u32,
    /// Synthesis nodes in the current generation.
    pub synthesis_total: u32,
}

/// A stable order for a source's items: an inbox's arrival numbers in
/// numeric order.
fn source_order(source: &FeedbackTriageHandoffSource) -> (&str, usize, &str, &str) {
    let (name, id) = source.name();
    let revision = match source {
        FeedbackTriageHandoffSource::Retained { source_ref, .. } => source_ref.revision.as_str(),
        FeedbackTriageHandoffSource::Erased { .. } => "",
    };
    (name, id.len(), id, revision)
}

impl Vault {
    /// Queues the Coach's feedback sweep now, coalescing with a sweep
    /// already queued, and answers its attempt. Joining a running sweep
    /// retains one later ordinary sweep (FIX 7552); waiting work covers the
    /// request without another sweep. The sweep runs on the bound
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
            let status = super::sweep_pending::requested_in_txn(self, txn, now)?;
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

    /// Sets the skill and intake scheduling policy at the revision the
    /// owner read. Keeping both unchanged keeps the revision. A changed
    /// skill must be a live, active, approved shared SKILL; the triage job's
    /// load rechecks it. Disabling intake scheduling leaves admitted work
    /// and manual or nightly sweeps unchanged.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds; [`Error::ConcurrentWrite`] when `seen`
    /// is not the current revision; a skill that is not a live SKILL;
    /// [`Error::InvalidClaimBody`] for an inactive, unapproved or resident-
    /// fork SKILL; storage errors.
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
            if current.skill == input.skill && current.enqueue_on_intake == input.enqueue_on_intake
            {
                return Ok(current);
            }
            if current.skill != input.skill
                && let Some(skill) = &input.skill
            {
                if !crate::vault::live_entity_row_in_txn(&self.store, txn, skill)?.is_live() {
                    return Err(Error::EntityNotFound);
                }
                let record = self.read_skill_record_in_txn(txn, skill)?;
                if crate::skill::resident_of(&record)?.is_some() {
                    return Err(Error::InvalidClaimBody(
                        "skill belongs to a different resident",
                    ));
                }
                if !crate::skill::skill_loadable(&record) {
                    return Err(Error::InvalidClaimBody(
                        "pack load requires an active approved skill",
                    ));
                }
            }
            let next = FeedbackTriageBinding {
                skill: input.skill,
                enqueue_on_intake: input.enqueue_on_intake,
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
    /// every sweep, each in-flight revision across every sweep, and each
    /// unacknowledged revision whose evidence the owner erased, by name
    /// only. `None` when the queue holds no such attempt.
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
        let mut pending = Vec::new();
        let mut erased = Vec::new();
        if binding.skill.is_none() {
            holds.push(FeedbackTriageHold::SkillUnbound);
        }
        // The open rows and this sweep's own, not every handoff (FIX 7550).
        let keys = super::handoff_index::status_keys(&self.store, &txn, &input.attempt)?;
        let mut handoffs = super::handoff_index::rows(&self.store, &txn, keys)?;
        handoffs.sort_by(|(_, a), (_, b)| source_order(&a.source).cmp(&source_order(&b.source)));
        for (key, handoff) in handoffs {
            if let FeedbackTriageHandoffSource::Retained { source_ref, .. } = &handoff.source
                && handoff_key(source_ref) != key
            {
                return Err(Error::CorruptedIndex("feedback triage handoff identity"));
            }
            let mine = handoff.sweep == input.attempt || handoff.queued_by == input.attempt;
            if !mine && handoff.result.is_some() {
                continue;
            }
            // A revision acknowledged before its evidence was erased keeps
            // its result, never its digest or evidence id (FIX 8305).
            if erased::evidence_erased_in_txn(self, &txn, &handoff)? {
                let (source, id) = handoff.source.name();
                erased.push(FeedbackTriageErased {
                    source: source.to_owned(),
                    id: id.to_owned(),
                    erased_at: handoff.erased_at(),
                    result: handoff.result,
                });
                continue;
            }
            let (source_ref, evidence) = handoff.retained()?;
            let record = queue.get_in_txn(&txn, attempt_id(&handoff.attempt)?)?;
            let state = record.as_ref().map(|record| record.state);
            let last_error = record.and_then(|record| record.last_error);
            if handoff.result.is_none() {
                // In flight (FIX 7553): a job neither failed nor settled
                // waits in `pending`, never in `holds`.
                if state.is_some_and(|s| !s.is_terminal()) {
                    pending.push(FeedbackTriagePending {
                        source_ref: source_ref.clone(),
                        attempt: handoff.attempt,
                        state,
                        last_error: last_error.clone(),
                    });
                } else {
                    holds.push(FeedbackTriageHold::Unacknowledged {
                        source_ref: source_ref.clone(),
                        attempt: handoff.attempt,
                        state,
                        last_error: last_error.clone(),
                    });
                }
            }
            if mine {
                // The current generation's part/synthesis progress (FIX
                // 10307): parts sit at level 0, synthesis above; retired
                // generations stay out.
                let progress = handoff.work.as_ref().map(|work| {
                    let mut parts_answered = 0;
                    let mut parts_total = 0;
                    let mut synthesis_answered = 0;
                    let mut synthesis_total = 0;
                    for node in &work.nodes {
                        if node.level == 0 {
                            parts_total += 1;
                            if node.answer.is_some() {
                                parts_answered += 1;
                            }
                        } else {
                            synthesis_total += 1;
                            if node.answer.is_some() {
                                synthesis_answered += 1;
                            }
                        }
                    }
                    FeedbackTriageProgress {
                        parts_answered,
                        parts_total,
                        synthesis_answered,
                        synthesis_total,
                    }
                });
                children.push(FeedbackTriageChild {
                    source_ref: source_ref.clone(),
                    evidence,
                    attempt: handoff.attempt,
                    state,
                    last_error,
                    result: handoff.result,
                    progress,
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
            pending,
            erased,
        }))
    }
}
