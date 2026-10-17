//! Exits from Blocked an owner can drive (OF-220).
//!
//! An engine block that would leave nobody to ask opens a real owner ask:
//! one engine-authored question CLAIM holds its label and a typed
//! continuation, and the ordinary ask admission asks it. An escalation ask
//! that holds a block carries the same continuation beside it, under the
//! same id. Either ask's group ref sits in the TASK's `Blocked.on`; that ref
//! is the currency check.
//!
//! When such an ask settles, its continuation moves the TASK once: met
//! lands the saved result, unmet requeues, proceed resumes, stop fails it.
//! A hold, an unknown or no answer changes nothing and is never recorded as
//! the owner's permission. Asks an agent supplied itself carry no
//! continuation; the agent's Progress is their exit.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

use super::ask_record;
use super::ask_types::{
    TaskAskDecision, TaskAskEvidenceReason, TaskAskHandle, TaskAskOptionId, TaskAskQuestion,
    TaskAskResult, TaskAskSpec, TaskAskTarget,
};
use super::brief::StoredBrief;
use super::consts::{
    TASK_BLOCK_QUESTION_ID_DOMAIN, TASK_BLOCK_QUESTION_PREDICATE, TASK_EXTERNAL_ATTEMPT_KIND,
};
use super::consult_payload::ConsultPayloadRef;
use super::highway::{attempt_hex, not_found};
use super::highway_post::envelope_actor_class;
use super::highway_report::{
    DONE_MET_OPTION, DONE_UNMET_OPTION, fail_final_in, fail_unmet_in, land_done_in, requeue,
    short_digest,
};
use super::terminal_state::TaskExecutionState;
use super::wire_decode::{task_body_optional, task_verb_body_in};
use super::wire_encode::canonical_bytes;

/// The option a blocked TASK's owner ask settles on to resume the work.
const BLOCK_PROCEED_OPTION: &str = "proceed";
/// The option a blocked TASK's owner ask settles on to stop it.
const BLOCK_STOP_OPTION: &str = "stop";
/// Failure reason of a TASK its owner stopped.
const BLOCK_STOPPED_REASON: &str = "stopped at the owner's answer";

/// What a blocked TASK waits on its owner for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum BlockPurpose {
    /// A result whose done-means is the owner's call, under the brief
    /// revision it was judged against.
    Done {
        result_ref: EntityId,
        brief_rev: u32,
    },
    /// Work its taker cannot go on with without the owner.
    Blocked,
}

/// The typed continuation one engine-opened ask on a blocked TASK runs when
/// it settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BlockContinuation {
    pub(super) task: EntityId,
    pub(super) purpose: BlockPurpose,
    /// The try that blocked, when its lane has one: an external or a runner
    /// try. A person's take has none.
    #[serde(default)]
    pub(super) attempt: Option<AttemptId>,
    pub(super) attempt_count: u32,
}

/// The option a settled ask chose: the chosen word's option under a first
/// decision, or the decided option. Anything else chose nothing.
pub(super) fn selected_task_ask_option(result: &TaskAskResult) -> Option<&TaskAskOptionId> {
    match &result.decision {
        TaskAskDecision::Answer(option) => Some(option),
        TaskAskDecision::First(answer) => result
            .evidence
            .iter()
            .find(|entry| entry.answer == *answer && entry.reason == TaskAskEvidenceReason::Counted)
            .and_then(|entry| entry.word.option.as_ref()),
        TaskAskDecision::Collected
        | TaskAskDecision::No
        | TaskAskDecision::Conflict
        | TaskAskDecision::Unknown => None,
    }
}

/// The question a block's owner ask puts.
pub(super) fn block_question_label(
    brief: &StoredBrief,
    purpose: &BlockPurpose,
    note: Option<&str>,
) -> String {
    let objective = &brief.brief.objective;
    match (purpose, note) {
        (BlockPurpose::Done { .. }, _) => format!(
            "Done means met for \"{objective}\"? {}",
            brief.brief.success.question
        ),
        (BlockPurpose::Blocked, Some(note)) => {
            format!("\"{objective}\" is blocked: {note} Proceed or stop?")
        }
        (BlockPurpose::Blocked, None) => format!("\"{objective}\" is blocked. Proceed or stop?"),
    }
}

/// The id of a block's question CLAIM, derived from its ask group.
fn block_question_id(group: EntityId) -> Result<EntityId> {
    EntityId::derive(TASK_BLOCK_QUESTION_ID_DOMAIN, &[group.as_bytes()])
}

/// The owner ask's intent key: the TASK, the purpose, the try that blocked
/// and the report, so a replayed report finds the same ask and a later try
/// asks anew.
fn block_intent_key(continuation: &BlockContinuation, key: &str) -> String {
    let purpose = match continuation.purpose {
        BlockPurpose::Done { .. } => "done",
        BlockPurpose::Blocked => "blocked",
    };
    let attempt = continuation
        .attempt
        .map_or_else(|| "none".to_owned(), attempt_hex);
    format!(
        "tasks.block/{}/{purpose}/{attempt}:{}/{}",
        continuation.task.to_hex(),
        continuation.attempt_count,
        short_digest(key)
    )
}

/// Who the owner ask goes to: the brief's escalation target when it names
/// anyone, else the TASK's owner.
fn block_ask_target(to: &TaskAskTarget, owner: EntityId) -> TaskAskTarget {
    match to {
        TaskAskTarget::People(people) if people.is_empty() => {
            TaskAskTarget::People(std::iter::once(owner).collect())
        }
        to => to.clone(),
    }
}

fn continuation_value(continuation: &BlockContinuation) -> MemoryResult<Value> {
    let encoded = rmp_serde::to_vec_named(continuation)
        .map_err(|_| MemoryError::bad_request("block continuation does not encode"))?;
    rmpv::decode::read_value(&mut encoded.as_slice())
        .map_err(|_| MemoryError::bad_request("block continuation does not encode"))
}

fn decode_continuation(value: &Value) -> Option<BlockContinuation> {
    let Value::Map(entries) = value else {
        return None;
    };
    let continuation = task_body_optional(entries, "continuation").ok()??;
    rmp_serde::from_slice(&canonical_bytes(continuation)).ok()
}

fn continuation_refusal(error: MemoryError) -> Error {
    Error::InvalidConfig(format!(
        "blocked task continuation refused: {}",
        error.message
    ))
}

impl Memory<'_> {
    /// Persists one block's question CLAIM under the id its ask group
    /// derives: the label text and the typed continuation. Written once; a
    /// replay finds it.
    pub(super) fn put_block_question_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        group: EntityId,
        continuation: &BlockContinuation,
        label: &str,
    ) -> MemoryResult<EntityId> {
        let id = block_question_id(group)?;
        if self.vault().get_raw_in(txn, &id)?.is_some() {
            return Ok(id);
        }
        let now = self.vault().store.clock.now_recorded_at();
        let value = Value::Map(vec![
            (Value::from("label"), Value::from(label)),
            (Value::from("group_ref"), Value::from(group.to_hex())),
            (
                Value::from("continuation"),
                continuation_value(continuation)?,
            ),
        ]);
        let mut candidate = ClaimCandidate::new(
            TASK_BLOCK_QUESTION_PREDICATE,
            ClaimSubject::Entity(continuation.task),
            value,
            1.0,
        );
        // Born where its writer's TASK would be, as a parked proposal is.
        let position = self.birth_position();
        if let Some(world) = position.claim_world() {
            candidate = candidate.with_world(world);
        }
        if let Some(facet) = position.facet {
            candidate = candidate.with_scope_stamps(facet, crate::claim::default_project_id());
        }
        let envelope = WriteEnvelope::new(
            WriteActor::new(self.actor(), self.actor_class()),
            ClaimSource::Generated,
            WriteProvenance::new(Value::Map(vec![
                (Value::from("surface"), Value::from("tasks.highway")),
                (
                    Value::from("verb"),
                    Value::from(TASK_BLOCK_QUESTION_PREDICATE),
                ),
                (
                    Value::from("task_ref"),
                    Value::from(continuation.task.to_hex()),
                ),
            ]))?,
            ClaimApprovalStatus::Proposed,
        );
        self.vault()
            .batch_in()
            .claim_candidate(
                &id,
                candidate,
                &envelope,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
            .apply(txn)?;
        Ok(id)
    }

    /// Opens the owner ask one engine block owes, inside `txn`: its question
    /// CLAIM, then the ordinary ask admission. Admission's read-only rules
    /// run before either write, and an actor they refuse (a propose-only
    /// one among them) opens nothing: the refusal comes back for the
    /// receipt. A replayed report finds its first ask.
    pub(super) fn open_block_ask_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        task_ref: EntityId,
        brief: &StoredBrief,
        continuation: &BlockContinuation,
        key: &str,
        note: Option<&str>,
    ) -> MemoryResult<std::result::Result<TaskAskHandle, MemoryError>> {
        let Some(authority) = self.vault().task_authority_state_in(txn, task_ref)? else {
            return Ok(Err(not_found()));
        };
        let rule = &brief.brief.escalation;
        let label = block_question_label(brief, &continuation.purpose, note);
        let intent_key = block_intent_key(continuation, key);
        let group = ask_record::group_id(self.vault(), txn, self.actor(), &intent_key)?;
        let mut question =
            TaskAskQuestion::new(ConsultPayloadRef::Claim(block_question_id(group)?));
        question.label = Some(label.clone());
        let options = match continuation.purpose {
            BlockPurpose::Done { .. } => [
                (DONE_MET_OPTION, "Done means met"),
                (DONE_UNMET_OPTION, "Done means not met"),
            ],
            BlockPurpose::Blocked => [
                (BLOCK_PROCEED_OPTION, "Proceed"),
                (BLOCK_STOP_OPTION, "Stop"),
            ],
        };
        for (option, text) in options {
            question
                .options
                .insert(TaskAskOptionId::new(option)?, text.to_owned());
        }
        if matches!(continuation.purpose, BlockPurpose::Done { .. }) {
            question.outcome_binding = brief.brief.success.outcome_binding.clone();
        }
        let mut spec = TaskAskSpec::shorthand(
            Some(block_ask_target(&rule.to, authority.owner_ref)),
            question,
            rule.until,
            rule.default,
        );
        spec.intent_key = intent_key;
        spec.task_ref = Some(task_ref);
        if ask_record::read_group(self.vault(), txn, group)?.is_none() {
            if let Err(refusal) = self.ask_admits_in(txn, &spec) {
                return Ok(Err(refusal));
            }
            self.put_block_question_in_txn(txn, group, continuation, &label)?;
        }
        Ok(Ok(self.tasks_ask_composed_in_txn(txn, &spec, None)?.handle))
    }
}

/// The try a continuation names, while that same try still holds its
/// lease on the TASK.
fn held_try_in(
    queue: &AttemptQueue<'_>,
    txn: &heed::RoTxn<'_>,
    continuation: &BlockContinuation,
    task_ref: EntityId,
) -> Result<Option<AttemptRecord>> {
    let Some(attempt) = continuation.attempt else {
        return Ok(None);
    };
    let task_hex = task_ref.to_hex();
    Ok(queue.get_in_txn(txn, attempt)?.filter(|record| {
        record.state.is_running()
            && record.attempt_count == continuation.attempt_count
            && record.task_ref.as_deref() == Some(task_hex.as_str())
    }))
}

/// The typed continuation of a settled ask (OF-220), run in the
/// transaction that settled it and again on every replay. It acts only on
/// an ask an engine block opened, only while its TASK is still Blocked with
/// this group in `on`, and only on a chosen option; so it moves the TASK
/// once. The TASK comes from the group's own typed task link, or else the
/// continuation's.
pub(super) fn continue_blocked_task_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    group_ref: EntityId,
    result: &TaskAskResult,
    now: u64,
) -> Result<()> {
    let Some(option) = selected_task_ask_option(result) else {
        return Ok(());
    };
    let Some(claim) = vault.get_claim_in_txn(txn, &block_question_id(group_ref)?)? else {
        return Ok(());
    };
    if claim.predicate != TASK_BLOCK_QUESTION_PREDICATE {
        return Ok(());
    }
    let Some(continuation) = decode_continuation(&claim.value) else {
        return Ok(());
    };
    let Some(group) = ask_record::read_group(vault, txn, group_ref)? else {
        return Ok(());
    };
    // The asker wrote the continuation, and the group's task link, when it
    // has one, names the same TASK.
    let asker = ask_record::entity(&group.owner)?;
    if crate::claim::session_claim_producer(&claim) != Some(asker) {
        return Ok(());
    }
    let task_ref = match group.class_tasks().next() {
        Some(task) if task != continuation.task => return Ok(()),
        Some(task) => task,
        None => continuation.task,
    };
    let Some(mut body) = task_verb_body_in(vault, txn, task_ref)? else {
        return Ok(());
    };
    if !matches!(
        &body.state,
        Some(TaskExecutionState::Blocked { on, .. }) if on.contains(&group_ref)
    ) || vault
        .task_standing_in(txn, task_ref)?
        .is_none_or(|standing| standing.cancelled)
    {
        return Ok(());
    }
    let Some(class) = envelope_actor_class(&claim) else {
        return Ok(());
    };
    let queue = AttemptQueue::new(vault);
    let held = held_try_in(&queue, txn, &continuation, task_ref)?;
    // Only an external try settles here; a runner settles its own.
    let external = held
        .as_ref()
        .filter(|record| record.kind == TASK_EXTERNAL_ATTEMPT_KIND)
        .and_then(|record| record.lease_owner.as_deref().map(|owner| (record, owner)));
    let moved = match (continuation.purpose, option.as_str()) {
        (BlockPurpose::Done { result_ref, .. }, DONE_MET_OPTION) => {
            land_done_in(&queue, txn, &mut body, external, result_ref, now)
        }
        (BlockPurpose::Done { .. }, DONE_UNMET_OPTION) => {
            fail_unmet_in(&queue, txn, &mut body, external, now)
        }
        (BlockPurpose::Blocked, BLOCK_PROCEED_OPTION) => {
            // The blocking try goes on while it still holds its lease; a
            // person's take always does. Otherwise the next Accept is a new
            // try.
            if held.is_some() || continuation.attempt.is_none() {
                body.state = Some(TaskExecutionState::Working { started_at: now });
            } else {
                requeue(&mut body);
            }
            Ok(())
        }
        (BlockPurpose::Blocked, BLOCK_STOP_OPTION) => fail_final_in(
            &queue,
            txn,
            &mut body,
            external,
            BLOCK_STOPPED_REASON,
            None,
            now,
        ),
        _ => return Ok(()),
    };
    moved.map_err(continuation_refusal)?;
    vault
        .memory(asker, class)
        .rewrite_task_in_txn(txn, task_ref, body, now)
        .map_err(continuation_refusal)
}
