//! A runner's "Done means met?", answered before it settles (OF-533).
//!
//! A runner reports Done inside the write that settles its try, where no
//! model may run, so the report alone always asks up on a TASK with a brief.
//! A runner instead reads the question first, has the host's decisions
//! answer it on its own thread, and carries the answer into the completion.
//! The answer binds the TASK, result, brief version and principal it judged;
//! a report that finds any of them changed asks up as before. It also names
//! the try it was asked for and the model whose answer stands, so the report
//! that takes it records that model as the run's judge (FIX 1877).

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::claim::ClaimReadStatus;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::decision::{ProviderPin, Reversibility};

use super::brief::StoredBrief;
use super::browser_workflow::task_workflow_binding_in_txn;
use super::decision_port::{PortAnswer, TaskDecisions, TaskQuestion, ask_traced};
use super::highway_report::done_question_inputs;
use super::highway_runner::workflow_try::WorkflowRunEnd;
use super::highway_runner::{runner_refusal, runner_task_in};
use super::highway_types::{HostBinding, TaskWorkflowOutcome};
use super::terminal_state::TaskExecutionState;
use super::wire_decode::task_verb_body_in;

/// What one runner Done is judged over, read outside any write.
#[derive(Debug, Clone)]
pub struct RunnerDoneQuestion {
    judged: Judged,
    evidence: Vec<EntityId>,
    state: serde_json::Value,
    reversibility: Reversibility,
    /// The leased try that asks it and its lease generation; `None` for a
    /// question no live lease asks.
    attempt: Option<(AttemptId, u32)>,
}

/// The answer to a [`RunnerDoneQuestion`], for the completion that reports
/// its Done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerDoneAnswer {
    judged: Judged,
    answer: PortAnswer,
    /// The try the question was asked for, at its lease generation.
    attempt: Option<(AttemptId, u32)>,
    /// The model whose answer stands; `None` when no model answered.
    answered_by: Option<ProviderPin>,
}

/// The report an answer was given for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Judged {
    task_ref: EntityId,
    result_ref: EntityId,
    brief_rev: u32,
    brief_digest: [u8; 32],
    principal: EntityId,
}

impl RunnerDoneQuestion {
    /// Asks the question through `decisions`; an abstention or a refused
    /// call answers "ask up".
    #[must_use]
    pub fn decide(&self, decisions: &TaskDecisions<'_>) -> RunnerDoneAnswer {
        let traced = ask_traced(
            Some(decisions),
            TaskQuestion::DoneMet,
            self.judged.principal,
            &self.evidence,
            &self.state,
            self.reversibility,
        );
        RunnerDoneAnswer {
            judged: self.judged,
            answer: traced.answer,
            attempt: self.attempt,
            answered_by: traced.answered_by,
        }
    }
}

impl RunnerDoneAnswer {
    /// The answer, when it was given for exactly this report.
    pub(super) fn for_report(
        &self,
        task_ref: EntityId,
        result_ref: EntityId,
        brief: &StoredBrief,
        principal: EntityId,
    ) -> Option<PortAnswer> {
        let judged = Judged {
            task_ref,
            result_ref,
            brief_rev: brief.rev,
            brief_digest: brief.digest,
            principal,
        };
        (judged == self.judged).then_some(self.answer)
    }

    /// Records the model whose answer stands as the judge of the try this
    /// answer was asked for (FIX 1877), in the report's writer `txn`, once
    /// [`Self::for_report`] took it. An answer no model gave records none. A
    /// join that fails is logged and leaves the judge unknown: it never fails
    /// the report or changes its answer.
    pub(super) fn record_judge_in_txn(&self, vault: &Vault, txn: &mut heed::RwTxn<'_>) {
        let (Some((attempt, generation)), Some(judge)) = (self.attempt, &self.answered_by) else {
            return;
        };
        if let Err(error) = crate::skill_attribution::finalize_run_judge_in_txn(
            vault, txn, attempt, generation, judge,
        ) {
            tracing::warn!(kind = ?error.kind(), "a run's Done judge was not recorded; it stays unknown");
        }
    }
}

/// The question a leased try's Done would ask, read before its runner
/// completes it. `None` when its Done asks none: no TASK the runner may
/// move, no durable result entity on the row, no brief (Done is met), or an
/// ask that already holds the TASK.
pub fn runner_done_question(
    vault: &Vault,
    attempt: AttemptId,
) -> Result<Option<RunnerDoneQuestion>> {
    let txn = vault.store.env.read_txn()?;
    let Some(record) = AttemptQueue::new(vault).get_in_txn(&txn, attempt)? else {
        return Ok(None);
    };
    if !record.state.is_running() {
        return Ok(None);
    }
    let Some(task_ref) = runner_task_in(vault, &txn, &record).map_err(runner_refusal)? else {
        return Ok(None);
    };
    let Some(result_ref) = record
        .result_ref
        .as_ref()
        .and_then(|result| EntityId::from_hex(result.as_str()).ok())
    else {
        return Ok(None);
    };
    if vault.get_entity_type_in_txn(&txn, &result_ref)?.is_none() {
        return Ok(None);
    }
    let attempt = Some((record.id, record.attempt_count));
    done_question_in(vault, &txn, task_ref, result_ref, &[], attempt)
}

/// A bound try's typed Done (CUA E4; Engine C1), given with no question
/// asked: its pin records Done, so its strict program met its postcondition
/// and every one of the TASK's browser checks held on the page it left, and
/// those checks are the TASK's whole goal. It binds the try's receipt NOTE
/// as the result and the brief version the try was leased under, read under
/// `binding`'s lease. `None` when the try is not so: no recorded Done, a goal
/// with a criterion or with no check, a brief revised since the try was
/// leased, an ask holding the TASK, or a TASK with no authority row; its
/// TASK's judge then decides as before.
///
/// # Errors
///
/// A lapsed lease, and storage errors.
pub fn runner_workflow_done_answer(
    vault: &Vault,
    binding: &HostBinding,
) -> Result<Option<RunnerDoneAnswer>> {
    let txn = vault.store.env.read_txn()?;
    let Some(pinned) = task_workflow_binding_in_txn(vault, &txn, binding)? else {
        return Ok(None);
    };
    let TaskWorkflowOutcome::Done { receipt_ref } = pinned.outcome() else {
        return Ok(None);
    };
    if !pinned.typed_goal() {
        return Ok(None);
    }
    let Some((_, task_ref)) = binding.leased_task_in_txn(vault, &txn)? else {
        return Ok(None);
    };
    if task_ref != pinned.task_ref() {
        return Ok(None);
    }
    let Some(body) = task_verb_body_in(vault, &txn, task_ref)? else {
        return Ok(None);
    };
    if matches!(&body.state, Some(TaskExecutionState::Blocked { on, .. }) if !on.is_empty()) {
        return Ok(None);
    }
    let Some(brief) = body.brief else {
        return Ok(None);
    };
    if brief.stamp() != pinned.brief() {
        return Ok(None);
    }
    let Some(authority) = vault.task_authority_state_in(&txn, task_ref)? else {
        return Ok(None);
    };
    Ok(Some(RunnerDoneAnswer {
        judged: Judged {
            task_ref,
            result_ref: *receipt_ref,
            brief_rev: brief.rev,
            brief_digest: brief.digest,
            principal: authority.owner_ref,
        },
        answer: PortAnswer::Yes,
        // A structural proof, which no model answered.
        attempt: None,
        answered_by: None,
    }))
}

/// The question an ended workflow run `end`'s Done asks over its report
/// NOTE `note` (FIX 4391), with each settled leaf's output as its evidence
/// too, as far as its binder's lane reads it (FIX 5293): the NOTE holds
/// only their handles. A leaf the lane does not read, or a lane that does
/// not open, adds nothing.
///
/// The question's state also carries `leaf_results`, each leaf's
/// `result_ref` and its whole text, unclipped, so a model rung that reads
/// the state alone reads them (FIX 6325): a NOTE's markdown and an ordinary
/// TURN's released words, both as the lane admits them, and the bytes of an
/// output handle of the run's own steps, read by producer lineage for that
/// binder alone. A leaf that does not read stays a ref only, an error
/// reading one is no text, never a refusal, and with no text read the key
/// is left out.
pub(super) fn workflow_done_question(
    vault: &Vault,
    end: &WorkflowRunEnd,
    note: EntityId,
) -> Result<Option<RunnerDoneQuestion>> {
    // The run's own steps' outputs, read whole before the question's
    // snapshot opens: their reads open their own.
    let mut texts: std::collections::HashMap<String, String> =
        crate::agent_dispatch::AgentDispatcher::new(vault)
            .workflow_done_output_refs(end.wrapper.id, end.bound_by)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(handle, output)| {
                let bytes = crate::compaction::output::restore_output(vault, output).ok()?;
                Some((handle, String::from_utf8(bytes).ok()?))
            })
            .collect();
    let judge = end.bound_by;
    let memory = vault.memory(judge.entity_ref(), judge.actor_class());
    // The lane verifies its actor in a snapshot of its own, closed before
    // the question's.
    let lane = memory.read_lane(ClaimReadStatus::Recorded).ok();
    let txn = vault.store.env.read_txn()?;
    let leaves: Vec<(&str, EntityId)> = end
        .results
        .iter()
        .filter_map(|step| {
            EntityId::from_hex(&step.result_ref)
                .ok()
                .map(|leaf| (step.result_ref.as_str(), leaf))
        })
        .collect();
    let ids: Vec<EntityId> = leaves.iter().map(|(_, leaf)| *leaf).collect();
    let mut readable = Vec::new();
    if let Some(lane) = &lane
        && let Ok(rows) = lane.get_entities_parts_in_txn(&txn, &ids)
    {
        for ((result_ref, leaf), row) in leaves.iter().zip(rows) {
            let Some((kind, _, body)) = row else {
                continue;
            };
            readable.push(*leaf);
            if let Some(text) = leaf_text(vault, lane, &txn, *leaf, kind, &body) {
                texts.insert((*result_ref).to_owned(), text);
            }
        }
    }
    // The run's wrapper closed before its TASK settles: no live lease asks.
    let mut question = done_question_in(vault, &txn, end.task, note, &readable, None)?;
    let leaf_results: Vec<serde_json::Value> = end
        .results
        .iter()
        .filter_map(|step| {
            texts
                .remove(&step.result_ref)
                .map(|text| serde_json::json!({ "result_ref": step.result_ref, "text": text }))
        })
        .collect();
    if let Some(question) = question.as_mut()
        && !leaf_results.is_empty()
        && let Some(state) = question.state.as_object_mut()
    {
        state.insert(
            "leaf_results".to_owned(),
            serde_json::Value::Array(leaf_results),
        );
    }
    Ok(question)
}

/// The whole text of the leaf `leaf`, a `kind` row whose `body` `lane`
/// admitted in `txn`: a NOTE's markdown, or an ordinary TURN's words its
/// messages give, each message the same lane releases. `None` for any other
/// kind, one with no text, or a read that fails.
fn leaf_text(
    vault: &Vault,
    lane: &crate::claim::ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    leaf: EntityId,
    kind: u8,
    body: &[u8],
) -> Option<String> {
    match kind {
        crate::registry::ENTITY_TYPE_NOTE => {
            crate::note::decode_note_body_in_txn(&vault.store, txn, body)
                .ok()
                .map(|note| note.markdown)
        }
        crate::registry::ENTITY_TYPE_TURN => {
            let policy = lane.policy_manifest_in(txn).ok()?;
            let text = crate::vault::entity_revision::served_turn_text_in_txn(
                vault,
                &lane.store_read(),
                txn,
                &leaf,
                crate::vault::ReadMode::Live,
                true,
            )
            .ok()??;
            let messages = text
                .released(|message| lane.is_entity_readable_with_policy_in(txn, &policy, message))
                .ok()?;
            crate::embed::joined_turn_text(&messages)
        }
        _ => None,
    }
}

/// The question a Done on `task_ref` with the durable `result_ref` asks, in
/// `txn`, over `leaves` too: a leased runner's, or an ended workflow run's
/// over its report NOTE (FIX 4391), asked for `attempt` when a live lease
/// asks it. `None` when it asks none: no brief, or an ask already holds the
/// TASK.
fn done_question_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task_ref: EntityId,
    result_ref: EntityId,
    leaves: &[EntityId],
    attempt: Option<(AttemptId, u32)>,
) -> Result<Option<RunnerDoneQuestion>> {
    let Some(body) = task_verb_body_in(vault, txn, task_ref)? else {
        return Ok(None);
    };
    if matches!(&body.state, Some(TaskExecutionState::Blocked { on, .. }) if !on.is_empty()) {
        return Ok(None);
    }
    let Some(brief) = body.brief else {
        return Ok(None);
    };
    // The principal the report asks for; a TASK with no authority row asks
    // up in the report.
    let Some(authority) = vault.task_authority_state_in(txn, task_ref)? else {
        return Ok(None);
    };
    let (mut evidence, state) = done_question_inputs(task_ref, result_ref, &brief);
    for leaf in leaves {
        if !evidence.contains(leaf) {
            evidence.push(*leaf);
        }
    }
    Ok(Some(RunnerDoneQuestion {
        judged: Judged {
            task_ref,
            result_ref,
            brief_rev: brief.rev,
            brief_digest: brief.digest,
            principal: authority.owner_ref,
        },
        evidence,
        state,
        reversibility: brief.brief.escalation.reversibility,
        attempt,
    }))
}
