//! The open questions a saved-workflow run's agents asked one reader (L1-03
//! PR 3; ARCH-0028 `#mcp-tasks`, form questions), read by the owner's
//! `vault.workflows.asks`. The MCP Tasks adapter puts them in a task's form.
//! Only an agent's plain questions are ever among them, whose answers are
//! words, evidence and never approval: every ask family the engine raises
//! itself is left out (a verb hook's, a code consent, a comm widen, a Coach's
//! or an office holder's ask), and so is a commitment question. A run parked
//! on a hook's ask reads as waiting on an approval instead.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::agent_dispatch::AgentDispatcher;
use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult, verify_actor_binding,
};

use super::ask_record::AskGroup;
use super::sdk::WorkflowRunRequest;
use super::{TaskAskHandle, TaskAskOptionId};

/// How many TASKs of one of a run's agents one page of the read looks
/// through for the member TASKs of its asks; the read pages on until the
/// agent's TASKs end.
const RUN_ASK_PAGE: usize = 512;

/// One option a question offers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRunOption {
    pub id: TaskAskOptionId,
    /// The asker's display label for the option.
    pub label: String,
}

/// One open question a run's agent asked the reader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRunQuestion {
    pub handle: TaskAskHandle,
    /// The question's revision. A changed question is a new ask with its own
    /// handle and revision; a stored ask never changes.
    pub revision: u64,
    /// The asker's label for the question, when it gave one.
    pub label: Option<String>,
    /// The offered options, in id order; never empty.
    pub options: Vec<WorkflowRunOption>,
    /// The record the question is about. A word given with no result record
    /// of its own names it as its result: the ask's census proved that both
    /// the asker and the reader read it.
    pub subject_ref: EntityId,
}

/// What a run waits on from one reader.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRunAsks {
    /// The open questions the run's agents asked the reader, in handle order.
    pub questions: Vec<WorkflowRunQuestion>,
    /// Whether the run is parked on an approval: a verb hook's ask that its
    /// active step waits for before its next call runs.
    pub waits_on_approval: bool,
}

/// Whether the ask `group` may be a form's question: an agent's plain
/// question, whose answer is a fact. An ask family the engine raises itself
/// settles through that family's own continuation, which approves, consents
/// or moves engine state: a verb hook's ask, a code consent ask, a comm widen
/// ask, a Coach's training offer, training swap or contribution pair ask, an
/// office proposal's or live edit's holder ask. None is ever a form's
/// question; nor is a commitment question, whose companion answer needs a
/// soft confirm of its own, nor one that offers no option to choose. (A
/// consult case's ask names its consult TASK, never a run's, so the run's
/// TASK rule leaves it out.)
fn is_form_question(group: &AskGroup) -> bool {
    let intent = group.requested.intent_key.as_str();
    let engine_family = intent.starts_with(crate::runtime_hooks::verb::VERB_HOOK_INTENT)
        || super::code_consent_word::is_code_consent_ask_intent(intent)
        || super::comm_widen::is_comm_widen_ask_intent(intent)
        || super::training_offer_ask::is_training_offer_ask_intent(intent)
        || super::training_swap_ask::is_training_swap_ask_intent(intent)
        || super::is_contribution_pair_ask_intent(intent)
        || crate::office_body::is_office_holder_ask_intent(intent)
        || crate::office_body::is_live_edit_ask(intent);
    let what = &group.effective.what;
    !engine_family && !what.commitment && !what.options.is_empty()
}

/// `vault.workflows.asks` (L1-03): the questions the saved-workflow run
/// `input` names asked the owner `owner`, read on `memory`, the owner's own
/// handle. A server passes the handle of the owner's credential, at its
/// locality and destination, so a group a device-local world keeps from that
/// destination reads as none, and every row the read takes is listed for the
/// answer's release. A handle bound to another actor is refused.
///
/// # Errors
///
/// A stale owner proof, a handle that is not the owner's, a missing or
/// malformed run, or storage.
pub fn read_workflow_run_asks_as(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: WorkflowRunRequest,
) -> MemoryResult<WorkflowRunAsks> {
    if owner.revalidate(memory.vault())? != memory.actor() {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "vault.workflows.asks reads the owner's own questions",
            &["Call it on the owner's own handle."],
        ));
    }
    memory.open_asks_for_run(input.root_attempt_ref)
}

impl Memory<'_> {
    /// The questions the saved-workflow run `root_attempt_ref` asked this
    /// actor and that stand open: each plain question (`is_form_question`)
    /// an agent one of the run's steps names raised since the run began,
    /// with a seat for this actor that the actor has not voided, no
    /// settlement, no stale standing and its deadline still ahead. An ask
    /// that names a TASK counts only when that TASK is the run's own. A run
    /// parked on a hook's ask says so in
    /// [`WorkflowRunAsks::waits_on_approval`]. The read lists only this
    /// actor's own seats and settles nothing; its one write is the TASK
    /// owner index's one-time backfill on a vault that predates the index
    /// ([`crate::Vault::tasks_by_owner`]).
    ///
    /// The run binds an ask by its asker and time: an ask its agent raised
    /// before the run began is never the run's, and two runs of one agent
    /// that overlap in time each see the other's asks (the ask records no
    /// attempt it was raised in).
    ///
    /// # Errors
    ///
    /// An unbound actor, a missing or malformed run, or storage.
    pub fn open_asks_for_run(&self, root_attempt_ref: EntityId) -> MemoryResult<WorkflowRunAsks> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let root = AttemptId::from_bytes(root_attempt_ref.as_bytes())?;
        let dispatcher = AgentDispatcher::new(self.vault());
        let status = dispatcher.workflow_status(root)?;
        let run_task = status
            .attempt
            .task_ref
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?;
        let began = status.attempt.created_at;
        let askers = status
            .captured_steps
            .iter()
            .map(|step| step.target.agent_definition_ref())
            .collect::<crate::Result<BTreeSet<_>>>()?;
        let waits_on_approval = dispatcher.workflow_tool_wait(root)?.is_some();
        let person = self.actor();
        let now = self.vault().store.clock.now_recorded_at();
        let mut questions = BTreeMap::new();
        for asker in askers {
            let mut after = None;
            loop {
                let tasks = self.vault().tasks_by_owner(asker, after, RUN_ASK_PAGE)?;
                let more = tasks.len() == RUN_ASK_PAGE;
                after = tasks.last().copied();
                let txn = self
                    .vault()
                    .store
                    .env
                    .read_txn()
                    .map_err(crate::Error::from)?;
                for task in tasks {
                    let Some(body) =
                        super::wire_decode::task_verb_body_in(self.vault(), &txn, task)?
                    else {
                        continue;
                    };
                    let Some(consult) = body.consult else {
                        continue;
                    };
                    let group_ref = consult.correlation_ref;
                    if questions.contains_key(&group_ref) {
                        continue;
                    }
                    // Judged on the stored group before the reader's read of
                    // it, so the answer lists the rows of its own questions
                    // only.
                    let Some(stored) =
                        super::ask_record::read_group(self.vault(), &txn, group_ref)?
                    else {
                        continue;
                    };
                    // Correlation alone is no seat: the TASK must be this
                    // actor's own member TASK of an ask the run's agent
                    // raised since the run began.
                    let named = stored.requested.task_ref.or(stored.governed_task);
                    if stored.owner != asker.to_hex()
                        || !stored.members.iter().any(|member| {
                            member.task == task.to_hex() && member.actor == person.to_hex()
                        })
                        || stored.created_at < began
                        || !is_form_question(&stored)
                        || named.is_some_and(|named| run_task != Some(named))
                        || stored.effective.until.is_some_and(|until| now >= until)
                        || super::ask_settlement::ask_standing_in(self.vault(), &txn, group_ref)?
                            .is_none_or(|standing| standing.settled || standing.stale)
                        || super::ask_option_link::seat_voided_in(
                            self.vault(),
                            &txn,
                            group_ref,
                            person,
                        )?
                    {
                        continue;
                    }
                    // The reader's own read: a group a device-local world
                    // keeps from its destination reads as none.
                    let Some(group) = self.ask_group_in(&txn, group_ref)? else {
                        continue;
                    };
                    let what = &group.effective.what;
                    questions.insert(
                        group_ref,
                        WorkflowRunQuestion {
                            handle: TaskAskHandle { group_ref },
                            revision: what.revision,
                            label: what.label.clone(),
                            options: what
                                .options
                                .iter()
                                .map(|(id, option)| WorkflowRunOption {
                                    id: id.clone(),
                                    label: option.label.clone(),
                                })
                                .collect(),
                            subject_ref: what.reference.entity_ref(),
                        },
                    );
                }
                if !more {
                    break;
                }
            }
        }
        Ok(WorkflowRunAsks {
            questions: questions.into_values().collect(),
            waits_on_approval,
        })
    }
}
