//! The open questions a saved-workflow run's agents asked one reader (L1-03
//! PR 3; ARCH-0028 `#mcp-tasks`, form questions). The MCP Tasks adapter puts
//! them in a task's form. Only `ask` questions are ever among them: their
//! answers are words, evidence and never approval. A verb hook's ask, a code
//! consent ask or any other approval never is; a run parked on a hook's ask
//! reads as waiting on an approval instead.

use std::collections::{BTreeMap, BTreeSet};

use crate::agent_dispatch::AgentDispatcher;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryResult, verify_actor_binding};

use super::{TaskAskHandle, TaskAskOptionId};

/// How many TASKs of each of a run's agents one read looks through for the
/// member TASKs of its asks.
const RUN_ASK_SCAN_LIMIT: usize = 512;

/// One open question a run's agent asked the reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowRunQuestion {
    pub handle: TaskAskHandle,
    /// The question's revision. A changed question is a new ask with its own
    /// handle and revision; a stored ask never changes.
    pub revision: u64,
    /// The asker's label for the question, when it gave one.
    pub label: Option<String>,
    /// The offered options by id, with their display labels, in id order.
    pub options: Vec<(TaskAskOptionId, String)>,
    /// The record the question is about. A word given with no result record
    /// of its own names it as its result: the ask's census proved that both
    /// the asker and the reader read it.
    pub subject_ref: EntityId,
}

/// What a run waits on from one reader.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkflowRunAsks {
    /// The open questions the run's agents asked the reader, in handle order.
    pub questions: Vec<WorkflowRunQuestion>,
    /// Whether the run is parked on an approval: a verb hook's ask that its
    /// active step waits for before its next call runs.
    pub waits_on_approval: bool,
}

/// Whether an ask's intent key marks an approval: a verb hook's ask or a
/// code consent ask. Its answer decides whether an act runs, so it is never
/// a form's question.
fn is_approval_intent(intent_key: &str) -> bool {
    intent_key.starts_with(crate::runtime_hooks::verb::VERB_HOOK_INTENT)
        || super::code_consent_word::is_code_consent_ask_intent(intent_key)
}

impl Memory<'_> {
    /// The questions the saved-workflow run `root_attempt_ref` asked this
    /// actor and that stand open: each `ask` group an agent the run
    /// dispatched raised, with a seat for this actor that the actor has not
    /// voided, no settlement and its deadline still ahead. An ask that names
    /// a TASK counts only when that TASK is the run's own. Approvals are
    /// never questions: a verb hook's ask and a code consent ask are left
    /// out, and a run parked on a hook's ask says so in
    /// [`WorkflowRunAsks::waits_on_approval`]. The read lists only this
    /// actor's own seats, and it settles and records nothing.
    ///
    /// # Errors
    ///
    /// An unbound actor, a missing or malformed run, or storage.
    pub fn open_asks_for_run(&self, root_attempt_ref: EntityId) -> MemoryResult<WorkflowRunAsks> {
        if !self.has_task_work_turn() {
            return self.task_work_memory().open_asks_for_run(root_attempt_ref);
        }
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
            let tasks = self
                .vault()
                .tasks_by_owner(asker, None, RUN_ASK_SCAN_LIMIT)?;
            let txn = self
                .vault()
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            for task in tasks {
                let Some(body) = super::wire_decode::task_verb_body_in(self.vault(), &txn, task)?
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
                let Some(group) = self.ask_group_in(&txn, group_ref)? else {
                    continue;
                };
                // Correlation alone is no seat: the TASK must be this
                // actor's own member TASK of an ask the run's agent raised.
                if group.owner != asker.to_hex()
                    || !group.members.iter().any(|member| {
                        member.task == task.to_hex() && member.actor == person.to_hex()
                    })
                {
                    continue;
                }
                let named = group.requested.task_ref.or(group.governed_task);
                if is_approval_intent(&group.requested.intent_key)
                    || named.is_some_and(|named| run_task != Some(named))
                    || group.effective.until.is_some_and(|until| now >= until)
                    || super::ask_settlement::read_result(self.vault(), &txn, group_ref)?.is_some()
                    || super::ask_option_link::seat_voided_in(
                        self.vault(),
                        &txn,
                        group_ref,
                        person,
                    )?
                {
                    continue;
                }
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
                            .map(|(id, option)| (id.clone(), option.label.clone()))
                            .collect(),
                        subject_ref: what.reference.entity_ref(),
                    },
                );
            }
        }
        Ok(WorkflowRunAsks {
            questions: questions.into_values().collect(),
            waits_on_approval,
        })
    }
}
