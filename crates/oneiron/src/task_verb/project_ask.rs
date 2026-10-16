//! Asks addressed to a project, over the ordinary TASK ask (ARCH-0067: a
//! proposal on a project's task goes to that project's lead and its board at
//! once; the first answer lands).
use super::ask_record;
use super::ask_types::*;
use super::create_validation::consult_refusal;
use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryError, MemoryResult, verify_actor_binding};
use crate::workspace_roster::ProjectAsk;

impl Memory<'_> {
    /// An ask on `task`, addressed to the project whose task list holds it.
    /// Its holders are that project's current leader and board, read from
    /// the project's folded authority and read again in the admission
    /// transaction, which mints the TASKs and appends the ask to the
    /// project's list. The caller names no recipient; a changed leader or
    /// board between the two reads refuses, and the caller asks again.
    pub fn tasks_ask_project(
        &self,
        task: EntityId,
        input: &TaskAskSpec,
    ) -> MemoryResult<TaskAskReceipt> {
        self.tasks_ask_project_with(task, input, |_, _| Ok(()))
    }

    /// [`Self::tasks_ask_project`] with `effect` composed into the same
    /// admission transaction, after the ask joins the project's list. A
    /// replay has already committed it and does not run it twice.
    pub(super) fn tasks_ask_project_with(
        &self,
        task: EntityId,
        input: &TaskAskSpec,
        effect: impl FnOnce(&mut heed::RwTxn<'_>, EntityId) -> MemoryResult<()>,
    ) -> MemoryResult<TaskAskReceipt> {
        if input.who.is_some() {
            return Err(MemoryError::bad_request(
                "a project ask goes to the project's leader and board",
            ));
        }
        let vault = self.vault();
        let (project, holders) = {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            vault.project_ask_route_in_txn(&txn, task)?
        };
        let mut spec = input.clone();
        spec.who = Some(TaskAskTarget::People(holders.clone()));
        spec.intent_key = format!("project.ask/{}/{}", task.to_hex(), input.intent_key);
        self.tasks_ask_with_txn_effect(&spec, |txn, ask| {
            let (current, people) = vault.project_ask_route_in_txn(txn, task)?;
            if current != project || people != holders {
                return Err(MemoryError::bad_request(
                    "the project's leader or board changed; ask again",
                ));
            }
            vault.append_project_ask_in_txn(txn, &ProjectAsk { project, task, ask })?;
            effect(txn, ask)
        })
    }

    /// The asks on a project's list this actor asked or answers, each with
    /// its status. Only a member the project's folded authority seats reads
    /// the list, and the list reads no ask past its own handle's audience.
    pub fn project_asks(
        &self,
        project: EntityId,
    ) -> MemoryResult<Vec<(TaskAskHandle, TaskAskStatus)>> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let actor = self.actor().to_hex();
        self.with_verified_actor_write_txn(|txn| {
            let Some((effective, asks)) = self.vault().project_asks_in_txn(txn, project)? else {
                return Err(MemoryError::from(crate::Error::EntityNotFound));
            };
            if !effective.seats(&actor)
                && effective.leader != actor
                && !effective.board.contains(&actor)
            {
                return Err(consult_refusal(
                    crate::memory::MEMORY_CODE_FORBIDDEN,
                    "a project's asks are read by its members",
                    "Read the asks of a project you sit in.",
                ));
            }
            let now = self.vault().store.clock.now_recorded_at();
            let mut listed = Vec::with_capacity(asks.len());
            for ask in asks {
                let Some(group) = self.ask_group_in(txn, ask)? else {
                    continue;
                };
                if group.owner != actor && !group.members.iter().any(|m| m.actor == actor) {
                    continue;
                }
                super::ask_settlement::settle_in(self.vault(), txn, ask, now)?;
                listed.push((
                    TaskAskHandle { group_ref: ask },
                    ask_record::status_in(self.vault(), txn, ask, &group)?,
                ));
            }
            Ok(listed)
        })
    }
}
