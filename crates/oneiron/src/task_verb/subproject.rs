//! A TASK that wraps a subproject (OF-389, ARCH-0079 "three kinds of work").
//!
//! When a promise must split, its leader spawns a child PROJECT inside the
//! TASK's wrapper. The parent still sees one checkbox: the wrapper keeps its
//! assignee and done bit, and no child task is listed beside it. The link is
//! durable both ways and lands in one write: the TASK body names the child as
//! its `subproject_ref`, and the child PROJECT names the TASK as its
//! `wrapper_task`. A spawn never mints a task; this door links one that
//! already exists, as the leader's explicit act.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::Scope;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
    verify_actor_binding,
};
use crate::workspace_roster::{ProjectRecord, ProjectWriteProof};

use super::create_validation::{consult_refusal, task_body_in_txn};
use super::verb_kind::{TaskAssignee, TaskKind};
use super::wire_decode::task_verb_body_in;
use super::wire_encode::encode_task_verb_body;

impl Memory<'_> {
    /// The bound leader spawns the subproject her TASK `wrapper` holds, in one
    /// verified write. The wrapper is her own open standard promise, and a
    /// brief that names a project names `parent`. The child is created by the
    /// signed project spawn door ([`Vault::spawn_subproject`]): `proof` is her
    /// slip signature over the child's authority, its slice narrows the
    /// parent's, and she sits on the child's board. Both links commit with it.
    ///
    /// A TASK wraps one subproject. A retry naming the linked child returns
    /// it and writes nothing; any other spawn on a linked wrapper is refused.
    #[expect(
        clippy::too_many_arguments,
        reason = "the wrapper, then the subproject spawn's own inputs"
    )]
    pub fn spawn_task_subproject(
        &self,
        wrapper: EntityId,
        parent: EntityId,
        child: EntityId,
        leader: EntityId,
        slice: Scope,
        proof: ProjectWriteProof,
        now: u64,
    ) -> MemoryResult<ProjectRecord> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        if now > self.vault().store.clock.now_recorded_at() {
            return Err(MemoryError::bad_request(
                "subproject spawn time is later than the engine clock",
            ));
        }
        // The proof writes as its holder: she spawns as herself.
        let holder = crate::authority::CapabilitySlip::from_token(&proof.slip_wire)?
            .claims
            .holder_ref;
        if EntityId::from_hex(&holder)? != self.actor() {
            return Err(consult_refusal(
                MEMORY_CODE_FORBIDDEN,
                "the subproject proof is not the caller's own",
                "Sign the spawn as the leader who holds the wrapper task.",
            ));
        }
        self.with_verified_actor_write_txn(|wtxn| {
            let mut body = task_body_in_txn(self.vault(), &*wtxn, wrapper)?;
            if body.assignee.and_then(TaskAssignee::entity_ref) != Some(self.actor()) {
                return Err(consult_refusal(
                    MEMORY_CODE_FORBIDDEN,
                    "only the wrapper task's assignee may spawn its subproject",
                    "Spawn as the leader the task is addressed to.",
                ));
            }
            if let Some(linked) = body.subproject_ref {
                let wrapper_hex = wrapper.to_hex();
                return self
                    .vault()
                    .visible_project_in_txn(&*wtxn, linked)?
                    .filter(|record| {
                        linked == child
                            && record.wrapper_task.as_deref() == Some(wrapper_hex.as_str())
                            && record.parents.contains(&parent.to_hex())
                    })
                    .ok_or_else(|| {
                        consult_refusal(
                            MEMORY_CODE_INVALID_STATE,
                            "this task already wraps a different subproject",
                            "Read the task's subproject; a wrapper holds one.",
                        )
                    });
            }
            if body.task_kind() != TaskKind::Standard {
                return Err(consult_refusal(
                    MEMORY_CODE_INVALID_STATE,
                    "only a standard task wraps a subproject",
                    "Split a promise, not a consult or reconciliation.",
                ));
            }
            if body.terminal().is_some() || body.settled_ladder_disposition().is_some() {
                return Err(consult_refusal(
                    MEMORY_CODE_INVALID_STATE,
                    "task is already settled",
                    "A settled task cannot be split; read its terminal record.",
                ));
            }
            if body
                .brief
                .as_ref()
                .and_then(|stored| stored.brief.project_ref)
                .is_some_and(|project| project != parent)
            {
                return Err(consult_refusal(
                    MEMORY_CODE_INVALID_STATE,
                    "the wrapper task belongs to a different project",
                    "Spawn the subproject under the project the task's brief names.",
                ));
            }
            let record = self.vault().spawn_subproject_in_txn(
                wtxn,
                parent,
                child,
                leader,
                slice,
                proof,
                Some(wrapper),
                now,
            )?;
            body.subproject_ref = Some(child);
            let encoded = encode_task_verb_body(body);
            self.put_task_body_in_txn(wtxn, wrapper, &encoded, now)?;
            Ok(record)
        })
    }
}

impl Vault {
    /// The subproject `task_ref` wraps, when the link holds both ways: the
    /// TASK names the child, and the visible child names the TASK back. A
    /// link on one side alone reads as none.
    pub fn task_subproject(&self, task_ref: EntityId) -> Result<Option<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let body = task_verb_body_in(self, &rtxn, task_ref)?;
        let Some(child) = body.and_then(|body| body.subproject_ref) else {
            return Ok(None);
        };
        let wrapper = task_ref.to_hex();
        Ok(self
            .visible_project_in_txn(&rtxn, child)?
            .filter(|record| record.wrapper_task.as_deref() == Some(wrapper.as_str()))
            .map(|_| child))
    }
}
