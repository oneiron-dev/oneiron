//! A TASK made from a room message, bound to that message's thread
//! in the same write (THREAD-TASK-ONE-SURFACE, `tasks.create.from_message`).
//! Entry [`Memory::tasks_create_from_message`]. The mint is `create_facade`'s
//! direct create; the binding is `Vault::bind_room_thread_task_in_txn`.

use crate::claim::ClaimReadStatus;
use crate::entity_id::EntityId;
use crate::gate::PolicyApprovalCeiling;
use crate::memory::{Memory, MemoryError, MemoryResult, facade_provenance, verify_actor_binding};

use super::create_facade::direct_create_receipt;
use super::create_spec::{TaskCreateRateLimit, TaskCreateSpec};
use super::create_validation::{admit_task_parent, validate_task_create};
use super::rate_limit::{record_task_create, task_actor_ceiling};
use super::route_receipts::TaskCreateReceipt;

/// The verb this door serves, as its TASK's provenance names it.
const TASKS_CREATE_FROM_MESSAGE: &str = "tasks.create.from_message";

impl Memory<'_> {
    /// Mints one TASK as [`Memory::tasks_create`] mints a brief-less one,
    /// and binds it to the root of the room thread that
    /// `source_ref`, a MESSAGE or TURN the actor reads, stands in. Mint and
    /// binding are one write: both commit or neither does. A later reply in
    /// that thread wakes the TASK's holder.
    ///
    /// Refused as a bad request, with nothing written: a spec that routes
    /// through approval (a typed brief or an intent key, which post through
    /// the task highway, or an actor ceiling short of Auto, which parks a
    /// proposal), and a source on the trunk or in no room thread.
    /// The binding's own checks are [`crate::Vault::bind_room_thread_task`]'s.
    pub fn tasks_create_from_message(
        &self,
        source_ref: EntityId,
        spec: &TaskCreateSpec,
    ) -> MemoryResult<TaskCreateReceipt> {
        if !self.has_task_work_turn() {
            return self
                .task_work_memory()
                .tasks_create_from_message(source_ref, spec);
        }
        if spec.brief.is_some() || spec.intent_key.is_some() {
            return Err(approval_routed());
        }
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let now = spec.now.unwrap_or_else(|| self.vault().now_recorded_at());
        let rate_now = self.vault().store.clock.now_recorded_at();
        let provenance = facade_provenance(TASKS_CREATE_FROM_MESSAGE);
        // Every refusal of this door is decided before anything writes, the
        // parent's refusal receipt included. The writer decides the thread
        // and the ceiling again on its own snapshot, and the binding checks
        // the thread's audience there.
        {
            let lane = self.read_lane(ClaimReadStatus::Recorded)?;
            let txn = self
                .vault()
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            if self
                .get_entity_in_txn(&lane, &txn, source_ref)?
                .value
                .is_none()
            {
                return Err(MemoryError::not_found(
                    "tasks.create.from_message names no MESSAGE or TURN this actor reads",
                ));
            }
            self.thread_task_place_in(&txn, source_ref)?;
        }
        admit_task_parent(self, spec.parent_ref)?;
        let validated = validate_task_create(self.vault(), spec, now)?;
        let (task_ref, route, root) = self.with_verified_actor_write_txn(|wtxn| {
            let (room, root) = self.thread_task_place_in(wtxn, source_ref)?;
            record_task_create(
                self.vault(),
                wtxn,
                self.actor(),
                rate_now,
                TaskCreateRateLimit::default(),
            )?;
            let (task_ref, route) =
                self.create_direct_task_in_txn(wtxn, spec, &validated, &provenance, now)?;
            self.vault()
                .bind_room_thread_task_in_txn(wtxn, self.actor(), room, root, task_ref)?;
            Ok((task_ref, route, root))
        })?;
        // The bound root reaches the room's live window after commit.
        #[cfg(feature = "sync")]
        self.vault().refresh_room_turn_in_live_window(&root);
        #[cfg(not(feature = "sync"))]
        let _ = root;
        Ok(direct_create_receipt(task_ref, route))
    }

    /// The room and thread root a TASK made from `source` binds to, once the
    /// actor's ceiling mints at once.
    fn thread_task_place_in(
        &self,
        txn: &heed::RoTxn<'_>,
        source: EntityId,
    ) -> MemoryResult<(EntityId, EntityId)> {
        let Some(place) =
            crate::workspace_roster::room_thread_source_in(self.vault(), txn, source)?
        else {
            return Err(MemoryError::bad_request_with(
                "tasks.create.from_message takes a MESSAGE or TURN inside a room thread; \
                 a trunk message binds no thread",
                &["Open the message's thread, then name a message in it."],
            ));
        };
        if task_actor_ceiling(self.vault(), txn, self.actor(), self.actor_class())?
            != PolicyApprovalCeiling::Auto
        {
            return Err(approval_routed());
        }
        Ok(place)
    }
}

/// The refusal of a spec that would route through approval: this door mints
/// at once and parks no proposal.
fn approval_routed() -> MemoryError {
    MemoryError::bad_request_with(
        "tasks.create.from_message mints at once and parks no proposal; this spec \
         routes through approval",
        &["Create it with tasks.create, which posts a briefed spec or parks a proposal."],
    )
}
