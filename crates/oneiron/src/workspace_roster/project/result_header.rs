//! Admitted origin and TASK result pointers on a project's room trunk.
use super::{RoomOriginCard, invalid};
use crate::memory::{Memory, MemoryResult};
use crate::workspace_roster::rooms::{self, RoomTrunkHeader, RoomTurn};
use crate::{EntityId, Error};

impl Memory<'_> {
    /// An origin is a pointer to another room, not permission to read it.
    pub(in crate::workspace_roster) fn admitted_room_origin(
        &self,
        room: EntityId,
        origin: &RoomOriginCard,
    ) -> MemoryResult<bool> {
        if !self.room_record_readable(room)? {
            return Ok(false);
        }
        let refs = [
            EntityId::from_hex(&origin.room)?,
            EntityId::from_hex(&origin.thread)?,
            EntityId::from_hex(&origin.message)?,
        ];
        let projection = self.for_room_projection(room)?;
        let lane = projection
            .memory()
            .read_lane(crate::claim::ClaimReadStatus::Recorded)?;
        let admitted = lane.all_refs_readable(&refs)?;
        if admitted {
            self.produced_from(refs);
        }
        Ok(admitted)
    }

    /// TASK terminal registers remain the only result facts. Explicit thread
    /// bindings and a converted project's task list join them to the trunk;
    /// neither a header nor a conversion mints a message or a second wait.
    pub(in crate::workspace_roster) fn room_result_headers(
        &self,
        room: EntityId,
        turns: &[RoomTurn],
        origin: Option<&RoomOriginCard>,
    ) -> MemoryResult<Vec<RoomTrunkHeader>> {
        let mut roots = rooms::thread_root_map(turns)?;
        let mut bindings = rooms::thread_task_bindings(turns, &roots)?;
        self.vault().backfill_tasks_by_owner()?;
        let (members, project_tasks, local_tasks) = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            let record = rooms::require_member(self.vault(), &txn, room, self.actor())?;
            if origin.is_some_and(|origin| record.origin.as_ref() != Some(origin)) {
                return Err(invalid().into());
            }
            let project = self
                .vault()
                .visible_project_in_txn(&txn, EntityId::from_hex(&record.project_id)?)?
                .ok_or_else(invalid)?;
            let members = record.member_ids.into_iter().collect();
            let local_tasks = crate::task_verb::room_thread_task_ids_in(
                self.vault(),
                &txn,
                &roots,
                &bindings,
                &members,
            )?;
            (members, project.tasks, local_tasks)
        };
        if let Some(origin) = origin
            && self.admitted_room_origin(room, origin)?
        {
            let thread = EntityId::from_hex(&origin.thread)?;
            roots.insert(thread, thread);
            for task in project_tasks {
                let task = EntityId::from_hex(&task)?;
                // A later thread binding in the home room takes precedence
                // over the project's original placement.
                bindings
                    .entry(task)
                    .or_insert_with(|| local_tasks.get(&task).copied().unwrap_or(thread));
            }
        }
        let projection = self.for_room_projection(room)?;
        let tasks = crate::task_verb::room_thread_tasks(
            projection.memory(),
            &roots,
            &bindings,
            &members,
            crate::unix_seconds_now(),
        )?;
        let mut headers = tasks
            .into_iter()
            .filter_map(|task| {
                task.delivered.map(|(result_ref, _)| RoomTrunkHeader {
                    thread: task.thread,
                    task: task.task,
                    result_ref,
                })
            })
            .collect::<Vec<_>>();
        headers.sort_by_key(|header| (header.thread, header.task));
        Ok(headers)
    }
}
