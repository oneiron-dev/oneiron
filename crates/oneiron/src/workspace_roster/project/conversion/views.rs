//! Thread task binding and conversion views.
//! Entry: `Vault::message_hangs`.
//! Project and `MessageHangs` types stay in their parent modules.

use super::*;

impl Vault {
    /// Bind an existing typed TASK to its room thread before conversion, as
    /// `actor`'s act. The binding is stored on the room turn, not inferred
    /// from task prose. A private thread (FIX 2951) is bound only from its
    /// audience (FIX 3125); to anyone else it is an unknown thread.
    pub fn bind_room_thread_task(
        &self,
        actor: EntityId,
        room: EntityId,
        thread: EntityId,
        task: EntityId,
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            // A binding with no policy row asks at the shipped threshold.
            let policy: crate::gate::ProjectConversionPolicy =
                crate::gate::resolve_policy_manifest(&self.store, txn)?
                    .project_conversion_policy()
                    .unwrap_or_default();
            let mut row = room_thread_in(self, txn, room, thread)?;
            rooms::require_thread_audience_in(self, txn, room, thread, actor)?;
            // Its census counts the turns `actor` reads alone (FIX 5654).
            let all = rooms::thread_turns_in(self, txn, room, thread)?;
            let (turns, _) = readable_turns_in(self, txn, all, actor)?;
            let source = rooms::room_in(self, txn, room)?;
            let members = source.member_ids.into_iter().collect();
            crate::task_verb::room_thread_task_roster_in(self, txn, task, &members)?;
            if self.get_entity_type_in_txn(txn, &task)? != Some(ENTITY_TYPE_TASK)
                || !crate::task_verb::thread_task_is_open_in(self, txn, task)?
                || row.converted_project.is_some()
                || thread_project_in(self, txn, room, thread, self.project_type_byte()?)?.is_some()
            {
                return Err(invalid());
            }
            // A thread binds however many tasks (rule 5). Once the bound set
            // passes the policy's task threshold, its census raises the
            // owner's question for the thread and the bind goes on.
            let mut census = crate::scan_check::ScanCount::start_at(
                crate::scan_check::EngineScan::ThreadTaskCensus,
                thread.as_bytes(),
                u64::try_from(policy.max_tasks).unwrap_or(u64::MAX),
            );
            census.rows(turns.iter().map(|turn| turn.task_ids.len()).sum());
            census.rows(usize::from(!row.task_ids.contains(&task.to_hex())));
            census.finish(self);
            if !row.task_ids.contains(&task.to_hex()) {
                row.task_ids.push(task.to_hex());
                rooms::TURNS.put(&self.store, txn, &thread, &row)?;
                rooms::index_task_bindings(&self.store, txn, &row)?;
            }
            // OF-529: an agent holding the task joins the thread now when a
            // Ready receipt stands there, else at its first passing claim.
            rooms::record_bound_task_in_txn(self, txn, room, &row, task)
        })?;
        // The changed turn reaches the room's live window after commit.
        #[cfg(feature = "sync")]
        self.refresh_room_turn_in_live_window(&thread);
        Ok(())
    }

    /// Thread lens: resolve what this thread became from replicated PROJECT
    /// records rather than trusting a device-local fold marker.
    pub fn thread_project(&self, room: EntityId, thread: EntityId) -> Result<Option<EntityId>> {
        let kind = self.project_type_byte()?;
        let txn = self.store.env.read_txn()?;
        thread_project_in(self, &txn, room, thread, kind)
    }

    pub(crate) fn thread_project_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
        thread: EntityId,
    ) -> Result<Option<EntityId>> {
        thread_project_in(self, txn, room, thread, self.project_type_byte()?)
    }

    /// The origin card is the first trunk projection of the new room. Its
    /// position is the original thread's position; no source message is copied.
    pub fn room_origin_card(&self, room: EntityId) -> Result<Option<RoomOriginCard>> {
        Ok(self.project_room(room)?.ok_or_else(invalid)?.origin)
    }

    /// Project the independent run/thread/project links on a message.
    pub fn message_hangs(&self, message: EntityId, room: EntityId) -> Result<MessageHangs> {
        let kind = self.project_type_byte()?;
        let txn = self.store.env.read_txn()?;
        if self.get_entity_type_in_txn(&txn, &message)? != Some(ENTITY_TYPE_MESSAGE) {
            return Err(invalid());
        }
        let turns = crate::conversation_dag::edge_ids(
            &self.store,
            &txn,
            &message,
            EdgeKind::PartOf,
            false,
            2,
        )?;
        let [turn] = turns.as_slice() else {
            return Err(invalid());
        };
        let owned = crate::conversation_dag::edge_ids(
            &self.store,
            &txn,
            &message,
            EdgeKind::BelongsTo,
            false,
            2,
        )?;
        if owned != [room] {
            return Err(invalid());
        }
        // Every run the turn spawned hangs on it, however many (rule 5).
        let runs = crate::vault::filtered_edge_peers_in(
            &self.store,
            &txn,
            crate::ports::EdgeDirection::In,
            turn,
            EdgeKind::SpawnedBy,
            None,
        )?;
        let mut threads = Vec::new();
        // The containing thread hangs on its own message, even when it has no child.
        if rooms::TURNS.contains(&self.store, &txn, turn)? {
            let mut source = rooms::turn_in(self, &txn, *turn)?;
            if source.room_id != room.to_hex() || !source.message_ids.contains(&message.to_hex()) {
                return Err(invalid());
            }
            if let Some(anchor) = source.thread_of.clone() {
                let mut seen = BTreeSet::new();
                while let Some(parent) = source.reply_to.as_deref() {
                    if parent == anchor {
                        break;
                    }
                    let parent = EntityId::from_hex(parent)?;
                    if !seen.insert(parent) {
                        return Err(invalid());
                    }
                    source = rooms::turn_in(self, &txn, parent)?;
                    if source.room_id != room.to_hex() || source.thread_of.as_ref() != Some(&anchor)
                    {
                        return Err(invalid());
                    }
                }
                threads.push(EntityId::from_hex(&source.turn_id)?);
            }
        }
        // Parent → child index scopes this read to matching threads only.
        // Every child is read, however many (rule 5); past the threshold row
        // the owner's check is raised for the parent turn.
        let prefix = [room.as_bytes().as_slice(), turn.as_bytes().as_slice()].concat();
        let mut children = crate::scan_check::ScanCount::start(
            &self.store,
            &txn,
            crate::scan_check::EngineScan::RoomThreadChildRows,
            &prefix,
        )?;
        for item in rooms::THREAD_CHILDREN.iter_from(&self.store, &txn, &prefix)? {
            children.row();
            let (_, child) = item?;
            let row = rooms::turn_in(self, &txn, child)?;
            if row.room_id != room.to_hex()
                || row.thread_of.as_deref() != Some(turn.to_hex().as_str())
            {
                return Err(Error::CorruptedIndex("room thread index"));
            }
            if !threads.contains(&child) {
                threads.push(child);
            }
        }
        children.finish(self);
        // Every project born from the message is read, however many.
        let mut born = crate::scan_check::ScanCount::start(
            &self.store,
            &txn,
            crate::scan_check::EngineScan::MessageOriginRows,
            message.as_bytes(),
        )?;
        let mut projects = Vec::new();
        for item in self
            .store
            .vault_meta
            .prefix_iter(&txn, &origin::message_prefix(message))?
        {
            born.row();
            let (_, bytes) = item?;
            let id = EntityId::from_bytes(
                bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("message project index"))?,
            )?;
            if record::<ProjectRecord>(&self.store, &txn, id, kind)?.is_none() {
                return Err(Error::CorruptedIndex("message project target"));
            }
            // A project the read fold hides does not hang off the message.
            let Some(project) = self.visible_project_in_txn(&txn, id)? else {
                continue;
            };
            if project.born_from.as_deref() != Some(message.to_hex().as_str())
                || project.origin_room.as_deref() != Some(room.to_hex().as_str())
            {
                return Err(Error::CorruptedIndex("message project target"));
            }
            let origin_thread =
                EntityId::from_hex(project.origin_thread.as_deref().ok_or_else(invalid)?)?;
            if thread_project_in(self, &txn, room, origin_thread, kind)? != Some(id) {
                return Err(Error::CorruptedIndex("message project index"));
            }
            if !threads.contains(&origin_thread) {
                threads.push(origin_thread);
            }
            projects.push(id);
        }
        born.finish(self);
        Ok(MessageHangs {
            runs,
            threads,
            projects,
        })
    }
}
