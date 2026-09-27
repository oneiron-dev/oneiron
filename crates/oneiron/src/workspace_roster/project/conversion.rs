//! Atomic conversion of a room thread into a project and its origin card.
use super::*;
use crate::edge::EdgeKind;
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TASK};
use crate::workspace_roster::rooms;

/// Renderer-neutral origin and surrounding hangs of one source message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageHangs {
    pub runs: Vec<EntityId>,
    pub threads: Vec<EntityId>,
    pub projects: Vec<EntityId>,
}

impl MessageHangs {
    /// The three independent links in the message metadata band.
    pub fn meta_line(&self) -> Vec<String> {
        self.runs
            .iter()
            .map(|id| format!("run:{}", id.to_hex()))
            .chain(
                self.threads
                    .iter()
                    .map(|id| format!("thread:{}", id.to_hex())),
            )
            .chain(
                self.projects
                    .iter()
                    .map(|id| format!("project:{}", id.to_hex())),
            )
            .collect()
    }
}

fn room_thread_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    thread: EntityId,
) -> Result<rooms::RoomTurn> {
    rooms::room_in(vault, txn, room)?;
    let row = rooms::turn_in(vault, txn, thread)?;
    if row.room_id != room.to_hex() || row.thread_of.is_none() {
        return Err(invalid());
    }
    Ok(row)
}

fn thread_project_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    thread: EntityId,
    kind: u8,
) -> Result<Option<EntityId>> {
    room_thread_in(vault, txn, room, thread)?;
    let mut found = None;
    for (n, item) in vault
        .store
        .type_index
        .prefix_iter(txn, &[kind])?
        .enumerate()
    {
        if n >= 4096 {
            return Err(Error::IndexOverflow("project_thread_scan"));
        }
        let (key, _) = item?;
        let id = EntityId::from_bytes(
            key[1..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("project index"))?,
        )?;
        if let Some(project) = record::<ProjectRecord>(&vault.store, txn, id, kind)?
            && project.origin_room.as_deref() == Some(room.to_hex().as_str())
            && project.origin_thread.as_deref() == Some(thread.to_hex().as_str())
            && found.replace(id).is_some()
        {
            return Err(invalid());
        }
    }
    Ok(found)
}

impl Vault {
    /// Bind an existing typed TASK to its room thread before conversion. The
    /// binding is stored on the room turn, not inferred from task prose.
    pub fn bind_room_thread_task(
        &self,
        room: EntityId,
        thread: EntityId,
        task: EntityId,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            let mut row = room_thread_in(self, txn, room, thread)?;
            if self.get_entity_type_in_txn(txn, &task)? != Some(ENTITY_TYPE_TASK)
                || crate::task_verb::open_thread_task_holder_in(self, txn, task)?.is_none()
                || row.converted_project.is_some()
                || row.task_ids.len() >= 4096
            {
                return Err(invalid());
            }
            if !row.task_ids.contains(&task.to_hex()) {
                row.task_ids.push(task.to_hex());
                self.store.vault_meta.put(
                    txn,
                    &rooms::key(rooms::TURNS, thread),
                    &rooms::encode(&row)?,
                )?;
            }
            Ok(())
        })
    }

    /// Convert a room thread once. The caller may name a leader, otherwise the
    /// first live task's stored execution holder wins, then the source room's
    /// project leader (its host). All resulting pointers co-commit.
    pub fn convert_thread_to_project(
        &self,
        room: EntityId,
        thread: EntityId,
        source_message: EntityId,
        project_id: EntityId,
        leader: Option<EntityId>,
        now: u64,
    ) -> Result<ProjectRecord> {
        let kind = self.project_type_byte()?;
        self.with_write_txn(|txn| {
            let mut row = room_thread_in(self, txn, room, thread)?;
            if row.converted_project.is_some()
                || self.get_entity_type_in_txn(txn, &project_id)?.is_some()
            {
                return Err(invalid());
            }
            let parent_turn = EntityId::from_hex(row.thread_of.as_deref().ok_or_else(invalid)?)?;
            let parent = rooms::turn_in(self, txn, parent_turn)?;
            if parent.room_id != room.to_hex()
                || !parent.message_ids.contains(&source_message.to_hex())
                || self.get_entity_type_in_txn(txn, &source_message)? != Some(ENTITY_TYPE_MESSAGE)
            {
                return Err(invalid());
            }
            let source = rooms::room_in(self, txn, room)?;
            let source_project_id = EntityId::from_hex(&source.project_id)?;
            let source_project: ProjectRecord =
                record(&self.store, txn, source_project_id, kind)?.ok_or_else(invalid)?;
            let mut holder = None;
            let mut tasks = Vec::new();
            for raw in &row.task_ids {
                let id = EntityId::from_hex(raw)?;
                if self.get_entity_type_in_txn(txn, &id)? != Some(ENTITY_TYPE_TASK) {
                    return Err(invalid());
                }
                if holder.is_none() {
                    holder = crate::task_verb::open_thread_task_holder_in(self, txn, id)?;
                }
                tasks.push(raw.clone());
            }
            let leader = leader
                .or(holder)
                .unwrap_or(EntityId::from_hex(&source_project.leader)?);
            if self.get_entity_type_in_txn(txn, &leader)?.is_none() {
                return Err(invalid());
            }
            let mut project = ProjectRecord::new(
                project_id,
                Some(source_project_id),
                EntityId::from_hex(&source_project.claims_scope_ref)?,
                leader,
            );
            project.tasks = tasks;
            project.roster = source_project.roster;
            if !project.roster.contains(&leader.to_hex()) {
                project.roster.push(leader.to_hex());
            }
            project.born_from = Some(source_message.to_hex());
            project.origin_room = Some(room.to_hex());
            project.origin_thread = Some(thread.to_hex());
            project.origin_at = Some(row.at);
            self.batch_in()
                .put(
                    &project_id,
                    kind,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &encode(&project)?,
                )
                .apply(txn)?;
            row.task_ids.clear();
            row.converted_project = Some(project_id.to_hex());
            self.store.vault_meta.put(
                txn,
                &rooms::key(rooms::TURNS, thread),
                &rooms::encode(&row)?,
            )?;
            Ok(project)
        })
    }

    /// Thread lens: resolve what this thread became from replicated PROJECT
    /// records rather than trusting a device-local fold marker.
    pub fn thread_project(&self, room: EntityId, thread: EntityId) -> Result<Option<EntityId>> {
        let kind = self.project_type_byte()?;
        let txn = self.store.env.read_txn()?;
        thread_project_in(self, &txn, room, thread, kind)
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
        let source = rooms::turn_in(self, &txn, *turn)?;
        if source.room_id != room.to_hex() || !source.message_ids.contains(&message.to_hex()) {
            return Err(invalid());
        }
        let runs = crate::conversation_dag::edge_ids(
            &self.store,
            &txn,
            turn,
            EdgeKind::SpawnedBy,
            true,
            4096,
        )?;
        let mut threads = Vec::new();
        for (n, item) in self
            .store
            .vault_meta
            .prefix_iter(
                &txn,
                &[b"rooms.history.v1/".as_slice(), room.as_bytes()].concat(),
            )?
            .enumerate()
        {
            if n >= 4096 {
                return Err(Error::IndexOverflow("room_thread_scan"));
            }
            let (_, bytes) = item?;
            let id = EntityId::from_bytes(
                bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("room history id"))?,
            )?;
            let row = rooms::turn_in(self, &txn, id)?;
            if row.thread_of.as_deref() == Some(turn.to_hex().as_str()) {
                threads.push(id);
            }
        }
        let mut projects = Vec::new();
        for thread in &threads {
            if let Some(id) = thread_project_in(self, &txn, room, *thread, kind)? {
                projects.push(id);
            }
        }
        Ok(MessageHangs {
            runs,
            threads,
            projects,
        })
    }
}
