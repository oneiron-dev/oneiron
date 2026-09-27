//! Atomic conversion of a room thread into a project and its origin card.
use super::*;
use crate::edge::EdgeKind;
use crate::gate::{LeaderFallback, RosterSelection};
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
    let Some(owner) = vault
        .store
        .vault_meta
        .get(txn, &origin::thread_key(room, thread))?
    else {
        return Ok(None);
    };
    let id = EntityId::from_bytes(
        owner
            .as_ref()
            .try_into()
            .map_err(|_| Error::CorruptedIndex("project origin index"))?,
    )?;
    let project = record::<ProjectRecord>(&vault.store, txn, id, kind)?
        .ok_or(Error::CorruptedIndex("project origin target"))?;
    if project.origin_room.as_deref() != Some(room.to_hex().as_str())
        || project.origin_thread.as_deref() != Some(thread.to_hex().as_str())
    {
        return Err(Error::CorruptedIndex("project origin target"));
    }
    Ok(Some(id))
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
            let policy: crate::gate::ProjectConversionPolicy =
                crate::gate::resolve_policy_manifest(&self.store, txn)?
                    .project_conversion_policy()
                    .ok_or_else(invalid)?;
            let mut row = room_thread_in(self, txn, room, thread)?;
            if self.get_entity_type_in_txn(txn, &task)? != Some(ENTITY_TYPE_TASK)
                || !crate::task_verb::thread_task_is_open_in(self, txn, task)?
                || row.converted_project.is_some()
                || row.task_ids.len() >= policy.max_tasks
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

    /// Convert a room thread once. A host may explicitly name a leader;
    /// the policy row resolves the otherwise unchosen leader and roster.
    pub fn convert_thread_to_project(
        &self,
        room: EntityId,
        thread: EntityId,
        source_message: EntityId,
        project_id: EntityId,
        leader: Option<EntityId>,
        now: u64,
    ) -> Result<ProjectRecord> {
        self.convert_thread_impl(room, thread, source_message, project_id, leader, None, now)
    }

    /// Card tap uses host-held placement and revalidates its authenticated
    /// owner inside the same transaction that mints the project and forks.
    pub(crate) fn convert_thread_with_card(
        &self,
        intent: &crate::genui::ProjectMintIntent,
        owner: &crate::consent::AuthenticatedOwner,
        project_id: EntityId,
        now: u64,
    ) -> Result<ProjectRecord> {
        let room = EntityId::from_hex(intent.source_room_ref.as_deref().ok_or_else(invalid)?)?;
        let thread = EntityId::from_hex(intent.source_thread_ref.as_deref().ok_or_else(invalid)?)?;
        let message = EntityId::from_hex(&intent.source_message_ref)?;
        self.convert_thread_impl(
            room,
            thread,
            message,
            project_id,
            None,
            Some((intent, owner)),
            now,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the private atomic door binds the source, chosen terms and time"
    )]
    fn convert_thread_impl(
        &self,
        room: EntityId,
        thread: EntityId,
        source_message: EntityId,
        project_id: EntityId,
        leader: Option<EntityId>,
        card: Option<(
            &crate::genui::ProjectMintIntent,
            &crate::consent::AuthenticatedOwner,
        )>,
        now: u64,
    ) -> Result<ProjectRecord> {
        let kind = self.project_type_byte()?;
        self.with_write_txn(|txn| {
            if let Some((intent, owner)) = card {
                owner.revalidate_in_txn(self, txn)?;
                if intent.principal_ref != owner.principal_ref()
                    || intent.source_message_ref != source_message.to_hex()
                    || intent.source_room_ref.as_deref() != Some(room.to_hex().as_str())
                    || intent.source_thread_ref.as_deref() != Some(thread.to_hex().as_str())
                {
                    return Err(invalid());
                }
            }
            let policy: crate::gate::ProjectConversionPolicy =
                crate::gate::resolve_policy_manifest(&self.store, txn)?
                    .project_conversion_policy()
                    .ok_or_else(invalid)?;
            let mut row = room_thread_in(self, txn, room, thread)?;
            if row.task_ids.len() > policy.max_tasks {
                return Err(invalid());
            }
            if row.converted_project.is_some()
                || self.get_entity_type_in_txn(txn, &project_id)?.is_some()
                || thread_project_in(self, txn, room, thread, kind)?.is_some()
            {
                return Err(invalid());
            }
            if !row.message_ids.contains(&source_message.to_hex())
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
                    holder = crate::task_verb::open_thread_task_holder_in(
                        self,
                        txn,
                        id,
                        policy.task_holder_fallback,
                    )?;
                }
                tasks.push(raw.clone());
            }
            let default_holder = match policy.leader_fallback {
                LeaderFallback::TaskHolderThenSourceLeader => holder,
                LeaderFallback::SourceLeaderOnly => None,
            };
            let leader = leader
                .or(default_holder)
                .unwrap_or(EntityId::from_hex(&source_project.leader)?);
            if self.get_entity_type_in_txn(txn, &leader)?.is_none()
                || !policy.allows_leader_override(leader, &source_project.roster, holder)
            {
                return Err(invalid());
            }
            let mut project = ProjectRecord::new(
                project_id,
                Some(source_project_id),
                EntityId::from_hex(&source_project.claims_scope_ref)?,
                leader,
            );
            project.tasks = tasks;
            project.roster = match policy.roster_selection {
                RosterSelection::InheritSource => source_project.roster,
                RosterSelection::LeaderOnly => vec![leader.to_hex()],
            };
            if !project.roster.contains(&leader.to_hex()) {
                project.roster.push(leader.to_hex());
            }
            project.born_from = Some(source_message.to_hex());
            project.origin_room = Some(room.to_hex());
            project.origin_thread = Some(thread.to_hex());
            project.origin_at = Some(row.at);
            if let Some((intent, _)) = card {
                self.apply_card_terms_in_txn(txn, intent, project_id, now, &mut project)?;
                let chosen = EntityId::from_hex(&project.leader)?;
                if !policy.allow_holder_override && !source.member_ids.contains(&chosen.to_hex()) {
                    return Err(invalid());
                }
                if policy.roster_selection == RosterSelection::LeaderOnly
                    && project.board.iter().any(|id| id != &project.leader)
                {
                    return Err(invalid());
                }
            }
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

    fn apply_card_terms_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        intent: &crate::genui::ProjectMintIntent,
        project_id: EntityId,
        now: u64,
        project: &mut ProjectRecord,
    ) -> Result<()> {
        use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON, ENTITY_TYPE_SKILL};
        let leader = EntityId::from_hex(&intent.leader_agent_def_ref)?;
        if self.get_entity_type_in_txn(txn, &leader)? != Some(ENTITY_TYPE_AGENT_DEF) {
            return Err(invalid());
        }
        project.leader = leader.to_hex();
        project.board.clear();
        for value in &intent.board_human_refs {
            let id = EntityId::from_hex(value)?;
            if self.get_entity_type_in_txn(txn, &id)? != Some(ENTITY_TYPE_PERSON) {
                return Err(invalid());
            }
            project.board.push(id.to_hex());
            if !project.roster.contains(&id.to_hex()) {
                project.roster.push(id.to_hex());
            }
        }
        if !project.roster.contains(&leader.to_hex()) {
            project.roster.push(leader.to_hex());
        }
        project.goal_record = Some(ProjectGoalRecord {
            goal: intent.goal.goal.clone(),
            why: intent.goal.why.clone(),
            axes: intent.goal.axes.clone(),
        });
        project.budget_share_bps = Some(intent.budget_share_bps);
        for (n, source) in intent.starting_skill_refs.iter().enumerate() {
            let parent = EntityId::from_hex(source)?;
            if self.get_entity_type_in_txn(txn, &parent)? != Some(ENTITY_TYPE_SKILL) {
                return Err(invalid());
            }
            let fork = self.store.clock.entity_id()?;
            let skill_id = format!("project.{}.{}", project_id.to_hex(), n);
            self.fork_skill_record_in_txn(
                txn,
                &parent,
                &fork,
                &skill_id,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )?;
            project.skill_forks.push(fork.to_hex());
        }
        Ok(())
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
        let runs = crate::conversation_dag::edge_ids(
            &self.store,
            &txn,
            turn,
            EdgeKind::SpawnedBy,
            true,
            4096,
        )?;
        let mut threads = Vec::new();
        // The containing thread hangs on its own message, even when it has no child.
        if self
            .store
            .vault_meta
            .get(&txn, &rooms::key(rooms::TURNS, *turn))?
            .is_some()
        {
            let source = rooms::turn_in(self, &txn, *turn)?;
            if source.room_id != room.to_hex() || !source.message_ids.contains(&message.to_hex()) {
                return Err(invalid());
            }
            if source.thread_of.is_some() {
                threads.push(*turn);
            }
        }
        // Parent → child index scopes this read to matching threads only.
        let prefix = [rooms::THREAD_CHILDREN, room.as_bytes(), turn.as_bytes()].concat();
        for (n, item) in self
            .store
            .vault_meta
            .prefix_iter(&txn, &prefix)?
            .enumerate()
        {
            if n >= 4096 {
                return Err(Error::IndexOverflow("message_thread_matches"));
            }
            let (_, bytes) = item?;
            let child = EntityId::from_bytes(
                bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("room thread index"))?,
            )?;
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
        let mut projects = Vec::new();
        for (n, item) in self
            .store
            .vault_meta
            .prefix_iter(&txn, &origin::message_prefix(message))?
            .enumerate()
        {
            if n >= 4096 {
                return Err(Error::IndexOverflow("message_project_matches"));
            }
            let (_, bytes) = item?;
            let id = EntityId::from_bytes(
                bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("message project index"))?,
            )?;
            let project = record::<ProjectRecord>(&self.store, &txn, id, kind)?
                .ok_or(Error::CorruptedIndex("message project target"))?;
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
        Ok(MessageHangs {
            runs,
            threads,
            projects,
        })
    }
}
