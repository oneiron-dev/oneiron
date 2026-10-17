//! Atomic conversion of a room thread into a project and its origin card.
use super::*;
use crate::edge::EdgeKind;
use crate::gate::{LeaderFallback, RosterSelection};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TASK};
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

/// One card tap's conversion inputs: its intent, the authenticated owner and
/// the owner-project signer, the tap's durable key and digest, and the
/// caller's step on the fresh receipt inside the birth's write.
struct CardBirth<'c, A> {
    intent: &'c crate::genui::ProjectMintIntent,
    owner: &'c crate::consent::AuthenticatedOwner,
    signer: &'c OwnerProjectSigner<'c>,
    tap_key: [u8; 32],
    digest: [u8; 32],
    after: A,
}

/// The plain conversion's absent card step.
type NoCardStep = fn(&mut heed::RwTxn<'_>, &ProjectMintReceipt) -> Result<()>;

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
    // Replicated origin indexes name held rows too. Only a project whose
    // history currently serves authority can fold a source thread.
    Ok(vault.visible_project_in_txn(txn, id)?.map(|_| id))
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
        self.with_write_txn_grouped(|txn| {
            let policy: crate::gate::ProjectConversionPolicy =
                crate::gate::resolve_policy_manifest(&self.store, txn)?
                    .project_conversion_policy()
                    .ok_or_else(invalid)?;
            let mut row = room_thread_in(self, txn, room, thread)?;
            let turns = rooms::thread_turns_in(self, txn, room, thread)?;
            let source = rooms::room_in(self, txn, room)?;
            let members = source.member_ids.into_iter().collect();
            crate::task_verb::room_thread_task_roster_in(self, txn, task, &members)?;
            if self.get_entity_type_in_txn(txn, &task)? != Some(ENTITY_TYPE_TASK)
                || !crate::task_verb::thread_task_is_open_in(self, txn, task)?
                || row.converted_project.is_some()
                || thread_project_in(self, txn, room, thread, self.project_type_byte()?)?.is_some()
                || (!row.task_ids.contains(&task.to_hex())
                    && turns.iter().map(|turn| turn.task_ids.len()).sum::<usize>()
                        >= policy.max_tasks)
            {
                return Err(invalid());
            }
            if !row.task_ids.contains(&task.to_hex()) {
                row.task_ids.push(task.to_hex());
                rooms::TURNS.put(&self.store, txn, &thread, &row)?;
            }
            // OF-529: an agent holding the task joins the thread now when a
            // Ready receipt stands there, else at its first passing claim.
            rooms::record_bound_task_in_txn(self, txn, room, &row, task)
        })
    }

    /// Convert a room thread once, as the owner's act: the owner is
    /// revalidated in the grouped write, the owner-project signer signs the
    /// new state for the owner, and only an installed head commits. A host
    /// may explicitly name a leader; the policy row resolves the otherwise
    /// unchosen leader and roster.
    #[expect(
        clippy::too_many_arguments,
        reason = "the owner door binds its owner, signer, source, chosen leader and time"
    )]
    pub fn convert_thread_to_project(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        signer: &OwnerProjectSigner<'_>,
        room: EntityId,
        thread: EntityId,
        source_message: EntityId,
        project_id: EntityId,
        leader: Option<EntityId>,
        now: u64,
    ) -> Result<ProjectRecord> {
        self.convert_thread_impl::<NoCardStep>(
            room,
            thread,
            source_message,
            project_id,
            leader,
            Some((owner, signer)),
            None,
            now,
        )
        .map(|(project, _)| project)
    }

    /// Card tap uses host-held placement and revalidates its authenticated
    /// owner inside the same transaction that mints the project and forks;
    /// the owner-project signer signs the new state for the owner. The tap's
    /// Grant and receipt are the standalone mint's, written by the same
    /// helper, and `after` runs on that receipt in the same write. An exact
    /// retry returns the recorded project and receipt and runs nothing.
    #[expect(
        clippy::too_many_arguments,
        reason = "one authenticated tap's card, owner, signer, birth id, time and step"
    )]
    pub(crate) fn convert_thread_with_card(
        &self,
        card: &crate::genui::ProjectProposalCard,
        tap: &crate::genui::ConsentActionRequest,
        owner: &crate::consent::AuthenticatedOwner,
        signer: &OwnerProjectSigner<'_>,
        project_id: EntityId,
        now: u64,
        after: impl FnOnce(&mut heed::RwTxn<'_>, &ProjectMintReceipt) -> Result<()>,
    ) -> Result<(ProjectRecord, ProjectMintReceipt)> {
        let intent = card.evaluate_action(self, tap, owner)?;
        let room = EntityId::from_hex(intent.source_room_ref.as_deref().ok_or_else(invalid)?)?;
        let thread = EntityId::from_hex(intent.source_thread_ref.as_deref().ok_or_else(invalid)?)?;
        let message = EntityId::from_hex(&intent.source_message_ref)?;
        let tap_key = super::mint::tap_key(card);
        let txn = self.store.env.read_txn()?;
        let digest = super::mint::tap_digest(card, owner.revalidate_in_txn(self, &txn)?)?;
        if let Some(receipt) = self.project_tap_in_txn(&txn, &tap_key, &digest)? {
            return Ok((self.tapped_project_in(&txn, &receipt)?, receipt));
        }
        drop(txn);
        let birth = CardBirth {
            intent: &intent,
            owner,
            signer,
            tap_key,
            digest,
            after,
        };
        match self.convert_thread_impl(
            room,
            thread,
            message,
            project_id,
            None,
            None,
            Some(birth),
            now,
        ) {
            Ok((project, Some(receipt))) => Ok((project, receipt)),
            Ok((_, None)) => Err(invalid()),
            Err(err) => {
                // A concurrent tap that won the writer holds the exact durable
                // result; any other refusal stands, never a second project.
                let txn = self.store.env.read_txn()?;
                owner.revalidate_in_txn(self, &txn)?;
                match self.project_tap_in_txn(&txn, &tap_key, &digest)? {
                    Some(receipt) => Ok((self.tapped_project_in(&txn, &receipt)?, receipt)),
                    None => Err(err),
                }
            }
        }
    }

    /// The project a recorded tap minted.
    fn tapped_project_in(
        &self,
        txn: &heed::RoTxn<'_>,
        receipt: &ProjectMintReceipt,
    ) -> Result<ProjectRecord> {
        let id = EntityId::from_hex(&receipt.project_id).map_err(|_| invalid())?;
        record::<ProjectRecord>(&self.store, txn, id, self.project_type_byte()?)?
            .ok_or_else(invalid)
    }

    /// Every conversion is the owner's act: the bare path carries its owner
    /// and signer in `bare`, a card tap in its `CardBirth`.
    #[expect(
        clippy::too_many_arguments,
        reason = "the private atomic door binds the source, chosen terms, owner and time"
    )]
    fn convert_thread_impl<A>(
        &self,
        room: EntityId,
        thread: EntityId,
        source_message: EntityId,
        project_id: EntityId,
        leader: Option<EntityId>,
        bare: Option<(&crate::consent::AuthenticatedOwner, &OwnerProjectSigner<'_>)>,
        card: Option<CardBirth<'_, A>>,
        now: u64,
    ) -> Result<(ProjectRecord, Option<ProjectMintReceipt>)>
    where
        A: FnOnce(&mut heed::RwTxn<'_>, &ProjectMintReceipt) -> Result<()>,
    {
        let kind = self.project_type_byte()?;
        self.backfill_tasks_by_owner()?;
        self.with_write_txn_grouped(|txn| {
            // The bare path's owner is revalidated here, before anything is
            // read for it; a card's below, with its intent.
            if let Some((owner, _)) = bare {
                owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            }
            if let Some(birth) = &card {
                let principal_ref = birth.owner.principal_ref_in_txn(self, txn)?;
                let intent = birth.intent;
                if intent.principal_ref != principal_ref
                    || intent.source_message_ref != source_message.to_hex()
                    || intent.source_room_ref.as_deref() != Some(room.to_hex().as_str())
                    || intent.source_thread_ref.as_deref() != Some(thread.to_hex().as_str())
                {
                    return Err(invalid());
                }
                // Two simultaneous taps can both see an absent mapping before
                // the writer; the loser finds the winner's here.
                if self
                    .project_tap_in_txn(txn, &birth.tap_key, &birth.digest)?
                    .is_some()
                {
                    return Err(invalid());
                }
            }
            let policy: crate::gate::ProjectConversionPolicy =
                crate::gate::resolve_policy_manifest(&self.store, txn)?
                    .project_conversion_policy()
                    .ok_or_else(invalid)?;
            let mut row = room_thread_in(self, txn, room, thread)?;
            let turns = rooms::thread_turns_in(self, txn, room, thread)?;
            if row.converted_project.is_some()
                || self.get_entity_type_in_txn(txn, &project_id)?.is_some()
                || thread_project_in(self, txn, room, thread, kind)?.is_some()
            {
                return Err(invalid());
            }
            if !turns
                .iter()
                .any(|turn| turn.message_ids.contains(&source_message.to_hex()))
                || self.get_entity_type_in_txn(txn, &source_message)? != Some(ENTITY_TYPE_MESSAGE)
            {
                return Err(invalid());
            }
            let source = rooms::room_in(self, txn, room)?;
            let source_project_id = EntityId::from_hex(&source.project_id)?;
            // The source's effective leader and claims scope, as its signed
            // history folds them.
            let (mut source_record, source_project) = self
                .effective_project_in_txn(txn, source_project_id)?
                .ok_or_else(invalid)?;
            // The card's confirmed leader, else the caller's explicit one, is
            // final. Only an unchosen leader falls back to the task holder,
            // then the room host.
            let confirmed = card
                .as_ref()
                .map(|birth| EntityId::from_hex(&birth.intent.leader_agent_def_ref))
                .transpose()?;
            let roots = turns
                .iter()
                .map(|turn| Ok((EntityId::from_hex(&turn.turn_id)?, thread)))
                .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
            let bindings = rooms::thread_task_bindings(&turns, &roots)?;
            let source_members = source.member_ids.iter().cloned().collect();
            for &task in bindings.keys() {
                crate::task_verb::room_thread_task_roster_in(self, txn, task, &source_members)?;
            }
            let task_ids = crate::task_verb::room_thread_task_ids_in(
                self,
                txn,
                &roots,
                &bindings,
                &source_members,
            )?;
            if task_ids.len() > policy.max_tasks {
                return Err(invalid());
            }
            let mut holder = None;
            let mut tasks = Vec::with_capacity(task_ids.len());
            for &id in task_ids.keys() {
                crate::task_verb::room_thread_task_roster_in(self, txn, id, &source_members)?;
                if confirmed.is_none() && holder.is_none() {
                    holder = crate::task_verb::open_thread_task_holder_in(
                        self,
                        txn,
                        id,
                        policy.task_holder_fallback,
                    )?
                    .filter(|candidate| {
                        policy.allows_leader_override(
                            *candidate,
                            &source.member_ids,
                            Some(*candidate),
                        )
                    });
                }
                tasks.push(id.to_hex());
            }
            let fallback = match policy.leader_fallback {
                LeaderFallback::TaskHolderThenSourceLeader => holder,
                LeaderFallback::SourceLeaderOnly => None,
            };
            let leader = match confirmed.or(leader).or(fallback) {
                Some(leader) => leader,
                None => EntityId::from_hex(&source_project.leader)?,
            };
            // The row checks that final leader once, before anything is written.
            let in_roster = source.member_ids.contains(&leader.to_hex());
            let allowed = if confirmed.is_some() {
                self.get_entity_type_in_txn(txn, &leader)? == Some(ENTITY_TYPE_AGENT_DEF)
                    && (policy.allow_holder_override || in_roster)
            } else {
                self.get_entity_type_in_txn(txn, &leader)?.is_some()
                    && policy.allows_leader_override(leader, &source.member_ids, holder)
            };
            if !allowed {
                return Err(invalid());
            }
            let mut project = ProjectRecord::new(
                project_id,
                Some(source_project_id),
                EntityId::from_hex(&source_project.claims_scope_ref)?,
                leader,
            )?;
            project.tasks = tasks;
            project.slice = source_project.slice.clone().ok_or_else(invalid)?;
            project.depth_limit = source_project.depth_limit;
            project.depth_remaining = source_project
                .depth_remaining
                .min(source_project.depth_limit)
                .checked_sub(1)
                .ok_or_else(invalid)?;
            project.roster = match policy.roster_selection {
                RosterSelection::InheritSource => source.member_ids,
                RosterSelection::LeaderOnly => vec![leader.to_hex()],
            };
            if !project.roster.contains(&leader.to_hex()) {
                project.roster.push(leader.to_hex());
            }
            project.born_from = Some(source_message.to_hex());
            project.origin_room = Some(room.to_hex());
            project.origin_thread = Some(thread.to_hex());
            project.origin_at = Some(row.at);
            if let Some(birth) = &card {
                self.apply_card_terms_in_txn(txn, birth.intent, project_id, now, &mut project)?;
                if policy.roster_selection == RosterSelection::LeaderOnly
                    && project.board.iter().any(|id| id != &project.leader)
                {
                    return Err(invalid());
                }
            }
            let destination_members = project.roster.iter().cloned().collect();
            for &task in task_ids.keys() {
                crate::task_verb::room_thread_task_roster_in(
                    self,
                    txn,
                    task,
                    &destination_members,
                )?;
            }
            // A move removes the old placement. A task owned by another
            // project's list is not silently taken from that project.
            let reader = ProjectReader::new(&self.store, txn, self.privacy_posture())?
                .ok_or_else(invalid)?;
            for (id, record, verdict) in reader.all()? {
                if id != source_project_id
                    && verdict == ProjectVerdict::Visible
                    && record.tasks.iter().any(|task| project.tasks.contains(task))
                {
                    return Err(invalid());
                }
            }
            let previous_tasks = source_record.tasks.len();
            source_record
                .tasks
                .retain(|task| !project.tasks.contains(task));
            let at = TimeRange {
                start: now,
                end: now,
            };
            let receipt = match card {
                // The owner's card: the host signs the new state for the
                // owner, it lands as history, and only an installed head
                // commits. The tap is the Grant move, as in a root mint.
                Some(birth) => {
                    let signed_at = owner_signer::owner_signed_at(self, txn)?;
                    self.sign_owner_project_in_txn(
                        txn,
                        birth.owner,
                        birth.signer,
                        project_id,
                        &mut project,
                        None,
                        signed_at,
                    )?;
                    self.batch_in()
                        .put_engine_history(&project_id, kind, at, now, &encode(&project)?)
                        .apply(txn)?;
                    self.require_owner_head_in_txn(txn, project_id, &project)?;
                    // A house mind the roster seats joins the new home room
                    // through the three consents, filed by the owner (OF-417).
                    let caller = crate::WriteActor::new(
                        birth.owner.revalidate_in_txn(self, txn)?,
                        crate::EdgeActorClass::Human,
                    );
                    let filed_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
                    crate::workspace_roster::workplace_join::file_house_joins_in_txn(
                        self,
                        txn,
                        EntityId::from_hex(&project.home_room)?,
                        &project.roster,
                        caller,
                        filed_at,
                    )?;
                    let receipt = self.grant_project_tap_in_txn(
                        txn,
                        birth.owner,
                        birth.intent,
                        leader,
                        project_id,
                        &birth.tap_key,
                        &birth.digest,
                    )?;
                    (birth.after)(txn, &receipt)?;
                    Some(receipt)
                }
                // The bare conversion is the owner's act as well: the host
                // signs the new state for the owner in this grouped write, it
                // lands as history, and only an installed head commits. No
                // conversion writes an unsigned row.
                None => {
                    let Some((owner, signer)) = bare else {
                        return Err(invalid());
                    };
                    let signed_at = owner_signer::owner_signed_at(self, txn)?;
                    self.sign_owner_project_in_txn(
                        txn,
                        owner,
                        signer,
                        project_id,
                        &mut project,
                        None,
                        signed_at,
                    )?;
                    self.batch_in()
                        .put_engine_history(&project_id, kind, at, now, &encode(&project)?)
                        .apply(txn)?;
                    self.require_owner_head_in_txn(txn, project_id, &project)?;
                    // The house mind joins here too, as on the carded path.
                    let caller = crate::WriteActor::new(
                        owner.revalidate_in_txn(self, txn)?,
                        crate::EdgeActorClass::Human,
                    );
                    let filed_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
                    crate::workspace_roster::workplace_join::file_house_joins_in_txn(
                        self,
                        txn,
                        EntityId::from_hex(&project.home_room)?,
                        &project.roster,
                        caller,
                        filed_at,
                    )?;
                    None
                }
            };
            if source_record.tasks.len() != previous_tasks {
                self.batch_in()
                    .put(&source_project_id, kind, at, now, &encode(&source_record)?)
                    .apply(txn)?;
            }
            // Keep historical thread bindings as references for result
            // headers. Only PROJECT.tasks determines current placement.
            row.converted_project = Some(project_id.to_hex());
            rooms::TURNS.put(&self.store, txn, &thread, &row)?;
            Ok((project, receipt))
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
        use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SKILL};
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
        project.why = Some(intent.goal.why.clone());
        project.goal_record = Some(ProjectGoalRecord {
            project_id: project_id.to_hex(),
            goal: intent.goal.goal.clone(),
            why: intent.goal.why.clone(),
            axes: intent.goal.axes.clone(),
        });
        project.budget_share = Some(ProjectBudgetShare {
            project_id: project_id.to_hex(),
            parent_id: project.parents.first().cloned().ok_or_else(invalid)?,
            share_bps: intent.budget_share_bps,
        });
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
        let prefix = [room.as_bytes().as_slice(), turn.as_bytes().as_slice()].concat();
        for (n, item) in rooms::THREAD_CHILDREN
            .iter_from(&self.store, &txn, &prefix)?
            .enumerate()
        {
            if n >= 4096 {
                return Err(Error::IndexOverflow("message_thread_matches"));
            }
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
        Ok(MessageHangs {
            runs,
            threads,
            projects,
        })
    }
}
