//! A project's leader as a resident of the project's home room
//! (UNBUILT3-22, FIX PROJECT-LEADER-NOT-RESIDENT; ARCH-0067 #agents: "The
//! leader is a persistent resident with an inbox and a wake dial, so a
//! message from a person wakes it").
//!
//! The binding is one `agent.resident` CLAIM per PROJECT: its subject is the
//! PROJECT, its value names the leader AGENT_DEF, the project's home room
//! and the home MESSAGE its questions thread under, with its wake mode and
//! wake hold. The project is its goal record, so it names no goal refs; the
//! home room is its inbox, so it names no inbox identity, and a direct
//! message to the leader wakes it only as any non-resident agent's would.
//! One AGENT_DEF that leads several projects holds one binding per project,
//! and each project's room wakes it in that project.
//!
//! A card mint binds its leader in the birth write, under the minting
//! owner's tap (RULED LEADER-RESIDENT-EXISTING-PROJECTS = A); a project
//! minted before this binds when its board next confirms or reassigns the
//! lead. A binding acts only while it is settled and still names the
//! project's effective leader and home room, so a lead change stops the
//! old leader's wakes there at once.
//!
//! A binding makes the leader a resident of its home room only: its room
//! wakes there run as resident wakes stamped with the project. Every other
//! run of the AGENT_DEF (a TASK assigned to it, a project's goal intake)
//! keeps the host it had.

use super::{AgentDispatchInput, PREDICATE, ResidentAgentSpec, ResidentWakeMode, invalid};
use crate::attempt_queue::AttemptRecord;
use crate::claim::{ClaimSubject, claim_surfaceable};
use crate::consent::AuthenticatedOwner;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::write_envelope::ClaimCandidate;
use crate::{
    ClaimApprovalStatus, ClaimSource, EntityId, TimeRange, Vault, WriteActor, WriteEnvelope,
    WriteProvenance,
};
use rmpv::Value;
use std::collections::BTreeSet;

/// The stored value's version: a project-subject binding.
const PROJECT_LEADER_VERSION: u64 = 4;

/// A project's leader bound as the resident of the project's home room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectLeaderResident {
    pub project_ref: EntityId,
    pub agent_def_ref: EntityId,
    /// The project's home room: the room whose turns wake the leader.
    pub home_conversation_ref: EntityId,
    /// The MESSAGE of the home room a run's questions thread under: the
    /// project's trunk header.
    pub home_message_ref: EntityId,
    pub wake: ResidentWakeMode,
    /// The wake hold, in seconds (AGM-4 = C), room by room as for any
    /// resident. Scheduling only; it conveys no scope.
    pub wake_hold_secs: u32,
}

/// The resident binding a resident run executes under: the agent's own
/// binding, or the binding of the project whose home room woke it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResidentRunBinding {
    Agent(ResidentAgentSpec),
    ProjectLeader(ProjectLeaderResident),
}

impl ResidentRunBinding {
    #[must_use]
    pub const fn agent_def_ref(&self) -> EntityId {
        match self {
            Self::Agent(spec) => spec.agent_def_ref,
            Self::ProjectLeader(binding) => binding.agent_def_ref,
        }
    }

    #[must_use]
    pub const fn home_conversation_ref(&self) -> EntityId {
        match self {
            Self::Agent(spec) => spec.home_conversation_ref,
            Self::ProjectLeader(binding) => binding.home_conversation_ref,
        }
    }

    /// Where the run's questions thread: its binding's home MESSAGE.
    #[must_use]
    pub const fn home_message_ref(&self) -> EntityId {
        match self {
            Self::Agent(spec) => spec.home_message_ref,
            Self::ProjectLeader(binding) => binding.home_message_ref,
        }
    }
}

/// How a staged room wake of one agent is taken: the binding whose wake
/// mode and hold apply, and the project a project binding stamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RoomWakePolicy {
    pub(super) wake: ResidentWakeMode,
    pub(super) wake_hold_secs: u32,
    pub(super) project: Option<EntityId>,
}

fn encode(binding: &ProjectLeaderResident) -> Value {
    Value::Array(vec![
        Value::from(PROJECT_LEADER_VERSION),
        Value::from(binding.agent_def_ref.to_hex()),
        Value::from(binding.home_conversation_ref.to_hex()),
        Value::from(binding.home_message_ref.to_hex()),
        Value::from(match binding.wake {
            ResidentWakeMode::HumanMessages => "human_messages",
            ResidentWakeMode::AllAddressed => "all_addressed",
            ResidentWakeMode::Manual => "manual",
        }),
        Value::from(binding.wake_hold_secs),
    ])
}

/// Whether a stored `agent.resident` value is a project leader binding's.
fn is_project_leader_value(value: &Value) -> bool {
    value
        .as_array()
        .and_then(|a| a.first())
        .and_then(Value::as_u64)
        == Some(PROJECT_LEADER_VERSION)
}

fn decode(project: EntityId, value: &Value) -> Result<ProjectLeaderResident> {
    let a = value
        .as_array()
        .filter(|a| a.len() == 6)
        .ok_or_else(invalid)?;
    if a[0].as_u64() != Some(PROJECT_LEADER_VERSION) {
        return Err(invalid());
    }
    let text = |index: usize| a[index].as_str().ok_or_else(invalid);
    let entity = |index| EntityId::from_hex(text(index)?).map_err(|_| invalid());
    let wake = match text(4)? {
        "human_messages" => ResidentWakeMode::HumanMessages,
        "all_addressed" => ResidentWakeMode::AllAddressed,
        "manual" => ResidentWakeMode::Manual,
        _ => return Err(invalid()),
    };
    Ok(ProjectLeaderResident {
        project_ref: project,
        agent_def_ref: entity(1)?,
        home_conversation_ref: entity(2)?,
        home_message_ref: entity(3)?,
        wake,
        wake_hold_secs: a[5]
            .as_u64()
            .and_then(|secs| u32::try_from(secs).ok())
            .ok_or_else(invalid)?,
    })
}

impl Vault {
    /// Binds `binding`'s leader as the resident of its project's home room,
    /// in the caller's write, under the owner's proof: the binding carries
    /// the owner's answer, as an owner's resident binding does, so it lands
    /// settled on any criticality class. It replaces the project's earlier
    /// binding; an identical one stands as it is.
    pub(crate) fn bind_project_leader_resident_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        binding: &ProjectLeaderResident,
        now: u64,
    ) -> Result<EntityId> {
        self.validate_project_leader_in_txn(txn, binding)?;
        let previous = self.project_leader_claim_in_txn(txn, binding.project_ref)?;
        if let Some((id, stored)) = &previous
            && stored == binding
        {
            return Ok(*id);
        }
        let id = EntityId::now();
        let envelope = WriteEnvelope::new(
            WriteActor::new(owner.revalidate_in_txn(self, txn)?, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::Map(vec![
                (
                    Value::from("op"),
                    Value::from("project.bind_leader_resident"),
                ),
                (
                    Value::from("authentication"),
                    Value::from(format!("{:?}", owner.decision_id())),
                ),
            ]))?,
            ClaimApprovalStatus::Approved,
        );
        let owner_authored = owner.owner_answer_in_txn(self, txn)?;
        self.batch_in()
            .with_owner_authored(owner_authored)
            .claim_candidate(
                &id,
                ClaimCandidate::new(
                    PREDICATE,
                    ClaimSubject::Entity(binding.project_ref),
                    encode(binding),
                    1.0,
                ),
                &envelope,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
            .apply(txn)?;
        if let Some((old, _)) = &previous {
            self.supersede_claim_in_txn(txn, &id, old, now)?;
        }
        Ok(id)
    }

    /// The leader binding of `project` that acts now: settled, and naming
    /// the project's effective leader and its home room. `None` for a
    /// project with no binding, a held one, or one a lead change left
    /// behind.
    pub fn project_leader_resident(
        &self,
        project: EntityId,
    ) -> Result<Option<ProjectLeaderResident>> {
        let txn = self.store.env.read_txn()?;
        self.project_leader_resident_for_effect_in_txn(&txn, project)
    }

    /// [`Self::project_leader_resident`] in the caller's snapshot.
    pub(crate) fn project_leader_resident_for_effect_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        project: EntityId,
    ) -> Result<Option<ProjectLeaderResident>> {
        let mut found = None;
        let mut settled = false;
        for id in self.claims_for_subject_in_txn(txn, &project)? {
            let Some(body) = self.get_claim_in_txn(txn, &id)? else {
                continue;
            };
            if body.predicate != PREDICATE || !claim_surfaceable(&body) {
                continue;
            }
            let binding = decode(project, &body.value)?;
            if found.as_ref().is_some_and(|old| old != &binding) {
                return Err(invalid());
            }
            settled |= crate::gate::claim_critical_confirm_settled_in_txn(&self.store, txn, &id)?;
            found = Some(binding);
        }
        // A held row still conflicts above; only a settled row binds a wake.
        let Some(binding) = found.filter(|_| settled) else {
            return Ok(None);
        };
        Ok(self
            .leads_from_home_room_in_txn(txn, &binding)?
            .then_some(binding))
    }

    /// The acting leader binding of the project whose home room `room` is.
    pub(crate) fn home_room_leader_resident_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
    ) -> Result<Option<ProjectLeaderResident>> {
        match crate::workspace_roster::room_project_in(self, txn, room)? {
            Some(project) => self.project_leader_resident_for_effect_in_txn(txn, project),
            None => Ok(None),
        }
    }

    /// Every acting leader binding that names `agent`, one per project it
    /// leads, in project order.
    pub(crate) fn project_leader_residents_for_effect_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        agent: EntityId,
    ) -> Result<Vec<ProjectLeaderResident>> {
        let mut bindings = Vec::new();
        for project in self.leader_bound_projects_in_txn(txn)? {
            if let Some(binding) = self.project_leader_resident_for_effect_in_txn(txn, project)?
                && binding.agent_def_ref == agent
            {
                bindings.push(binding);
            }
        }
        Ok(bindings)
    }

    /// Every agent a project's acting leader binding names: each leads a
    /// project as the resident of its home room. An agent's own binding is
    /// [`Self::settled_resident_agent`]'s.
    pub fn project_leader_resident_agents(&self) -> Result<BTreeSet<EntityId>> {
        let txn = self.store.env.read_txn()?;
        let mut agents = BTreeSet::new();
        for project in self.leader_bound_projects_in_txn(&txn)? {
            if let Some(binding) = self.project_leader_resident_for_effect_in_txn(&txn, project)? {
                agents.insert(binding.agent_def_ref);
            }
        }
        Ok(agents)
    }

    /// Every project a leader binding was written for, by the predicate's
    /// posting list: the PROJECT subjects of `agent.resident` rows.
    fn leader_bound_projects_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<BTreeSet<EntityId>> {
        Ok(self
            .claims_with_predicate_in_txn(txn, PREDICATE)?
            .into_iter()
            .filter_map(|(_, body)| match &body.subject {
                ClaimSubject::Entity(subject) if is_project_leader_value(&body.value) => {
                    Some(*subject)
                }
                _ => None,
            })
            .collect())
    }

    /// Whether a resident's inbox pass takes the staged room wake `wake`:
    /// its agent's own binding takes every room's, a project leader binding
    /// its home room's. The STREAM hands over only the rest.
    pub(crate) fn resident_takes_room_wake(
        &self,
        wake: &crate::workspace_roster::RoomWake,
    ) -> Result<bool> {
        if self.settled_resident_agent(wake.agent)?.is_some() {
            return Ok(true);
        }
        let txn = self.store.env.read_txn()?;
        Ok(self
            .home_room_leader_resident_in_txn(&txn, wake.room)?
            .is_some_and(|binding| binding.agent_def_ref == wake.agent))
    }

    /// The binding resident run `row` of `agent` executes under: a room wake
    /// stamped with a project runs under that project's acting leader
    /// binding when it names `agent`; every other resident run under the
    /// agent's own binding.
    pub(crate) fn resident_run_binding_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        row: &AttemptRecord,
        agent: EntityId,
        input: &AgentDispatchInput,
    ) -> Result<Option<ResidentRunBinding>> {
        if row.task_ref.is_none()
            && let Some(project) = input.project_ref
            && let Some(binding) = self.project_leader_resident_for_effect_in_txn(txn, project)?
            && binding.agent_def_ref == agent
        {
            return Ok(Some(ResidentRunBinding::ProjectLeader(binding)));
        }
        Ok(self
            .resident_binding_for_effect_in_txn(txn, agent)?
            .map(|(_, spec)| ResidentRunBinding::Agent(spec)))
    }

    /// The policy a staged wake of `agent` in `room` is taken under: the
    /// leader binding of the project whose home room it is, when that names
    /// `agent`, else `own`, the agent's own binding. `None`: no resident
    /// binding takes it.
    pub(super) fn room_wake_policy_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        agent: EntityId,
        room: EntityId,
        own: Option<&ResidentAgentSpec>,
    ) -> Result<Option<RoomWakePolicy>> {
        if let Some(binding) = self.home_room_leader_resident_in_txn(txn, room)?
            && binding.agent_def_ref == agent
        {
            return Ok(Some(RoomWakePolicy {
                wake: binding.wake,
                wake_hold_secs: binding.wake_hold_secs,
                project: Some(binding.project_ref),
            }));
        }
        Ok(own.map(|spec| RoomWakePolicy {
            wake: spec.wake,
            wake_hold_secs: spec.wake_hold_secs,
            project: None,
        }))
    }

    /// The project's stored leader binding, settled or not, with its claim.
    fn project_leader_claim_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        project: EntityId,
    ) -> Result<Option<(EntityId, ProjectLeaderResident)>> {
        for id in self.claims_for_subject_in_txn(txn, &project)? {
            let Some(body) = self.get_claim_in_txn(txn, &id)? else {
                continue;
            };
            if body.predicate == PREDICATE && claim_surfaceable(&body) {
                return Ok(Some((id, decode(project, &body.value)?)));
            }
        }
        Ok(None)
    }

    /// Whether `binding` still names its project's effective leader and its
    /// home room.
    fn leads_from_home_room_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        binding: &ProjectLeaderResident,
    ) -> Result<bool> {
        let Some((_, effective)) = self.effective_project_in_txn(txn, binding.project_ref)? else {
            return Ok(false);
        };
        Ok(effective.leader == binding.agent_def_ref.to_hex()
            && crate::workspace_roster::room_project_in(self, txn, binding.home_conversation_ref)?
                == Some(binding.project_ref))
    }

    /// A binding names the project's effective leader, its home room, and
    /// a MESSAGE of that room.
    fn validate_project_leader_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        binding: &ProjectLeaderResident,
    ) -> Result<()> {
        if !self.leads_from_home_room_in_txn(txn, binding)? {
            return Err(invalid());
        }
        let rooms = self
            .store
            .port_edges(
                txn,
                &binding.home_message_ref,
                EdgeDirection::Out,
                Some(EdgeKind::BelongsTo),
                None,
            )?
            .collect::<Result<Vec<_>>>()?;
        if rooms.len() != 1 || rooms[0].target != binding.home_conversation_ref {
            return Err(invalid());
        }
        Ok(())
    }
}
