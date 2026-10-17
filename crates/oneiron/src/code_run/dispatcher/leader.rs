//! Host entry points for the CEO starter on a leased, task-bound leader.

use super::HostSelfDispatcher;
use crate::agent_dispatch::{
    AgentDispatcher, LeaderStarter, LeaderStarterSkills, LeaderTeamPlanner, LivePlanRequest,
    PlannerDecisions, PlannerSeat, PlannerSkills, SpawnPlanReceipt, VaultLeaderTeamPlanner,
    agent_dispatch_actor, decode_agent_dispatch_input,
};
use crate::attempt_queue::AttemptRecord;
use crate::code_run::storage::ExecutorStorage;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::error::{ArtifactError, Error, Result};
use crate::memory::MemoryResult;
use crate::workspace_roster::{ProjectProofVersion, ProjectRecord, ProjectWriteProof};
use crate::{EntityId, Vault};

fn invalid() -> Error {
    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
        "leader starter requires its host-bound acquired agent lease",
    ))
}

impl HostSelfDispatcher<'_> {
    /// Load the starter and an optional CEO-selected pattern before running
    /// the leader. Host bindings supply identity and lease, not guest text.
    pub fn prepare_leader_starter(
        &self,
        skills: &LeaderStarterSkills,
        executor: &str,
        at: u64,
    ) -> Result<LeaderStarter> {
        let (vault, leased) = self.leader_attempt()?;
        AgentDispatcher::new(vault).prepare_leader_starter(&leased, skills, executor, at)
    }

    /// Ask the configured team-shape ladder without starting any work. The
    /// caller may use the advice to choose its next pattern skill load.
    pub fn leader_top_shapes(
        &self,
        team_shape_skill: EntityId,
        executor: &str,
        planner: &mut dyn LeaderTeamPlanner,
        at: u64,
    ) -> Result<serde_json::Value> {
        let (vault, leased) = self.leader_attempt()?;
        AgentDispatcher::new(vault).leader_top_shapes(
            &leased,
            team_shape_skill,
            executor,
            planner,
            at,
        )
    }

    /// OF-541: plan this agent's next spawn on the live vault planner, over
    /// its host-bound lease. The receipt rides the spawn's context
    /// ([`crate::agent_dispatch::AgentSpawnContext::plan`]); planning launches
    /// nothing.
    pub fn plan_agent_spawn(
        &self,
        request: &LivePlanRequest<'_>,
        at: u64,
    ) -> Result<SpawnPlanReceipt> {
        let (vault, leased) = self.leader_attempt()?;
        AgentDispatcher::new(vault).plan_spawn_for_attempt(&leased, request, at)
    }

    /// OF-541: place a spawn's type once, against the tree in force for
    /// this agent's project, before it is planned; the host's placement
    /// ladder routes it past the skill's rule rung.
    pub fn place_agent_spawn_type(
        &self,
        need: &str,
        requested: Option<&crate::task_type::TaskTypeRef>,
        decisions: Option<&crate::task_type::PlacementDecisions<'_>>,
    ) -> Result<crate::task_type::TaskTypeRef> {
        let (vault, leased) = self.leader_attempt()?;
        AgentDispatcher::new(vault).place_spawn_type(&leased, need, requested, decisions)
    }

    /// OF-389: the CEO's top shapes on the installed vault planner, over
    /// the leader's host-bound lease. Advice only: no work starts.
    #[expect(
        clippy::too_many_arguments,
        reason = "the advice binds the starter skills, planner skills, seats, executor, ladder, width and clock"
    )]
    pub fn leader_advice(
        &self,
        skills: &LeaderStarterSkills,
        planner_skills: PlannerSkills,
        seats: Vec<PlannerSeat>,
        executor: &str,
        decisions: Option<&PlannerDecisions<'_>>,
        top: usize,
        at: u64,
    ) -> Result<serde_json::Value> {
        let (vault, leased) = self.leader_attempt()?;
        let dispatcher = AgentDispatcher::new(vault);
        let planner = VaultLeaderTeamPlanner::new(
            &dispatcher,
            leased.clone(),
            planner_skills,
            seats,
            executor,
            top,
            at,
        );
        let mut planner = match decisions {
            Some(decisions) => planner.with_decisions(decisions),
            None => planner,
        };
        dispatcher.leader_advice(&leased, skills, executor, &mut planner, at)
    }

    /// The bound leader splits her wrapper TASK into a subproject under
    /// `parent`, led by `leader` (OF-389). The host signs her spawn proof
    /// ([`Self::leader_spawn_proof`]), and
    /// [`crate::memory::Memory::spawn_task_subproject`] links the TASK and the
    /// child both ways in one write.
    pub fn spawn_leader_subproject(
        &self,
        issuer: &crate::authority::HostSlipIssuer,
        wrapper: EntityId,
        parent: EntityId,
        leader: EntityId,
        slice: crate::llm::Scope,
        now: u64,
    ) -> MemoryResult<ProjectRecord> {
        let (vault, _) = self.leader_attempt()?;
        let child = EntityId::now();
        let proof = self.leader_spawn_proof(vault, issuer, parent, child, leader, &slice)?;
        vault
            .memory(self.actor.entity_ref(), self.actor.actor_class())
            .spawn_task_subproject(wrapper, parent, child, leader, slice, proof, now)
    }

    /// The leader's proof for spawning `child` under `parent`: the host mints
    /// her a slip narrowed to `project.write` on `parent`, held under the
    /// host's binding key, and signs the child's authority as the spawn door
    /// builds it, so the signature covers what lands.
    fn leader_spawn_proof(
        &self,
        vault: &Vault,
        issuer: &crate::authority::HostSlipIssuer,
        parent: EntityId,
        child: EntityId,
        leader: EntityId,
        slice: &crate::llm::Scope,
    ) -> Result<ProjectWriteProof> {
        let actor = self.actor.entity_ref();
        let effective = {
            let txn = vault.store.env.read_txn()?;
            vault
                .effective_project_in_txn(&txn, parent)?
                .map(|(_, effective)| effective)
                .ok_or(crate::error::RecordError::InvalidProjectBody(
                    "missing parent project",
                ))?
        };
        let mut body = ProjectRecord::new(
            child,
            Some(parent),
            EntityId::from_hex(&effective.claims_scope_ref)?,
            leader,
        )?;
        body.slice = slice.clone();
        body.depth_limit = effective.depth_limit;
        body.depth_remaining = effective
            .depth_remaining
            .min(effective.depth_limit)
            .saturating_sub(1);
        body.board.push(actor.to_hex());
        let mut claims = vault.ensure_host_root_slip(issuer)?.claims;
        claims.slip_id = *blake3::hash(child.as_bytes()).as_bytes();
        claims.parent_id = None;
        claims.holder_ref = actor.to_hex();
        let mut scope = crate::federation::Scope::top();
        scope.audience = crate::federation::ScopeAxis::Some(std::collections::BTreeSet::from([
            crate::federation::ScopeId(parent),
        ]));
        scope.verbs = crate::federation::ScopeAxis::Some(std::collections::BTreeSet::from([
            "project.write".into(),
        ]));
        claims.scope = scope;
        let slip = vault.mint_capability_slip(issuer, claims)?;
        let signed_at = slip.claims.issued_at;
        let version = ProjectProofVersion::V3;
        let challenge = body
            .authority_at(version)
            .write_challenge(child, version, signed_at, None)?;
        Ok(ProjectWriteProof {
            slip_wire: slip.to_token()?,
            holder_signature: issuer.binding_proof(&slip, &challenge)?,
            signed_at,
            anchor: None,
            version,
        })
    }

    fn leader_attempt(&self) -> Result<(&Vault, AttemptRecord)> {
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Err(invalid());
        };
        let parent = self.agent_parent.ok_or_else(invalid)?;
        let lease = self.agent_lease.as_ref().ok_or_else(invalid)?;
        let status = DreamerRunnerStore::new(vault)
            .status(parent)?
            .ok_or_else(invalid)?;
        let input = decode_agent_dispatch_input(&status.payload.input)?;
        if agent_dispatch_actor(&input)? != self.actor
            || status.attempt.lease_owner.as_deref() != Some(lease.owner.as_str())
            || status.attempt.attempt_count != lease.generation
        {
            return Err(invalid());
        }
        Ok((vault, status.attempt))
    }
}
