//! Host entry points for the CEO starter on a leased, task-bound leader.

use super::HostSelfDispatcher;
use crate::agent_dispatch::{
    AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, LeaderStarter, LeaderStarterSkills,
    LeaderTeamPlanner, LivePlanRequest, PlannerDecisions, PlannerSeat, PlannerSkills,
    SpawnPlanReceipt, VaultLeaderTeamPlanner, agent_dispatch_actor, decode_agent_dispatch_input,
};
use crate::attempt_queue::AttemptRecord;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::{
    SelfDispatchOutcome, SelfEffect, SelfFailedResult, SelfLeaderCall, SelfSpawnAsk,
};
use crate::dreamer_runner::DreamerRunnerStore;
use crate::error::{ArtifactError, Error, Result};
use crate::memory::MemoryResult;
use crate::skill::LoadedSkillPack;
use crate::task_type::PlacementDecisions;
use crate::workspace_roster::{ProjectProofVersion, ProjectRecord, ProjectWriteProof};
use crate::{EntityId, Vault};

fn invalid() -> Error {
    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
        "leader starter requires its host-bound acquired agent lease",
    ))
}

/// The host's planner (OF-541, OF-389): the skills, seats, executor and
/// ladders a planned spawn, its type placement and the leader's advice read
/// on this run. Host configuration only: no guest call, transcript or replay
/// row reaches it.
pub struct HostPlannerBinding<'a> {
    pub skills: PlannerSkills,
    pub seats: Vec<PlannerSeat>,
    /// The planner's `model@revision`, stamped on its pack loads.
    pub executor: String,
    /// The host's planner ladder; unset, the deterministic plan answers.
    pub planner: Option<&'a PlannerDecisions<'a>>,
    /// The host's placement ladder; unset, the placement skill's rule rung
    /// reads alone.
    pub placement: Option<&'a PlacementDecisions<'a>>,
    /// The leader's starter, pattern and team-shape skills.
    pub leader: LeaderStarterSkills,
    /// How many shapes advice returns when the leader names no count.
    pub top: usize,
}

impl<'a> HostSelfDispatcher<'a> {
    /// Lends the run the host's planner. Without one, a planned spawn and
    /// the leader's calls answer `planner_unbound`.
    #[must_use]
    pub fn with_planner(mut self, planner: HostPlannerBinding<'a>) -> Self {
        self.planner = Some(planner);
        self
    }
}

impl HostSelfDispatcher<'_> {
    pub(super) fn planner_unbound(effect: SelfEffect) -> SelfDispatchOutcome {
        SelfDispatchOutcome::Failed(SelfFailedResult {
            effect,
            error: "planner_unbound".to_owned(),
        })
    }

    pub(super) const fn planner_bound(&self) -> bool {
        self.planner.is_some()
    }

    /// OF-541: a leased agent's spawn, placed once and planned on the host's
    /// planner. The plan's seat is the target, its receipt and stamp ride
    /// the context, and a budget the ask sets narrows the child's carve.
    pub(super) fn planned_spawn(
        &self,
        mut context: AgentSpawnContext,
        ask: SelfSpawnAsk,
        at: u64,
    ) -> Result<(AgentDispatchTarget, AgentSpawnContext)> {
        if self.agent_lease.is_none() {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "a planned spawn requires the agent's acquired lease",
            )));
        }
        let planner = self.planner.as_ref().ok_or_else(invalid)?;
        let type_ref =
            self.place_agent_spawn_type(&ask.need, context.type_ref.as_ref(), planner.placement)?;
        let receipt = self.plan_agent_spawn(
            &LivePlanRequest {
                need: ask.into_need(type_ref),
                seats: &planner.seats,
                skills: &planner.skills,
                executor: &planner.executor,
                decisions: planner.planner,
            },
            at,
        )?;
        narrow_budget(&mut context, receipt.asked.budget_cap_units.as_ref());
        context.type_ref = Some(receipt.asked.type_ref.clone());
        let target = AgentDispatchTarget::Custom(receipt.plan.agent_def);
        context.plan = Some(receipt);
        Ok((target, context))
    }

    /// `self.leader.advice` and `self.leader.pattern` (OF-389), on the
    /// host's planner over the leader's host-bound lease.
    pub(super) fn dispatch_leader(&self, call: SelfLeaderCall) -> Result<SelfDispatchOutcome> {
        let Some(planner) = self.planner.as_ref() else {
            return Ok(Self::planner_unbound(SelfEffect::Leader));
        };
        let at = crate::unix_seconds_now();
        let answer = match call {
            SelfLeaderCall::Advice { top } => self.leader_advice(
                &planner.leader,
                planner.skills.clone(),
                planner.seats.clone(),
                &planner.executor,
                planner.planner,
                top.map_or(planner.top, |top| {
                    usize::try_from(top).unwrap_or(usize::MAX)
                }),
                at,
            )?,
            SelfLeaderCall::Pattern { skill } => {
                pattern_json(&self.reload_leader_pattern(skill, &planner.executor, at)?)
            }
        };
        Ok(SelfDispatchOutcome::Leader(answer.to_string()))
    }

    /// OF-389: load the pattern the leader picked from her advice, through
    /// the lease-fenced manifest door, after re-reading her live task.
    pub fn reload_leader_pattern(
        &self,
        pattern: EntityId,
        executor: &str,
        at: u64,
    ) -> Result<LoadedSkillPack> {
        let (vault, leased) = self.leader_attempt()?;
        AgentDispatcher::new(vault).reload_leader_pattern(&leased, pattern, executor, at)
    }

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

/// A budget the spawner set, seed or pin, narrows the child's hard carve; it
/// never widens it.
pub(super) fn narrow_budget(
    context: &mut AgentSpawnContext,
    asked: Option<&crate::agent_dispatch::SpawnOverride<u64>>,
) {
    if let Some(asked) = asked.map(|cap| *cap.value()) {
        context.budget = Some(context.budget.map_or(asked, |carve| carve.min(asked)));
    }
}

/// A loaded pattern as the leader reads it: the entity that loaded (an
/// exploration trial may route to its proposal), its revision and its files.
fn pattern_json(loaded: &LoadedSkillPack) -> serde_json::Value {
    serde_json::json!({
        "skill": loaded.entity.to_hex(),
        "skill_id": loaded.record.skill_id,
        "version": loaded.record.version,
        "desc": loaded.record.desc,
        "files": loaded.source_files.as_ref().map(|files| {
            files
                .iter()
                .map(|file| {
                    serde_json::json!({
                        "path": file.path,
                        "text": String::from_utf8_lossy(&file.content),
                    })
                })
                .collect::<Vec<_>>()
        }),
    })
}
