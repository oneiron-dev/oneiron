//! The owner's planned launch (DOOR-111 S4a): a planned intent's plan,
//! launched at the root as one group.
//!
//! A team runs its plan's selected pattern skill first: the exact revision
//! the plan froze, read as the root reads an admitted package, runs on the
//! host's pattern runner with no writer held, and the start it writes (the
//! leader's briefing and one per member) is frozen under the intent. The
//! first start frozen is the one that launches. One write transaction then
//! queues the leader and exactly width - 1 members as its children, binds
//! them as one team and marks the intent launched. Anything but a fresh
//! queued attempt drops the whole group, and the refusal is kept. A solo
//! queues its one agent the same way, with no team.
//!
//! A launched intent answers the identities it kept and never runs the
//! runner or a dispatch again. Until a host binds a runner, a team plan
//! refuses and stays planned. Only the owner's proof, the plan and the
//! dispatcher's own admission bound a launch, never where an agent runs.

use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::consent::AuthenticatedOwner;
use crate::context_projection::{ContextSpec, normalize_context_spec, validate_spec_narrows};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::team::{
    PatternLaunchRunner, PatternLaunchSpec, PatternSkillRef, PlannedIntentView, PlannedSpawnHost,
    PlannedSpawnRequest, SpawnPhase, TeamRunBinding, record_team_start_in_txn,
};

use super::super::types::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentSpawnContext, DispatchAgent,
};
use super::super::widen_record::invalid;
use super::super::{AgentDispatcher, SpawnPlanReceipt, TeamRunStamp, team_pattern};
use super::intent::{LaunchStand, PlannedLaunch, retained};

const NO_RUNNER: &str = "this host has no pattern runner bound yet; the plan stays frozen under \
     this intent key; ask again once the host binds one";
const RUNNER_FAILED: &str = "the pattern runner wrote no start for this plan; the plan stays \
     frozen under this intent key; ask again to run it again";
const INCOMPLETE_START: &str = "the pattern runner's start does not brief the leader and every \
     member the plan launches; the plan stays frozen under this intent key; ask again to run it \
     again";
const PATTERN_MOVED: &str = "the pattern skill this plan froze is no longer the approved \
     revision; ask again under a new intent key";
const START_MOVED: &str = "another call froze a different start for this intent; ask again \
     under the same intent key to launch the one it froze";
const NOT_FRESH: &str = "a planned launch queues fresh agents only, and its dispatch answered \
     otherwise";

impl AgentDispatcher<'_> {
    /// The owner's planned spawn, launched (DOOR-111 S4a). The intent is
    /// reserved, placed and planned first, or replayed, as
    /// [`Self::plan_reserved_spawn_as_owner`] does; a planned intent then
    /// launches. A team runs its plan's pattern skill on `runner` once and
    /// freezes the start it writes; the leader, exactly width - 1 members
    /// and their team are queued and bound in one write transaction, which
    /// marks the intent launched. A solo queues its one agent.
    ///
    /// The same key then answers what launched and never runs the runner
    /// or a dispatch again. A launch the dispatcher refuses is kept as the
    /// intent's refusal.
    ///
    /// # Errors
    ///
    /// As [`Self::plan_reserved_spawn_as_owner`]; a team plan with no
    /// runner bound, a runner that errs, or a start that does not brief the
    /// leader and every member, each of which leaves the intent planned;
    /// storage errors.
    pub fn launch_reserved_spawn_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        request: &PlannedSpawnRequest,
        host: &PlannedSpawnHost<'_>,
        runner: Option<&dyn PatternLaunchRunner>,
        at: u64,
    ) -> Result<PlannedIntentView> {
        let view = self.plan_reserved_spawn_as_owner(owner, request, host, at)?;
        if view.phase != SpawnPhase::Planned {
            return Ok(view);
        }
        let stand =
            self.planned_launch_in_txn(&self.vault.store.env.read_txn()?, owner, request)?;
        let planned = match stand {
            LaunchStand::Planned(planned) => planned,
            LaunchStand::Settled(view) => return Ok(*view),
        };
        let pattern = planned.plan()?.plan.pattern_skill.clone();
        let planned = match pattern {
            // A team's start is frozen once; a frozen one never runs again.
            Some(pattern) if planned.spec().is_none() => {
                match self.start_pattern(owner, request, runner, &planned, &pattern, at)? {
                    LaunchStand::Planned(planned) => planned,
                    LaunchStand::Settled(view) => return Ok(*view),
                }
            }
            _ => planned,
        };
        self.materialize_planned(owner, request, host, &planned, at)
    }

    /// Runs a planned team's pattern skill and freezes the start it writes.
    /// The exact revision the plan froze is read as an admitted package
    /// first, and one that moved is kept as the intent's refusal. The runner
    /// runs with no writer held; a runner that errs, or a start that does
    /// not brief the whole team, refuses and leaves the intent planned, so
    /// the next ask runs it again.
    fn start_pattern(
        &self,
        owner: &AuthenticatedOwner,
        request: &PlannedSpawnRequest,
        runner: Option<&dyn PatternLaunchRunner>,
        planned: &PlannedLaunch,
        pattern: &PatternSkillRef,
        at: u64,
    ) -> Result<LaunchStand> {
        let runner = runner.ok_or_else(|| invalid(NO_RUNNER))?;
        let pack = self.root_pattern_pack_in_txn(&self.vault.store.env.read_txn()?, pattern);
        let pack = match pack {
            Ok(pack) => pack,
            Err(error) => {
                let view = self.keep_refusal(planned, error, PATTERN_MOVED.to_owned(), at)?;
                return Ok(LaunchStand::Settled(Box::new(view)));
            }
        };
        let plan = planned.plan()?;
        let start = runner
            .run(&pack, &plan.asked, &request.prompt, &plan.plan)
            .map_err(|error| {
                tracing::warn!(
                    skill = %pattern.skill.to_hex(),
                    error = %error,
                    "a pattern runner wrote no start for a planned team"
                );
                invalid(RUNNER_FAILED)
            })?;
        check_start(&start, plan.plan.shape.width)?;
        self.freeze_pattern_launch(owner, request, start, at)
    }

    /// Launches a planned intent as one group. The leader's context resolves
    /// first, as a public dispatch's does, and each member's declared
    /// context must narrow the leader's. One writer then proves the owner
    /// and the intent again, rechecks the pattern revision, queues the
    /// leader and each member, binds the team, marks the intent launched and
    /// commits once.
    fn materialize_planned(
        &self,
        owner: &AuthenticatedOwner,
        request: &PlannedSpawnRequest,
        host: &PlannedSpawnHost<'_>,
        planned: &PlannedLaunch,
        at: u64,
    ) -> Result<PlannedIntentView> {
        let plan = planned.plan()?;
        let start = planned.spec();
        // The owner's prompt verbatim, then the start's leader briefing.
        let leader_spec = briefed(match start {
            Some(start) => format!("{}\n\n{}", request.prompt, start.leader_briefing),
            None => request.prompt.clone(),
        });
        let member_specs: Vec<ContextSpec> = start.map_or_else(Vec::new, |start| {
            start
                .member_briefings
                .iter()
                .cloned()
                .map(briefed)
                .collect()
        });
        if let Err(error) = self.preflight_group(plan, &leader_spec, &member_specs) {
            let refusal = format!("{error}; ask again under a new intent key");
            return self.keep_refusal(planned, error, refusal, at);
        }

        let mut wtxn = self.vault.store.env.write_txn()?;
        let current = match self.planned_launch_in_txn(&wtxn, owner, request)? {
            LaunchStand::Planned(current) if current.spec() == start => current,
            LaunchStand::Planned(_) => return Err(invalid(START_MOVED)),
            LaunchStand::Settled(view) => return Ok(*view),
        };
        if let Some(pattern) = &plan.plan.pattern_skill
            && let Err(error) = self.root_pattern_pack_in_txn(&wtxn, pattern)
        {
            drop(wtxn);
            return self.keep_refusal(planned, error, PATTERN_MOVED.to_owned(), at);
        }
        // The leader sets the group's one cap: the host's root scope, carved
        // to the ask's budget as a leased planned spawn's is. Members reserve
        // under the leader and name none.
        let leader = AgentSpawnContext {
            budget: plan.asked.budget_cap_units.as_ref().map(|cap| *cap.value()),
            spend: host.spend.cloned(),
            ..planned_context(plan, leader_spec)
        };
        let members = member_specs
            .into_iter()
            .map(|spec| planned_context(plan, spec))
            .collect();
        let digest = planned.digest_hex();
        match self.queue_group_in_txn(&mut wtxn, plan, leader, members, &digest, at) {
            Ok((root, members, team_ref)) => {
                let view = self.launch_planned_intent_in_txn(
                    &mut wtxn, *current, root, members, team_ref, at,
                )?;
                wtxn.commit()?;
                self.vault.store.notify_attempt_observers();
                Ok(view)
            }
            Err(error) => {
                drop(wtxn);
                let refusal = format!("{error}; ask again under a new intent key");
                self.keep_refusal(planned, error, refusal, at)
            }
        }
    }

    /// The public dispatch's preflight for the group, before any writer:
    /// the plan's seat is dispatchable and the leader's context resolves
    /// against fresh state at the root, and each member's declared context
    /// narrows the leader's, its parent's.
    fn preflight_group(
        &self,
        plan: &SpawnPlanReceipt,
        leader: &ContextSpec,
        members: &[ContextSpec],
    ) -> Result<()> {
        let seat = AgentDispatchTarget::Custom(plan.plan.agent_def);
        let definition = self.dispatchable_definition(&seat)?;
        self.resolve_dispatch_context(
            None,
            Some(leader),
            &[],
            None,
            definition.scope.to_world_scope(),
        )?;
        for member in members {
            validate_spec_narrows(leader, member)?;
        }
        Ok(())
    }

    /// Queues the leader at the root and each member as its child in the
    /// caller's writer, and binds the members as the leader's team; a solo
    /// queues its one agent and binds none. The dedupe keys and the team
    /// reference carry the intent's digest. Only a fresh queued attempt
    /// passes: anything else refuses, and the caller drops the whole group.
    /// Answers the leader, the members and the team.
    fn queue_group_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        plan: &SpawnPlanReceipt,
        leader_context: AgentSpawnContext,
        member_contexts: Vec<AgentSpawnContext>,
        digest: &str,
        at: u64,
    ) -> Result<(AttemptId, Vec<AttemptId>, Option<String>)> {
        let seat = AgentDispatchTarget::Custom(plan.plan.agent_def);
        let dispatch = |parent_attempt: Option<AttemptId>, role: &str| DispatchAgent {
            target: seat.clone(),
            parent_attempt,
            dedupe_key: Some(format!("planned:{digest}:{role}")),
            run_id: None,
            now: at,
        };
        let leader = self.queue_fresh_in_txn(wtxn, dispatch(None, "leader"), leader_context)?;
        let Some(pattern) = team_pattern(plan.plan.shape.pattern) else {
            return Ok((leader.id, Vec::new(), None));
        };
        let team_ref = format!("team:{}:{digest}", bytes_to_hex_lower(leader.id.as_bytes()));
        let stamp = TeamRunStamp::new(team_ref, pattern)?;
        let mut members = Vec::with_capacity(member_contexts.len());
        for (ordinal, context) in member_contexts.into_iter().enumerate() {
            let input = dispatch(Some(leader.id), &format!("member:{ordinal}"));
            let member = self.queue_fresh_in_txn(wtxn, input, context.with_team(stamp.clone()))?;
            members.push(member.id);
        }
        let binding = TeamRunBinding {
            stamp,
            leader: leader.id,
            root_task: leader.task_ref,
            started_at: at,
            members,
            proposals: Vec::new(),
        };
        record_team_start_in_txn(self.vault, wtxn, &binding)?;
        Ok((
            binding.leader,
            binding.members,
            Some(binding.stamp.team_ref),
        ))
    }

    /// One dispatch of the group in its writer: a fresh queued attempt, or
    /// a refusal that drops the group.
    fn queue_fresh_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: DispatchAgent,
        context: AgentSpawnContext,
    ) -> Result<AttemptRecord> {
        match self.dispatch_in_txn(wtxn, None, input, context)? {
            AgentDispatchOutcome::Dispatched(status) => Ok(status.attempt),
            _ => Err(invalid(NOT_FRESH)),
        }
    }

    /// Keeps `refusal` as the intent's answer when `error` is a refusal the
    /// intent keeps. A storage fault is no answer, and the intent stays
    /// planned.
    fn keep_refusal(
        &self,
        planned: &PlannedLaunch,
        error: Error,
        refusal: String,
        at: u64,
    ) -> Result<PlannedIntentView> {
        if retained(&error) {
            self.refuse_planned_launch(planned, refusal, at)
        } else {
            Err(error)
        }
    }
}

/// A context that briefs and asks for nothing else: the default projection,
/// no sibling results, and no scope, comm or target of the workflow's own.
fn briefed(briefing: String) -> ContextSpec {
    normalize_context_spec(ContextSpec::default().with_briefing(briefing))
}

/// One agent of the plan, as a leased planned spawn passes it: the plan
/// rides the dispatch, which seats the plan's model on its AGENT_DEF and
/// takes the type stamp the plan read.
fn planned_context(plan: &SpawnPlanReceipt, spec: ContextSpec) -> AgentSpawnContext {
    AgentSpawnContext::default()
        .with_context_spec(spec)
        .with_type_ref(plan.asked.type_ref.clone())
        .with_plan(plan.clone())
}

/// A runner's start is whole when it briefs the leader and exactly the
/// width less one members, none blank. Every pattern runs either axis (a
/// pattern skill's axis is a default, not a bound), so the plan admits
/// both. Rule 5 caps no briefing.
fn check_start(start: &PatternLaunchSpec, width: u32) -> Result<()> {
    let members = u32::try_from(start.member_briefings.len()).ok();
    if members.and_then(|count| count.checked_add(1)) != Some(width)
        || start.leader_briefing.trim().is_empty()
        || start
            .member_briefings
            .iter()
            .any(|briefing| briefing.trim().is_empty())
    {
        return Err(invalid(INCOMPLETE_START));
    }
    Ok(())
}
