//! The planned launch (DOOR-111 S4a, S4c-2): a planned intent's plan,
//! launched as one group, at the root for the owner, or under a leased
//! agent's real attempt (`child`).
//!
//! A team runs its plan's selected pattern skill first: the exact revision
//! the plan froze, read as the root reads an admitted package (a leased
//! agent's loads exactly through its parent's lease), runs on the caller's
//! pattern runner with no writer held, and the start it writes (the
//! leader's briefing and one per member) is frozen under the intent with
//! the pack it ran on. The first pair frozen is the one that launches. One
//! write transaction then queues the leader and exactly width - 1 members as
//! its children, binds them as one team and marks the intent launched.
//! Anything but a fresh queued attempt drops the whole group, and the
//! refusal is kept. A solo queues its one agent the same way, with no team.
//!
//! A launched intent answers the identities it kept and never runs the
//! runner or a dispatch again. Until a host binds a runner, a team plan
//! refuses and stays planned. Only the asker's proof, the plan and the
//! dispatcher's own admission bound a launch, never where an agent runs. A
//! launch on a target an erase took records that typed outcome on the
//! intent and launches nothing (Engine 10-22): no pattern loads or runs,
//! and the group writer queues nothing.

mod child;

use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::consent::AuthenticatedOwner;
use crate::context_projection::{ContextSpec, normalize_context_spec, validate_spec_narrows};
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::skill::LoadedSkillPack;
use crate::team::{
    PatternLaunchRunner, PatternLaunchSpec, PatternSkillRef, PlannedIntentView, PlannedSpawnHost,
    PlannedSpawnRequest, SpawnPhase, TeamRunBinding, record_team_start_in_txn,
};
use crate::write_envelope::WriteActor;

use super::super::planner::launch_budget;
use super::super::types::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentSpawnContext, DispatchAgent,
};
use super::super::widen_record::invalid;
use super::super::{AgentDispatcher, SpawnPlanReceipt, TeamRunStamp, team_pattern};
use super::intent::{IntentName, LaunchStand, PlannedLaunch, retained};

const NO_RUNNER: &str = "this host has no pattern runner bound yet; the plan stays frozen under \
     this intent key; ask again once the host binds one";
const RUNNER_FAILED: &str = "the pattern runner failed on a host fault (see the host log) and \
     wrote no start; the plan stays frozen under this intent key; ask again to run it again";
const INCOMPLETE_START: &str = "the pattern runner's start does not brief the leader and every \
     member the plan launches; the plan stays frozen under this intent key; ask again to run it \
     again";
const PATTERN_MOVED: &str = "the pattern skill this plan froze is no longer the approved \
     revision; ask again under a new intent key";
const START_MOVED: &str = "another call froze a different start for this intent; ask again \
     under the same intent key to launch the one it froze";
const NOT_FRESH: &str = "a planned launch queues fresh agents only, and its dispatch answered \
     otherwise";

/// One planned group's launch: the intent it launches, where its leader
/// goes and on which run, the leader's context before the plan stamps it,
/// and the payer its pattern run is metered to. The owner's leader goes to
/// the root on no run, under the host's root spend; a leased agent's goes
/// under the attempt it spawns from, on its run, in the context the agent
/// asked for. Members go under the leader.
struct GroupLaunch<'a> {
    name: &'a IntentName<'a>,
    parent: Option<AttemptId>,
    run_id: Option<String>,
    leader: AgentSpawnContext,
    payer: WriteActor,
}

/// Where a group queues: the intent's digest its dedupe keys and team
/// reference carry, the leader's parent (none at the root), and the run
/// every agent of the group rides.
struct GroupAnchor<'a> {
    digest: &'a str,
    parent: Option<AttemptId>,
    run_id: Option<&'a str>,
}

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
        let name = IntentName::owner(owner, request)?;
        // The owner's prompt verbatim leads the leader's briefing; the leader
        // goes to the root under the host's root spend scope, and the owner
        // pays for the pattern run (FIX 4638).
        let launch = GroupLaunch {
            name: &name,
            parent: None,
            run_id: None,
            leader: AgentSpawnContext {
                context_spec: Some(ContextSpec::default().with_briefing(request.prompt.clone())),
                spend: host.spend.cloned(),
                ..AgentSpawnContext::default()
            },
            payer: WriteActor::new(owner.actor_for_read(self.vault)?, EdgeActorClass::Human),
        };
        let load = |pattern: &PatternSkillRef| -> Result<LoadedSkillPack> {
            self.root_pattern_pack_in_txn(&self.vault.store.env.read_txn()?, pattern)
        };
        self.launch_planned_group(launch, runner, &request.prompt, load, at)
    }

    /// Launches the planned intent `launch` names. A team's start is frozen
    /// once: its pattern skill, read by `load`, runs on `runner` with
    /// `prompt` as the work, and a frozen start never runs again. The group
    /// then queues in one writer. A launched, refused or erased intent
    /// answers what it kept, and one whose target an erase took records
    /// that before any pattern loads.
    fn launch_planned_group(
        &self,
        launch: GroupLaunch<'_>,
        runner: Option<&dyn PatternLaunchRunner>,
        prompt: &str,
        load: impl FnOnce(&PatternSkillRef) -> Result<LoadedSkillPack>,
        at: u64,
    ) -> Result<PlannedIntentView> {
        let rtxn = self.vault.store.env.read_txn()?;
        let planned = match self.planned_launch_in_txn(&rtxn, launch.name)? {
            LaunchStand::Planned(planned) => planned,
            LaunchStand::Settled(view) => {
                if let Some(plan) = &view.plan {
                    self.observe_seat(plan.plan.agent_def);
                }
                return Ok(*view);
            }
        };
        // FIX 9180: the plan's AGENT_DEF seats the leader and every member,
        // noted before anything below can fail.
        if let Ok(plan) = planned.plan() {
            self.observe_seat(plan.plan.agent_def);
        }
        let erased = self.target_erased_in_txn(&rtxn, &planned);
        drop(rtxn);
        if erased {
            return self.record_target_erased(launch.name, at);
        }
        let pattern = planned.plan()?.plan.pattern_skill.clone();
        let planned = match pattern {
            // A team's start is frozen once; a frozen one never runs again.
            Some(pattern) if planned.spec().is_none() => {
                let pack = || load(&pattern);
                match self.start_pattern(&launch, runner, &planned, prompt, pack, at)? {
                    LaunchStand::Planned(planned) => planned,
                    LaunchStand::Settled(view) => return Ok(*view),
                }
            }
            _ => planned,
        };
        self.materialize_planned(launch, &planned, at)
    }

    /// Runs a planned team's pattern skill and freezes the start it writes
    /// with the pack it ran on. The exact revision the plan froze is read by
    /// `load` first, and one that moved is kept as the intent's refusal. The
    /// runner runs with no writer held, metered to the launch's payer. Its
    /// own refusal, an [`Error::Refused`] that names what to fund or
    /// configure, answers as it is, as does its wait on rested offers,
    /// [`Error::ProviderUnavailable`]; any other error it returns is a host
    /// fault, logged and answered with a fixed refusal. Either, or a start that does not brief
    /// the whole team, leaves the intent planned, so the next ask runs it
    /// again.
    fn start_pattern(
        &self,
        launch: &GroupLaunch<'_>,
        runner: Option<&dyn PatternLaunchRunner>,
        planned: &PlannedLaunch,
        prompt: &str,
        load: impl FnOnce() -> Result<LoadedSkillPack>,
        at: u64,
    ) -> Result<LaunchStand> {
        let runner = runner.ok_or_else(|| invalid(NO_RUNNER))?;
        let pack = match load() {
            Ok(pack) => pack,
            Err(error) => {
                let moved = PATTERN_MOVED.to_owned();
                let view = self.keep_refusal(launch.name, planned, error, moved, at)?;
                return Ok(LaunchStand::Settled(Box::new(view)));
            }
        };
        let plan = planned.plan()?;
        let start = runner
            .run(&pack, &plan.asked, prompt, &plan.plan, &launch.payer)
            .map_err(|error| {
                tracing::warn!(
                    skill = %pack.entity.to_hex(),
                    error = %error,
                    "a pattern runner wrote no start for a planned team"
                );
                // A wait on rested offers stays typed (FIX 9535): the
                // intent stays planned, and the same ask continues it.
                if matches!(error, Error::Refused(_) | Error::ProviderUnavailable { .. }) {
                    error
                } else {
                    invalid(RUNNER_FAILED)
                }
            })?;
        check_start(&start, plan.plan.shape.width)?;
        self.freeze_pattern_launch(launch.name, start, &pack, at)
    }

    /// Launches a planned intent as one group. The leader's context resolves
    /// first against its real parent, as a public dispatch's does, and each
    /// member's declared context must narrow the leader's. One writer then
    /// proves the asker and re-reads the intent, rechecks its target and the
    /// pattern revision, queues the leader and each member, binds the team,
    /// marks the intent launched and commits once. A target an erase took
    /// since commits that outcome instead, with nothing queued.
    fn materialize_planned(
        &self,
        launch: GroupLaunch<'_>,
        planned: &PlannedLaunch,
        at: u64,
    ) -> Result<PlannedIntentView> {
        let GroupLaunch {
            name,
            parent,
            run_id,
            mut leader,
            payer: _,
        } = launch;
        let plan = planned.plan()?;
        let start = planned.spec();
        let leader_spec = leader_briefed(leader.context_spec.take().unwrap_or_default(), start);
        let member_specs: Vec<ContextSpec> = start.map_or_else(Vec::new, |start| {
            start
                .member_briefings
                .iter()
                .cloned()
                .map(briefed)
                .collect()
        });
        let digest = planned.digest_hex();
        let anchor = GroupAnchor {
            digest: &digest,
            parent,
            run_id: run_id.as_deref(),
        };
        let preflight = self.preflight_group(
            plan,
            &anchor,
            &leader_spec,
            &leader.context_from,
            &member_specs,
        );
        if let Err(error) = preflight {
            let refusal = format!("{error}; ask again under a new intent key");
            return self.keep_refusal(name, planned, error, refusal, at);
        }

        let mut wtxn = self.vault.store.env.write_txn()?;
        let current = match self.planned_launch_in_txn(&wtxn, name)? {
            LaunchStand::Planned(current) if current.holds_frozen(planned) => current,
            LaunchStand::Planned(_) => return Err(invalid(START_MOVED)),
            LaunchStand::Settled(view) => return Ok(*view),
        };
        if self.target_erased_in_txn(&wtxn, &current) {
            return self.record_target_erased_in_txn(wtxn, *current, at);
        }
        if let Some(pattern) = &plan.plan.pattern_skill
            && let Err(error) =
                self.vault
                    .exact_workflow_pack_in_txn(&wtxn, &pattern.skill, &pattern.version)
        {
            drop(wtxn);
            return self.keep_refusal(name, planned, error, PATTERN_MOVED.to_owned(), at);
        }
        // The leader sets the group's one cap: the carve its asker set (none
        // at the root), narrowed to the ask's budget as a leased planned
        // spawn's is, under its parent's scope or the host's root scope.
        // Members reserve under the leader and name none.
        let budget = narrowed(leader.budget, launch_budget(&plan.asked, &plan.plan));
        let leader = AgentSpawnContext {
            budget,
            ..planned_context(leader, plan, leader_spec)
        };
        let members = member_specs
            .into_iter()
            .map(|spec| planned_context(AgentSpawnContext::default(), plan, spec))
            .collect();
        match self.queue_group_in_txn(&mut wtxn, plan, &anchor, leader, members, at) {
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
                self.keep_refusal(name, planned, error, refusal, at)
            }
        }
    }

    /// The public dispatch's preflight for the group, before any writer:
    /// the plan's seat is dispatchable and the leader's context resolves
    /// against fresh state under its real parent and run, and each member's
    /// declared context narrows the leader's, its parent's.
    fn preflight_group(
        &self,
        plan: &SpawnPlanReceipt,
        anchor: &GroupAnchor<'_>,
        leader: &ContextSpec,
        context_from: &[EntityId],
        members: &[ContextSpec],
    ) -> Result<()> {
        let seat = AgentDispatchTarget::Custom(plan.plan.agent_def);
        let definition = self.dispatchable_definition(&seat)?;
        self.resolve_dispatch_context(
            anchor.parent,
            Some(leader),
            context_from,
            anchor.run_id,
            definition.scope.to_world_scope(),
        )?;
        for member in members {
            validate_spec_narrows(leader, member)?;
        }
        Ok(())
    }

    /// Queues the leader under the anchor's parent and each member as its
    /// child in the caller's writer, all on the anchor's run, and binds the
    /// members as the leader's team; a solo queues its one agent and binds
    /// none. The dedupe keys and the team reference carry the intent's
    /// digest. Only a fresh queued attempt passes: anything else refuses,
    /// and the caller drops the whole group. Answers the leader, the members
    /// and the team.
    fn queue_group_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        plan: &SpawnPlanReceipt,
        anchor: &GroupAnchor<'_>,
        leader_context: AgentSpawnContext,
        member_contexts: Vec<AgentSpawnContext>,
        at: u64,
    ) -> Result<(AttemptId, Vec<AttemptId>, Option<String>)> {
        let seat = AgentDispatchTarget::Custom(plan.plan.agent_def);
        let digest = anchor.digest;
        let dispatch = |parent_attempt: Option<AttemptId>, role: &str| DispatchAgent {
            target: seat.clone(),
            parent_attempt,
            dedupe_key: Some(format!("planned:{digest}:{role}")),
            run_id: anchor.run_id.map(str::to_owned),
            now: at,
        };
        let leader =
            self.queue_fresh_in_txn(wtxn, dispatch(anchor.parent, "leader"), leader_context)?;
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
        name: &IntentName<'_>,
        planned: &PlannedLaunch,
        error: Error,
        refusal: String,
        at: u64,
    ) -> Result<PlannedIntentView> {
        if retained(&error) {
            self.refuse_planned_launch(name, planned, refusal, at)
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

/// The leader's context spec: the one its asker gave, whole, and once a
/// team's start is frozen, its briefing followed after a blank line by the
/// start's leader briefing.
fn leader_briefed(mut asked: ContextSpec, start: Option<&PatternLaunchSpec>) -> ContextSpec {
    if let Some(start) = start {
        asked.briefing = Some(match asked.briefing.take() {
            Some(briefing) if !briefing.trim().is_empty() => {
                format!("{briefing}\n\n{}", start.leader_briefing)
            }
            _ => start.leader_briefing.clone(),
        });
    }
    normalize_context_spec(asked)
}

/// One agent of the plan, as a leased planned spawn passes it: `base` with
/// the plan riding the dispatch, which seats the plan's model on its
/// AGENT_DEF and takes the type stamp the plan read.
fn planned_context(
    base: AgentSpawnContext,
    plan: &SpawnPlanReceipt,
    spec: ContextSpec,
) -> AgentSpawnContext {
    base.with_context_spec(spec)
        .with_type_ref(plan.asked.type_ref.clone())
        .with_plan(plan.clone())
}

/// The group's one cap: the carve its asker set, narrowed by the ask's
/// pinned budget, or by the budget a seeded ask resolved to and the plan was
/// fitted under (FIX 9561); never widened by it.
fn narrowed(carve: Option<u64>, asked: Option<u64>) -> Option<u64> {
    match (carve, asked) {
        (Some(carve), Some(asked)) => Some(carve.min(asked)),
        (carve, asked) => carve.or(asked),
    }
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
