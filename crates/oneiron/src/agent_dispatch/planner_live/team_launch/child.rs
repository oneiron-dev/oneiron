//! The leased child's planned launch (DOOR-111 S4c-2, S4c-3): a leased
//! agent's planned intent, launched under its real parent attempt as one
//! group.
//!
//! The intent is reserved, placed and planned first, or replayed, as the
//! child intent does it. A team then loads the exact pattern revision its
//! plan froze through the parent's lease, with no exploration trial and no
//! other arm standing in, runs it with no writer held on the runner the
//! caller binds (the agent's own capture, never the house's), and freezes
//! the start with the pack it ran on. One writer proves the parent's lease
//! and actor again, re-reads the intent, rechecks the revision, queues the
//! leader under the spawning attempt on its run and exactly width - 1
//! members under the leader, binds the team and marks the intent launched.
//!
//! The leader keeps the context the agent asked for, whole, with the plan,
//! the type the plan read and the frozen leader briefing stamped on it, and
//! holds the group's one cap beneath the parent's scope. Only the parent's
//! lease, the plan and the dispatcher's own admission bound the launch,
//! never where an agent runs.

use crate::agent_dispatch::{AgentDispatcher, AgentSpawnContext};
use crate::attempt_queue::AttemptRecord;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::team::{
    LeasedSpawnRequest, PatternLaunchRunner, PatternSkillRef, PlannedIntentView, PlannedSpawnHost,
    SpawnPhase,
};

use super::super::intent::IntentName;
use super::GroupLaunch;

impl AgentDispatcher<'_> {
    /// A leased agent's planned spawn, launched (DOOR-111 S4c). The intent
    /// is reserved, placed and planned first, or replayed, as
    /// [`Self::plan_reserved_spawn_for_attempt`] does; a planned intent then
    /// launches under `leased`. A team loads its plan's exact pattern
    /// revision through the parent's lease, runs it on `runner` once and
    /// freezes the start it writes with that pack; the leader under the
    /// spawning attempt, exactly width - 1 members under the leader and
    /// their team are queued and bound in one write transaction, which marks
    /// the intent launched. A solo queues its one agent.
    ///
    /// The same key then answers what launched and never runs the runner
    /// or a dispatch again. A launch the dispatcher refuses is kept as the
    /// intent's refusal; a team with no `runner` refuses and stays planned.
    ///
    /// # Errors
    ///
    /// As [`Self::plan_reserved_spawn_for_attempt`]; a parent that no longer
    /// holds its lease or runs as another actor when a launch writer proves
    /// it again; a team plan with no runner bound, a runner that errs, or a
    /// start that does not brief the leader and every member, each of which
    /// leaves the intent planned; storage errors.
    pub fn launch_planned_spawn_for_attempt(
        &self,
        leased: &AttemptRecord,
        actor: &EntityId,
        request: &LeasedSpawnRequest,
        host: &PlannedSpawnHost<'_>,
        runner: Option<&dyn PatternLaunchRunner>,
        at: u64,
    ) -> Result<PlannedIntentView> {
        let view = self.plan_reserved_spawn_for_attempt(leased, actor, request, host, at)?;
        if view.phase != SpawnPhase::Planned {
            return Ok(view);
        }
        let name = IntentName::leased(leased, actor, request)?;
        // The leader goes under the spawning attempt, on its run, in the
        // context the agent asked for; it spends under its parent's scope
        // and names no spend of its own.
        let launch = GroupLaunch {
            name: &name,
            parent: Some(leased.id),
            run_id: leased.run_id.clone(),
            leader: AgentSpawnContext {
                spend: None,
                ..request.context.clone()
            },
        };
        let load = |pattern: &PatternSkillRef| {
            self.vault.load_leased_exact_skill_pack(
                leased,
                &pattern.skill,
                &pattern.version,
                host.executor,
                at,
            )
        };
        self.launch_planned_group(launch, runner, runner_prompt(request), load, at)
    }
}

/// The work the pattern runner reads (an Engine call, 10-19): the child's
/// requested briefing when it is set and not blank, else the ask's need.
fn runner_prompt(request: &LeasedSpawnRequest) -> &str {
    request
        .context
        .context_spec
        .as_ref()
        .and_then(|spec| spec.briefing.as_deref())
        .filter(|briefing| !briefing.trim().is_empty())
        .unwrap_or(request.ask.need.as_str())
}
