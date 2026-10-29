//! A live run's own pattern runner for an action between its entries
//! (OF-181, DOOR-111 S4c-4).
//!
//! An action's planned team writes its start as an entry's does: on the
//! seat the run was born on, under the frozen definition it entered with,
//! as its agent, while its leased try holds, all as the run registered
//! them. The line is the entries' line too, opened for each start and
//! never kept: its spend scope's meter and the payer that scope bills, else
//! the provider's own meter. What a scoped start used is booked on the
//! scope once it ends, whatever it answered; a scope that cannot fund it
//! stops it, and it never spends on the provider's meter instead. An
//! action that writes no start opens no line, and an action whose line
//! cannot fund a start when it binds lends no runner, so its planned spawn
//! keeps the path a host with no runner takes.

use std::sync::Arc;

use oneiron::agent_def::AgentDefinition;
use oneiron::agent_dispatch::{SpawnNeed, SpendScopeId, TeamPlan};
use oneiron::attempt_queue::AttemptRecord;
use oneiron::llm::run_admission::PayerPerson;
use oneiron::llm::seat::ModelSeat;
use oneiron::skill::LoadedSkillPack;
use oneiron::team::{PatternLaunchRunner, PatternLaunchSpec};
use oneiron::{BudgetGuard, Result, Vault, WriteActor};

use super::LiveRunEntry;
use crate::ai_host::live_lease::LiveLease;
use crate::mcp::{McpCodeModeProvider, ScopeMeter};
use crate::server::SyncServer;
use crate::server::core::pattern_workflow::stop;
use crate::server::resident_pump::pattern_launch::agent_runner_for_attempt;

const NO_BACKEND: &str = "this host has no pattern runner bound yet: its provider lends the \
     spawning agent's line no backend; ask again once the host binds one";
const LINE_CLOSED: &str = "the spawning agent's line did not open for its pattern run; fund the \
     scope its run spends under, then ask again";

/// A live run's pattern runner for its actions: what the run registered,
/// and the host's native provider whose line each start opens.
struct ActionPatternRunner {
    vault: Arc<Vault>,
    provider: Arc<dyn McpCodeModeProvider>,
    /// The leased try the run's runner holds, by its lease owner and
    /// generation: the start spends only while it holds.
    leased: AttemptRecord,
    definition: AgentDefinition,
    actor: WriteActor,
    seat: ModelSeat,
    spend: Option<SpendScopeId>,
    /// The host's model handle, whose turn tracker sees each capture.
    ai: crate::ai_host::AiHandle,
}

/// The runner an action on `entry`'s run lends its planner, on `server`'s
/// native provider. `None` where the run's entry lends none either (a run
/// born on no seat, a vault with no model manifest, or holding no lease; a
/// host with no native provider), and where [`funds_a_start`] says the
/// run's line cannot fund a start now.
pub(super) fn runner(
    server: &SyncServer,
    entry: &LiveRunEntry,
) -> Option<Arc<dyn PatternLaunchRunner>> {
    let seat = entry.model_seat.clone()?;
    let provider = server.code_execution_host()?.engine_native()?.provider();
    if entry.leased.lease_owner.is_none()
        || !funds_a_start(
            server.vault(),
            provider.as_ref(),
            entry.spend_scope.as_ref(),
        )
    {
        return None;
    }
    Some(Arc::new(ActionPatternRunner {
        vault: Arc::clone(server.vault()),
        provider: Arc::clone(provider),
        leased: entry.leased.clone(),
        definition: entry.definition.clone(),
        actor: entry.actor,
        seat,
        spend: entry.spend_scope.clone(),
        ai: server.ai.clone(),
    }))
}

/// Whether the run's line could fund a start now: its scope's meter opens
/// with units left, else the provider's own meter has units left, and the
/// provider lends that line a backend. Only reads; each start opens its own
/// line. The policy hook for an unfunded action (Engine 10-19 09:2x): it
/// keeps the planned path it took before the runner was bound, never a
/// refusal.
fn funds_a_start(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    spend: Option<&SpendScopeId>,
) -> bool {
    let line = match spend {
        Some(scope) => ScopeMeter::open(vault, scope)
            .ok()
            .map(|meter| (meter.guard, meter.payer)),
        None => provider.host_meter().map(|guard| (guard, None)),
    };
    line.is_some_and(|(guard, payer)| {
        guard.read().remaining_units > 0 && provider.reader_backend(guard, payer).is_some()
    })
}

impl PatternLaunchRunner for ActionPatternRunner {
    /// The agent's own runner, on a line opened for this start: its scope's
    /// meter, whose use is booked on the scope once, after the start and
    /// whatever it answered, else the provider's meter.
    fn run(
        &self,
        skill: &LoadedSkillPack,
        asked: &SpawnNeed,
        prompt: &str,
        plan: &TeamPlan,
        caller: &WriteActor,
    ) -> Result<PatternLaunchSpec> {
        let Some(scope) = &self.spend else {
            let line = self.provider.host_meter().map(|guard| (guard, None));
            return self.agent_runner(line)?.run(skill, asked, prompt, plan, caller);
        };
        // The open's own error can name the payer the scope bills, who may
        // not be the caller: the host log keeps it, the refusal names the
        // bound.
        let ScopeMeter { guard, payer, .. } =
            ScopeMeter::open(&self.vault, scope).map_err(|error| {
                tracing::warn!(
                    agent = %self.actor.entity_ref().to_hex(),
                    error = %error,
                    "a live run's pattern run found its spend scope's line closed"
                );
                stop(LINE_CLOSED)
            })?;
        let live = LiveLease::new(
            &self.vault,
            Some(scope.clone()),
            guard.clone(),
            guard.read().limit_units,
            0,
        );
        let started = self.agent_runner(Some((guard, payer))).and_then(|agent| {
            // The start makes one model call, the capture: its look is
            // taken here, just before it.
            live.book_and_revise();
            agent.run(skill, asked, prompt, plan, caller)
        });
        live.book_rest()?;
        started
    }
}

impl ActionPatternRunner {
    /// The agent's own runner on `line`, as its run's entry builds it.
    fn agent_runner(
        &self,
        line: Option<(BudgetGuard, Option<PayerPerson>)>,
    ) -> Result<Arc<dyn PatternLaunchRunner>> {
        agent_runner_for_attempt(
            &self.vault,
            self.provider.as_ref(),
            &self.ai,
            &self.leased,
            &self.definition,
            self.actor,
            Some(&self.seat),
            line,
        )
        .ok_or_else(|| stop(NO_BACKEND))
    }
}
