//! A leased agent's own pattern runs, and its planned leader's frozen pack
//! (DOOR-111 S4c-4, S4c-5).
//!
//! A leased agent's planned team writes its start as the agent: on the seat
//! its run was born on, a model its frozen definition lists, through the
//! backend its own steps take, on the line its run's model calls spend on
//! (its spend scope's meter and the payer that scope bills, else its
//! provider's own meter). The request, its schema and the decode of the
//! reply are the house runner's (`core::pattern_workflow`); only the seat,
//! the identity and the meter are the agent's. The capture offers no tool,
//! cannot spawn and takes no house authority: it returns a start the engine
//! checks.
//!
//! A planned team's leader runs with the exact pack its launch froze. Each
//! claim of its run records the pack on the run's own lease, once, and puts
//! the pack's SKILL.md in its task before its other skills: a fresh run's
//! task takes it, a process re-entry builds the same task from the same
//! frozen bytes, and a continuation, whose task is its source's fork, reuses
//! the exposure its source run kept once the forked task holds the body
//! there. Each run keeps its own exposure, so a retry never moves the one a
//! continuation of an older run reads. Nothing reads the skill's current
//! head or runs an exploration trial.

use std::sync::Arc;

use oneiron::agent_def::{AgentDefinition, ensure_listed};
use oneiron::agent_dispatch::{AgentDispatchStatus, AgentDispatcher, SpawnNeed, TeamPlan};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use oneiron::code_run::TaskExposure;
use oneiron::engine_executor::EngineExecutorConfig;
use oneiron::engine_executor::continuation::run_continuation;
use oneiron::llm::run_admission::PayerPerson;
use oneiron::llm::seat::ModelSeat;
use oneiron::llm::{LlmError, LlmRequest, LlmResponse, ResponseFormat};
use oneiron::skill::LoadedSkillPack;
use oneiron::team::{FrozenPatternPack, PatternLaunchRunner, PatternLaunchSpec};
use oneiron::{
    BudgetGuard, BudgetLease, EntityId, Error, LlmBackend, LlmCapability, Result, Vault, WriteActor,
};

use super::SKILL_SEPARATOR;
use crate::ai_host::AiHandle;
use crate::mcp::McpCodeModeProvider;
use crate::server::core::pattern_workflow::{
    decode_launch_spec, fault, launch_members, launch_request, launch_spec_schema, stop,
    warn_launch_input,
};

const LEASE_LOST: &str = "the spawning agent's run no longer holds its lease, so its pattern run \
     spends nothing; ask again from the agent's live run";
const STOPPED: &str = "the spawning agent's pattern run stopped before its model answered; ask \
     again";
const RECORD_ONLY: &str = "this planned team's frozen pattern pack is a record-only skill with no \
     SKILL.md, so its leader has no pattern to read; publish the pattern skill as a package whose \
     SKILL.md teaches it, then spawn the team again under a new intent key";
const NO_SKILL_MD: &str = "this planned team's frozen pattern pack holds no SKILL.md text for its \
     leader to read; publish the pattern skill as a package whose SKILL.md teaches it, then spawn \
     the team again under a new intent key";
const SKILL_MD_NOT_TEXT: &str = "this planned team's frozen pattern pack's SKILL.md is not UTF-8 \
     text; publish the pattern skill as a package whose SKILL.md is, then spawn the team again \
     under a new intent key";
const NO_KEPT_EXPOSURE: &str = "this continued leader's source run kept no exposure of its frozen \
     pattern pack, so its forked task cannot be checked against it; run the leader afresh rather \
     than as a continuation";
const EXPOSURE_MOVED: &str = "this continued leader's forked task does not hold its frozen pattern \
     pack where its source run put it, and nothing newer is loaded in its place; run the leader \
     afresh rather than as a continuation";

/// A leased agent's own pattern runner: its run's seat, identity and line.
struct AgentPatternLaunchRunner {
    vault: Arc<Vault>,
    /// The agent the run runs as.
    agent: EntityId,
    /// The leased try the spawn runs under, by its lease owner and
    /// generation: the capture spends only while it holds.
    attempt: AttemptId,
    lease_owner: String,
    generation: u32,
    /// The agent's frozen definition, whose model list the capture keeps
    /// to.
    definition: AgentDefinition,
    /// The seat the run was born on.
    seat: ModelSeat,
    /// The provider's backend on the run's line, and the admission lease
    /// its calls are charged to.
    backend: Arc<dyn LlmBackend>,
    lease: BudgetLease,
    /// The host's model handle, whose turn tracker sees each capture.
    ai: AiHandle,
}

/// The runner a leased agent's run lends its planner for one entry
/// (DOOR-111 S4c-4): the run's seat (`seat`, born on a model the agent's
/// definition lists), the agent and its leased try (`status`, `actor`), and
/// the line the entry's model calls spend on (`line`: its scope's meter and
/// payer, else the provider's own meter), through the backend `provider`
/// meters its steps on. `None` when the run was born on no seat (a vault
/// with no model manifest), holds no lease, or its provider lends no
/// backend on its line: its planned spawns then take the path a host with
/// no runner takes.
pub(super) fn agent_runner(
    vault: &Arc<Vault>,
    provider: &dyn McpCodeModeProvider,
    ai: &AiHandle,
    status: &AgentDispatchStatus,
    actor: WriteActor,
    seat: Option<&ModelSeat>,
    line: Option<(BudgetGuard, Option<PayerPerson>)>,
) -> Option<Arc<dyn PatternLaunchRunner>> {
    agent_runner_for_attempt(
        vault,
        provider,
        ai,
        &status.attempt,
        &status.input.definition,
        actor,
        seat,
        line,
    )
}

/// [`agent_runner`]'s runner from the leased try `attempt` and the frozen
/// `definition` the run entered with, as a live run's action builds it
/// between entries from what its run registered (OF-181), with the same
/// `None` cases.
pub(in crate::server) fn agent_runner_for_attempt(
    vault: &Arc<Vault>,
    provider: &dyn McpCodeModeProvider,
    ai: &AiHandle,
    attempt: &AttemptRecord,
    definition: &AgentDefinition,
    actor: WriteActor,
    seat: Option<&ModelSeat>,
    line: Option<(BudgetGuard, Option<PayerPerson>)>,
) -> Option<Arc<dyn PatternLaunchRunner>> {
    let seat = seat?.clone();
    let lease_owner = attempt.lease_owner.clone()?;
    let (guard, payer) = line?;
    let backend = provider.reader_backend(guard, payer)?;
    Some(Arc::new(AgentPatternLaunchRunner {
        vault: Arc::clone(vault),
        agent: actor.entity_ref(),
        attempt: attempt.id,
        lease_owner,
        generation: attempt.attempt_count,
        definition: definition.clone(),
        seat,
        backend,
        lease: provider.lease().clone(),
        ai: ai.clone(),
    }))
}

impl PatternLaunchRunner for AgentPatternLaunchRunner {
    /// The pack must be the workflow revision `plan` froze, and the seat's
    /// model one the agent's definition lists; the start briefs the leader
    /// and exactly the width less one members.
    fn run(
        &self,
        skill: &LoadedSkillPack,
        asked: &SpawnNeed,
        prompt: &str,
        plan: &TeamPlan,
    ) -> Result<PatternLaunchSpec> {
        let members = launch_members(skill, plan)?;
        self.held()?;
        let schema = launch_spec_schema(members);
        let mut request = launch_request(
            self.seat.model(),
            self.seat.locality(),
            skill,
            asked,
            prompt,
            plan,
            &schema,
        )?;
        self.seat.bind(&mut request);
        // The model that serves the capture is one the agent lists.
        ensure_listed(&self.definition, &request.model).map_err(|error| {
            stop(format!(
                "{error}; list that model on the agent, or spawn from a run born on a model it \
                 lists"
            ))
        })?;
        // The prompt carries the same schema, and the reply is checked
        // against it either way.
        if !self
            .backend
            .supports(&request.model, LlmCapability::JsonResponse)
        {
            request.envelope.response_format = ResponseFormat::Text;
        }
        warn_launch_input(&self.vault, &request);
        let response = self.capture(request)?;
        decode_launch_spec(&response, &schema)
    }
}

impl AgentPatternLaunchRunner {
    /// Whether the run still holds the lease its spawn runs under.
    fn held(&self) -> Result<()> {
        let held = AttemptQueue::new(&self.vault)
            .get(self.attempt)?
            .is_some_and(|live| {
                live.state == AttemptState::Leased
                    && live.lease_owner.as_deref() == Some(self.lease_owner.as_str())
                    && live.attempt_count == self.generation
            });
        if held {
            return Ok(());
        }
        tracing::warn!(
            agent = %self.agent.to_hex(),
            "a leased agent's pattern run found its run's lease gone"
        );
        Err(stop(LEASE_LOST))
    }

    /// One model turn on the run's own line, exact on its seat, through the
    /// backend its steps take. The call drives its own runtime on a thread
    /// of its own, since the spawn runs inside the run's runtime, which
    /// cannot block on another.
    fn capture(&self, request: LlmRequest) -> Result<LlmResponse> {
        // A running turn to shutdown's grace and the Dreamer's idle sample,
        // until the capture returns on any path (FIX 4639).
        let _turn = self.ai.enter_turn();
        std::thread::scope(|scope| {
            scope
                .spawn(move || -> Result<LlmResponse> {
                    let reactor = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|error| {
                            fault(format!(
                                "the spawning agent's pattern run's runtime did not start: \
                                 {error}; ask again"
                            ))
                        })?;
                    reactor
                        .block_on(self.backend.generate(request, &self.lease))
                        .map_err(unanswered)
                })
                .join()
        })
        .unwrap_or_else(|_| Err(fault(STOPPED)))
    }
}

/// The exposure of the pattern pack a planned team's leader runs with
/// (DOOR-111 S4c-5), for one claim of its run; `None` for a run that leads
/// no planned team. The pack is the snapshot its launch froze. A fresh
/// run's task takes the pack's SKILL.md after the separator its other
/// skills take; a continued run's task, its source's fork, holds it already,
/// where the exposure its source run (the run its checkpoint names) kept
/// says, and takes nothing again. The pack's manifest row and the exposure
/// are then recorded on the run's own lease, the row once and the exposure
/// under the run's own id, which a continuation of this run reads.
///
/// # Errors
///
/// A record-only pack, or one with no SKILL.md text; a continued run whose
/// source run kept no exposure, or whose task does not hold the body where
/// it says; the engine's refusals, a damaged launch included; storage
/// errors.
pub(super) fn leader_exposure(
    vault: &Vault,
    leased: &AttemptRecord,
    config: &mut EngineExecutorConfig,
    continues: bool,
    at: u64,
) -> Result<Option<TaskExposure>> {
    let dispatcher = AgentDispatcher::new(vault);
    let Some(launch) = dispatcher.planned_launch_for_leader(leased.id)? else {
        return Ok(None);
    };
    let pack = &launch.pack;
    let body = skill_text(pack)?;
    let revision = format!("{}@{}", pack.skill_id(), pack.version());
    let exposure = if continues {
        // The source run's own exposure, never the latest retry's.
        let source = run_continuation(vault, leased.id)?
            .map(|continuation| continuation.checkpoint.source_run);
        let kept = source
            .and_then(|source| launch.exposures.get(&source).cloned())
            .ok_or_else(|| refused(NO_KEPT_EXPOSURE))?;
        held_in(&config.task, kept, body, pack.entity(), &revision)?
    } else {
        TaskExposure::append(
            &mut config.task,
            SKILL_SEPARATOR,
            body,
            pack.entity(),
            revision,
        )
    };
    dispatcher.record_planned_leader_run(leased, &exposure, config.model.as_str(), at)?;
    Ok(Some(exposure))
}

/// The frozen pack's SKILL.md, exactly as it loaded, trimmed as a run's
/// task takes a skill's body. Rule 5 caps none.
fn skill_text(pack: &FrozenPatternPack) -> Result<&str> {
    let files = pack.files().ok_or_else(|| refused(RECORD_ONLY))?;
    let file = files
        .iter()
        .find(|file| file.path() == "SKILL.md")
        .ok_or_else(|| refused(NO_SKILL_MD))?;
    let text = std::str::from_utf8(file.content())
        .map_err(|_| refused(SKILL_MD_NOT_TEXT))?
        .trim();
    if text.is_empty() {
        return Err(refused(NO_SKILL_MD));
    }
    Ok(text)
}

/// The exposure a continued leader's source kept, once the forked `task`
/// holds exactly the separator and the frozen `body` in its span, hashed as
/// it says, under the frozen pack's own `skill` and `revision`. A suffix
/// check would not do: other skills' bodies follow it.
fn held_in(
    task: &str,
    kept: TaskExposure,
    body: &str,
    skill: EntityId,
    revision: &str,
) -> Result<TaskExposure> {
    let held = task.get(kept.start..kept.end).is_some_and(|span| {
        span.strip_prefix(SKILL_SEPARATOR) == Some(body)
            && *blake3::hash(span.as_bytes()).as_bytes() == kept.content_hash
    });
    if held && kept.skill == skill && kept.revision == revision {
        Ok(kept)
    } else {
        Err(refused(EXPOSURE_MOVED))
    }
}

/// The run's line answered nothing: it refused the call, or every rung
/// failed.
fn unanswered(error: LlmError) -> Error {
    match &error {
        LlmError::BudgetDenied(_) => stop(format!(
            "the spawning agent's line refused its pattern run: {error}; raise the budget its \
             run spends under, or wait for its spend to settle, then ask again"
        )),
        _ => stop(format!(
            "the spawning agent's seat did not answer its pattern run: {error}; ask again"
        )),
    }
}

/// Why a planned leader's run takes no pattern, and what to do next.
fn refused(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
