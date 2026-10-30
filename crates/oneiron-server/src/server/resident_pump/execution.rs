//! Execution of a leased agent run, including its model and planner seats.
//! `run_bound` owns the run's door, readers, compaction, and entry loop.
//! Claims, shared run state, and pump admission remain in the parent module.

use super::{
    AgentDefinition, AgentDispatchStatus, AgentDispatcher, AgentModel, AgentVerbDoor, Arc,
    AttemptQueue, AttemptRecord, BoundRun, Claimed, DecisionHost, EngineExecutorConfig,
    EngineExecutorOutcome, EngineExecutorStatus, EngineRunError, EntityId, HostPlannerBinding,
    HostPlannerDecisions, HostSelfDispatcher, LeaderStarterSkills, McpCodeModeProvider, ModelId,
    ModelSeat, PlannedModel, PlannerSeat, PlannerSettings, PlannerSkills,
    ProjectConversationSkills, ReadSetProducer, ReaderSeats, RunCompaction, RunHostDoor,
    SKILL_SEPARATOR, ScopeMeter, SeatKind, SeatTask, SpawnHostSeat, SpendScopeId, SyncServer,
    TaskExposure, TaskTypeRef, UNBOUND_LIST_KEEPS_ROUTE, Vault, WINDOW_FULL_TRIES,
    WINDOW_FULL_WAIT, WriteActor, agent_dispatch_actor, browser_workflow, child_pin, craft,
    ensure_listed, enter_engine_native_run, finalize_step_captures, fork_executor_run,
    note_stale_listed_models, note_unbound_listed_run, pattern_launch, pump_caller,
    run_continuation, scope_funding, task_engine_run_seat, task_run_seat, text, unix_now,
};
use crate::mcp::LiveLeaseRunner;

/// Runs the leased attempt until it ends, waits, or fails: a yielded slice
/// enters again at once, a full window once its compaction can land.
pub(super) fn run_bound(
    server: &Arc<SyncServer>,
    provider: &dyn McpCodeModeProvider,
    claimed: &Claimed,
    key: &str,
    seats: &ReaderSeats,
    runtime: tokio::runtime::Handle,
) -> Result<BoundRun, EngineRunError> {
    let vault = server.vault();
    let status = &claimed.status;
    let actor = agent_dispatch_actor(&status.input).map_err(text)?;
    // The run is the attempt's own: a retry is a fresh attempt, and so a
    // fresh run.
    let run_id = EntityId::from_bytes(*status.attempt.id.as_bytes()).map_err(text)?;
    // One door for the whole run, so its browser lives as long as the run.
    let door = Arc::new(RunHostDoor::new(server, actor, runtime, run_id));
    let template = provider
        .executor_config(vault, run_id, &claimed.task)
        .map_err(text)?;
    // FIX 3694: a successor that carries the owner's approved prompt
    // continuation goes on as the fork of its failed predecessor's run, from
    // its cut, on the task, model and effort that run had. It is born on a
    // seat of its own bound to them, and its task takes no skill again: the
    // source's task already holds it.
    let continued = continued_config(vault, &status.attempt, &template)?;
    let continues = continued.is_some();
    let mut config = continued.unwrap_or_else(|| template.clone());
    // CUA E4 (FIX 7603): a try whose TASK binds a library program runs it
    // strict on this door before its seat is born. One that met its TASK's
    // goal settles the try with no model call; one that handed off names its
    // receipt to the planner after its task. A continued run's source ran it.
    if !continues {
        match browser_workflow::before_seat(
            vault,
            &*door,
            actor,
            &status.attempt,
            run_id,
            unix_now(),
        )? {
            browser_workflow::BeforeSeat::Unbound => {}
            browser_workflow::BeforeSeat::Done(receipt) => return Ok(BoundRun::Library(receipt)),
            browser_workflow::BeforeSeat::Handoff(text) => config.task.push_str(&text),
        }
    }
    // FIX 4472: the run is born on a model its frozen definition lists. A
    // listed model its provider retired, or no registry row names (FIX
    // 4545), tells the owner, once, and the run goes on with the rest of the
    // list; a note that fails does not stop it.
    let definition = &status.input.definition;
    if let Err(error) = note_stale_listed_models(vault, actor.entity_ref(), definition) {
        tracing::warn!(%error, agent = %actor.entity_ref().to_hex(), "a retired listed model's owner note was not recorded");
    }
    // OF-541: the run is born on its seat once, from its own task, before
    // its skill adds to it, and each entry runs on that seat. A run its
    // parent planned is born on the model its plan picked. The attempt is
    // stamped with what runs it: the seat's model, beside the template seat
    // its host configured, and its pack loads and planner take that model.
    // A vault with no manifest bears no seat, so the template stays the
    // stamp its pack loads write. DOOR-111 S5: the seat is born stamped
    // with the dispatch's type, so its route reads with its own stamp.
    let type_ref = &status.input.type_ref;
    let model_seat = if continues {
        continued_seat(
            vault,
            provider,
            &config,
            type_ref,
            definition.models.clone(),
        )?
    } else {
        task_engine_run_seat(
            vault,
            provider,
            &config,
            format!("agent-run:{}", run_id.to_hex()),
            type_ref,
            status.input.plan.as_ref(),
            definition.models.clone(),
        )?
    };
    // FIX 2310 (OF-541 PR H): a planned child no seat binds runs its plan's
    // pick exactly where its provider routes that model so and its frozen
    // definition lists it; else the provider's own model, each call another
    // model answers marked on its receipts. Its row keeps the binding its
    // first entry chose (FIX 7720, 7721), and a continuation takes its
    // source's (FIX 7723): no later entry decides it again.
    let pin = status
        .input
        .plan
        .as_ref()
        .filter(|_| model_seat.is_none())
        .map(|plan| {
            child_pin::select(
                vault,
                provider,
                &status.attempt,
                definition,
                &plan.plan.model,
                continues,
                &mut config,
            )
        });
    if let Some(seat) = &model_seat {
        ensure_listed(definition, seat.model()).map_err(text)?;
        let lease_owner = status
            .attempt
            .lease_owner
            .as_deref()
            .ok_or_else(|| "a claimed agent run holds no lease".to_owned())?;
        AttemptQueue::new(vault)
            .set_executor_stamp(
                status.attempt.id,
                lease_owner,
                status.attempt.attempt_count,
                seat.model().as_str(),
                template.model.as_str(),
                // The native code-mode template is the chat seat
                // (`ai_host/code_mode.rs`, `runtime.seat(CHAT_ROLE)`).
                crate::ai_host::CHAT_ROLE,
            )
            .map_err(text)?;
        config.model = seat.model().clone();
        // The diary says, as the agent, which model this wake ran on when
        // that is not the one its last wake ran on.
        if let Err(error) =
            vault.note_wake_model(actor.entity_ref(), seat.model(), &seat.receipt().why)
        {
            tracing::warn!(%error, agent = %actor.entity_ref().to_hex(), "a wake's model change was not noted in the agent's diary");
        }
    } else {
        hold_seatless_to_list(vault, actor, definition, &config.model)?;
    }
    // Held to its list, the binding is frozen on the row and noted in the
    // agent's diary before any pack loads (FIX 7720, 7726).
    let planned = pin.map(|pin| pin.bind(vault, &status.attempt, actor, run_id, &mut config));
    // FIX 1876: a run no seat bore and no plan bound is stamped with the
    // model its settled config runs on, before any pack loads.
    if model_seat.is_none() && planned.is_none() {
        super::attribution::stamp_seatless_executor(vault, &status.attempt, &config);
    }
    super::attribution::bind_before_entry(vault, &status.attempt);
    // DOOR-111 S4c-5: a planned team's leader runs with the exact pattern
    // pack its launch froze, its SKILL.md before any other skill's body; a
    // continued run's task, its source's fork, already holds it there.
    let leader =
        pattern_launch::leader_exposure(vault, &status.attempt, &mut config, continues, unix_now())
            .map_err(text)?;
    craft::append_resident_craft(vault, &status.attempt, actor, &mut config, continues)
        .map_err(text)?;
    // A project conversation run runs with its skill's SKILL.md (OF-501); a
    // run whose skill does not load is refused, never run unskilled. The
    // body is tagged where it went, so the run's first step is captured with
    // it marked for a contribution check (FIX 3028). A continued run loads
    // it too, and its task already holds the body: it is tagged where its
    // source's append put it.
    let skills = ProjectConversationSkills::shipped(None).map_err(text)?;
    let mut exposures: Vec<TaskExposure> = leader.into_iter().collect();
    if let Some(skill) = AgentDispatcher::new(vault)
        .prepare_project_conversation_run(
            &status.attempt,
            &skills,
            config.model.as_str(),
            unix_now(),
        )
        .map_err(text)?
        && let Some(body) = skill
            .source_files
            .iter()
            .flatten()
            .find(|file| file.path == "SKILL.md")
            .and_then(|file| std::str::from_utf8(&file.content).ok())
    {
        let revision = format!("{}@{}", skill.record.skill_id, skill.record.version);
        if continues {
            exposures.extend(appended_exposure(
                &config.task,
                SKILL_SEPARATOR,
                body.trim(),
                skill.entity,
                revision,
            ));
        } else {
            exposures.push(TaskExposure::append(
                &mut config.task,
                SKILL_SEPARATOR,
                body.trim(),
                skill.entity,
                revision,
            ));
        }
    }
    // Its model calls and its reader children spend under the attempt's
    // scope. An unmetered attempt's calls stay on the provider's meter, and
    // so do its children's. Its door withholds nothing, so its children's
    // reads withhold nothing, as its own do.
    let metered = AgentDispatcher::new(vault)
        .spend_scope_for_attempt(status.attempt.id)
        .map_err(text)?;
    // A room-bound run's root must name its payer (OF-531): one whose payer
    // cannot be read or billed stops here, typed, before any call. Each
    // entry binds that payer to its calls.
    if status.input.room.is_some() {
        scope_funding(vault, metered.as_ref(), true).map_err(EngineRunError::Payer)?;
    }
    // The run's caller, as this host leased it: its reader children and its
    // compaction read under that one binding.
    let caller = pump_caller(actor);
    // A scoped child queued under the run borrows the lease of the attempt
    // it is (FIX 7507): it lives only while this host holds that lease. No
    // clock is lent, so its children keep one window from its first spawn,
    // and its ordinary readers outlive it as before.
    let parent = crate::ai_host::scoped_child::ReaderParentHost::for_attempt(&status.attempt);
    let mut seat = seats.seat_with_parent(
        run_id,
        metered.clone(),
        caller.locality(),
        provider.reader_window_tokens(),
        parent.as_ref(),
    );
    // FIX 4539: its reader and summary children are held to the list its
    // frozen definition names, as its own seat is.
    seat.listed = definition.models.clone();
    let reactor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(text)?;
    // Its compaction passes spend under the attempt's scope too. An agent
    // whose profile names `self` writes them as itself (FIX 4465), as it
    // would on any other host.
    // A planned child's live admission sees its plan's binding (Engine C5).
    let mut compaction = match &planned {
        Some(planned) => provider.planned_compaction(caller, key, metered.as_ref(), planned),
        None => provider.compaction(caller, key, metered.as_ref()),
    };
    // The host's root key signs a leader's subproject spawn (OF-389): the
    // managed issuer, else this install's own self-host root (FIX-LIST 3018).
    let issuer = server.host_issuer();
    let mut full = 0;
    loop {
        let outcome = enter_run(
            vault,
            provider,
            status,
            actor,
            &config,
            &door,
            &seat,
            model_seat.as_ref(),
            metered.as_ref(),
            compaction.as_mut(),
            &reactor,
            server.decision_host(),
            issuer,
            &server.live_runs,
            &exposures,
            &server.ai,
            planned.as_ref(),
        );
        // The first step's capsule takes the rung that answered it, on the
        // thread the entry ran its calls on.
        finalize_step_captures(vault);
        let outcome = outcome?;
        // The rows its tool answers were served from, each time the run
        // stops (FIX 7017). Capture only: a set not recorded stays unknown,
        // and the run goes on.
        let rows = outcome.replay_record.agent_verb_rows();
        let id = status.attempt.id;
        if let Err(error) = vault.record_attempt_sources(id, ReadSetProducer::TOOL_ANSWERS, rows) {
            tracing::warn!(kind = ?error.kind(), "a resident run's tool answer rows were not recorded");
            let _ = vault.record_attempt_sources(id, ReadSetProducer::TOOL_ANSWERS, None);
        }
        match outcome.status {
            EngineExecutorStatus::Yielded { .. } => full = 0,
            EngineExecutorStatus::WindowFull { .. }
                if compaction.is_some() && full < WINDOW_FULL_TRIES =>
            {
                full += 1;
                std::thread::sleep(WINDOW_FULL_WAIT);
            }
            EngineExecutorStatus::Complete => {
                // CUA E8b: a TASK run that ended keeps what its browser
                // solved toward its done-means, before its door drops.
                browser_workflow::capture_task_run(vault, &door, actor, &status.attempt, type_ref);
                return Ok(BoundRun::Agent(outcome));
            }
            _ => return Ok(BoundRun::Agent(outcome)),
        }
    }
}

/// The exposure a source run's [`TaskExposure::append`] left at the end of
/// a continued run's forked task (FIX 3694): the separator and `body`.
/// `None` when the task does not end with them, as when the skill changed
/// since the source ran.
fn appended_exposure(
    task: &str,
    separator: &str,
    body: &str,
    skill: EntityId,
    revision: String,
) -> Option<TaskExposure> {
    let start = task.len().checked_sub(separator.len() + body.len())?;
    let tail = task.get(start..)?;
    (tail.strip_prefix(separator)? == body).then(|| TaskExposure {
        skill,
        revision,
        content_hash: *blake3::hash(tail.as_bytes()).as_bytes(),
        start,
        end: task.len(),
    })
}

/// The config a leased successor runs under when it carries the owner's
/// approved prompt continuation (FIX 3694): its fork of the failed
/// predecessor's run, seeded from the cut, or re-opened on a later entry.
/// `None` for any other run. A fork that refuses fails the run under the
/// refusal's code.
fn continued_config(
    vault: &Vault,
    attempt: &AttemptRecord,
    template: &EngineExecutorConfig,
) -> Result<Option<EngineExecutorConfig>, EngineRunError> {
    if run_continuation(vault, attempt.id).map_err(text)?.is_none() {
        return Ok(None);
    }
    fork_executor_run(vault, attempt, template)
        .map(|prepared| Some(prepared.config))
        .map_err(|refusal| EngineRunError::Binding(refusal.to_string()))
}

/// The seat a continued run is born on (FIX 3694): one of its own, under its
/// own run's receipt, bound to the model, locality and effort its source ran
/// on, so the fork's config marker holds on every entry. That model must
/// still be on the agent's list (`listed`, FIX 4472). It is stamped with
/// the successor's own dispatch stamp (`type_ref`, DOOR-111 S5).
fn continued_seat(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    config: &EngineExecutorConfig,
    type_ref: &TaskTypeRef,
    listed: Vec<AgentModel>,
) -> Result<Option<ModelSeat>, String> {
    task_run_seat(vault, provider, config.run_id, type_ref, |facet| SeatTask {
        kind: SeatKind::Attempt,
        warm_scope: format!("agent-run:{}", config.run_id.to_hex()),
        task: config.task.clone(),
        purpose: oneiron::CallPurpose::Other {
            name: oneiron::engine_executor::ENGINE_EXECUTOR_PURPOSE_NAME.into(),
        },
        facet: facet.to_owned(),
        required: Vec::new(),
        min_context_tokens: 1,
        locality: config.model_locality,
        override_model: Some(config.model.clone()),
        override_effort: config.seat_effort,
        listed,
    })
}

/// FIX 6030: with no seat the run is still held to its list; a configured
/// route off the list refuses, naming it. Under the old hook (FIX 4544) the
/// run keeps that route, as before lists, and the owner is told once per
/// model it ran on; a note that fails does not stop it. A definition that
/// lists none holds nothing.
fn hold_seatless_to_list(
    vault: &Vault,
    actor: WriteActor,
    definition: &AgentDefinition,
    model: &ModelId,
) -> Result<(), String> {
    if definition.models.is_empty() {
        return Ok(());
    }
    if !UNBOUND_LIST_KEEPS_ROUTE {
        ensure_listed(definition, model).map_err(text)?;
    } else if let Err(error) = note_unbound_listed_run(vault, actor.entity_ref(), definition, model)
    {
        tracing::warn!(%error, agent = %actor.entity_ref().to_hex(), "a listed agent's seatless run's owner note was not recorded");
    }
    Ok(())
}

/// One entry of the run, as `execute_code` enters its runs, but bound to the
/// leased attempt: its dispatcher carries the attempt, so `tasks.refuse`
/// reaches the TASK it realizes, a TASK it creates runs under it, its
/// program calls the vault's callable skills, its host rows take `door`,
/// its model calls spend under `spend`, and `seat`, which its reader
/// children spawn under. Its `ai.speech` spends on the meter its other model
/// calls do (FIX 3194): `spend`'s guard for the entry, else the provider's.
/// It runs on `model_seat`, the one `run_bound` bore it on. With the host's
/// `[models.planner]` seats, its spawns are planned on `decisions`' ladder
/// and its leader calls answer, and its planned team's start is written on
/// `model_seat` and the entry's line (DOOR-111 S4c-4); `issuer` signs its
/// leader's subproject spawn.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one axis of the run's host binding"
)]
fn enter_run(
    vault: &Arc<Vault>,
    provider: &dyn McpCodeModeProvider,
    status: &AgentDispatchStatus,
    actor: WriteActor,
    config: &EngineExecutorConfig,
    door: &Arc<RunHostDoor>,
    seat: &SpawnHostSeat,
    model_seat: Option<&ModelSeat>,
    spend: Option<&SpendScopeId>,
    compaction: Option<&mut RunCompaction>,
    reactor: &tokio::runtime::Runtime,
    decisions: &DecisionHost,
    issuer: Option<&oneiron::authority::HostSlipIssuer>,
    live_runs: &super::LiveRuns,
    exposures: &[TaskExposure],
    ai: &crate::ai_host::AiHandle,
    planned: Option<&PlannedModel>,
) -> Result<EngineExecutorOutcome, EngineRunError> {
    let mut bound = HostSelfDispatcher::for_leased_agent_attempt(vault, actor, &status.attempt)
        .map_err(text)?
        .with_callable_skills(Arc::clone(vault))
        .map_err(text)?
        .with_agent_verb_door(Arc::clone(door) as Arc<dyn AgentVerbDoor>)
        .with_reader_spawn(seat.clone())
        .with_replay_exposures(exposures.to_vec())
        // FIX 6867, FIX 8268: the run's repo proposals take the vault's own review policy.
        .with_repo_review_policy(Arc::new(
            oneiron::memory::repo_doors::OwnerProposalReviewPolicy::new(Arc::clone(vault)),
        ));
    let meter = spend
        .map(|scope| ScopeMeter::open(vault, scope))
        .transpose()?;
    // The line the entry's model calls spend on: its scope's meter and the
    // payer it bills, else the provider's.
    let line = match &meter {
        Some(meter) => Some((meter.guard.clone(), meter.payer.clone())),
        None => provider.host_meter().map(|guard| (guard, None)),
    };
    // The entry's one live lease, which its door's speech and its planner
    // runner's start look on too, and book on once (FIX 11747).
    let lease = meter.as_ref().map(|meter| meter.lease.clone());
    let planner = decisions.host_planner_decisions(actor.entity_ref());
    if let Some(mut planner) = planner_binding(vault, provider, config, planner)? {
        planner.pattern_runner = pattern_launch::agent_runner(
            vault,
            provider,
            ai,
            status,
            actor,
            model_seat,
            line.clone(),
        )
        .map(|runner| LiveLeaseRunner::lend(runner, vault, lease.as_ref()));
        bound = bound.with_planner(planner);
    }
    if let Some(issuer) = issuer {
        bound = bound.with_slip_issuer(issuer);
    }
    // OF-181: the run's lease proof, registered for the handle a harness
    // attaches, and its guard, held through the whole entry: an action
    // through that handle runs only between entries.
    let proof = bound.live_run_host_binding(config.run_id).map_err(text)?;
    let _serial = live_runs
        .register(
            vault,
            config.run_id,
            actor,
            &status.attempt,
            proof,
            provider.planner().cloned(),
            config.model.as_str().to_owned(),
            model_seat.cloned(),
            status.input.definition.clone(),
            spend.cloned(),
        )
        .map_err(text)?
        .enter();
    door.bind_meter(line);
    door.bind_lease(lease);
    door.bind_attempt(Some(oneiron_contracts::entity_id::bytes_to_hex_lower(
        status.attempt.id.as_bytes(),
    )));
    let entered = enter_engine_native_run(
        vault, provider, &bound, config, compaction, reactor, meter, model_seat, planned,
    );
    door.bind_meter(None);
    door.bind_lease(None);
    door.bind_attempt(None);
    entered
}

/// The host's planner for one entry of a leased agent run (OF-541, OF-389):
/// the `[models.planner]` seats whose AGENT_DEF this vault holds, the shipped
/// planner and leader skills, the model the run is stamped with (its seat's
/// once born, else its template) as the executor, and the host's ladder.
/// `None` when no seat resolves.
fn planner_binding<'a>(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    config: &EngineExecutorConfig,
    decisions: HostPlannerDecisions<'a>,
) -> Result<Option<HostPlannerBinding<'a>>, String> {
    let Some(settings) = provider.planner() else {
        return Ok(None);
    };
    seated_planner(vault, settings, config.model.as_str(), decisions)
}

/// The host's planner under `settings` for a run executing on `executor`:
/// [`planner_binding`]'s for one entry, and an action's on a live run
/// (OF-181), from what the run registered with. `None` when no seat
/// resolves.
pub(crate) fn seated_planner<'a>(
    vault: &Vault,
    settings: &PlannerSettings,
    executor: &str,
    decisions: HostPlannerDecisions<'a>,
) -> Result<Option<HostPlannerBinding<'a>>, String> {
    let mut seats = Vec::with_capacity(settings.seats.len());
    for seat in &settings.seats {
        match planner_seat_agent(vault, &seat.agent).map_err(text)? {
            Some(agent_def) => seats.push(PlannerSeat {
                model: seat.model.clone(),
                agent_def,
            }),
            None => tracing::warn!(
                agent = %seat.agent,
                model = seat.model.as_str(),
                "a models.planner seat names no AGENT_DEF in this vault; the planner skips it"
            ),
        }
    }
    if seats.is_empty() {
        return Ok(None);
    }
    Ok(Some(HostPlannerBinding {
        skills: PlannerSkills::seeded().map_err(text)?,
        seats,
        executor: executor.to_owned(),
        decisions: Some(decisions),
        leader: LeaderStarterSkills::seeded().map_err(text)?,
        top: settings.top,
        // Callers attach the run's own runner after this binding is built:
        // a leased entry in `enter_run`, and a live-run action through
        // `ResolvedLiveRun::pattern_runner`. It stays `None` when no runner
        // is available, preserving the host-with-no-runner planned path.
        pattern_runner: None,
    }))
}

/// A planner seat's AGENT_DEF: a hex ID this vault holds, or a seeded
/// definition's logical ID.
fn planner_seat_agent(vault: &Vault, agent: &str) -> oneiron::Result<Option<EntityId>> {
    if let Ok(id) = EntityId::from_hex(agent) {
        return Ok(vault.get_agent_definition(&id)?.map(|_| id));
    }
    Ok(vault
        .get_seeded_agent_definition_by_logical_id(agent)?
        .map(|(id, _)| id))
}
