//! The owner's task-type tree doors (DOOR-111), with the owner's own proof:
//! store an authored tree on an open team-shape fork as a candidate, and
//! read the tree in force or one kept version; and the owner's launch of one
//! planned agent or team on this host's planner, and the owner's read of one
//! spawned agent by its attempt; and the owner's run doors over one TASK's
//! branches (DOOR-100): the unrefusable force-stop of every live branch,
//! and the read of every branch; and the owner's read of one consult's
//! terminal register (DOOR-063); and the owner's reads of this node's
//! Dreamer runner (DOOR-101): its MACRO home and one consolidation job's
//! lineage, and his pick of the home node. `host_doors` re-exports them, so
//! the generated HTTP facade handler and the MCP dispatcher call them by the
//! name every host door has.
use std::sync::Arc;
use std::time::Instant;

use oneiron::agent_dispatch::PlannerDecisions;
use oneiron::code_run::HostPlannerBinding;
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{
    ConsolidationHomePickReceipt, ConsolidationHomePickRequest, ConsolidationHomeView,
    ConsolidationLineageRequest, ConsolidationLineageView,
};
use oneiron::memory::{MEMORY_CODE_INTERNAL, MemoryError, MemoryResult};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::task_type::PlacementDecisions;
use oneiron::task_verb::run_doors::{
    CancelForceReceipt, CancelForceRequest, ConsultInspection, ConsultReadRequest,
    ConsultSummaryView, RunBranchesRequest, RunBranchesView,
};
use oneiron::task_verb::sdk::EmptyRequest;
use oneiron::team::PlannedSpawnHost;
use oneiron::team::doors::{
    CriticAssociation, PlannedSpawnObservation, PlannedSpawnRead, SpawnIntentReply,
    SpawnIntentRequest, TaskTypeTreePin, TaskTypeTreePinReceipt, TaskTypeTreeRead,
    TaskTypeTreeReadReply,
};

use super::host_doors::{MaybeListed, owner_proof};
use super::shared_act_doors::as_person_naming;
use crate::auth::CoreAuth;
use crate::server::{SyncServer, seated_planner};

/// The placement adapter the owner's served launch is stated under: this
/// host's own placement and planner, which keep no idempotency key.
const OWNER_SPAWN_ADAPTER: &str = "server.owner_spawn.v1";
/// What the owner does when the host's planner does not load.
const PLANNER_LOAD_FIX: &str = "The host could not read its planner seats' AGENT_DEFs or its seeded planner skills; check the server log and the vault's store, then ask again. The intent key is still free.";

/// A pin names the fork it stored the tree on.
pub(crate) async fn vault_task_types_pin(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TaskTypeTreePin,
) -> MaybeListed<TaskTypeTreePinReceipt> {
    const VERB: &str = "vault.task_types.pin";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| oneiron::team::doors::pin_tree_as(server.vault(), &owner, input),
        |stored| Some(vec![stored.fork_ref]),
    )
    .await
}

/// A read names the team-shape skill in force, when one is.
pub(crate) async fn vault_task_types_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TaskTypeTreeRead,
) -> MaybeListed<TaskTypeTreeReadReply> {
    const VERB: &str = "vault.task_types.get";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| oneiron::team::doors::read_tree_as(server.vault(), &owner, input),
        |read| Some(read.in_force_skill_ref.into_iter().collect()),
    )
    .await
}

/// A launch names each attempt it queued, the AGENT_DEF its plan seats and
/// each skill revision its plan read or selected.
pub(crate) async fn vault_agents_spawn(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SpawnIntentRequest,
) -> MaybeListed<SpawnIntentReply> {
    const VERB: &str = "vault.agents.spawn";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| served_spawn(server, &owner, input),
        spawn_intent_rows,
    )
    .await
}

/// The owner's launch on this host's planner (DOOR-111): the seats and
/// skills a leased run's planner resolves, the code-mode template's model
/// as the executor, and the host's ladder for the type placement and the
/// shape pick, each on a fresh hard clock of its budget. The launch is
/// stated under no spend scope and no adapter key; the team's start is
/// written on the house pattern runner. A host that lends no planner
/// passes none, and the engine refuses before it reserves anything.
fn served_spawn(
    server: &Arc<SyncServer>,
    owner: &AuthenticatedOwner,
    input: SpawnIntentRequest,
) -> MemoryResult<SpawnIntentReply> {
    let vault = server.vault();
    let at = vault.now_recorded_at();
    let runner = server.pattern_launch_runner();
    let Some(planner) = owner_planner(server, owner)? else {
        return oneiron::team::doors::spawn_as_owner(vault, owner, input, None, runner, at);
    };
    // Built from the binding's own fields, as a leased run's are; the
    // helpers that build those are the engine's.
    let decisions = planner.decisions.as_ref();
    let started = Instant::now();
    let placement_clock =
        decisions.map(|host| RetrievalDeadline::hard(started, host.placement_budget));
    let planner_clock = decisions.map(|host| RetrievalDeadline::hard(started, host.planner_budget));
    let placement = decisions
        .zip(placement_clock.as_ref())
        .map(|(host, deadline)| PlacementDecisions {
            ladder: host.ladder.ladder(),
            principal: host.principal,
            dial: host.placement_dial,
            bands: host.bands.clone(),
            wording: host.placement_wording.clone(),
            deadline,
        });
    let shape = decisions
        .zip(planner_clock.as_ref())
        .map(|(host, deadline)| PlannerDecisions {
            ladder: host.ladder.ladder(),
            principal: host.principal,
            bands: host.bands.clone(),
            wording: host.planner_wording.clone(),
            deadline,
        });
    let host = PlannedSpawnHost {
        seats: &planner.seats,
        skills: &planner.skills,
        executor: &planner.executor,
        placement: placement.as_ref(),
        planner: shape.as_ref(),
        spend: None,
        placement_adapter: OWNER_SPAWN_ADAPTER,
        placement_key: None,
    };
    oneiron::team::doors::spawn_as_owner(vault, owner, input, Some(&host), runner, at)
}

/// This host's planner for the owner: the `[models.planner]` seats whose
/// AGENT_DEF this vault holds and the shipped skills, through
/// [`seated_planner`], on the code-mode template's model and the host's
/// ladder for the owner. `None` when no code-mode host, no planner settings
/// or no seat that resolves serves one.
fn owner_planner<'s>(
    server: &'s SyncServer,
    owner: &AuthenticatedOwner,
) -> MemoryResult<Option<HostPlannerBinding<'s>>> {
    let Some(host) = server
        .code_execution_host()
        .and_then(|host| host.engine_native())
    else {
        return Ok(None);
    };
    let provider = host.provider();
    let Some(settings) = provider.planner() else {
        return Ok(None);
    };
    let vault = server.vault();
    let principal = owner.revalidate(vault)?;
    let model = provider.template_model(vault, principal)?;
    // The seats' AGENT_DEF reads and the seeded skills are the host's own
    // loads, so a failure is the host's, not the owner's ask (FIX 4660).
    seated_planner(
        vault,
        settings,
        model.as_str(),
        server.decision_host().host_planner_decisions(principal),
    )
    .map_err(|error| {
        MemoryError::new(
            MEMORY_CODE_INTERNAL,
            format!("this host's planner did not load: {error}"),
            &[PLANNER_LOAD_FIX],
        )
    })
}

/// A spawn read names the attempt, every attempt that launched with it and
/// the team start's leader and members, and each critique's lens and, for
/// one keyed under a launched attempt, that attempt.
pub(crate) async fn vault_agents_spawn_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PlannedSpawnRead,
) -> MaybeListed<PlannedSpawnObservation> {
    const VERB: &str = "vault.agents.spawn.get";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| oneiron::team::doors::observe_spawn_as(server.vault(), &owner, input),
        spawn_rows,
    )
    .await
}

/// A force names the TASK whose branches it stopped.
pub(crate) async fn vault_tasks_cancel_force(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CancelForceRequest,
) -> MaybeListed<CancelForceReceipt> {
    const VERB: &str = "vault.tasks.cancel_force";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| {
            oneiron::task_verb::run_doors::cancel_force_as(server.vault(), &owner, input)
        },
        |receipt| Some(vec![receipt.task_ref]),
    )
    .await
}

/// A branch read names the TASK whose branches it read.
pub(crate) async fn vault_runs_branches_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RunBranchesRequest,
) -> MaybeListed<RunBranchesView> {
    const VERB: &str = "vault.runs.branches.get";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| {
            oneiron::task_verb::run_doors::read_branches_as(server.vault(), &owner, input)
        },
        |read| Some(vec![read.task_ref]),
    )
    .await
}

/// A consult read names the TASK, the result its settlement wrote, each
/// evidence or reason ref and a countered outcome's new TASK.
pub(crate) async fn vault_consults_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConsultReadRequest,
) -> MaybeListed<ConsultInspection> {
    const VERB: &str = "vault.consults.get";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| {
            oneiron::task_verb::run_doors::read_consult_as(server.vault(), &owner, input)
        },
        consult_rows,
    )
    .await
}

fn consult_rows(read: &ConsultInspection) -> Option<Vec<oneiron::EntityId>> {
    let mut rows = vec![read.task_ref];
    if let Some(terminal) = &read.terminal {
        rows.extend(terminal.result_ref);
        match &terminal.summary {
            Some(ConsultSummaryView::Answer { evidence_refs }) => {
                rows.extend(evidence_refs.iter().map(|evidence| evidence.entity_ref()));
            }
            Some(ConsultSummaryView::Abstained { reason_ref }) => {
                rows.push(reason_ref.entity_ref());
            }
            None => {}
        }
        rows.extend(terminal.counter_task_ref);
    }
    rows.sort_unstable();
    rows.dedup();
    Some(rows)
}

/// A home read names no row: the designation and the client id are this
/// node's private runner state, not vault records.
pub(crate) async fn vault_consolidation_home_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> MaybeListed<ConsolidationHomeView> {
    const VERB: &str = "vault.consolidation.home.get";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        |server, owner| oneiron::dreamer_runner::consolidation_home_as(server.vault(), &owner),
        |_| Some(Vec::new()),
    )
    .await
}

/// A pick names the AUTHORITY_LOG row it landed as. The act records where
/// the owner said so (audit only): `surface`, the host's own reading of the
/// request (the facade call's verified headers, or the MCP connection's
/// proven peer), never its input (FIX 4650).
pub(crate) async fn vault_consolidation_home_pick(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: oneiron::authority::ActSurface,
    input: ConsolidationHomePickRequest,
) -> MaybeListed<ConsolidationHomePickReceipt> {
    const VERB: &str = "vault.consolidation.home.pick";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| {
            oneiron::dreamer_runner::consolidation_home_pick_as(
                server.vault(),
                &owner,
                surface,
                input,
            )
        },
        |receipt| Some(receipt.act_row().into_iter().collect()),
    )
    .await
}

/// A lineage read names each committed step's claim; the tries are this
/// node's private queue rows, not vault records.
pub(crate) async fn vault_consolidation_lineage(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConsolidationLineageRequest,
) -> MaybeListed<Option<ConsolidationLineageView>> {
    const VERB: &str = "vault.consolidation.lineage";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| {
            oneiron::dreamer_runner::consolidation_lineage_as(server.vault(), &owner, input)
        },
        |read| {
            Some(
                read.iter()
                    .flat_map(|lineage| lineage.steps.iter().map(|step| step.claim_ref))
                    .collect(),
            )
        },
    )
    .await
}

fn spawn_intent_rows(reply: &SpawnIntentReply) -> Option<Vec<oneiron::EntityId>> {
    let mut rows: Vec<_> = reply
        .root_attempt
        .into_iter()
        .chain(reply.member_attempts.iter().copied())
        .chain(reply.agent_def_ref)
        .collect();
    if let Some(plan) = &reply.plan {
        rows.extend(
            [&plan.team_shape, &plan.pattern_skill, &plan.rung_skill]
                .into_iter()
                .flatten()
                .map(|skill| skill.skill_ref),
        );
    }
    rows.sort_unstable();
    rows.dedup();
    Some(rows)
}

fn spawn_rows(read: &PlannedSpawnObservation) -> Option<Vec<oneiron::EntityId>> {
    let mut rows = vec![read.spawn_ref];
    rows.extend(read.launched.iter().map(|member| member.attempt_ref));
    if let Some(binding) = &read.binding {
        rows.push(binding.leader);
        rows.extend(binding.member_attempt_refs.iter().copied());
    }
    for critic in &read.critics {
        rows.push(critic.lens_ref);
        if critic.association == CriticAssociation::BranchAttempt {
            rows.push(critic.branch_attempt_ref);
        }
    }
    rows.sort_unstable();
    rows.dedup();
    Some(rows)
}
