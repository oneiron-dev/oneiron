//! The agent run's handover when its machine closes or vanishes (FIX 4747
//! slice 6; canon CROSS-ARCH-0019 "Where work runs", items 02-05: a run on
//! another machine falls back to the home node when that machine closes and
//! resumes from its last finished step; with no machine to take it, it
//! pauses and resumes on the next machine that comes up; it moves only
//! within world privacy and capability), with the orphaned-attempt reaper
//! the ruling names as the fallback.
//!
//! On every machine the host's housekeeping pass runs the reaper
//! ([`Vault::reap_agent_run_leases`]) beside the send reaper, and a closing
//! process runs none. It reads every live run TASK (`super::run_task`) whose
//! executor lease another machine holds and that is expired: one its holder
//! released as it closed, or one no pass renewed within a hold. The ruled
//! order says when this machine may take it (`agent_run_handover_due`): at
//! expiry when it is the vault's elected home node, else a grace later. The
//! run must be able to run here (`agent_run_runs_here`). A run no machine
//! can take waits: its TASK stays as it is, and the pass of the next able
//! machine that comes up takes it.
//!
//! The take is one writer (PDU-001): while the TASK still holds exactly the
//! expired lease, it moves the lease here at the next generation with a
//! fresh hold and, in the same write, makes sure a try of the run is queued
//! in this machine's queue (`handover_local_try`). The queued row is the
//! recovery wake, persisted with the take: the agent run pump's next pass
//! claims it, and no other scheduler runs. A second pass, an early wake or a
//! concurrent taker finds the lease moved, or the try's id taken, and does
//! nothing; two machines that take at once resolve as the lease does, by
//! whole-row LWW and the fence, so one executor stands down once copies
//! agree. The take reserves the run's launch spend here as its dispatch did
//! (`AgentDispatcher::reserve_handed_over_launch_in_txn`), and seeds nothing
//! the other machine spent: cross-node budget custody is FIX 4889.
//!
//! The same pass renews this machine's own lease on each run with a try
//! pending in its queue (`own_agent_run_lease_renewal`): a parked or queued
//! try, or a step that runs past half a hold, commits nothing that renews it.
//!
//! The old executor needs nothing from here: slice 5's fence stands it down
//! at its next step commit or effect, and its settlement ends its local try
//! with `agent_run_executor_moved` and leaves the run TASK as it is.
//!
//! Handover moves roots only (REVIEW-6638). Only a root run has a run TASK:
//! a child its run spawned runs under its root's, fenced at the root's
//! generation (`super::run_task`). So the reaper sees roots only: the root
//! reruns on the taker from its frozen payload and spawns its children
//! there, under new ids. Every child on the old machine stands down at its
//! root's fence with the root's own try. A child that outlived its root is a
//! root of its own, with its own run TASK, and moves as a root does; the
//! taker holds no row of its settled parent and runs it without one
//! (`super::agent_run`).
//! Entry: `Vault::reap_agent_run_leases`.

use std::collections::BTreeMap;

use super::run_task::{
    AgentRunExecutorLease, AgentRunTaskBody, agent_run_lease_held_until, agent_run_lease_renewal,
    agent_run_task_body_in, agent_run_task_ref_in, closing, open_agent_runs_in,
    update_agent_run_task_body_in_txn,
};
use super::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchInput, AgentDispatcher, decode_agent_dispatch_input,
};
use crate::Vault;
use crate::agent_def::{AgentDefinition, AgentModel};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptState, EnqueueAttempt, EnqueueOutcome};
use crate::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, DreamerRunnerStore, decode_dreamer_attempt_payload,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};

/// How long after an expired lease's `held_until` a machine that is not the
/// vault's elected home node waits before it takes the run (FIX 4747 slice
/// 6), so the home node, which takes at expiry, goes first. Engine call
/// (CALLS, FIX 4747): five minutes, five housekeeping ticks, the send
/// handover's grace.
const AGENT_RUN_HANDOVER_GRACE_SECS: u64 = 5 * 60;

/// Why the pass leaves a run for now: its agent is not dispatchable here.
const AGENT_NOT_DISPATCHABLE: &str = "agent_not_dispatchable";
/// The requester whose request queued the run was withdrawn.
const REQUESTER_WITHDRAWN: &str = "requester_withdrawn";
/// No model on the run's list has a route on this machine.
const NO_MODEL_ROUTE_HERE: &str = "no_model_route_here";
/// The host runs no agent runs.
const HOST_RUNS_NO_AGENT_RUNS: &str = "host_runs_no_agent_runs";
/// The run's world is not readable on this machine.
const WORLD_NOT_READABLE_HERE: &str = "world_not_readable_here";
/// The TASK's frozen payload or try ids do not read.
const RUN_TASK_UNREADABLE: &str = "run_task_unreadable";
/// A try of the run is leased, landing or paused here.
const TRY_HELD_HERE: &str = "try_held_here";
/// The run's newest try here ended another way than failed.
const TRY_ENDED_HERE: &str = "try_ended_here";
/// A try of the run here has two retries, so no one try is its newest.
const TRY_LINEAGE_FORKED_HERE: &str = "try_lineage_forked_here";
/// The run's try here changed since the pass read it; the next pass judges
/// it again.
const LOCAL_TRY_CHANGED: &str = "local_try_changed";
/// A pending row here holds the run's dedupe key.
const DEDUPE_KEY_HELD_HERE: &str = "dedupe_key_held_here";
/// The try, as queued here, is no run of the agent run pump's here.
const NOT_THE_AGENT_PUMPS: &str = "not_the_agent_pumps";
/// This machine cannot fund the run as its launch was stated.
const LAUNCH_UNFUNDED_HERE: &str = "launch_unfunded_here";

/// What one reaper pass came to (FIX 4747 slice 6).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AgentRunLeaseReap {
    /// Runs this machine took, each with a try of it queued here.
    pub taken: usize,
    /// Runs with an expired lease this machine left for now: the ruled
    /// order puts the home node first, or the run cannot run here. They wait.
    pub waiting: usize,
    /// This machine's own leases it renewed, each on a run with a try
    /// pending here.
    pub renewed: usize,
}

/// What a take does with the run's tries in this machine's queue (FIX 4747
/// slice 6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalTry {
    /// A try of the run is queued or scheduled here: it stays as it is, and
    /// the pump's claim runs it under the moved lease.
    Keep(AttemptId),
    /// No try of the run is here: the live try is queued here under its own
    /// id from the TASK's frozen payload.
    Recreate,
    /// This machine failed the newest try of the run it holds (the live try
    /// or a retry of it): a successor of that try is queued here.
    Succeed(AttemptId),
    /// The take waits, for the reason named.
    Wait(&'static str),
}

/// Where a run this machine took goes on from (FIX 4747 slice 6; canon item
/// 03, "it resumes from its last finished step").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentRunResume {
    /// A try of the run was queued here already. Its executor run's id is
    /// the try's own, so it reopens this machine's replay row of that try
    /// and goes on from its last finished step; its finished model steps hit
    /// the step memo the try keys.
    QueuedHere,
    /// The live try, re-created here under its own id. The run's step
    /// capsules, its replay row and its step memo rows are device-local, so
    /// none of them is on this machine: the run reruns from the frozen
    /// payload, and an effect-free step runs again. A finished model step
    /// whose synced terminal claim this machine indexed under that id is a
    /// memo hit when the rebuilt request matches.
    FrozenPayload,
    /// A successor of the newest try of the run this machine failed. This
    /// machine holds that try's capsules, but the one fork from a capsule
    /// (FIX 3694, `engine_executor::continuation`) needs an owner's approval
    /// and puts the approved note on every turn from its cut; a handover has
    /// neither, so the successor reruns from the frozen payload under its new
    /// id.
    Successor,
}

impl AgentRunResume {
    const fn as_str(self) -> &'static str {
        match self {
            Self::QueuedHere => "queued_here",
            Self::FrozenPayload => "frozen_payload",
            Self::Successor => "successor",
        }
    }
}

/// What one take came to (FIX 4747 slice 6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentRunTake {
    /// The lease moved here at `generation`, and `try_id` is queued here.
    Taken {
        generation: u64,
        try_id: AttemptId,
        resume: AgentRunResume,
    },
    /// The TASK moved on since the pass read it: a renewal, a release,
    /// another machine's take, or its settlement.
    Moved,
    /// This machine leaves the run for now, for the reason named.
    Waits(&'static str),
}

/// One expired run the pass decided to take, as its snapshot read it.
#[derive(Clone, Copy, Debug)]
struct ExpiredRun {
    task_ref: EntityId,
    lease: AgentRunExecutorLease,
    local: LocalTry,
}

impl Vault {
    /// The orphaned-run reaper (FIX 4747 slice 6): takes each agent run
    /// whose executor lease another machine holds and is expired, in the
    /// ruled order (`agent_run_handover_due`), when it can run here
    /// (`agent_run_runs_here`, with `runs_here` the host's own read-only
    /// check of the run's frozen definition). Each take, in one writer,
    /// moves the lease here at the next generation and queues a try of the
    /// run here; a run neither lets this machine take waits. In one writer
    /// of its own, the pass renews this machine's own lease on each run with
    /// a try pending here (`own_agent_run_lease_renewal`). A closing process
    /// reaps and renews nothing. With no other machine, every lease is this
    /// machine's, so nothing is ever handed over.
    ///
    /// # Errors
    /// Storage errors. One run's failed take leaves it waiting, logged, and
    /// the pass goes on.
    pub fn reap_agent_run_leases(
        &self,
        runs_here: &dyn Fn(&AgentDefinition) -> bool,
    ) -> Result<AgentRunLeaseReap> {
        if closing(self) {
            return Ok(AgentRunLeaseReap::default());
        }
        let now = self.now_recorded_at();
        let node_id = crate::identity::load_or_mint_client_id(self)?;
        let mut reap = AgentRunLeaseReap::default();
        let (renew, takes) = {
            let rtxn = self.store.env.read_txn()?;
            let runs: Vec<(EntityId, AgentRunTaskBody)> = open_agent_runs_in(self, &rtxn)?
                .into_iter()
                .filter(|(_, body)| {
                    let lease = body.executor;
                    if lease.node_id == node_id {
                        own_agent_run_lease_renewal(lease, true, now).is_some()
                    } else {
                        lease.expired_at(now)
                    }
                })
                .collect();
            if runs.is_empty() {
                return Ok(reap);
            }
            let local = local_agent_run_tries_in(self, &rtxn)?;
            // The home designation is read only when an expired lease of
            // another machine asks the ruled order.
            let home = runs
                .iter()
                .any(|(_, body)| body.executor.node_id != node_id)
                && elected_home_here_in(self, &rtxn, node_id)?;
            let mut renew = Vec::new();
            let mut takes = Vec::new();
            for (task_ref, body) in runs {
                let lease = body.executor;
                let pending = local.get(&task_ref).copied();
                if lease.node_id == node_id {
                    if let Some(held_until) =
                        own_agent_run_lease_renewal(lease, pending.is_some(), now)
                    {
                        renew.push((task_ref, lease, held_until));
                    }
                    continue;
                }
                if !agent_run_handover_due(lease, home, now) {
                    reap.waiting += 1;
                    continue;
                }
                let reason = match agent_run_runs_here(self, &rtxn, &body, runs_here) {
                    Ok(reason) => reason,
                    Err(error) => {
                        tracing::warn!(
                            task = %task_ref.to_hex(),
                            kind = ?error.kind(),
                            "the agent run reaper could not judge a run; it waits"
                        );
                        reap.waiting += 1;
                        continue;
                    }
                };
                let local_try = match reason {
                    Some(reason) => LocalTry::Wait(reason),
                    None => match attempt_id_from_hex(&body.live_attempt_ref) {
                        Some(live) => {
                            handover_local_try(pending, newest_local_try_in(self, &rtxn, live)?)
                        }
                        None => LocalTry::Wait(RUN_TASK_UNREADABLE),
                    },
                };
                if let LocalTry::Wait(reason) = local_try {
                    tracing::debug!(
                        task = %task_ref.to_hex(),
                        reason,
                        "the agent run reaper left an expired run waiting"
                    );
                    reap.waiting += 1;
                    continue;
                }
                takes.push(ExpiredRun {
                    task_ref,
                    lease,
                    local: local_try,
                });
            }
            (renew, takes)
        };
        for run in takes {
            match take_expired_agent_run(self, run, node_id, now) {
                Ok(AgentRunTake::Taken {
                    generation,
                    try_id,
                    resume,
                }) => {
                    tracing::info!(
                        task = %run.task_ref.to_hex(),
                        attempt = %bytes_to_hex_lower(try_id.as_bytes()),
                        node_id,
                        generation,
                        expired_node_id = run.lease.node_id,
                        expired_generation = run.lease.generation,
                        resume = resume.as_str(),
                        "the agent run reaper took a run whose lease expired"
                    );
                    reap.taken += 1;
                }
                Ok(AgentRunTake::Moved) => {}
                Ok(AgentRunTake::Waits(reason)) => {
                    tracing::debug!(
                        task = %run.task_ref.to_hex(),
                        reason,
                        "the agent run reaper left an expired run waiting"
                    );
                    reap.waiting += 1;
                }
                // One run's failed take leaves it waiting and the pass goes on.
                Err(error) => {
                    tracing::warn!(
                        task = %run.task_ref.to_hex(),
                        kind = ?error.kind(),
                        "the agent run reaper could not take a run; it waits"
                    );
                    reap.waiting += 1;
                }
            }
        }
        if !renew.is_empty() {
            reap.renewed = self.with_write_txn_grouped(|wtxn| {
                let mut renewed = 0_usize;
                for (task_ref, lease, held_until) in renew {
                    let mut done = false;
                    update_agent_run_task_body_in_txn(self, wtxn, task_ref, now, |body| {
                        if body.outcome.is_none() && body.executor.same_holding(lease) {
                            body.executor.held_until = held_until;
                            done = true;
                        }
                        Ok(())
                    })?;
                    renewed += usize::from(done);
                }
                Ok(renewed)
            })?;
        }
        if reap.taken > 0 {
            self.store.notify_attempt_observers();
        }
        Ok(reap)
    }
}

/// Whether the ruled handover order lets this machine take a run whose
/// lease expired at `lease.held_until`, at `now` (FIX 4747 slice 6; canon
/// items 02-03, "a run on another machine falls back to the home node").
/// Engine call (CALLS, FIX 4747): the vault's elected home node (`home`)
/// takes at expiry; any other live machine, as this one is while it runs the
/// pass, only [`AGENT_RUN_HANDOVER_GRACE_SECS`] later, so the home node, when
/// it can run the run, goes first. With no machine able, the run waits.
fn agent_run_handover_due(lease: AgentRunExecutorLease, home: bool, now: u64) -> bool {
    let due_at = if home {
        lease.held_until
    } else {
        lease
            .held_until
            .saturating_add(AGENT_RUN_HANDOVER_GRACE_SECS)
    };
    now >= due_at
}

/// Whether this machine (`node_id`) is the vault's elected home node, read
/// in `txn` (FIX 4747 slice 6). Engine call (CALLS, FIX 4747): the committed
/// MACRO home designation (`dreamer_runner::home`), which the owner's pick
/// wins and an attached cloud, then an always-on machine, then the primary
/// device fill; the handover holds no election of its own.
fn elected_home_here_in(vault: &Vault, txn: &heed::RoTxn<'_>, node_id: u64) -> Result<bool> {
    Ok(DreamerRunnerStore::new(vault)
        .home_node_designation_in_txn(txn)?
        .is_some_and(|home| home.node_id == node_id))
}

/// Whether the pass renews this machine's own `lease` at `now`, and to
/// which `held_until` (FIX 4747 slice 6): only while a try of its run is
/// pending in this machine's queue (`pending_here`), parked on a wait,
/// queued, scheduled, or leased to an executor whose step runs past half a
/// hold. Engine call (CALLS, FIX 4747): a machine that is up and holds a try
/// of its run keeps the lease, as the send reaper keeps a send held paused
/// here; it renews once less than half a hold is left, at the same
/// generation, so the fence its claim took still holds. A lease that expired
/// while this machine slept or closed is not renewed here: the claim of its
/// try takes it again, or another machine takes the run.
fn own_agent_run_lease_renewal(
    lease: AgentRunExecutorLease,
    pending_here: bool,
    now: u64,
) -> Option<u64> {
    if !pending_here || lease.expired_at(now) {
        return None;
    }
    agent_run_lease_renewal(lease.held_until, now)
}

/// What the take does with the run's tries in this machine's queue (FIX
/// 4747 slice 6), from `pending`, the newest try of the run pending here,
/// and `newest`, the newest try of the live try's retry lineage this queue
/// holds (`newest_local_try_in`). Engine call (CALLS, FIX 4747): a try
/// queued or scheduled here is kept, and runs as itself; a try leased,
/// landing or paused here makes the take wait, as an executor or a pause
/// still holds it, and the fence stands an old executor down before a later
/// pass takes the run. With no try pending here, a live try this queue
/// holds no row of is re-created under its own id; a newest try here that
/// failed (it stood down, or a claim ended it unrun, while another machine
/// held the run) gets a successor, as the queue has no requeue of an ended
/// try as the same try; one that ended any other way, or a lineage with two
/// retries of one try, makes the take wait.
fn handover_local_try(
    pending: Option<(AttemptId, AttemptState)>,
    newest: Option<Option<(AttemptId, AttemptState)>>,
) -> LocalTry {
    match (pending, newest) {
        (Some((id, AttemptState::Queued | AttemptState::Scheduled)), _) => LocalTry::Keep(id),
        (Some(_), _) => LocalTry::Wait(TRY_HELD_HERE),
        (None, None) => LocalTry::Wait(TRY_LINEAGE_FORKED_HERE),
        (None, Some(None)) => LocalTry::Recreate,
        (None, Some(Some((id, AttemptState::Failed)))) => LocalTry::Succeed(id),
        (None, Some(Some(_))) => LocalTry::Wait(TRY_ENDED_HERE),
    }
}

/// The newest try of `live`'s retry lineage this machine's queue holds,
/// read in `txn`, each try's one retry followed forward, with its state:
/// `Some(None)` when this queue holds no row of `live`, and `None` when a
/// try has two retries here, so no one try is newest.
fn newest_local_try_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    live: AttemptId,
) -> Result<Option<Option<(AttemptId, AttemptState)>>> {
    let queue = AttemptQueue::new(vault);
    let Some(newest) = queue.newest_retry_in_txn(txn, live)? else {
        return Ok(None);
    };
    Ok(Some(
        queue
            .get_in_txn(txn, newest)?
            .map(|row| (row.id, row.state)),
    ))
}

/// Whether the run `body` names may run on this machine now, read in `txn`
/// (FIX 4747 slice 6; canon item 05, "within world privacy and
/// capability"): `None` when it may, else why not. Engine call (CALLS, FIX
/// 4747), read-only, each part the check the run's own path makes:
///
/// - its agent definition is dispatchable here, the claim's check
///   (`AgentDispatcher::dispatchable_definition_in_txn`);
/// - its requester was not withdrawn, the claim's check
///   (`AgentDispatcher::requester_withdrawn_in_txn`);
/// - a model on its frozen list has a route here (`listed_model_routes_here_in`);
/// - the host's own check, `runs_here`, of its frozen definition;
/// - its world is readable on this machine (`world_readable_here_in`).
///
/// The connectors and code-mode MCP servers a definition names have no
/// read-only presence check on the run's path, so none is read here.
fn agent_run_runs_here(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    body: &AgentRunTaskBody,
    runs_here: &dyn Fn(&AgentDefinition) -> bool,
) -> Result<Option<&'static str>> {
    let Some(input) = frozen_dispatch_input(&body.queue_payload) else {
        return Ok(Some(RUN_TASK_UNREADABLE));
    };
    let dispatcher = AgentDispatcher::new(vault);
    match dispatcher.dispatchable_definition_in_txn(txn, &input.target) {
        Ok(_) => {}
        Err(Error::Artifact(_) | Error::Record(_)) => return Ok(Some(AGENT_NOT_DISPATCHABLE)),
        Err(error) => return Err(error),
    }
    if dispatcher.requester_withdrawn_in_txn(txn, &input).is_some() {
        return Ok(Some(REQUESTER_WITHDRAWN));
    }
    if !listed_model_routes_here_in(vault, txn, &input.definition.models)? {
        return Ok(Some(NO_MODEL_ROUTE_HERE));
    }
    if !runs_here(&input.definition) {
        return Ok(Some(HOST_RUNS_NO_AGENT_RUNS));
    }
    if let Some(world) = &body.world_ref
        && !world_readable_here_in(vault, txn, world)?
    {
        return Ok(Some(WORLD_NOT_READABLE_HERE));
    }
    Ok(None)
}

/// Whether this machine has a route to a model on `listed`, a run's frozen
/// list, read in `txn`: a model a live (not retired) registry row here
/// names, the rows the run's seat birth picks among (`llm::seat`) and its
/// wake's retired-model note reads (`agent_def::note_stale_listed_models`).
/// An empty list runs on its one house-routed model, which only the host's
/// check judges.
fn listed_model_routes_here_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    listed: &[AgentModel],
) -> Result<bool> {
    if listed.is_empty() {
        return Ok(true);
    }
    for entry in listed {
        if vault
            .model_registry_row_in_txn(txn, &entry.model_ref)?
            .is_some_and(|row| !row.is_stale())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether this machine may read `world`'s rows under its world privacy,
/// read in `txn`, as a private world's recognition material is judged
/// (`voice_identity::recognition`): the world's read setting must admit this
/// machine. A machine with no machine identity, or a fold that cannot judge
/// (a conflicted vault root), reads none.
fn world_readable_here_in(vault: &Vault, txn: &heed::RoTxn<'_>, world: &str) -> Result<bool> {
    let Ok(world) = EntityId::from_hex(world) else {
        return Ok(false);
    };
    let Some(machine) = crate::identity::read_machine_id_in_txn(vault, txn)? else {
        return Ok(false);
    };
    match crate::authority::world_readable_on_machine_in(
        vault,
        txn,
        world,
        crate::authority::Destination::Machine(machine),
    ) {
        Ok(readable) => Ok(readable),
        Err(error) => {
            tracing::warn!(
                world = %world.to_hex(),
                kind = ?error.kind(),
                "the agent run reaper could not judge a run's world on this machine; it waits"
            );
            Ok(false)
        }
    }
}

/// The run TASKs with a try of their own still pending in this machine's
/// queue (a root's, or a child's that outlived its root), read in `txn`,
/// each with its newest such try's id and state. A pending child under a
/// run's TASK is no try of it here (REVIEW-6638): the take never keeps it as
/// the run's try, and it renews nothing.
fn local_agent_run_tries_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<EntityId, (AttemptId, AttemptState)>> {
    let mut local = BTreeMap::new();
    for row in AttemptQueue::new(vault)
        .kind_working_rows_in_txn(txn, DREAMER_RUNNER_ATTEMPT_KIND)?
        .into_iter()
        .filter(|row| row.state.is_pending())
    {
        if let Some(link) = agent_run_task_ref_in(vault, txn, &row)?
            && !link.child
        {
            local.insert(link.task_ref, (row.id, row.state));
        }
    }
    Ok(local)
}

/// Takes `run`, whose lease the pass judged expired, for this machine
/// (`node_id`) in one writer (FIX 4747 slice 6).
fn take_expired_agent_run(
    vault: &Vault,
    run: ExpiredRun,
    node_id: u64,
    now: u64,
) -> Result<AgentRunTake> {
    vault.with_write_txn_grouped(|wtxn| {
        take_expired_agent_run_in_txn(vault, wtxn, run, node_id, now)
    })
}

/// [`take_expired_agent_run`]'s write, while the run TASK still holds
/// exactly `run.lease` and no outcome: a try of the run is queued here as
/// `run.local` rules, with its launch spend reserved here, in a savepoint
/// that commits only when the try is a run of the agent run pump's here and
/// this machine can fund it; then the lease moves here at the next
/// generation with a fresh hold, and the TASK names a re-created or
/// successor try as its live one. A kept try is named by its own claim.
fn take_expired_agent_run_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    run: ExpiredRun,
    node_id: u64,
    now: u64,
) -> Result<AgentRunTake> {
    let Some(body) = agent_run_task_body_in(vault, &*wtxn, run.task_ref)? else {
        return Ok(AgentRunTake::Moved);
    };
    if body.outcome.is_some() || body.executor != run.lease {
        return Ok(AgentRunTake::Moved);
    }
    let (Some(live), Some(original)) = (
        attempt_id_from_hex(&body.live_attempt_ref),
        attempt_id_from_hex(&body.attempt_ref),
    ) else {
        return Ok(AgentRunTake::Waits(RUN_TASK_UNREADABLE));
    };
    let queue = AttemptQueue::new(vault);
    let (try_id, resume) = match run.local {
        LocalTry::Wait(reason) => return Ok(AgentRunTake::Waits(reason)),
        LocalTry::Keep(id) => {
            let queued = queue.get_in_txn(&*wtxn, id)?.is_some_and(|row| {
                matches!(row.state, AttemptState::Queued | AttemptState::Scheduled)
            });
            if !queued {
                return Ok(AgentRunTake::Waits(LOCAL_TRY_CHANGED));
            }
            (id, AgentRunResume::QueuedHere)
        }
        LocalTry::Recreate | LocalTry::Succeed(_) => {
            let Some(input) = frozen_dispatch_input(&body.queue_payload) else {
                return Ok(AgentRunTake::Waits(RUN_TASK_UNREADABLE));
            };
            let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
            let (record, resume) = if let LocalTry::Succeed(failed) = run.local {
                (
                    queue.successor_of_failed_in_txn(&mut savepoint, failed, now)?,
                    AgentRunResume::Successor,
                )
            } else {
                if queue.get_in_txn(&savepoint, live)?.is_some() {
                    return Ok(AgentRunTake::Waits(LOCAL_TRY_CHANGED));
                }
                // The live try keeps its own id, so its finished steps' memo
                // keys match; a later try links the run's original one, whose
                // id names the run TASK.
                let enqueued = DreamerRunnerStore::new(vault).enqueue_handed_over_in_txn(
                    &mut savepoint,
                    live,
                    EnqueueAttempt {
                        kind: DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
                        payload: body.queue_payload.clone(),
                        dedupe_key: body.dedupe_key.clone(),
                        run_id: body.run_id.clone(),
                        now: body.created_at,
                    },
                    body.realized_task_ref.clone(),
                    (live != original).then_some(original),
                )?;
                match enqueued {
                    EnqueueOutcome::Enqueued(record) => (record, AgentRunResume::FrozenPayload),
                    EnqueueOutcome::Existing(_) => {
                        return Ok(AgentRunTake::Waits(DEDUPE_KEY_HELD_HERE));
                    }
                }
            };
            if !super::agent_run::agent_pump_claims_in(vault, &savepoint, &record)? {
                return Ok(AgentRunTake::Waits(NOT_THE_AGENT_PUMPS));
            }
            if !AgentDispatcher::new(vault).reserve_handed_over_launch_in_txn(
                &mut savepoint,
                record.id,
                &input,
                now,
            )? {
                return Ok(AgentRunTake::Waits(LAUNCH_UNFUNDED_HERE));
            }
            savepoint.commit()?;
            // The transaction's owner re-arms the deadline watch after its
            // commit, as a dispatch's enqueue does.
            crate::batch::queue_proactivity_change(vault, wtxn);
            (record.id, resume)
        }
    };
    let lease = AgentRunExecutorLease {
        node_id,
        generation: run.lease.generation.saturating_add(1),
        held_until: agent_run_lease_held_until(now),
    };
    update_agent_run_task_body_in_txn(vault, wtxn, run.task_ref, now, |body| {
        body.executor = lease;
        if resume != AgentRunResume::QueuedHere {
            body.live_attempt_ref = bytes_to_hex_lower(try_id.as_bytes());
        }
        Ok(())
    })?;
    Ok(AgentRunTake::Taken {
        generation: lease.generation,
        try_id,
        resume,
    })
}

/// The agent dispatch input a run TASK's frozen queue payload carries;
/// `None` for one that does not decode as an agent dispatch.
fn frozen_dispatch_input(payload: &[u8]) -> Option<AgentDispatchInput> {
    let payload = decode_dreamer_attempt_payload(payload).ok()?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return None;
    }
    decode_agent_dispatch_input(&payload.input).ok()
}

/// An attempt id from the 32-hex form a run TASK stores it in.
fn attempt_id_from_hex(hex: &str) -> Option<AttemptId> {
    AttemptId::from_bytes(&crate::task_verb::decode_hex::<16>(hex)?).ok()
}
