//! Where an agent run runs (FIX 4747 slice 7; pass 34 row P4, DESIGN 4.8;
//! canon CROSS-ARCH-0019 "Where work runs", items 01, 02, 03 and 05).
//!
//! Two cases move a run off the machine that dispatched it:
//!
//! - Cloud users run in the cloud (item 01). When the vault's elected home is
//!   a cloud node and this machine is not it, the dispatch mints the run
//!   TASK's lease released (`super::run_task::mint_agent_run_task_in_txn`),
//!   so the cloud's reaper, which takes at expiry as the home
//!   (`super::run_handover`), takes the run at once.
//! - The owner's `agents` machines (row P4). At its first claim on the
//!   dispatching machine, before any step, a root run is placed among the
//!   machines whose `machines.work_roles` names `agents`, and the home,
//!   which is a candidate whether or not it is tagged. When no machine is
//!   tagged, nothing is placed and nothing is written: the run runs where it
//!   was dispatched, as before (item 02 holds until the owner tags one).
//!
//! The facts are the vault's own, read in one snapshot, so any machine of
//! the owner's places with no issuer and no network: each machine's home
//! candidacy (its sync node id), its policy (`machines.execution`,
//! `machines.windows`), its last capacity record (the agents it can run,
//! its GPUs, its power), the open runs it holds or is placed for, and
//! whether the run's world is readable there under the world's privacy
//! (item 05). The limits leave out a machine that is paused or draining,
//! outside its window, or that may not read the run's world. The rule
//! `role_warm_waste_headroom@1`, read for a run (DESIGN 4.3): every
//! candidate has the role; no warm step, as no world residence level is in
//! the vault yet; fewest GPUs, which keeps runs off the GPU boxes; most
//! room (the agents it can run less its open runs); the home; the lowest
//! machine id. The PLACE slot's named decider may pick another of the
//! rule's first [`PLACE_OPTIONS_MAX`] (`super::agent_run`); a run never
//! waits, as the home is always its fallback.
//!
//! Only a run's first claim places it: a try no claim has taken yet, so a
//! run that already ran a step (a resumed or retaken try) is never moved.
//! The pick is kept on the run TASK ([`RunPlacement`]), with its time read
//! after the ask, so the time a decider takes is not taken from the
//! takers' graces. A pick of another machine releases the lease in the
//! same write, and the takers of that lease go in order
//! ([`placed_take_due`]): the placed machine at once, the home after
//! `policy.slots.place_grace_ms`, every other machine the handover grace
//! after the home's turn. The taking machine's own check
//! (`agent_run_runs_here`: the agent is dispatchable, a model route exists
//! there, the host runs agent runs, the world is readable there) is the one
//! that counts, and the placed machine takes only while it takes new work
//! ([`takes_new_work_in`]): a run the placed machine does not take, the
//! home takes after the grace (item 03). Only the lease the placement
//! released is ordered: a pick of the dispatching machine itself releases
//! nothing and orders no one, the first take ends the order, and a later
//! handover follows the reaper's order as before. The reaper
//! (`super::run_handover`) asks this module for both orders
//! ([`take_due_in`]).

use std::cmp::Reverse;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::AgentDispatcher;
use super::run_task::{
    AGENT_RUN_LEASE_FIRST_GENERATION, AgentRunExecutorLease, AgentRunTaskBody,
    agent_run_task_body_in, agent_run_task_ref_in, open_agent_runs_in,
    update_agent_run_task_body_in_txn,
};
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::authority::{Destination, home_candidacies_by_machine_in_txn};
use crate::dreamer_runner::{DreamerHomeNodeClass, DreamerRunnerStore};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::machine_capacity::{MachineCapacity, MachinePower, machine_capacity_in_txn};
use crate::machine_policy::{ExecutionState, MachinePolicy, machine_policy_in_txn};
use crate::work_order::decider::setting_keys::place_grace_secs_in_txn;
use crate::work_order::decider::{PassAsks, SlotQuestion, SlotScope, SlotSubject, rule_fact};
use crate::work_order::record::{DecidedBy, SlotDecision, SlotName};
use crate::work_order::{Blocker, PLACE_RULE};

/// The work role that makes a machine a candidate for agent runs (DESIGN
/// 4.3 step 1: `agents` for a session or a native run).
pub const AGENTS_ROLE: &str = "agents";

/// How many of the rule's candidates the PLACE decider is shown (DESIGN
/// 4.4: the top six).
pub const PLACE_OPTIONS_MAX: usize = 6;

/// Where a run was placed at its first claim, and why (row P4): kept on its
/// run TASK. Never part of the frozen fields its writer proof covers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct RunPlacement {
    /// The MACHINE the run was placed on.
    pub(crate) machine: EntityId,
    /// The generation of the lease the placement ordered: only that lease's
    /// takers go in the placement's order, and its first take ends it.
    pub(crate) lease_generation: u64,
    /// Whether the placement released that lease to another machine. A
    /// pick of the dispatching machine itself releases nothing and orders
    /// no taker: its later handover follows the reaper's order.
    pub(crate) released: bool,
    /// When it was placed, in the lease's unit (unix seconds): after the
    /// PLACE ask, the time the release stamps on the lease.
    pub(crate) at: u64,
    /// The PLACE slot's decision: the options, the pick, who made it, why.
    pub(crate) decision: SlotDecision,
}

impl RunPlacement {
    /// Whether this placement orders the takers of `lease`: the lease it
    /// released to another machine, not yet taken by any machine.
    pub(super) const fn orders(&self, lease: AgentRunExecutorLease) -> bool {
        self.released && self.lease_generation == lease.generation
    }
}

/// Which taker of a placed lease a machine is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PlacedTaker {
    /// The machine the run was placed on.
    Placed,
    /// The vault's elected home.
    Home,
    /// Any other machine, the dispatching one included.
    Other,
}

/// When `taker` may take a placed run whose lease the placement released at
/// `lease.held_until` (row P4): the placed machine at once, the home after
/// `place_grace_secs`, any other machine `handover_grace_secs` after the
/// home's turn, as the reaper's own order puts the home first, whatever
/// grace the owner sets.
pub(super) const fn placed_take_due(
    lease: AgentRunExecutorLease,
    taker: PlacedTaker,
    place_grace_secs: u64,
    handover_grace_secs: u64,
) -> u64 {
    let home_due = lease.held_until.saturating_add(place_grace_secs);
    match taker {
        PlacedTaker::Placed => lease.held_until,
        PlacedTaker::Home => home_due,
        PlacedTaker::Other => home_due.saturating_add(handover_grace_secs),
    }
}

/// How long after an expired lease's `held_until` a machine that is not the
/// vault's elected home node waits before it takes the run (FIX 4747 slice
/// 6), so the home node, which takes at expiry, goes first. Engine call
/// (CALLS, FIX 4747): five minutes, five housekeeping ticks, the send
/// handover's grace.
pub(super) const AGENT_RUN_HANDOVER_GRACE_SECS: u64 = 5 * 60;

/// Whether the ruled handover order lets this machine take a run whose
/// lease expired at `lease.held_until`, at `now` (FIX 4747 slice 6; canon
/// items 02-03, "a run on another machine falls back to the home node").
/// Engine call (CALLS, FIX 4747): the vault's elected home node (`home`)
/// takes at expiry; any other live machine, as this one is while it runs the
/// pass, only [`AGENT_RUN_HANDOVER_GRACE_SECS`] later, so the home node, when
/// it can run the run, goes first. With no machine able, the run waits.
pub(super) fn agent_run_handover_due(lease: AgentRunExecutorLease, home: bool, now: u64) -> bool {
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
pub(super) fn elected_home_here_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    node_id: u64,
) -> Result<bool> {
    Ok(DreamerRunnerStore::new(vault)
        .home_node_designation_in_txn(txn)?
        .is_some_and(|home| home.node_id == node_id))
}

/// Whether this machine (`here`; the home when `home`) may take, at `now`,
/// the run of `body`, whose lease another machine holds and is expired:
/// in its placement's order while the placement orders that lease (row P4,
/// [`placed_take_due`]), else in the handover's ruled order
/// ([`agent_run_handover_due`]).
pub(super) fn take_due_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    body: &AgentRunTaskBody,
    home: bool,
    here: Option<EntityId>,
    now: u64,
) -> Result<bool> {
    let lease = body.executor;
    let Some(placement) = body.placement.as_ref().filter(|p| p.orders(lease)) else {
        return Ok(agent_run_handover_due(lease, home, now));
    };
    let taker = if here == Some(placement.machine) {
        PlacedTaker::Placed
    } else if home {
        PlacedTaker::Home
    } else {
        PlacedTaker::Other
    };
    let place_grace = place_grace_secs_in_txn(vault, txn, body.project())?;
    Ok(now >= placed_take_due(lease, taker, place_grace, AGENT_RUN_HANDOVER_GRACE_SECS))
}

/// Whether the vault's elected home node is a cloud node other than this
/// machine (`node_id`), read in `txn` (FIX 4747 slice 7). Engine call
/// (CALLS, FIX 4747): the committed MACRO home designation the handover's
/// ruled order reads ([`elected_home_here_in`]) names the node;
/// the host's home candidacy says whether it is a cloud node, by its
/// `cloud` flag. A candidacy that lists no row for that node falls back to
/// the designation's own election class (`CloudAttached`). No designation
/// places nothing.
pub(super) fn cloud_home_elsewhere_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    node_id: u64,
) -> Result<bool> {
    let store = DreamerRunnerStore::new(vault);
    let Some(home) = store.home_node_designation_in_txn(txn)? else {
        return Ok(false);
    };
    if home.node_id == node_id {
        return Ok(false);
    }
    let listed = store.home_candidates_in_txn(txn)?.and_then(|candidates| {
        candidates
            .into_iter()
            .find(|candidate| candidate.node_id == home.node_id)
    });
    Ok(match listed {
        Some(candidate) => candidate.cloud,
        None => home.class == DreamerHomeNodeClass::CloudAttached,
    })
}

/// Whether this machine's claim at `now` leaves its own expired lease on
/// the run TASK `body` for another machine: while the run is placed on
/// another machine, until this machine's turn in the placement's order
/// (the home's, or any other machine's); while the vault's home is a cloud
/// node elsewhere (FIX 4747 slice 7), for the placement grace past the
/// lease's release. After that it takes its own lease again at its claim,
/// as before, so a machine that cannot run the run never strands it.
pub(super) fn leaves_own_lease_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    body: &AgentRunTaskBody,
    node_id: u64,
    now: u64,
) -> Result<bool> {
    let lease = body.executor;
    let place_grace = place_grace_secs_in_txn(vault, txn, body.project())?;
    if let Some(placement) = body.placement.as_ref().filter(|p| p.orders(lease)) {
        if crate::identity::read_machine_id_in_txn(vault, txn)? == Some(placement.machine) {
            return Ok(false);
        }
        let taker = if elected_home_here_in(vault, txn, node_id)? {
            PlacedTaker::Home
        } else {
            PlacedTaker::Other
        };
        let due = placed_take_due(lease, taker, place_grace, AGENT_RUN_HANDOVER_GRACE_SECS);
        return Ok(now < due);
    }
    Ok(cloud_home_elsewhere_in(vault, txn, node_id)?
        && now < lease.held_until.saturating_add(place_grace))
}

/// One machine the run may be placed on, with the facts the rule reads.
#[derive(Clone, Debug)]
struct Candidate {
    machine: EntityId,
    home: bool,
    /// The GPUs its last capacity record names.
    gpus: usize,
    /// The agents it can run less the open runs it holds or is placed for;
    /// `None` with no capacity record.
    room: Option<u64>,
    /// The open runs it holds or is placed for.
    open_runs: u64,
    /// What keeps it out; empty when it fits.
    blockers: Vec<Blocker>,
}

impl Candidate {
    /// The rule's order: fewest GPUs, most room (a known room first), the
    /// home, the lowest machine id.
    fn rank_key(&self) -> (usize, bool, Reverse<u64>, bool, EntityId) {
        (
            self.gpus,
            self.room.is_none(),
            Reverse(self.room.unwrap_or(0)),
            !self.home,
            self.machine,
        )
    }

    fn fact(&self) -> Value {
        json!({
            "machine": self.machine.to_hex(),
            "home": self.home,
            "gpus": self.gpus,
            "room": self.room,
            "open_runs": self.open_runs,
        })
    }
}

/// Why the rule put `first` ahead of `second`, in one phrase (DESIGN 4.3).
fn rule_why(first: &Candidate, second: Option<&Candidate>) -> &'static str {
    let Some(second) = second else {
        return "the only machine that fits";
    };
    if first.gpus != second.gpus {
        "keeps GPU machines free"
    } else if first.room != second.room {
        "most room"
    } else if first.home != second.home {
        "the home"
    } else {
        "tie"
    }
}

/// A run its first claim places, as one snapshot read it.
struct Placing {
    task_ref: EntityId,
    lease: AgentRunExecutorLease,
    here: Option<EntityId>,
    project: Option<EntityId>,
    /// The fitting candidates in the rule's order, at most
    /// [`PLACE_OPTIONS_MAX`].
    ranked: Vec<Candidate>,
    agent: String,
    world: Option<String>,
}

/// The run of the try `id` when this is its first claim here and the vault
/// has a machine tagged [`AGENTS_ROLE`], with its fitting candidates; `None`
/// leaves the run where it was dispatched.
fn placing_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
    node_id: u64,
    now: u64,
) -> Result<Option<Placing>> {
    let Some(row) = AttemptQueue::new(vault).get_in_txn(txn, id)? else {
        return Ok(None);
    };
    if !unclaimed_try(&row) {
        return Ok(None);
    }
    let Some(link) = agent_run_task_ref_in(vault, txn, &row)? else {
        return Ok(None);
    };
    if link.child {
        return Ok(None);
    }
    let Some(body) = agent_run_task_body_in(vault, txn, link.task_ref)? else {
        return Ok(None);
    };
    let lease = body.executor;
    let first_claim = body.placement.is_none()
        && body.outcome.is_none()
        && lease.node_id == node_id
        && lease.generation == AGENT_RUN_LEASE_FIRST_GENERATION
        && !lease.expired_at(now)
        && body.live_attempt_ref == body.attempt_ref
        && body.attempt_ref == bytes_to_hex_lower(id.as_bytes());
    if !first_claim {
        return Ok(None);
    }
    let home_node = DreamerRunnerStore::new(vault)
        .home_node_designation_in_txn(txn)?
        .map(|home| home.node_id);
    let mut machines = Vec::new();
    let mut tagged = false;
    for (machine, candidacy) in home_candidacies_by_machine_in_txn(vault, txn)? {
        if !(candidacy.stands && candidacy.owner_machine) {
            continue;
        }
        let policy = machine_policy_in_txn(vault, txn, machine, &[], &[])?;
        let has_role = policy.work_roles.0.contains(AGENTS_ROLE);
        let home = home_node == Some(candidacy.node_id);
        tagged |= has_role;
        if has_role || home {
            machines.push((machine, candidacy.node_id, home, policy));
        }
    }
    if !tagged {
        return Ok(None);
    }
    let mut open = BTreeMap::<EntityId, u64>::new();
    for (_, run) in open_agent_runs_in(vault, txn)? {
        let holder = machines
            .iter()
            .find(|(_, node, ..)| *node == run.executor.node_id)
            .map(|(machine, ..)| *machine);
        let placed = run
            .placement
            .as_ref()
            .filter(|placement| placement.orders(run.executor))
            .map(|placement| placement.machine);
        if let Some(machine) = placed.or(holder) {
            *open.entry(machine).or_default() += 1;
        }
    }
    let world = body
        .world_ref
        .as_deref()
        .and_then(|world| EntityId::from_hex(world).ok());
    let now_ms = now.saturating_mul(1_000);
    let mut fitting = Vec::new();
    for (machine, _, home, policy) in machines {
        let capacity = machine_capacity_in_txn(vault, txn, machine)?;
        let open_runs = open.get(&machine).copied().unwrap_or(0);
        let mut blockers = new_work_blockers(&policy, capacity.as_ref(), now_ms);
        if let Some(world) = world
            && !world_readable_on(vault, txn, world, machine)
        {
            blockers.push(Blocker::WorldNotResident);
        }
        let candidate = Candidate {
            machine,
            home,
            gpus: capacity.as_ref().map_or(0, |capacity| capacity.gpus.len()),
            room: capacity
                .as_ref()
                .map(|capacity: &MachineCapacity| capacity.agents.saturating_sub(open_runs)),
            open_runs,
            blockers,
        };
        if candidate.blockers.is_empty() {
            fitting.push(candidate);
        }
    }
    if fitting.is_empty() {
        return Ok(None);
    }
    fitting.sort_by_key(Candidate::rank_key);
    fitting.truncate(PLACE_OPTIONS_MAX);
    Ok(Some(Placing {
        task_ref: link.task_ref,
        lease,
        here: crate::identity::read_machine_id_in_txn(vault, txn)?,
        project: body.project(),
        ranked: fitting,
        agent: body.agent_definition_ref.clone(),
        world: body.world_ref.clone(),
    }))
}

/// Whether the queue row `row` is a try no claim has taken yet: queued or
/// scheduled, at its first attempt (a claim advances `attempt_count`). Only
/// such a try is placed, so a run that already ran a step, whose resumed
/// try is queued again as the same try, is never moved.
fn unclaimed_try(row: &AttemptRecord) -> bool {
    matches!(row.state, AttemptState::Queued | AttemptState::Scheduled) && row.attempt_count == 0
}

/// What keeps a machine from new work at `now_ms` (unix milliseconds) under
/// its `policy` and its last `capacity` record: paused or draining
/// (`machines.execution`), outside its window, or on battery in a
/// mains-only window (`machines.windows`).
fn new_work_blockers(
    policy: &MachinePolicy,
    capacity: Option<&MachineCapacity>,
    now_ms: u64,
) -> Vec<Blocker> {
    let mut blockers = Vec::new();
    match policy.execution.state {
        ExecutionState::On => {}
        ExecutionState::Paused => blockers.push(Blocker::Paused {
            why: "machines.execution".to_owned(),
        }),
        ExecutionState::Draining => blockers.push(Blocker::Drained {
            why: "machines.execution".to_owned(),
        }),
    }
    let on_battery = capacity.is_some_and(|capacity| capacity.power == MachinePower::Battery);
    if !policy.windows.covers(now_ms) || (policy.windows.mains_only && on_battery) {
        blockers.push(Blocker::OutsideWindow { opens_ms: None });
    }
    blockers
}

/// Whether `machine` takes new work at `now` (unix seconds), read in `txn`
/// as the placement's limits read a candidate ([`new_work_blockers`]): the
/// placed machine's own check when its turn comes, since the owner may have
/// paused it, or its window closed, after the placement.
///
/// # Errors
/// Storage errors.
pub(super) fn takes_new_work_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    machine: EntityId,
    now: u64,
) -> Result<bool> {
    let policy = machine_policy_in_txn(vault, txn, machine, &[], &[])?;
    let capacity = machine_capacity_in_txn(vault, txn, machine)?;
    Ok(new_work_blockers(&policy, capacity.as_ref(), now.saturating_mul(1_000)).is_empty())
}

/// Whether `world` may be read on `machine` under its world privacy, as the
/// reaper judges it for itself (`run_handover::world_readable_here_in`); a
/// fold that cannot judge reads as no.
fn world_readable_on(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    world: EntityId,
    machine: EntityId,
) -> bool {
    crate::authority::world_readable_on_machine_in(vault, txn, world, Destination::Machine(machine))
        .unwrap_or(false)
}

impl AgentDispatcher<'_> {
    /// Places the run of the try `id` at its first claim here (row P4): the
    /// rule's pick among the fitting candidates, or the PLACE decider's
    /// among the rule's first [`PLACE_OPTIONS_MAX`], asked through `asks`
    /// outside every transaction. One write, stamped after the ask, keeps
    /// the placement on the run TASK and, for another machine, releases the
    /// lease, while the TASK still holds the lease the read saw and no claim
    /// has taken the try. Nothing is placed for a child, a retry, a try a
    /// claim already took (a resumed one included), a run already placed or
    /// taken, or a vault with no machine tagged [`AGENTS_ROLE`].
    ///
    /// # Errors
    /// Storage errors.
    pub(super) fn place_agent_run(
        &self,
        id: AttemptId,
        now: u64,
        asks: &PassAsks<'_>,
    ) -> Result<()> {
        let node_id = crate::identity::load_or_mint_client_id(self.vault)?;
        let placing = {
            let txn = self.vault.store.env.read_txn()?;
            placing_in(self.vault, &txn, id, node_id, now)?
        };
        let Some(placing) = placing else {
            return Ok(());
        };
        let Some(first) = placing.ranked.first() else {
            return Ok(());
        };
        let options: Vec<String> = placing
            .ranked
            .iter()
            .map(|candidate| candidate.machine.to_hex())
            .collect();
        let rule = SlotDecision {
            slot: SlotName::Place,
            options: options.clone(),
            pick: first.machine.to_hex(),
            by: DecidedBy::Rule {
                name: PLACE_RULE.to_owned(),
            },
            why: rule_why(first, placing.ranked.get(1)).to_owned(),
        };
        let rule_pick = rule_fact(&rule);
        let facts = || {
            json!({
                "rule": PLACE_RULE,
                "run": { "agent": placing.agent, "world": placing.world },
                "candidates": placing.ranked.iter().map(Candidate::fact).collect::<Vec<_>>(),
                "rule_pick": rule_pick,
            })
        };
        let question = SlotQuestion {
            slot: SlotName::Place,
            subject: SlotSubject::NativeRun,
            scope: SlotScope::Project(placing.project),
            options,
            facts: Box::new(facts),
        };
        let decision = self.vault.decide_slot(asks, question, rule)?;
        let Ok(machine) = EntityId::from_hex(&decision.pick) else {
            return Ok(());
        };
        let elsewhere = placing.here != Some(machine);
        // The clock is read after the ask: the release and the record carry
        // the time of this write, so the time the decider took is not taken
        // from the takers' graces.
        let placed_at = self.vault.now_recorded_at().max(now);
        let released = self.vault.with_write_txn_grouped(|wtxn| {
            // A claim that took the try since the read keeps the run.
            let unclaimed = AttemptQueue::new(self.vault)
                .get_in_txn(&*wtxn, id)?
                .is_some_and(|row| unclaimed_try(&row));
            if !unclaimed {
                return Ok(false);
            }
            let mut released = false;
            update_agent_run_task_body_in_txn(
                self.vault,
                wtxn,
                placing.task_ref,
                placed_at,
                |body| {
                    if body.placement.is_some()
                        || body.outcome.is_some()
                        || body.executor != placing.lease
                    {
                        return Ok(());
                    }
                    if elsewhere {
                        body.executor.held_until = placed_at;
                    }
                    body.placement = Some(RunPlacement {
                        machine,
                        lease_generation: body.executor.generation,
                        released: elsewhere,
                        at: placed_at,
                        decision,
                    });
                    released = elsewhere;
                    Ok(())
                },
            )?;
            Ok(released)
        })?;
        if released {
            tracing::info!(
                task = %placing.task_ref.to_hex(),
                machine = %machine.to_hex(),
                "an agent run was placed on another machine at its first claim"
            );
            self.vault.store.notify_attempt_observers();
        }
        Ok(())
    }
}

/// The machine the run of the try `attempt` was placed on and the PLACE
/// decision, as its run TASK keeps them; `None` when it was not placed (the
/// test door's read).
///
/// # Errors
/// Storage errors.
pub(crate) fn run_placement_of(vault: &Vault, attempt: AttemptId) -> Result<Option<RunPlacement>> {
    let txn = vault.store.env.read_txn()?;
    let task_ref = super::run_task::agent_run_task_id(attempt)?;
    Ok(agent_run_task_body_in(vault, &txn, task_ref)?.and_then(|body| body.placement))
}
