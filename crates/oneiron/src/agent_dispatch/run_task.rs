//! The agent-run TASK (FIX 4747 slice 5; canon CROSS-ARCH-0019 "Where work
//! runs", items 02-05): the synced, portable record of one agent run, and
//! the executor lease that says which machine runs it.
//!
//! The dispatch that enqueues an agent run mints, in its own write, one TASK
//! of subkind [`AGENT_RUN_TASK_SUBKIND`] under an id derived from the run's
//! attempt id. It freezes the exact queue payload bytes, so another machine
//! can re-create the identical queue row and model request bytes (slice 6),
//! and holds an [`AgentRunExecutorLease`] for this machine. The agent pump's
//! claim takes or renews that lease in its write; the claim's
//! [`AgentRunFence`] guards every step commit and outbound effect of the
//! run, and every write that settles it: the result it publishes, the report
//! on the TASK it realizes, and the terminal door, which sets the run TASK's
//! outcome in the same write. A write that meets a moved or unreadable run
//! TASK aborts, and the try ends unrun. A closing process releases the
//! leases it holds, and takes and renews none after
//! (`Vault::executor_leases_released`).
//!
//! A run tree moves with its root (REVIEW-6638): only a root run, a dispatch
//! with no parent attempt, gets a run TASK at its dispatch. A child the run
//! spawns, at any depth, runs under its nearest ancestor's: its claim walks
//! `parent_attempt` up to that run TASK and runs it only while this machine
//! holds that lease, under a fence at its generation, and takes, renews and
//! settles nothing on it. When the root moves, every child on the old
//! machine stands down at that fence, and the root, rerun on the machine
//! that took it, spawns its children there.
//!
//! A child that outlives its root becomes a root of its own (REVIEW-6638).
//! The write that settles a run TASK mints one, flagged `outlived_root`, for
//! each child of the run still pending in this queue with no pending try
//! above it, as a root's dispatch mints its own: its frozen payload keeps
//! its parent's identity. From then on it takes, renews and settles its own
//! lease, its own children follow it, and the reaper hands it over as a
//! root; the machine that takes it holds no row of its settled parent and
//! runs it without one (`super::agent_run`). Its context there resolves
//! under the bound that parent handed it, frozen into its run TASK at its
//! promotion ([`FrozenContextBound`]), so it never widens past what it saw
//! here.
//!
//! On one machine the lease is always its own, so nothing new refuses: a
//! run with no run TASK (dispatched before this change) runs as before. A
//! run whose run TASK stands but does not read is not one with none: it does
//! not run here.
//! A hard erase that takes an erased actor's text out of a run's queue
//! payload takes its run TASK, which froze a copy, in the same transaction
//! (`erase_agent_run_tasks_in_txn`, REVIEW-6615). The run then has none: it
//! stays on this machine and runs as before.
//! The handover to another machine, the reaper and the re-creation of the
//! queue row there, is `super::run_handover` (slice 6).
//! Entry: `mint_agent_run_task_in_txn`, `take_agent_run_lease_in_txn`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::PoisonError;

use serde::{Deserialize, Serialize};

use super::{AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchInput, AgentDispatcher};
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::context_projection::ResolvedContextProjection;
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::entity_id::derived_domains::AGENT_RUN_TASK;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, RecordError, Result};
use crate::federation::record_scope::{BirthPosition, stamp_task_birth};
use crate::ports::{DeletionMarker, EntityStoreRead, TombstoneStoreRead};
use crate::registry::ENTITY_TYPE_TASK;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::write_envelope::task_body::TaskRole;

/// TASK-body subkind for the portable record of one agent run (FIX 4747).
pub const AGENT_RUN_TASK_SUBKIND: &str = "agent_run";

const AGENT_RUN_TASK_SCHEMA_VERSION: u8 = 0;

/// The generation an agent run's executor lease starts at, when its
/// dispatch mints the run TASK. Engine call (CALLS, FIX 4747).
pub(crate) const AGENT_RUN_LEASE_FIRST_GENERATION: u64 = 1;

/// How long an agent run's executor lease holds past the pass that last
/// renewed it: its claim, each terminal step commit, and each park or
/// resume of its attempt. Engine call (CALLS, FIX 4747): fifteen minutes,
/// the send executor's hold, so a machine that vanished without its release
/// lets its runs go within one hold, while a run that commits a step at
/// least once a half hold keeps its lease.
pub(crate) const AGENT_RUN_LEASE_HOLD_SECS: u64 = 15 * 60;

/// How many links a claim or a settlement follows back to find the run TASK
/// a try runs under: each `retry_of` link from a retry, a landing successor,
/// an owner's continuation or a try a handover queued here to the try its
/// run TASK was minted under, and each `parent_attempt` link from a spawned
/// child up to its nearest ancestor with one (REVIEW-6638), all within this
/// one bound. Engine call (CALLS, FIX 4747): past it, or past a try this
/// queue does not hold whose own id names no run TASK, the row has no run
/// TASK and runs as before.
const AGENT_RUN_RETRY_CHAIN_WALK: usize = 64;

/// The typed cause a local try ends with when its run TASK names another
/// machine as the run's executor (FIX 4747): that machine runs it.
pub(crate) const AGENT_RUN_EXECUTOR_MOVED: &str = "agent_run_executor_moved";

/// The typed cause a local try ends with when another machine already
/// settled its run (FIX 4747): this machine's row is stale.
pub(crate) const AGENT_RUN_SETTLED_ELSEWHERE: &str = "agent_run_settled_elsewhere";

/// The typed cause a local try ends with when an entity stands under its run
/// TASK's id that this version does not read as an agent-run TASK body (FIX
/// 4747): a body of another version or subkind, or no TASK. Another machine
/// may run it, so this machine does not run it unfenced.
pub(crate) const AGENT_RUN_TASK_UNREADABLE: &str = "agent_run_task_unreadable";

/// Every typed cause a local try ends with unrun, its run TASK unchanged.
const AGENT_RUN_UNRUN_CAUSES: [&str; 3] = [
    AGENT_RUN_EXECUTOR_MOVED,
    AGENT_RUN_SETTLED_ELSEWHERE,
    AGENT_RUN_TASK_UNREADABLE,
];

/// The receipt field an outbound effect the run fence stood down carries,
/// valued [`AGENT_RUN_STOOD_DOWN`] (FIX 4747).
pub(crate) const AGENT_RUN_FENCE_FIELD: &str = "agent_run_fence";

/// The value of [`AGENT_RUN_FENCE_FIELD`], and the refusal a connector call
/// the fence stopped names.
pub(crate) const AGENT_RUN_STOOD_DOWN: &str = "agent_run_stood_down";

/// The executor of one agent run (FIX 4747; canon CROSS-ARCH-0019 item 03):
/// only the machine `node_id` names runs it, and only while the run TASK
/// still holds this holder at this `generation`. The holder renews
/// `held_until` while the run is its; a lease no pass renewed, or one its
/// holder released as it closed, is expired from `held_until` on, and the
/// reaper (`super::run_handover`) may hand it over at the next generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentRunExecutorLease {
    /// The holder's stable sync node id (`m:client_id`).
    pub node_id: u64,
    /// Raised by one on every handover and on every retake of an expired
    /// lease at a claim.
    pub generation: u64,
    /// Until when the holder holds it, vault clock seconds: expired at and
    /// after this instant.
    pub held_until: u64,
}

impl AgentRunExecutorLease {
    /// Whether `other` names this lease's holder at this generation,
    /// whatever either's `held_until`.
    #[must_use]
    pub fn same_holding(self, other: Self) -> bool {
        self.node_id == other.node_id && self.generation == other.generation
    }

    /// Whether the lease is expired at `now`.
    #[must_use]
    pub fn expired_at(self, now: u64) -> bool {
        now >= self.held_until
    }
}

/// How an agent run ended, as its TASK records it for every machine (FIX
/// 4747). `None` on the TASK while the run is live.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRunOutcome {
    Completed,
    Failed,
    Cancelled,
}

/// The lease one claim of an agent run took (FIX 4747): the run TASK, this
/// machine, and the generation it holds. The run's step commits and its
/// outbound effects go only while the TASK still names this holder at this
/// generation. In memory only, never persisted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentRunFence {
    pub task_ref: EntityId,
    pub node_id: u64,
    pub generation: u64,
    /// The try the claim fenced.
    pub attempt: AttemptId,
    /// A spawned child's fence on its nearest ancestor's run TASK
    /// (REVIEW-6638): it holds that lease at the generation the child's
    /// claim read, and renews nothing; only that run's own claim, steps,
    /// park and resume, and the reaper's pass renew it. Once that run
    /// settles here, the fence follows the run TASK its settlement minted
    /// for the child's tree, read through `attempt`
    /// (`outlived_root_standing_in`).
    pub child: bool,
}

impl AgentRunFence {
    /// Whether `lease` is the holding this fence took; a renewal or a
    /// release since keeps it.
    #[must_use]
    pub fn holds(self, lease: AgentRunExecutorLease) -> bool {
        lease.node_id == self.node_id && lease.generation == self.generation
    }
}

/// What taking an agent run's executor lease at its claim came to (FIX
/// 4747).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AgentRunLeaseTake {
    /// No entity stands under the run TASK id of the row, of any try it
    /// retries, or of its root: it runs as before, unfenced.
    NoRunTask,
    /// This machine holds the lease (for a spawned child, its root's); the
    /// run goes under this fence.
    Taken(AgentRunFence),
    /// Another machine holds the lease: this machine does not run it.
    HeldElsewhere,
    /// Another machine settled the run: the local row is stale.
    Settled,
    /// An entity stands under the run TASK id that this version does not
    /// read as an agent-run TASK body: this machine does not run it.
    Unreadable,
    /// This process released its leases as it closes: it claims nothing,
    /// and the row stays queued for the next process or machine.
    Closing,
}

/// What the run TASK says of a claim by this machine (FIX 4747).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClaimStanding {
    /// The run is this machine's to run, under the lease the TASK holds.
    Own(AgentRunExecutorLease),
    /// Another machine holds the run.
    HeldElsewhere,
    /// Another machine settled the run.
    Settled,
    /// The run TASK does not read.
    Unreadable,
}

/// What a writer read of the run TASK a fence names (FIX 4747).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FenceStanding {
    /// The TASK still names the fence's holder at its generation.
    Holds(AgentRunExecutorLease),
    /// The TASK names another holder or generation.
    Moved(AgentRunExecutorLease),
    /// No run TASK stands under the fence's id: the run goes on as before.
    Absent,
}

/// The synced body of an agent-run TASK (FIX 4747), MessagePack like the
/// connector-send TASK body. It is one value of its window's `entities` map,
/// so a concurrent write from two machines resolves by whole-row LWW; a
/// raised generation is always a read-modify-write of the lease it replaces.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct AgentRunTaskBody {
    role: u8,
    schema_version: u8,
    subkind: String,
    /// The run's original attempt id, hex: the try its dispatch enqueued.
    pub(super) attempt_ref: String,
    /// The try that last took the lease, hex: the original, or a retry or
    /// successor of it. A handover re-creates the queue row under this id
    /// (`super::run_handover`), so the memo keys of its finished steps match.
    pub(super) live_attempt_ref: String,
    pub(super) run_id: Option<String>,
    /// The TASK the dispatch realizes, when it realizes one.
    pub(super) realized_task_ref: Option<String>,
    agent_definition_ref: String,
    /// The caller whose request queued the run; `None` for the host's own
    /// work.
    requester_ref: Option<String>,
    /// The queue dedupe key the row was enqueued under.
    pub(super) dedupe_key: Option<String>,
    /// The exact dreamer payload bytes the queue row stores: what another
    /// machine re-creates the row and its model request from.
    #[serde(with = "queue_payload_bytes")]
    pub(super) queue_payload: Vec<u8>,
    /// The world the dispatch's scope names, as its TASK's birth stamp
    /// places it; `None` for base reality.
    pub(super) world_ref: Option<String>,
    project_ref: Option<String>,
    pub(super) executor: AgentRunExecutorLease,
    pub(super) outcome: Option<AgentRunOutcome>,
    /// The run is a spawned child that outlived its root (REVIEW-6638): the
    /// settlement of the run it ran under minted this TASK, and its frozen
    /// payload names the parent that settled. A machine that takes it holds
    /// no row of that parent, and runs it as a root of its own.
    outlived_root: bool,
    /// The context bound the settled parent of a run that outlived its root
    /// handed it, frozen at its promotion ([`FrozenContextBound`]); `None`
    /// when that parent resolved no projection, and for every other run.
    parent_context: Option<FrozenContextBound>,
    pub(super) created_at: u64,
}

/// The context bound a spawned child that outlived its root (REVIEW-6638)
/// had from its settled parent, frozen into its run TASK at its promotion,
/// where the whole ancestor chain is present: that parent's projection as a
/// child of it resolves under it, its layers and its memory and chat
/// section refs (`"<domain>:cl_<hex>"`, `"tn_<hex>"`), never a row's body.
///
/// Engine call (CALLS, FIX 4747): a machine that took the child over holds
/// no row of that parent, so its context walk ends at the child
/// (`super::context`); it resolves the child under this bound, so a
/// `Default` there inherits what it inherited here and never widens to a
/// fresh scan. The sections are those the parent's projection kept, after
/// the cut of any member lane or binder above it, not the bound before that
/// cut: that machine's walk crosses no wrapper above the child, so the cut
/// rides in the sections.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct FrozenContextBound {
    layers: Vec<String>,
    memory_sections: Vec<String>,
    chat_sections: Vec<String>,
}

impl FrozenContextBound {
    /// The bound `projection` hands a child that resolves under it.
    fn of(projection: ResolvedContextProjection) -> Self {
        Self {
            layers: projection.layers,
            memory_sections: projection.memory_sections,
            chat_sections: projection.chat_sections,
        }
    }
}

impl AgentRunTaskBody {
    /// The parent projection this run resolves its context under where the
    /// row of its settled parent is absent (REVIEW-6638): the bound frozen at
    /// its promotion, rebuilt by
    /// [`ResolvedContextProjection::from_frozen_bound`]. `None` when its
    /// parent resolved no projection, as the run then resolved under none on
    /// the machine it left too, and for a run that did not outlive its root.
    pub(super) fn into_frozen_parent_projection(self) -> Option<ResolvedContextProjection> {
        self.parent_context.map(|bound| {
            ResolvedContextProjection::from_frozen_bound(
                bound.layers,
                bound.memory_sections,
                bound.chat_sections,
            )
        })
    }
}

/// The frozen queue payload as one MessagePack bin, not an array of
/// integers.
mod queue_payload_bytes {
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], out: S) -> Result<S::Ok, S::Error> {
        out.serialize_bytes(bytes)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(input: D) -> Result<Vec<u8>, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Vec<u8>, E> {
                Ok(bytes.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, bytes: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(bytes)
            }
        }
        input.deserialize_bytes(Visitor)
    }
}

/// The run TASK id of the agent run whose dispatch enqueued `attempt`.
pub(crate) fn agent_run_task_id(attempt: AttemptId) -> Result<EntityId> {
    EntityId::derive(AGENT_RUN_TASK, &[attempt.as_bytes().as_slice()])
}

/// The `held_until` a lease taken or renewed at `now` holds to.
pub(super) fn agent_run_lease_held_until(now: u64) -> u64 {
    now.saturating_add(AGENT_RUN_LEASE_HOLD_SECS)
}

/// The `held_until` a renewal at `now` leaves on a lease held until
/// `held_until`, or `None` while the lease covers the pass. Engine call
/// (CALLS, FIX 4747): it renews once less than half a hold is left, so a run
/// writes its TASK at most once a half hold.
pub(super) fn agent_run_lease_renewal(held_until: u64, now: u64) -> Option<u64> {
    let renew_below = now.saturating_add(AGENT_RUN_LEASE_HOLD_SECS / 2);
    (held_until < renew_below).then(|| agent_run_lease_held_until(now))
}

/// This machine's own lease as its claim comes back to it at `now`: an
/// expired one is taken again at the next generation, as
/// `own_expired_send_executor_lease_retaken` takes a send's, since another
/// machine may have taken the run while this one was away and sync may not
/// show it yet; the new generation stands that machine's executor down once
/// copies agree. `None` for a lease still held. Engine call (CALLS, FIX
/// 4747).
fn own_expired_agent_run_lease_retaken(
    lease: AgentRunExecutorLease,
    now: u64,
) -> Option<AgentRunExecutorLease> {
    lease.expired_at(now).then(|| AgentRunExecutorLease {
        node_id: lease.node_id,
        generation: lease.generation.saturating_add(1),
        held_until: agent_run_lease_held_until(now),
    })
}

/// What the run TASK `body` says of a claim by this machine (`node_id`).
/// Engine call (CALLS, FIX 4747): a run another machine settled is stale
/// here; a run this machine settled whose later try is queued here (a
/// retry, a landing successor, or the owner's continuation of a failed try)
/// is this machine's own and reopens, as it ran before the lease; any run
/// another machine holds, expired or not, is that machine's until the
/// reaper (`super::run_handover`) hands it over.
fn claim_standing(body: &AgentRunTaskBody, node_id: u64) -> ClaimStanding {
    match (body.executor.node_id == node_id, body.outcome) {
        (true, _) => ClaimStanding::Own(body.executor),
        (false, Some(_)) => ClaimStanding::Settled,
        (false, None) => ClaimStanding::HeldElsewhere,
    }
}

/// [`claim_standing`] of the run TASK `task_ref`, which stands in `txn`
/// (FIX 4747). Engine call (CALLS): a body this version cannot read (another
/// version, another subkind, or no TASK) is logged and stands the claim
/// down, as a run another machine holds does: it is never read as no run
/// TASK, which would run it unfenced.
fn claim_standing_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task_ref: EntityId,
    node_id: u64,
) -> Result<ClaimStanding> {
    match agent_run_task_body_in(vault, txn, task_ref) {
        Ok(Some(body)) => Ok(claim_standing(&body, node_id)),
        // `task_ref` names an entity this read found standing.
        Ok(None) | Err(Error::Record(_)) => {
            tracing::warn!(
                reason = AGENT_RUN_TASK_UNREADABLE,
                task = %task_ref.to_hex(),
                "an agent run's TASK does not read; this machine does not run it"
            );
            Ok(ClaimStanding::Unreadable)
        }
        Err(error) => Err(error),
    }
}

/// Whether this process released its executor leases as it closes.
pub(super) fn closing(vault: &Vault) -> bool {
    vault
        .executor_leases_released
        .load(std::sync::atomic::Ordering::SeqCst)
}

/// Mints the run TASK of the agent run whose dispatch just enqueued
/// `attempt`, in the dispatch's write (FIX 4747): the frozen queue payload
/// the row stores, the run's refs, its world and project, and this machine's
/// lease at the first generation. A closing process mints it released
/// (`held_until` now). The TASK is born at the dispatch scope's world and
/// facet, as `tasks.create` stamps a narrowed writer's TASKs.
///
/// Only a root run gets one at its dispatch (REVIEW-6638): a dispatch with a
/// parent attempt, a child its run spawned, mints none. The child runs under
/// its root's run TASK and moves with it: the root, rerun on the machine
/// that takes it, spawns its children there. A child that outlives its root
/// gets one of its own when the root settles
/// ([`settle_agent_run_task_in_txn`]), and becomes a root.
///
/// It never fails the dispatch it rides. Engine call (CALLS, FIX 4747): the
/// mint runs in a savepoint, and one the batch refuses (the secret scan
/// refuses a payload that carries a credential-shaped text) or that fails
/// leaves the run with no run TASK, so it stays on this machine and runs as
/// before. A row whose run TASK already stands mints nothing.
pub(super) fn mint_agent_run_task_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    input: &AgentDispatchInput,
    now: u64,
) -> Result<()> {
    let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
    let record = AttemptQueue::new(vault).get_in_txn(&savepoint, attempt);
    let minted = match record {
        // Only a root run gets a run TASK at its dispatch (REVIEW-6638): a
        // spawned child runs under its root's (`agent_run_task_ref_in`).
        Ok(Some(record)) if spawning_parent(&record.payload).is_none() => {
            put_agent_run_task_in_txn(vault, &mut savepoint, &record, input, false, now)
        }
        Ok(_) => Ok(false),
        Err(error) => Err(error),
    };
    commit_minted_agent_run_task(savepoint, attempt, minted)
}

/// Commits the savepoint a run TASK's mint for the try `attempt` wrote in,
/// when it `minted` one; a mint that failed is logged and leaves the run with
/// no run TASK of its own (FIX 4747).
fn commit_minted_agent_run_task(
    savepoint: heed::RwTxn<'_>,
    attempt: AttemptId,
    minted: Result<bool>,
) -> Result<()> {
    match minted {
        Ok(true) => savepoint.commit()?,
        Ok(false) => {}
        Err(error) => tracing::warn!(
            attempt = %bytes_to_hex_lower(attempt.as_bytes()),
            kind = ?error.kind(),
            "an agent run's TASK was not minted; the run stays on this machine"
        ),
    }
    Ok(())
}

/// The write that mints the run TASK of the try `record` under its own id,
/// from `input`, the dispatch input its payload freezes: `false` when that
/// run TASK already stands or the run is not one to mint for. A root's
/// dispatch mints it; a root's settlement mints it for a child that outlived
/// that root, `outlived_root` (REVIEW-6638). Both pass the same gates.
fn put_agent_run_task_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
    input: &AgentDispatchInput,
    outlived_root: bool,
    now: u64,
) -> Result<bool> {
    let attempt = record.id;
    let task_ref = agent_run_task_id(attempt)?;
    if vault.get_entity_type_in_txn(&*wtxn, &task_ref)?.is_some() {
        return Ok(false);
    }
    // Only a run whose claim takes the lease gets a run TASK: a workflow
    // leaf and a resident's TASK-root run keep their pumps' path, and their
    // leases would never be renewed.
    if !super::agent_run::agent_pump_claims_in(vault, &*wtxn, record)? {
        return Ok(false);
    }
    let world = input.scope.as_ref().and_then(|scope| scope.world);
    // TASKs ride the shared base window to every machine, whatever their
    // world stamp, so a run whose world keeps its text on this device gets
    // no run TASK and stays here: a run moves only within world privacy
    // (cross-arch-0019 item 05). Engine call (CALLS, FIX 4747): the model
    // call's off-device verdict for the run's world; a run that names no
    // world may carry any world's text, so it goes only while no world stays
    // on this device.
    if vault
        .model_call_hold_in_txn(
            &*wtxn,
            world,
            &crate::settings::CallerLocality::OffDevice.into(),
        )?
        .is_some()
    {
        return Ok(false);
    }
    // A child that outlived its root takes the bound its settled parent
    // hands it, frozen here, where that parent's row and its whole ancestor
    // chain are present (REVIEW-6638; engine call, CALLS, FIX 4747).
    let parent_context = if outlived_root {
        frozen_parent_context_in(vault, &*wtxn, record)?
    } else {
        None
    };
    let node_id = crate::identity::load_or_mint_client_id_in_txn(vault, wtxn)?;
    let facet = input.scope.as_ref().and_then(|scope| scope.facet);
    let held_until = if closing(vault) {
        now
    } else {
        agent_run_lease_held_until(now)
    };
    let body = AgentRunTaskBody {
        role: TaskRole::Task.role_byte(),
        schema_version: AGENT_RUN_TASK_SCHEMA_VERSION,
        subkind: AGENT_RUN_TASK_SUBKIND.to_owned(),
        attempt_ref: bytes_to_hex_lower(attempt.as_bytes()),
        live_attempt_ref: bytes_to_hex_lower(attempt.as_bytes()),
        run_id: record.run_id.clone(),
        realized_task_ref: record.task_ref.clone(),
        agent_definition_ref: input.target.agent_definition_ref()?.to_hex(),
        requester_ref: input
            .requester
            .as_ref()
            .map(|requester| requester.actor.to_hex()),
        dedupe_key: record.dedupe_key.clone(),
        queue_payload: record.payload.clone(),
        world_ref: world
            .filter(|world| *world != crate::claim::base_world_id())
            .map(|world| world.to_hex()),
        project_ref: input.project_ref.map(|project| project.to_hex()),
        executor: AgentRunExecutorLease {
            node_id,
            generation: AGENT_RUN_LEASE_FIRST_GENERATION,
            held_until,
        },
        outcome: None,
        outlived_root,
        parent_context,
        created_at: record.created_at,
    };
    let encoded = rmp_serde::to_vec_named(&body)
        .map_err(|_| Error::InvariantViolation("agent run task body encode failed"))?;
    vault
        .batch_in()
        .put(
            &task_ref,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: body.created_at,
                end: body.created_at,
            },
            now,
            &encoded,
        )
        .apply(wtxn)?;
    // Born in the dispatch's world and facet (ARCH-0067 §5), as
    // `tasks.create` stamps a narrowed writer's TASKs: a reader narrowed
    // elsewhere, and a machine a device-local world keeps it from, reads none
    // of it.
    let position = BirthPosition { world, facet };
    if position != BirthPosition::default() {
        stamp_task_birth(&vault.store, wtxn, task_ref, position)?;
    }
    Ok(true)
}

/// The context bound the settled parent of the spawned child `record`
/// hands it, read in `txn` at the child's promotion (REVIEW-6638): that
/// parent's projection as a child of it resolves under it, the one its own
/// dispatch resolved under
/// ([`AgentDispatcher::resolve_ancestor_projection_in_txn`]), frozen as
/// [`FrozenContextBound`]. `None` when that parent resolves no projection,
/// as the child then resolves under none here either.
///
/// Engine call (CALLS, FIX 4747): a parent this queue does not hold fails
/// the mint, as the child's own context walk here fails on it: no bound is
/// frozen that this machine did not resolve, and the child stays under the
/// settled run's TASK, on this machine, as before.
fn frozen_parent_context_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &AttemptRecord,
) -> Result<Option<FrozenContextBound>> {
    let Some(parent) = spawning_parent(&record.payload) else {
        return Ok(None);
    };
    if AttemptQueue::new(vault).get_in_txn(txn, parent)?.is_none() {
        return Err(super::widen_record::invalid(
            "an outliving child's parent is missing",
        ));
    }
    Ok(AgentDispatcher::new(vault)
        .resolve_ancestor_projection_in_txn(txn, parent)?
        .map(FrozenContextBound::of))
}

/// Takes the executor lease of `row`'s run at its claim, in the claim's
/// write (FIX 4747): this machine's lease stays its own at its generation,
/// renewed when less than half a hold is left; an expired one of its own is
/// taken again at the next generation; a run this machine settled reopens
/// for its later try (`claim_standing`). Another machine's lease, another
/// machine's settlement, or a run TASK this version does not read is left as
/// it is. A closing process takes none.
///
/// A spawned child's claim (REVIEW-6638) reads its nearest ancestor's run
/// TASK, its root's or a child's that outlived its root: while that lease
/// names this machine, the child runs under a fence at its generation as it
/// stands, and the claim writes nothing to the TASK; it takes, renews and
/// reopens nothing, as only that run's own claim and the reaper's pass do.
/// A run another machine holds or settled, or whose run TASK does not read,
/// ends the child unrun, as it ends that run's own try. A child that
/// outlived its root claims its own run TASK as a root does.
pub(crate) fn take_agent_run_lease_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    row: &AttemptRecord,
    now: u64,
) -> Result<AgentRunLeaseTake> {
    let Some(AgentRunTaskLink { task_ref, child }) = agent_run_task_ref_in(vault, &*wtxn, row)?
    else {
        return Ok(AgentRunLeaseTake::NoRunTask);
    };
    if closing(vault) {
        return Ok(AgentRunLeaseTake::Closing);
    }
    let node_id = crate::identity::load_or_mint_client_id_in_txn(vault, wtxn)?;
    match claim_standing_in(vault, &*wtxn, task_ref, node_id)? {
        ClaimStanding::HeldElsewhere => Ok(AgentRunLeaseTake::HeldElsewhere),
        ClaimStanding::Settled => Ok(AgentRunLeaseTake::Settled),
        ClaimStanding::Unreadable => Ok(AgentRunLeaseTake::Unreadable),
        ClaimStanding::Own(held) if child => Ok(AgentRunLeaseTake::Taken(AgentRunFence {
            task_ref,
            node_id,
            generation: held.generation,
            attempt: row.id,
            child: true,
        })),
        ClaimStanding::Own(held) => {
            let lease =
                own_expired_agent_run_lease_retaken(held, now).unwrap_or(AgentRunExecutorLease {
                    held_until: agent_run_lease_renewal(held.held_until, now)
                        .unwrap_or(held.held_until),
                    ..held
                });
            // The TASK follows the try that takes it: its id and its payload
            // as the queue holds it now, scrubs included.
            update_agent_run_task_body_in_txn(vault, wtxn, task_ref, now, |body| {
                body.executor = lease;
                body.outcome = None;
                body.live_attempt_ref = bytes_to_hex_lower(row.id.as_bytes());
                body.queue_payload.clone_from(&row.payload);
                Ok(())
            })?;
            Ok(AgentRunLeaseTake::Taken(AgentRunFence {
                task_ref,
                node_id,
                generation: lease.generation,
                attempt: row.id,
                child: false,
            }))
        }
    }
}

/// The typed cause a queued `row` ends with unrun, judged in `wtxn` (FIX
/// 4747): another machine holds its run (for a spawned child, its nearest
/// ancestor's), or settled it, or its run TASK stands but does not read.
/// `None` for a row this machine may run, one with no run TASK, and any row
/// while this process closes.
pub(crate) fn agent_run_unrun_cause_in(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    row: &AttemptRecord,
) -> Result<Option<&'static str>> {
    let Some(AgentRunTaskLink { task_ref, .. }) = agent_run_task_ref_in(vault, &*wtxn, row)? else {
        return Ok(None);
    };
    if closing(vault) {
        return Ok(None);
    }
    let node_id = crate::identity::load_or_mint_client_id_in_txn(vault, wtxn)?;
    Ok(match claim_standing_in(vault, &*wtxn, task_ref, node_id)? {
        ClaimStanding::Own(_) => None,
        ClaimStanding::HeldElsewhere => Some(AGENT_RUN_EXECUTOR_MOVED),
        ClaimStanding::Settled => Some(AGENT_RUN_SETTLED_ELSEWHERE),
        ClaimStanding::Unreadable => Some(AGENT_RUN_TASK_UNREADABLE),
    })
}

/// The run TASK a try runs under (FIX 4747), and how the try stands to it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AgentRunTaskLink {
    pub(super) task_ref: EntityId,
    /// The try is a child its run spawned, at any depth, or a retry of one
    /// (REVIEW-6638): the run TASK is its nearest ancestor's, its root's or
    /// a child's that outlived its root. Its claim fences it on that lease
    /// and takes nothing; its settlement settles nothing.
    pub(super) child: bool,
}

/// Which links a walk to a try's run TASK follows (FIX 4747).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentRunTaskWalk {
    /// `retry_of` only: the run TASK that froze this try's own payload or
    /// the payload of a try it retries. What a hard erase takes.
    Retries,
    /// The `retry_of` chain, then `parent_attempt` from a spawned child up
    /// to the try that spawned it, and so on up the tree: the run TASK the
    /// try runs under.
    Tree,
}

/// The run TASK `row` runs under, read in `txn`: the one minted under its
/// own id, else the one of the try it retries, followed back through
/// `retry_of`; for a spawned child with none in its retry lineage
/// (REVIEW-6638), its nearest ancestor's, followed up through
/// `parent_attempt` ([`AGENT_RUN_RETRY_CHAIN_WALK`] bounds both). So the
/// run TASK a child got when it outlived its root wins over its root's. A
/// try this queue does not hold ends the walk at the run TASK its own id
/// names: a try a handover queued here links the run's original try, which
/// another machine ran (FIX 4747 slice 6). `None` for a row with none.
/// Any entity that stands under a run TASK id is that run's TASK, whether or
/// not this version reads its body: only no entity there is no run TASK. A
/// run TASK a hard erase took is none either (REVIEW-6615): the run runs
/// here as one with no run TASK, never as one whose TASK does not read.
pub(super) fn agent_run_task_ref_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &AttemptRecord,
) -> Result<Option<AgentRunTaskLink>> {
    Ok(agent_run_task_slot_in(
        &vault.store,
        txn,
        row.id,
        row.retry_of,
        spawning_parent(&row.payload),
        AgentRunTaskWalk::Tree,
    )?
    .and_then(|(link, erased)| (!erased).then_some(link)))
}

/// The try that spawned the try whose queue payload is `payload`: `None` for
/// a root, and for a payload that does not read as a dreamer attempt's. A
/// try's retries, successors and continuations copy its payload, so a
/// child's whole retry lineage names the same parent.
fn spawning_parent(payload: &[u8]) -> Option<AttemptId> {
    decode_dreamer_attempt_payload(payload).ok()?.parent_attempt
}

/// Whether a hard erase took the run TASK `task_ref`: its permanent
/// hard-delete marker stands (REVIEW-6615).
fn agent_run_task_erased_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> Result<bool> {
    store.port_deletion_marked(txn, DeletionMarker::HardDelete, &task_ref)
}

/// The run TASK the try `attempt`, retrying `retry_of` and spawned by
/// `parent`, links to by `walk`, read in `txn`, with whether a hard erase
/// took it: the first try the walk reaches under whose id a run TASK stands
/// or a hard erase took one. From each try it follows `retry_of`; a tree
/// walk ([`AgentRunTaskWalk::Tree`]), at a try that retries none, goes on up
/// `parent_attempt` to the try that spawned it (REVIEW-6638), as a child's
/// retries name its parent too. So a child's own run TASK, minted when it
/// outlived its root, wins over every ancestor's, and a child with none
/// passes over its lineage to its parent's. Every link counts against
/// [`AGENT_RUN_RETRY_CHAIN_WALK`].
fn agent_run_task_slot_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    retry_of: Option<AttemptId>,
    parent: Option<AttemptId>,
    walk: AgentRunTaskWalk,
) -> Result<Option<(AgentRunTaskLink, bool)>> {
    let queue = AttemptQueue::from_store(store);
    let (mut id, mut retry_of) = (attempt, retry_of);
    let mut parent = parent.filter(|_| walk == AgentRunTaskWalk::Tree);
    let mut child = false;
    let linked = |slot: Option<(EntityId, bool)>, child: bool| {
        slot.map(|(task_ref, erased)| (AgentRunTaskLink { task_ref, child }, erased))
    };
    for _ in 0..AGENT_RUN_RETRY_CHAIN_WALK {
        if let Some(slot) = agent_run_task_slot_at_in(store, txn, id)? {
            return Ok(linked(Some(slot), child));
        }
        if let Some(prior) = retry_of {
            if let Some(prior_row) = queue.get_in_txn(txn, prior)? {
                if walk == AgentRunTaskWalk::Tree {
                    parent = spawning_parent(&prior_row.payload);
                }
                (id, retry_of) = (prior_row.id, prior_row.retry_of);
                continue;
            }
            // A try this queue does not hold (a handover queued this try
            // after another machine ran that one) ends the walk at its own
            // run TASK id (FIX 4747 slice 6); with none there, a child's walk
            // goes on to the try that spawned its lineage.
            let slot = agent_run_task_slot_at_in(store, txn, prior)?;
            if slot.is_some() || parent.is_none() {
                return Ok(linked(slot, child));
            }
        }
        let Some(spawner) = parent else {
            return Ok(None);
        };
        child = true;
        // A spawner this queue does not hold ends the walk at its own run
        // TASK id, as a retried try does.
        let Some(spawner_row) = queue.get_in_txn(txn, spawner)? else {
            return Ok(linked(
                agent_run_task_slot_at_in(store, txn, spawner)?,
                child,
            ));
        };
        parent = spawning_parent(&spawner_row.payload);
        (id, retry_of) = (spawner_row.id, spawner_row.retry_of);
    }
    Ok(None)
}

/// Whether `row` is a try of a spawned child that outlived its root
/// (REVIEW-6638), read in `txn`: the run TASK of its own retry lineage,
/// which the settlement of the run it ran under minted, says so. Such a run
/// is a root of its own. Its parent settled, and a machine that took the run
/// over may hold no row of that parent: a walk up its tree ends at it there.
pub(super) fn outlived_root_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &AttemptRecord,
) -> Result<bool> {
    Ok(outlived_root_task_in(vault, txn, row)?.is_some())
}

/// The run TASK body that says `row` is a try of a spawned child that
/// outlived its root ([`outlived_root_in`]), read in `txn`: the one of its
/// own retry lineage, which carries the context bound its settled parent
/// handed it ([`AgentRunTaskBody::into_frozen_parent_projection`]). `None` for
/// any other try.
fn outlived_root_task_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &AttemptRecord,
) -> Result<Option<AgentRunTaskBody>> {
    let Some((link, false)) = agent_run_task_slot_in(
        &vault.store,
        txn,
        row.id,
        row.retry_of,
        None,
        AgentRunTaskWalk::Retries,
    )?
    else {
        return Ok(None);
    };
    match agent_run_task_body_in(vault, txn, link.task_ref) {
        Ok(body) => Ok(body.filter(|body| body.outlived_root)),
        Err(Error::Record(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// [`outlived_root_in`] of the try `attempt`, read in `txn`; `false` for a
/// try this queue does not hold.
pub(super) fn attempt_outlived_root_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<bool> {
    Ok(attempt_outlived_root_task_in(vault, txn, attempt)?.is_some())
}

/// [`outlived_root_task_in`] of the try `attempt`, read in `txn`; `None`
/// for a try this queue does not hold. A context walk that ends at such a
/// try, its settled parent's row absent, resolves it under the bound that
/// body froze (REVIEW-6638; engine call, CALLS, FIX 4747).
pub(super) fn attempt_outlived_root_task_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<Option<AgentRunTaskBody>> {
    match AttemptQueue::new(vault).get_in_txn(txn, attempt)? {
        Some(row) => outlived_root_task_in(vault, txn, &row),
        None => Ok(None),
    }
}

/// The run TASK id `attempt` names, read in `txn`, with whether a hard erase
/// took it, when a run TASK stands there or a hard erase took one.
fn agent_run_task_slot_at_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<Option<(EntityId, bool)>> {
    let task_ref = agent_run_task_id(attempt)?;
    let erased = agent_run_task_erased_in(store, txn, task_ref)?;
    Ok(
        (erased || store.port_entity_record(txn, &task_ref)?.is_some())
            .then_some((task_ref, erased)),
    )
}

/// Whether `task_ref` names an agent-run TASK, read in `txn`: the board and
/// the owner's task lists pass over it, as it is no person's task.
pub(crate) fn is_agent_run_task_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> Result<bool> {
    Ok(vault
        .store
        .port_entity_record(txn, &task_ref)?
        .is_some_and(|raw| raw.entity_type == ENTITY_TYPE_TASK && has_agent_run_subkind(&raw.body)))
}

/// Whether the TASK body names the agent-run subkind; a body that is no
/// MessagePack map names none.
fn has_agent_run_subkind(body: &[u8]) -> bool {
    rmpv::decode::read_value(&mut std::io::Cursor::new(body))
        .ok()
        .and_then(|value| {
            value.as_map().map(|entries| {
                entries.iter().any(|(key, value)| {
                    key.as_str() == Some("subkind")
                        && value.as_str() == Some(AGENT_RUN_TASK_SUBKIND)
                })
            })
        })
        .unwrap_or(false)
}

/// Decodes a stored agent-run TASK body of the current version.
fn decode_agent_run_task_body(entity_type: u8, body: &[u8]) -> Result<AgentRunTaskBody> {
    if entity_type != ENTITY_TYPE_TASK {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "agent run entity is not a TASK",
        )));
    }
    let body: AgentRunTaskBody = rmp_serde::from_slice(body)
        .map_err(|_| Error::Record(RecordError::InvalidTaskBody("invalid agent run body")))?;
    if body.schema_version != AGENT_RUN_TASK_SCHEMA_VERSION
        || body.subkind != AGENT_RUN_TASK_SUBKIND
        || body.role != TaskRole::Task.role_byte()
    {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "unsupported agent run body version",
        )));
    }
    Ok(body)
}

/// The stored run TASK body, read in `txn`; `None` while none stands, and
/// for a run TASK a hard erase took (REVIEW-6615), so each fence and the
/// settlement read that run as one with no run TASK.
pub(super) fn agent_run_task_body_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> Result<Option<AgentRunTaskBody>> {
    if agent_run_task_erased_in(&vault.store, txn, task_ref)? {
        return Ok(None);
    }
    vault
        .store
        .port_entity_record(txn, &task_ref)?
        .map(|raw| decode_agent_run_task_body(raw.entity_type, &raw.body))
        .transpose()
}

/// Read-modify-write of one run TASK body in the caller's write; a no-op
/// update writes nothing, so a renewal not yet due leaves the row
/// byte-identical.
pub(super) fn update_agent_run_task_body_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    now: u64,
    update: impl FnOnce(&mut AgentRunTaskBody) -> Result<()>,
) -> Result<()> {
    let raw = vault
        .store
        .port_entity_record(&*wtxn, &task_ref)?
        .ok_or(Error::EntityNotFound)?;
    let mut body = decode_agent_run_task_body(raw.entity_type, &raw.body)?;
    update(&mut body)?;
    let encoded = rmp_serde::to_vec_named(&body)
        .map_err(|_| Error::InvariantViolation("agent run task body encode failed"))?;
    if raw.body == encoded[..] {
        return Ok(());
    }
    vault
        .batch_in()
        .put(
            &task_ref,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: body.created_at,
                end: body.created_at,
            },
            now,
            &encoded,
        )
        .apply(wtxn)
}

/// What the run TASK `fence` names says of it, read in `txn`. A spawned
/// child's fence follows the run TASK a settlement minted for the child's
/// tree while it was claimed here instead (REVIEW-6638,
/// [`outlived_root_standing_in`]).
fn agent_run_fence_standing_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fence: &AgentRunFence,
) -> Result<FenceStanding> {
    if fence.child
        && let Some(standing) = outlived_root_standing_in(vault, txn, fence)?
    {
        return Ok(standing);
    }
    Ok(match agent_run_task_body_in(vault, txn, fence.task_ref)? {
        None => FenceStanding::Absent,
        Some(body) if fence.holds(body.executor) => FenceStanding::Holds(body.executor),
        Some(body) => FenceStanding::Moved(body.executor),
    })
}

/// What a spawned child's `fence` holds once the run whose TASK it names
/// settled here with the child claimed (REVIEW-6638): that settlement
/// minted a run TASK for the child, or for the pending try above it that the
/// child follows, with this machine's lease at the first generation. The
/// child's walk ends there now, and it runs under that run TASK, as a claim
/// then would: the fence holds while it names this machine at that
/// generation, and a handover moves it and stands the child down. `None`
/// while the child's walk still ends at the run TASK the fence names: no
/// settlement minted one for its tree, and that run TASK judges the fence.
fn outlived_root_standing_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fence: &AgentRunFence,
) -> Result<Option<FenceStanding>> {
    let Some(row) = AttemptQueue::new(vault).get_in_txn(txn, fence.attempt)? else {
        return Ok(None);
    };
    let Some(link) =
        agent_run_task_ref_in(vault, txn, &row)?.filter(|link| link.task_ref != fence.task_ref)
    else {
        return Ok(None);
    };
    let promoted = AgentRunFence {
        task_ref: link.task_ref,
        generation: AGENT_RUN_LEASE_FIRST_GENERATION,
        ..*fence
    };
    Ok(
        agent_run_task_body_in(vault, txn, link.task_ref)?.map(|body| {
            if promoted.holds(body.executor) {
                FenceStanding::Holds(body.executor)
            } else {
                FenceStanding::Moved(body.executor)
            }
        }),
    )
}

/// The one local log line a run's stand-down writes: the TASK, this
/// machine's node and generation, and the lease the TASK holds now. It names
/// no body.
fn log_agent_run_stand_down(fence: &AgentRunFence, held: Option<AgentRunExecutorLease>) {
    tracing::warn!(
        reason = AGENT_RUN_EXECUTOR_MOVED,
        task = %fence.task_ref.to_hex(),
        node_id = fence.node_id,
        generation = fence.generation,
        held_node_id = ?held.map(|lease| lease.node_id),
        held_generation = ?held.map(|lease| lease.generation),
        "an agent run stood down: this machine does not hold its run TASK's executor lease"
    );
}

/// The fence a terminal step commit of `attempt`'s run meets in its own
/// write (FIX 4747): the step commits only while the run TASK names the
/// fence's holder at its generation, and the lease is renewed there when
/// less than half a hold is left. A stale executor's step commits nothing:
/// [`Error::AgentRunExecutorMoved`] aborts the write, and the run stands
/// down at its settlement. An attempt no claim fenced commits as before.
/// Engine call (CALLS, FIX 4747): a run TASK this version cannot read stands
/// the step down too, as the send fence does. A spawned child's step meets
/// its root's fence and renews nothing (REVIEW-6638).
pub(crate) fn fence_agent_run_step_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
) -> Result<()> {
    let Some(fence) = vault.agent_run_fence(attempt) else {
        return Ok(());
    };
    let lease = match agent_run_fence_standing_in(vault, &*wtxn, &fence) {
        Ok(FenceStanding::Holds(lease)) => lease,
        Ok(FenceStanding::Absent) => return Ok(()),
        Ok(FenceStanding::Moved(held)) => {
            log_agent_run_stand_down(&fence, Some(held));
            return Err(Error::AgentRunExecutorMoved);
        }
        Err(Error::Record(_)) => {
            log_agent_run_stand_down(&fence, None);
            return Err(Error::AgentRunExecutorMoved);
        }
        Err(error) => return Err(error),
    };
    if fence.child {
        return Ok(());
    }
    renew_held_agent_run_lease_in_txn(vault, wtxn, fence.task_ref, lease)
}

/// Renews the lease of `attempt`'s run at its park or resume (FIX 4747), in
/// the caller's write, when less than half a hold is left and the run TASK
/// still names the holding its claim took. A renewal never fails the write
/// that parks or resumes the attempt: a run TASK that does not read, or a
/// lease that moved, is left as it is. A spawned child's park or resume
/// renews nothing (REVIEW-6638).
pub(crate) fn renew_agent_run_lease_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
) -> Result<()> {
    let Some(fence) = vault.agent_run_fence(attempt).filter(|fence| !fence.child) else {
        return Ok(());
    };
    match agent_run_fence_standing_in(vault, &*wtxn, &fence) {
        Ok(FenceStanding::Holds(lease)) => {
            renew_held_agent_run_lease_in_txn(vault, wtxn, fence.task_ref, lease)
        }
        Ok(FenceStanding::Moved(_) | FenceStanding::Absent) | Err(Error::Record(_)) => Ok(()),
        Err(error) => Err(error),
    }
}

/// Renews `lease`, which the run TASK `task_ref` holds for this machine,
/// when less than half a hold is left. Engine call (CALLS, FIX 4747): a
/// renewal inside the run keeps the generation, even past `held_until`, as
/// the fence just read that no other machine holds the run; only a claim
/// takes an expired lease at the next generation, and mints its fence from
/// it. A closing process renews nothing.
fn renew_held_agent_run_lease_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    lease: AgentRunExecutorLease,
) -> Result<()> {
    if closing(vault) {
        return Ok(());
    }
    let now = vault.store.clock.now_recorded_at();
    let Some(held_until) = agent_run_lease_renewal(lease.held_until, now) else {
        return Ok(());
    };
    update_agent_run_task_body_in_txn(vault, wtxn, task_ref, now, |body| {
        if body.executor.same_holding(lease) && body.outcome.is_none() {
            body.executor.held_until = held_until;
        }
        Ok(())
    })
}

/// The fence an outbound effect the run starts meets in the caller's write
/// (FIX 4747): a connector-send TASK the run creates is created only while
/// the run's TASK names the fence's holder at its generation. An attempt
/// with no fence is no fenced run. A stale executor's effect is refused
/// with [`Error::AgentRunExecutorMoved`], and nothing is scheduled.
pub(crate) fn fence_agent_run_effect_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<()> {
    let Some(fence) = vault.agent_run_fence(attempt) else {
        return Ok(());
    };
    require_agent_run_fence_in(vault, txn, &fence)
}

/// The fence each write that settles `attempt`'s run meets in that write
/// (FIX 4747): the write that publishes the run's result
/// (`AttemptQueue::set_result_in_txn`, and the attribution output), the one
/// that reports the TASK the run realizes (`report_leased_task_in_txn`), and
/// the one that retries its try each go only while the run TASK names the
/// fence's holder at its generation. A stale executor's settling write aborts
/// with [`Error::AgentRunExecutorMoved`], and its try ends unrun. The
/// terminal door meets the same fence in [`settle_agent_run_task_in_txn`]. An
/// attempt no claim fenced settles as before.
pub(crate) fn fence_agent_run_settlement_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<()> {
    let Some(fence) = vault.agent_run_fence(attempt) else {
        return Ok(());
    };
    require_agent_run_fence_in(vault, txn, &fence)
}

/// The fence check one write makes, read in its `txn` (FIX 4747): `Ok` while
/// the run TASK names `fence`'s holder at its generation, or no run TASK
/// stands; [`Error::AgentRunExecutorMoved`], with its one log line, while it
/// names another holding or does not read.
fn require_agent_run_fence_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fence: &AgentRunFence,
) -> Result<()> {
    match agent_run_fence_standing_in(vault, txn, fence) {
        Ok(FenceStanding::Holds(_) | FenceStanding::Absent) => Ok(()),
        Ok(FenceStanding::Moved(held)) => {
            log_agent_run_stand_down(fence, Some(held));
            Err(Error::AgentRunExecutorMoved)
        }
        Err(Error::Record(_)) => {
            log_agent_run_stand_down(fence, None);
            Err(Error::AgentRunExecutorMoved)
        }
        Err(error) => Err(error),
    }
}

/// Whether the transport call `fence` guards may start (FIX 4747), read in a
/// fresh read right before it, as the send executor fence reads. A
/// stand-down writes its one log line. Engine call (CALLS, FIX 4747): a run
/// TASK the fence cannot read stands the effect down too.
pub(crate) fn agent_run_fence_permits_effect(vault: &Vault, fence: &AgentRunFence) -> bool {
    let standing = vault
        .store
        .env
        .read_txn()
        .map_err(Error::from)
        .and_then(|rtxn| agent_run_fence_standing_in(vault, &rtxn, fence));
    match standing {
        Ok(FenceStanding::Holds(_) | FenceStanding::Absent) => true,
        Ok(FenceStanding::Moved(held)) => {
            log_agent_run_stand_down(fence, Some(held));
            false
        }
        Err(error) => {
            tracing::warn!(
                reason = AGENT_RUN_EXECUTOR_MOVED,
                task = %fence.task_ref.to_hex(),
                kind = ?error.kind(),
                "an agent run's effect stood down: the fence could not read its run TASK"
            );
            false
        }
    }
}

/// Whether the claimed run `fence` guards has moved to another machine,
/// read in `txn` (FIX 4747): the settlement stands it down instead of
/// settling it. A run TASK that does not read counts as moved.
pub(crate) fn agent_run_moved_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fence: &AgentRunFence,
) -> Result<bool> {
    match agent_run_fence_standing_in(vault, txn, fence) {
        Ok(FenceStanding::Holds(_) | FenceStanding::Absent) => Ok(false),
        Ok(FenceStanding::Moved(held)) => {
            log_agent_run_stand_down(fence, Some(held));
            Ok(true)
        }
        Err(Error::Record(_)) => {
            log_agent_run_stand_down(fence, None);
            Ok(true)
        }
        Err(error) => Err(error),
    }
}

/// Sets the run TASK's outcome as `record`, an agent-run try, settles for
/// good, in the write that settles it (FIX 4747): completed, failed or
/// abandoned, or cancelled. Only while this machine holds the run: the
/// holding its claim fenced, or, for a try no claim of this process fenced
/// (a workflow leaf, a resident's run), a lease that names this machine.
///
/// The settlement fence: a try this process's claim fenced completes, fails
/// or is abandoned only while its run TASK names the holding the claim took.
/// A run TASK that names another holding, or does not read, aborts the write
/// that settles it with [`Error::AgentRunExecutorMoved`], and the try ends
/// unrun. A cancellation is another actor's door (the owner's, an erasure's,
/// a lease expiry's): it ends the local try and leaves a run TASK that moved
/// as it is. A try ended unrun (its cause one of `AGENT_RUN_UNRUN_CAUSES`)
/// leaves its run TASK as it is. A run already settled is left as it is; a
/// retry or a landing handoff settles no run, as its later try carries it
/// on. For an unfenced try, a body that does not read is passed over.
///
/// Only the run's own try settles it (REVIEW-6638): the try the TASK names
/// live, or its retry lineage, as the walk finds it, of a root or of a child
/// that outlived its root. A spawned child under the run's TASK never does:
/// its settlement only meets that fence above, so a child of a run that
/// moved aborts and ends unrun.
///
/// A child that outlives its root becomes a root of its own (REVIEW-6638):
/// the write that settles the run mints a run TASK for each of its children
/// still pending in this queue ([`promote_outliving_children_in_txn`]), so
/// none is left with no portable record when this machine closes.
pub(crate) fn settle_agent_run_task_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
) -> Result<()> {
    let outcome = match record.state {
        AttemptState::Completed => AgentRunOutcome::Completed,
        AttemptState::Failed | AttemptState::Abandoned => AgentRunOutcome::Failed,
        AttemptState::Cancelled => AgentRunOutcome::Cancelled,
        _ => return Ok(()),
    };
    if record.kind != DREAMER_RUNNER_ATTEMPT_KIND
        || !decode_dreamer_attempt_payload(&record.payload)
            .is_ok_and(|payload| payload.attempt_type == AGENT_DISPATCH_ATTEMPT_TYPE)
    {
        return Ok(());
    }
    if record.state == AttemptState::Failed
        && record
            .last_error
            .as_deref()
            .is_some_and(|cause| AGENT_RUN_UNRUN_CAUSES.contains(&cause))
    {
        return Ok(());
    }
    let fence = vault.agent_run_fence(record.id);
    if let Some(fence) = &fence
        && record.state != AttemptState::Cancelled
    {
        require_agent_run_fence_in(vault, &*wtxn, fence)?;
    }
    let Some(AgentRunTaskLink { task_ref, child }) = agent_run_task_ref_in(vault, &*wtxn, record)?
    else {
        return Ok(());
    };
    if child {
        return Ok(());
    }
    let Some(node_id) = crate::identity::read_client_id_in_txn(vault, &*wtxn)? else {
        return Ok(());
    };
    let body = match agent_run_task_body_in(vault, &*wtxn, task_ref) {
        Ok(Some(body)) => body,
        Ok(None) | Err(Error::Record(_)) => return Ok(()),
        Err(error) => return Err(error),
    };
    if body.outcome.is_some() {
        return Ok(());
    }
    let holds = match fence {
        Some(fence) if fence.task_ref == task_ref => fence.holds(body.executor),
        _ => body.executor.node_id == node_id,
    };
    if !holds {
        return Ok(());
    }
    let now = vault.store.clock.now_recorded_at();
    // A settled run needs its frozen payload no more: the TASK drops it, so
    // its text lives on no machine past the run (the TASK's sync history
    // keeps the old bytes until its window is cut). Each child it leaves
    // pending carries its own. A run that outlived its root keeps its frozen
    // parent bound, refs only: on a machine that holds no row of its parent,
    // each context walk of a child below it still ends at it, the
    // promotions this settlement mints included (REVIEW-6638).
    update_agent_run_task_body_in_txn(vault, wtxn, task_ref, now, |body| {
        body.outcome = Some(outcome);
        body.queue_payload.clear();
        Ok(())
    })?;
    promote_outliving_children_in_txn(vault, wtxn, task_ref, now)
}

/// Mints a run TASK of its own, in the write that settles the run TASK
/// `run_task`, for each spawned child that outlives that run (REVIEW-6638):
/// each try still pending in this queue (queued, scheduled, leased, parked
/// or landing) that runs under `run_task` as a child, with no pending try
/// of the run above it on its walk there. A pending try below another
/// follows it, as it then walks to that try's new run TASK; a terminal
/// child gets none, and its pending children are minted for in its place.
///
/// Each run TASK is minted as a root's dispatch mints its own
/// (`put_agent_run_task_in_txn`): under the child's own id, with this
/// machine's lease at the first generation, the child's frozen payload
/// (which names its parent) and its world and project, through the same
/// gates, and flagged `outlived_root`, with the context bound its settled
/// parent hands it frozen in (`frozen_parent_context_in`), as a machine that
/// takes it holds no row of that parent. A mint the gates pass over or that
/// fails, in its own savepoint, leaves that child under the settled run's
/// TASK, on this machine, as before. A child claimed here when its run
/// settled follows its new run TASK at its fence
/// (`outlived_root_standing_in`).
fn promote_outliving_children_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    run_task: EntityId,
    now: u64,
) -> Result<()> {
    let queue = AttemptQueue::new(vault);
    // Each try pending here that runs under `run_task`, and whether it is
    // a child there.
    let mut pending = BTreeMap::new();
    for row in queue.kind_working_rows_in_txn(&*wtxn, DREAMER_RUNNER_ATTEMPT_KIND)? {
        if !row.state.is_pending() {
            continue;
        }
        if let Some(link) = agent_run_task_ref_in(vault, &*wtxn, &row)?
            && link.task_ref == run_task
        {
            pending.insert(row.id, (row, link.child));
        }
    }
    for (row, child) in pending.values() {
        if !child || pending_try_above_in(&queue, &*wtxn, row, &pending)? {
            continue;
        }
        let Some(input) = super::codec::record_dispatch_input(row) else {
            continue;
        };
        let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
        let minted = put_agent_run_task_in_txn(vault, &mut savepoint, row, &input, true, now);
        commit_minted_agent_run_task(savepoint, row.id, minted)?;
    }
    Ok(())
}

/// Whether a try of `pending` stands above `row` on its walk to its run
/// TASK: up its `retry_of` chain, then to the try that spawned it, as
/// [`agent_run_task_slot_in`] walks, within [`AGENT_RUN_RETRY_CHAIN_WALK`].
fn pending_try_above_in(
    queue: &AttemptQueue<'_>,
    txn: &heed::RoTxn<'_>,
    row: &AttemptRecord,
    pending: &BTreeMap<AttemptId, (AttemptRecord, bool)>,
) -> Result<bool> {
    let above = |below: &AttemptRecord| below.retry_of.or_else(|| spawning_parent(&below.payload));
    let mut next = above(row);
    for _ in 0..AGENT_RUN_RETRY_CHAIN_WALK {
        let Some(id) = next else {
            return Ok(false);
        };
        if pending.contains_key(&id) {
            return Ok(true);
        }
        let Some(next_row) = queue.get_in_txn(txn, id)? else {
            return Ok(false);
        };
        next = above(&next_row);
    }
    Ok(false)
}

/// Hard-erases the run TASK of each try in `rows`, each a try's id and the
/// try it retries, in the hard erase that just took an erased actor's text
/// out of those tries' queue payloads (REVIEW-6615): the run TASK froze a
/// copy of that payload, and its body names the run's agent and requester.
/// Each is found by its try's derived id, following `retry_of` as a claim
/// does but never `parent_attempt`, as a spawned child's payload is in no
/// run TASK but the one it got when it outlived its root, under its own
/// lineage's id (REVIEW-6638), and goes by the engine row's hard erase in this
/// transaction, as an erased participant's connector reply body goes in the
/// same pass: its provenance, indexes and row, its permanent `dt:` marker,
/// and its `pt:` tombstone in the window of its learned time, which that
/// window's next load publishes. The marker puts it among the erased ids the
/// erasure sweep takes out of every window it compacts, so the sweep the
/// erase queues cuts the TASK's history with the erased actor's. A run whose
/// TASK went has none: it stays on this machine and runs as before. A TASK a
/// legal hold keeps stays whole, with a warning.
///
/// # Errors
///
/// Storage errors, and a tear that fails.
pub(crate) fn erase_agent_run_tasks_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    rows: &[(AttemptId, Option<AttemptId>)],
) -> Result<()> {
    let mut tasks = BTreeSet::new();
    for (attempt, retry_of) in rows {
        // The run TASK that froze this try's payload: a spawned child's
        // payload is in no run TASK of an ancestor's, as each froze only its
        // own, and in its own once it outlived its root.
        if let Some((link, _)) = agent_run_task_slot_in(
            write.store,
            &*wtxn,
            *attempt,
            *retry_of,
            None,
            AgentRunTaskWalk::Retries,
        )? {
            tasks.insert(link.task_ref);
        }
    }
    for task_ref in tasks {
        hard_erase_agent_run_task_in_txn(write, wtxn, &task_ref)?;
    }
    Ok(())
}

/// [`erase_agent_run_tasks_in_txn`] for one run TASK; one no row stands
/// under is gone already.
fn hard_erase_agent_run_task_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: &EntityId,
) -> Result<()> {
    let store = write.store;
    let Some(learned_at) = store
        .port_entity_record(&*wtxn, task_ref)?
        .map(|row| row.learned_at)
    else {
        return Ok(());
    };
    if let Err(error) = store.reject_legal_hold_in_txn(&*wtxn, task_ref.as_bytes()) {
        if !crate::store::legal_hold::held_in_txn(store, &*wtxn, task_ref.as_bytes())? {
            return Err(error);
        }
        tracing::warn!(
            task = %task_ref.to_hex(),
            "agent run TASK erase: a hold or selected storage-only restriction keeps the run TASK"
        );
        return Ok(());
    }
    crate::provenance::erase_row_provenance_without_attempt_payloads_in_txn(
        write, wtxn, task_ref, true,
    )?;
    let (_, vector, graph, neighbors) = crate::batch::deindex_entity(write, wtxn, task_ref)?;
    crate::ppr::invalidate_ppr_for_delete(store, wtxn, task_ref, &neighbors)?;
    if graph {
        crate::store::graph_version::increment_graph_version(store, wtxn)?;
    }
    if vector {
        crate::store::vector_index::increment_vector_version(store, wtxn)?;
    }
    let value = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserHardDelete,
        deleted_at: crate::ports::recorded_at_in_txn(store, wtxn)?,
        request_id: *task_ref.as_bytes(),
    };
    crate::deletion::stage_engine_row_hard_erasure_in_txn(store, wtxn, task_ref, learned_at, &value)
}

/// Every live agent-run TASK and the lease it holds, read in `txn` (FIX
/// 4747): what the release judges. A body this version does not read is
/// passed over.
fn open_agent_run_leases_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(EntityId, AgentRunExecutorLease)>> {
    Ok(open_agent_runs_in(vault, txn)?
        .into_iter()
        .map(|(task_ref, body)| (task_ref, body.executor))
        .collect())
}

/// Every live agent-run TASK and its body, read in `txn` (FIX 4747): what
/// the release and the reaper judge. A body this version does not read is
/// passed over.
pub(super) fn open_agent_runs_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(EntityId, AgentRunTaskBody)>> {
    let mut runs = Vec::new();
    for task_ref in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_TASK, None)?
    {
        let task_ref = task_ref?;
        // A run TASK a hard erase took is no run to release or hand over
        // (REVIEW-6615).
        if agent_run_task_erased_in(&vault.store, txn, task_ref)? {
            continue;
        }
        let Some(raw) = vault.store.port_entity_record(txn, &task_ref)? else {
            continue;
        };
        if !has_agent_run_subkind(&raw.body) {
            continue;
        }
        let Ok(body) = decode_agent_run_task_body(raw.entity_type, &raw.body) else {
            continue;
        };
        if body.outcome.is_none() {
            runs.push((task_ref, body));
        }
    }
    Ok(runs)
}

impl Vault {
    /// Releases every live agent-run lease this machine holds (FIX 4747
    /// slice 5), in one writer: each keeps its holder and generation and is
    /// held until now, so the reaper on another machine
    /// ([`Vault::reap_agent_run_leases`]) may take it at once. The host calls
    /// it beside [`Vault::release_send_executor_leases`], as it shuts down
    /// gracefully and before its device-sync link stops. From then on this
    /// process takes, renews and settles no run lease until
    /// [`Vault::resume_executor_leases`]; a run in flight here still passes
    /// its fence until another machine takes its lease. Returns how many it
    /// released.
    ///
    /// # Errors
    /// Storage errors.
    pub fn release_agent_run_leases(&self) -> Result<usize> {
        self.executor_leases_released
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let now = self.now_recorded_at();
        let (node_id, held) = {
            let rtxn = self.store.env.read_txn()?;
            let Some(node_id) = crate::identity::read_client_id_in_txn(self, &rtxn)? else {
                return Ok(0);
            };
            let held: Vec<EntityId> = open_agent_run_leases_in(self, &rtxn)?
                .into_iter()
                .filter(|(_, lease)| lease.node_id == node_id && !lease.expired_at(now))
                .map(|(task_ref, _)| task_ref)
                .collect();
            (node_id, held)
        };
        if held.is_empty() {
            return Ok(0);
        }
        self.with_write_txn_grouped(|wtxn| {
            let mut released = 0_usize;
            for task_ref in held {
                let mut done = false;
                update_agent_run_task_body_in_txn(self, wtxn, task_ref, now, |body| {
                    if body.outcome.is_none()
                        && body.executor.node_id == node_id
                        && !body.executor.expired_at(now)
                    {
                        body.executor.held_until = now;
                        done = true;
                    }
                    Ok(())
                })?;
                released += usize::from(done);
            }
            Ok(released)
        })
    }

    /// The fence the agent pump's claim of `attempt` took, while its run is
    /// on this process's host (FIX 4747): what each step commit and effect
    /// of that attempt meets. In memory only.
    pub(crate) fn agent_run_fence(&self, attempt: AttemptId) -> Option<AgentRunFence> {
        self.agent_run_fences
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&attempt)
            .copied()
    }

    /// Keeps `fence` for `attempt` once its claim committed.
    pub(super) fn register_agent_run_fence(&self, attempt: AttemptId, fence: AgentRunFence) {
        self.agent_run_fences
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(attempt, fence);
    }

    /// Drops `attempt`'s fence once its run left the host.
    pub(super) fn forget_agent_run_fence(&self, attempt: AttemptId) {
        self.agent_run_fences
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&attempt);
    }
}

/// The in-memory fences of the runs on this process's host, by attempt.
pub(crate) type AgentRunFences = HashMap<AttemptId, AgentRunFence>;
