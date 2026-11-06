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
//! run; the attempt's terminal settlement sets the TASK's outcome in the
//! same write, only while this machine holds the run. A closing process
//! releases the leases it holds, and takes and renews none after
//! (`Vault::executor_leases_released`).
//!
//! On one machine the lease is always its own, so nothing new refuses: a
//! run with no run TASK (dispatched before this change) runs as before.
//! The handover to another machine, the reaper and the re-creation of the
//! queue row there, is `super::run_handover` (slice 6).
//! Entry: `mint_agent_run_task_in_txn`, `take_agent_run_lease_in_txn`.

use std::collections::HashMap;
use std::sync::PoisonError;

use serde::{Deserialize, Serialize};

use super::{AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchInput};
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::entity_id::derived_domains::AGENT_RUN_TASK;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, RecordError, Result};
use crate::federation::record_scope::{BirthPosition, stamp_task_birth};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_TASK;
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

/// How many `retry_of` links a claim or a settlement follows back to find
/// the run TASK a retry, a landing successor, an owner's continuation or a
/// try a handover queued here shares with the try its dispatch minted.
/// Engine call (CALLS, FIX 4747): past it, or past a try this queue does not
/// hold whose own id names no run TASK, the row has no run TASK and runs as
/// before.
const AGENT_RUN_RETRY_CHAIN_WALK: usize = 64;

/// The typed cause a local try ends with when its run TASK names another
/// machine as the run's executor (FIX 4747): that machine runs it.
pub(crate) const AGENT_RUN_EXECUTOR_MOVED: &str = "agent_run_executor_moved";

/// The typed cause a local try ends with when another machine already
/// settled its run (FIX 4747): this machine's row is stale.
pub(crate) const AGENT_RUN_SETTLED_ELSEWHERE: &str = "agent_run_settled_elsewhere";

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
    /// The row has no run TASK: it runs as before, unfenced.
    NoRunTask,
    /// This machine holds the lease; the run goes under this fence.
    Taken(AgentRunFence),
    /// Another machine holds the lease: this machine does not run it.
    HeldElsewhere,
    /// Another machine settled the run: the local row is stale.
    Settled,
    /// This process released its leases as it closes: it claims nothing,
    /// and the row stays queued for the next process or machine.
    Closing,
}

/// What the run TASK says of a claim by this machine (FIX 4747).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClaimStanding {
    /// The run is this machine's to run.
    Own,
    /// Another machine holds the run.
    HeldElsewhere,
    /// Another machine settled the run.
    Settled,
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
    parent_attempt_ref: Option<String>,
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
    pub(super) created_at: u64,
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
        (true, _) => ClaimStanding::Own,
        (false, Some(_)) => ClaimStanding::Settled,
        (false, None) => ClaimStanding::HeldElsewhere,
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
    match put_agent_run_task_in_txn(vault, &mut savepoint, attempt, input, now) {
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

/// [`mint_agent_run_task_in_txn`]'s write: `false` when the run TASK already
/// stands or the row is gone.
fn put_agent_run_task_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    input: &AgentDispatchInput,
    now: u64,
) -> Result<bool> {
    let task_ref = agent_run_task_id(attempt)?;
    if vault.get_entity_type_in_txn(&*wtxn, &task_ref)?.is_some() {
        return Ok(false);
    }
    let Some(record) = AttemptQueue::new(vault).get_in_txn(&*wtxn, attempt)? else {
        return Ok(false);
    };
    // Only a run whose claim takes the lease gets a run TASK: a workflow
    // leaf and a resident's TASK-root run keep their pumps' path, and their
    // leases would never be renewed.
    if !super::agent_run::agent_pump_claims_in(vault, &*wtxn, &record)? {
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
    let parent = decode_dreamer_attempt_payload(&record.payload)?.parent_attempt;
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
        parent_attempt_ref: parent.map(|parent| bytes_to_hex_lower(parent.as_bytes())),
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

/// Takes the executor lease of `row`'s run at its claim, in the claim's
/// write (FIX 4747): this machine's lease stays its own at its generation,
/// renewed when less than half a hold is left; an expired one of its own is
/// taken again at the next generation; a run this machine settled reopens
/// for its later try (`claim_standing`). Another machine's lease, or another
/// machine's settlement, is left as it is. A closing process takes none.
pub(crate) fn take_agent_run_lease_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    row: &AttemptRecord,
    now: u64,
) -> Result<AgentRunLeaseTake> {
    let Some(task_ref) = agent_run_task_ref_in(vault, &*wtxn, row)? else {
        return Ok(AgentRunLeaseTake::NoRunTask);
    };
    if closing(vault) {
        return Ok(AgentRunLeaseTake::Closing);
    }
    let node_id = crate::identity::load_or_mint_client_id_in_txn(vault, wtxn)?;
    let Some(body) = readable_body_in(vault, &*wtxn, task_ref)? else {
        return Ok(AgentRunLeaseTake::NoRunTask);
    };
    match claim_standing(&body, node_id) {
        ClaimStanding::HeldElsewhere => Ok(AgentRunLeaseTake::HeldElsewhere),
        ClaimStanding::Settled => Ok(AgentRunLeaseTake::Settled),
        ClaimStanding::Own => {
            let held = body.executor;
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
            }))
        }
    }
}

/// The typed cause a queued `row` ends with unrun, judged in `wtxn` (FIX
/// 4747): another machine holds its run, or settled it. `None` for a row
/// this machine may run, one with no run TASK, and any row while this
/// process closes.
pub(crate) fn agent_run_unrun_cause_in(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    row: &AttemptRecord,
) -> Result<Option<&'static str>> {
    let Some(task_ref) = agent_run_task_ref_in(vault, &*wtxn, row)? else {
        return Ok(None);
    };
    if closing(vault) {
        return Ok(None);
    }
    let node_id = crate::identity::load_or_mint_client_id_in_txn(vault, wtxn)?;
    let Some(body) = readable_body_in(vault, &*wtxn, task_ref)? else {
        return Ok(None);
    };
    Ok(match claim_standing(&body, node_id) {
        ClaimStanding::Own => None,
        ClaimStanding::HeldElsewhere => Some(AGENT_RUN_EXECUTOR_MOVED),
        ClaimStanding::Settled => Some(AGENT_RUN_SETTLED_ELSEWHERE),
    })
}

/// The run TASK `row` shares, read in `txn`: the one its own dispatch
/// minted, else the one of the try it retries, followed back through
/// `retry_of` ([`AGENT_RUN_RETRY_CHAIN_WALK`]). A try this queue does not
/// hold ends the walk at the run TASK its own id names: a try a handover
/// queued here links the run's original try, which another machine ran
/// (FIX 4747 slice 6). `None` for a row with none.
pub(super) fn agent_run_task_ref_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &AttemptRecord,
) -> Result<Option<EntityId>> {
    let queue = AttemptQueue::new(vault);
    let (mut id, mut retry_of) = (row.id, row.retry_of);
    for _ in 0..AGENT_RUN_RETRY_CHAIN_WALK {
        let task_ref = agent_run_task_id(id)?;
        if is_agent_run_task_in(vault, txn, task_ref)? {
            return Ok(Some(task_ref));
        }
        let Some(parent) = retry_of else {
            return Ok(None);
        };
        let Some(parent_row) = queue.get_in_txn(txn, parent)? else {
            let task_ref = agent_run_task_id(parent)?;
            return Ok(is_agent_run_task_in(vault, txn, task_ref)?.then_some(task_ref));
        };
        (id, retry_of) = (parent_row.id, parent_row.retry_of);
    }
    Ok(None)
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

/// The stored run TASK body, read in `txn`; `None` while none stands.
pub(super) fn agent_run_task_body_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> Result<Option<AgentRunTaskBody>> {
    vault
        .store
        .port_entity_record(txn, &task_ref)?
        .map(|raw| decode_agent_run_task_body(raw.entity_type, &raw.body))
        .transpose()
}

/// [`agent_run_task_body_in`] for a claim: a body this version cannot read
/// is logged and read as no run TASK, so the row runs as before.
fn readable_body_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> Result<Option<AgentRunTaskBody>> {
    match agent_run_task_body_in(vault, txn, task_ref) {
        Err(Error::Record(_)) => {
            tracing::warn!(
                task = %task_ref.to_hex(),
                "an agent run's TASK does not read; its row runs as before"
            );
            Ok(None)
        }
        read => read,
    }
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

/// What the run TASK `fence` names says of it, read in `txn`.
fn agent_run_fence_standing_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fence: &AgentRunFence,
) -> Result<FenceStanding> {
    Ok(match agent_run_task_body_in(vault, txn, fence.task_ref)? {
        None => FenceStanding::Absent,
        Some(body) if fence.holds(body.executor) => FenceStanding::Holds(body.executor),
        Some(body) => FenceStanding::Moved(body.executor),
    })
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
/// the step down too, as the send fence does.
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
    renew_held_agent_run_lease_in_txn(vault, wtxn, fence.task_ref, lease)
}

/// Renews the lease of `attempt`'s run at its park or resume (FIX 4747), in
/// the caller's write, when less than half a hold is left and the run TASK
/// still names the holding its claim took. A renewal never fails the write
/// that parks or resumes the attempt: a run TASK that does not read, or a
/// lease that moved, is left as it is.
pub(crate) fn renew_agent_run_lease_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
) -> Result<()> {
    let Some(fence) = vault.agent_run_fence(attempt) else {
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
    match agent_run_fence_standing_in(vault, txn, &fence) {
        Ok(FenceStanding::Holds(_) | FenceStanding::Absent) => Ok(()),
        Ok(FenceStanding::Moved(held)) => {
            log_agent_run_stand_down(&fence, Some(held));
            Err(Error::AgentRunExecutorMoved)
        }
        Err(Error::Record(_)) => {
            log_agent_run_stand_down(&fence, None);
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
/// (a workflow leaf, a resident's run, a queued try ended unrun), a lease
/// that names this machine. A run another machine holds, or one already
/// settled, is left as it is; a retry or a landing handoff settles no run,
/// as its later try carries it on. A body that does not read is passed
/// over, so the settlement never fails on it.
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
    let Some(task_ref) = agent_run_task_ref_in(vault, &*wtxn, record)? else {
        return Ok(());
    };
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
    let holds = match vault.agent_run_fence(record.id) {
        Some(fence) if fence.task_ref == task_ref => fence.holds(body.executor),
        _ => body.executor.node_id == node_id,
    };
    if !holds {
        return Ok(());
    }
    let now = vault.store.clock.now_recorded_at();
    // A settled run needs its frozen payload no more: the TASK drops it, so
    // its text lives on no machine past the run (the TASK's sync history
    // keeps the old bytes until its window is cut).
    update_agent_run_task_body_in_txn(vault, wtxn, task_ref, now, |body| {
        body.outcome = Some(outcome);
        body.queue_payload.clear();
        Ok(())
    })
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
