//! A run's wait over the AGENT children it spawned (slice 6.5b, primitive
//! D): `tasks.wait({agents, all?, n_of?, step_key})`, the children named by
//! the attempt ids `self.agents.spawn` answered with.
//!
//! One wait is one row, keyed by the waiting attempt and its step key. Its
//! first done reduction is kept and answers every later call of that key,
//! after a restart too. A child counts once the newest try of its retry
//! lineage is terminal. The queue's settled hook, which every terminal door
//! of an attempt ends in, reduces the waits that name the child in the
//! child's own transaction, and a done one is delivered there as the reply
//! of each run parked on it.
//!
//! The wait reads state only: each child's terminal state and the ref of
//! the result it attached. A child's words stay in its own lane.
//!
//! The rows and the hook live here, in core beside the spawn and the kill
//! they stand with, because the queue's settled hook calls them; the run's
//! dispatcher and the host door only open a wait and read its reduction.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::limit_ask::EngineLimit;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::{EntityId, Error, Result, Vault, WriteActor};

/// One row per wait, keyed by its id.
const WAITS: SideTable<EntityId, AgentWaitSet, Raw> =
    SideTable::new(&side_table::AGENT_DISPATCH_CHILD_WAIT);
/// Whether a masked copy of an `AGENT_DISPATCH_CHILD_WAIT` row still decodes
/// as its typed value, for the historical lift sweep (FIX 2680).
pub(crate) fn agent_dispatch_child_wait_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<AgentWaitSet, Raw>(bytes)
}

/// The tagged index rows the declaration names: `w`, a child's waits.
const INDEX: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::AGENT_DISPATCH_CHILD_WAIT_INDEX);

/// A `w` row's value: a presence marker.
const WAITER: &[u8] = b"w";
/// What a stored row that does not read as a wait is.
const CORRUPT: &str = "agent child wait set";
/// The state of a child whose row was pruned: it had ended before that.
const CHILD_GONE: &str = "gone";

/// One AGENT child a wait names, once it has ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWaitChild {
    /// The child's attempt id, hex, as the wait named it.
    pub attempt: String,
    /// How it ended: `completed`, `failed`, `cancelled` or `abandoned`;
    /// `gone` when its row was pruned after it ended.
    pub state: String,
    /// The ref of the result it attached, when it attached one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_ref: Option<String>,
}

/// One reduction of a wait over a run's AGENT children.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWaitSetResult {
    /// The wait's id, hex: the same for every call of its step key, and the
    /// id a run parked on the wait is parked under.
    pub wait: String,
    /// The children that have ended, in the order the wait named them.
    pub settled: Vec<AgentWaitChild>,
    /// The children still queued or running: their attempt ids, hex.
    pub pending: Vec<String>,
    /// Whether the wait is over. A done reduction is kept, and answers every
    /// later call of the same step key.
    pub done: bool,
    /// Why it is done: `all`, `quorum` or `impossible`; `None` while it is
    /// not.
    pub reason: Option<String>,
}

/// How many children a wait waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum AgentWaitPolicy {
    /// Every child has ended.
    All,
    /// This many children have completed.
    NOf { n: u32 },
}

/// One wait over an attempt's AGENT children, keyed by the attempt and its
/// step key. Attempt ids are kept as the 32 hex digits the wire names them
/// by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AgentWaitSet {
    id: EntityId,
    parent: String,
    children: Vec<String>,
    policy: AgentWaitPolicy,
    step_key: String,
    settled: Option<AgentWaitSetResult>,
}

impl RawValue for AgentWaitSet {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        serde_json::to_vec(self).map_err(|_| Error::CorruptedIndex(CORRUPT).into())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        serde_json::from_slice(bytes).map_err(|_| Error::CorruptedIndex(CORRUPT).into())
    }
}

/// What opening a wait answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AgentWaitOpen {
    /// The wait and its reduction as it stands now.
    Reduced {
        wait: EntityId,
        result: AgentWaitSetResult,
    },
    /// The step key already names a wait over other children, or under
    /// another policy.
    Changed,
    /// Two of the named attempts are tries of one child: a retry keeps a
    /// spawn's place under a new id, and a repeated spawn answers with it.
    SameChild,
    /// The caller is not the actor its attempt was dispatched as, or a named
    /// attempt is not a child that attempt spawned in its own run. One
    /// answer for every such miss, so a wait probes nothing.
    NotOwn,
}

/// The attempt 32 hex digits name.
pub(crate) fn agent_wait_attempt(text: &str) -> Option<AttemptId> {
    if text.len() != 32 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0_u8; 16];
    for (at, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[at * 2..at * 2 + 2], 16).ok()?;
    }
    AttemptId::from_bytes(&bytes).ok()
}

fn hex(id: AttemptId) -> String {
    crate::entity_id::bytes_to_hex_lower(id.as_bytes())
}

/// The wait an attempt's step key names.
fn agent_wait_id(parent: AttemptId, step_key: &str) -> Result<EntityId> {
    EntityId::derive(
        b"oneiron:code-agent-wait:v1",
        &[parent.as_bytes().as_slice(), step_key.as_bytes()],
    )
}

fn waiter_prefix(child: AttemptId) -> Vec<u8> {
    let mut key = vec![b'w'];
    key.extend_from_slice(child.as_bytes());
    key
}

fn waiter_key(child: AttemptId, wait: EntityId) -> Vec<u8> {
    let mut key = waiter_prefix(child);
    key.extend_from_slice(wait.as_bytes());
    key
}

/// The wait a `w` row's key names: the 16 bytes after its tag and child.
fn waiter_wait(key: &[u8]) -> Result<EntityId> {
    let bytes: [u8; 16] = key
        .get(17..33)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::CorruptedIndex("agent child wait index key"))?;
    EntityId::from_bytes(bytes)
}

/// Opens, or reads again, the wait `step_key` names for `parent`, the
/// attempt `actor` runs as, over `children` in the order given, and reduces
/// it, all in one write. A new wait is admitted only over children `parent`
/// spawned in its own run; a kept one answers what it kept.
///
/// # Errors
///
/// Storage errors, and a stored wait that does not decode.
pub(crate) fn open_agent_wait(
    vault: &Vault,
    actor: WriteActor,
    parent: AttemptId,
    children: &[AttemptId],
    policy: AgentWaitPolicy,
    step_key: &str,
) -> Result<AgentWaitOpen> {
    let wait = agent_wait_id(parent, step_key)?;
    let queue = AttemptQueue::new(vault);
    vault.with_write_txn_grouped(|wtxn| {
        // The caller is the actor its own attempt was dispatched as, read in
        // the transaction that reads the children.
        let Some(parent_row) = queue.get_in_write_txn(wtxn, parent)? else {
            return Ok(AgentWaitOpen::NotOwn);
        };
        let dispatched = super::record_dispatch_input(&parent_row)
            .and_then(|input| super::agent_dispatch_actor(&input).ok());
        if dispatched != Some(actor) {
            return Ok(AgentWaitOpen::NotOwn);
        }
        let named: Vec<String> = children.iter().copied().map(hex).collect();
        let set = match WAITS.get(&vault.store, wtxn, &wait)? {
            Some(set) if set.children != named || set.policy != policy => {
                return Ok(AgentWaitOpen::Changed);
            }
            Some(set) => set,
            None => {
                let mut tips = HashSet::with_capacity(children.len());
                for child in children {
                    if !spawned_by(&queue, wtxn, *child, &parent_row)? {
                        return Ok(AgentWaitOpen::NotOwn);
                    }
                    // Two tries of one child count once: each stands as the
                    // newest try of its lineage, as the reduction reads it.
                    let tip = queue.newest_retry_in_txn(wtxn, *child)?.unwrap_or(*child);
                    if !tips.insert(tip) {
                        return Ok(AgentWaitOpen::SameChild);
                    }
                }
                let set = AgentWaitSet {
                    id: wait,
                    parent: hex(parent),
                    children: named,
                    policy,
                    step_key: step_key.to_owned(),
                    settled: None,
                };
                WAITS.put(&vault.store, wtxn, &wait, &set)?;
                for child in children {
                    INDEX.put(
                        &vault.store,
                        wtxn,
                        &waiter_key(*child, wait),
                        &WAITER.to_vec(),
                    )?;
                }
                set
            }
        };
        let result = settle_in_txn(vault, &queue, wtxn, set, None)?;
        Ok(AgentWaitOpen::Reduced { wait, result })
    })
}

/// Whether `child` is an attempt `parent` spawned in its own run: a Dreamer
/// queue row whose payload names `parent` as the attempt that spawned it,
/// under the parent's run id. It is the standing `kill_spawn` reads.
fn spawned_by(
    queue: &AttemptQueue<'_>,
    txn: &heed::RoTxn<'_>,
    child: AttemptId,
    parent: &AttemptRecord,
) -> Result<bool> {
    let Some(row) = queue.get_in_txn(txn, child)? else {
        return Ok(false);
    };
    if row.kind != DREAMER_RUNNER_ATTEMPT_KIND {
        return Ok(false);
    }
    let Ok(payload) = decode_dreamer_attempt_payload(&row.payload) else {
        return Ok(false);
    };
    Ok(payload.parent_attempt == Some(parent.id) && row.run_id == parent.run_id)
}

/// Reduces `set` over its children's rows as `txn` holds them. `ended` is a
/// row the caller's own transaction just ended, read in place of its stored
/// copy. A child stands as the newest try of its retry lineage; a lineage
/// with no one newest try stands as the try the wait named. Only a completed
/// child counts toward a quorum.
fn reduce(
    queue: &AttemptQueue<'_>,
    txn: &heed::RoTxn<'_>,
    set: &AgentWaitSet,
    ended: Option<&AttemptRecord>,
) -> Result<AgentWaitSetResult> {
    let mut settled = Vec::new();
    let mut pending = Vec::new();
    let mut completed = 0_usize;
    for child in &set.children {
        let id = agent_wait_attempt(child).ok_or(Error::CorruptedIndex(CORRUPT))?;
        let tip = queue.newest_retry_in_txn(txn, id)?.unwrap_or(id);
        let row = match ended.filter(|row| row.id == tip) {
            Some(row) => Some(row.clone()),
            None => queue.get_in_txn(txn, tip)?,
        };
        match row {
            Some(row) if row.state.is_terminal() => {
                if row.state == AttemptState::Completed {
                    completed += 1;
                }
                settled.push(AgentWaitChild {
                    attempt: child.clone(),
                    state: row.state.as_str().to_owned(),
                    result_ref: row
                        .result_ref
                        .as_ref()
                        .map(|result| result.as_str().to_owned()),
                });
            }
            Some(_) => pending.push(child.clone()),
            None => settled.push(AgentWaitChild {
                attempt: child.clone(),
                state: CHILD_GONE.to_owned(),
                result_ref: None,
            }),
        }
    }
    let reason = match set.policy {
        AgentWaitPolicy::All if pending.is_empty() => Some("all"),
        AgentWaitPolicy::NOf { n } if completed >= n as usize => Some("quorum"),
        AgentWaitPolicy::NOf { n } if completed + pending.len() < n as usize => Some("impossible"),
        _ => None,
    };
    Ok(AgentWaitSetResult {
        wait: set.id.to_hex(),
        settled,
        pending,
        done: reason.is_some(),
        reason: reason.map(str::to_owned),
    })
}

/// Reduces `set` in the caller's transaction. A first done reduction is
/// kept, its index rows go, and it is delivered as the reply of every run
/// parked on the wait. A settled set answers the reduction it kept.
fn settle_in_txn(
    vault: &Vault,
    queue: &AttemptQueue<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    mut set: AgentWaitSet,
    ended: Option<&AttemptRecord>,
) -> Result<AgentWaitSetResult> {
    if let Some(result) = &set.settled {
        return Ok(result.clone());
    }
    let result = reduce(queue, wtxn, &set, ended)?;
    if !result.done {
        return Ok(result);
    }
    set.settled = Some(result.clone());
    WAITS.put(&vault.store, wtxn, &set.id, &set)?;
    for child in &set.children {
        let child = agent_wait_attempt(child).ok_or(Error::CorruptedIndex(CORRUPT))?;
        INDEX.delete(&vault.store, wtxn, &waiter_key(child, set.id))?;
    }
    let reply = serde_json::to_value(&result)
        .map_err(|_| Error::InvariantViolation("agent wait answer encode"))?;
    crate::code_run::deliver_wait_in_txn(vault, wtxn, set.id, &reply, crate::unix_millis_now())?;
    Ok(result)
}

/// The queue's settled hook: `ended` just reached a terminal state in
/// `wtxn`. Every unsettled wait that names it, or an earlier try of its
/// retry lineage (a wait names the try its spawn answered with, and a retry
/// carries the child on under a new id), is reduced, and a done one is
/// delivered, in that transaction.
///
/// # Errors
///
/// Storage errors, and a stored wait or index row that does not decode.
pub(crate) fn settle_agent_child_waits_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    ended: &AttemptRecord,
) -> Result<()> {
    if ended.kind != DREAMER_RUNNER_ATTEMPT_KIND {
        return Ok(());
    }
    let queue = AttemptQueue::new(vault);
    // Every earlier try of the ended row is read, however long the lineage:
    // the wait's index row stands under the try it named. A walk that meets
    // a row twice stops.
    let mut named = vec![ended.id];
    let mut seen = HashSet::from([ended.id]);
    let mut earlier = ended.retry_of;
    while let Some(id) = earlier {
        if !seen.insert(id) {
            break;
        }
        named.push(id);
        earlier = queue.get_in_txn(wtxn, id)?.and_then(|row| row.retry_of);
    }
    vault
        .store
        .limit_watch
        .measure(EngineLimit::AttemptRetryTipRows, named.len() as u64);
    for id in named {
        for key in INDEX.scan_keys(&vault.store, wtxn, &waiter_prefix(id))? {
            let wait = waiter_wait(&key)?;
            if let Some(set) = WAITS
                .get(&vault.store, wtxn, &wait)?
                .filter(|set| set.settled.is_none())
            {
                settle_in_txn(vault, &queue, wtxn, set, Some(ended))?;
            }
        }
    }
    Ok(())
}
