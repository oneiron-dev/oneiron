//! The child-done producer (census L2-38; ARCH-0067 STREAM delivery "Default
//! subscription: my tasks · my children · consults to me"; Engine RULING
//! L2-38-CHILD-KEY = A, 13 Nov 17:34).
//!
//! A native child agent is an AGENT dispatch attempt with a committed parent
//! attempt, and most spawns mint no TASK, so the own-task producer never sees
//! a child end. Now the write that settles a child's try as done, failed or
//! abandoned also stages one row: the child, its spawner's actor and the end
//! ([`stage_child_done_in_txn`]). The spawner's actor comes from the committed
//! parent attempt's dispatch input, never from a caller. A try that is retried
//! or handed over settles nothing, so it stages nothing.
//!
//! After each commit the host takes the staged rows ([`ChildDone::take_all`])
//! and hands them to [`BoardStreamRegistry::publish_children_done`]. That
//! sends each spawner's connections that subscribe to
//! [`SubscriptionScope::MyChildren`](super::SubscriptionScope::MyChildren) one
//! CARRIER delta keyed `children:<attempt id>`, whose line is the child's
//! handle and its end and nothing else. Like a done TASK's delta it rides the
//! next tool result once the connection holds a keyframe, and it is not kept
//! after the pass: `board.refresh` stays the floor. A narrowed connection
//! hears its own children too, since they are its own lineage.
//!
//! The rows are node-local runtime state. A row no pass took within a day is
//! dropped by a later stage, so a vault that no host serves keeps no more
//! than a day of them.

use super::events::{BoardEvent, RouteObservation};
use super::frames::DeltaRow;
use super::provenance::ChildEvent;
use super::registry::BoardStreamRegistry;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Error;
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Result, Vault};

/// Staged child ends. Key: u64be(settled at, recorded seconds), id16(child
/// attempt). Value: id16(spawner actor), then the end's tag byte.
const STAGED: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::CONTEXT_BOARD_CHILD_DONE);

/// How long a staged row no pass took is kept, in recorded seconds.
const STAGED_KEEP_SECS: u64 = 24 * 60 * 60;

/// How many expired rows one stage drops at most.
const STAGED_PRUNE_PER_STAGE: usize = 16;

/// The prefix of a child-done delta's key; the child's attempt id follows.
pub const CHILD_DONE_KEY_PREFIX: &str = "children:";

/// How a child's try ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildEnd {
    Done,
    Failed,
    Abandoned,
}

impl ChildEnd {
    /// The end's word on the child's line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Abandoned => "abandoned",
        }
    }

    const fn of(state: AttemptState) -> Option<Self> {
        match state {
            AttemptState::Completed => Some(Self::Done),
            AttemptState::Failed => Some(Self::Failed),
            AttemptState::Abandoned => Some(Self::Abandoned),
            _ => None,
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Done => b'd',
            Self::Failed => b'f',
            Self::Abandoned => b'a',
        }
    }

    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            b'd' => Some(Self::Done),
            b'f' => Some(Self::Failed),
            b'a' => Some(Self::Abandoned),
            _ => None,
        }
    }
}

/// One child's end as the board STREAM sends it: the child's attempt, its
/// spawner's actor, the end, and the line it rides with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildDone {
    child: String,
    spawner: EntityId,
    end: ChildEnd,
    line: String,
}

impl ChildDone {
    /// Takes every staged child end: reads each row, deletes them all in one
    /// write, and answers them oldest first, each with its line read from
    /// the child's attempt.
    pub fn take_all(vault: &Vault) -> Result<Vec<Self>> {
        let rows = {
            let txn = vault.store.env.read_txn()?;
            STAGED.scan(&vault.store, &txn)?
        };
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        vault.with_write_txn(|txn| {
            for (key, _) in &rows {
                STAGED.delete(&vault.store, txn, key)?;
            }
            Ok(())
        })?;
        let queue = AttemptQueue::new(vault);
        let mut taken = Vec::with_capacity(rows.len());
        for (key, value) in rows {
            let (child, spawner, end) = decode_row(&key, &value)?;
            let label = queue
                .get(child)?
                .and_then(|record| dispatch_agent_label(&record));
            let child = bytes_to_hex_lower(child.as_bytes());
            let handle = label.unwrap_or_else(|| child.clone());
            taken.push(Self {
                line: format!("{handle}:{}", end.as_str()),
                child,
                spawner,
                end,
            });
        }
        Ok(taken)
    }

    /// The child's attempt id, hex.
    #[must_use]
    pub fn child(&self) -> &str {
        &self.child
    }

    #[must_use]
    pub fn spawner(&self) -> EntityId {
        self.spawner
    }

    #[must_use]
    pub fn end(&self) -> ChildEnd {
        self.end
    }
}

/// Stages `record`'s end for its spawner's board when it is an AGENT child's
/// try that ended done, failed or abandoned, in the write that settles it. A
/// root run, another kind of row, another end, or a parent whose dispatch
/// names no agent stages nothing.
pub(crate) fn stage_child_done_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
) -> Result<()> {
    let Some(end) = ChildEnd::of(record.state) else {
        return Ok(());
    };
    let Some(spawner) = spawner_in_txn(vault, wtxn, record)? else {
        return Ok(());
    };
    let now = vault.store.clock.now_recorded_at();
    let mut key = now.to_be_bytes().to_vec();
    key.extend_from_slice(record.id.as_bytes());
    let mut value = spawner.as_bytes().to_vec();
    value.push(end.tag());
    STAGED.put(&vault.store, wtxn, &key, &value)?;
    let horizon = now.saturating_sub(STAGED_KEEP_SECS).to_be_bytes();
    let expired: Vec<Vec<u8>> = STAGED
        .scan_keys(&vault.store, wtxn, &[])?
        .into_iter()
        .take(STAGED_PRUNE_PER_STAGE)
        .take_while(|key| key.get(..8).is_some_and(|at| at < horizon.as_slice()))
        .collect();
    for key in &expired {
        STAGED.delete(&vault.store, wtxn, key)?;
    }
    Ok(())
}

/// The actor that spawned `child`, read from its committed parent attempt's
/// dispatch input. `None` when `child` is no AGENT child, or its parent is
/// gone or names no agent.
fn spawner_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    child: &AttemptRecord,
) -> Result<Option<EntityId>> {
    if child.kind != crate::store::dreamer_attempt_kind::DREAMER_RUNNER_ATTEMPT_KIND {
        return Ok(None);
    }
    let Ok(payload) = crate::dreamer_runner::decode_dreamer_attempt_payload(&child.payload) else {
        return Ok(None);
    };
    if payload.attempt_type != crate::attempt_queue::dispatch_payload::AGENT_DISPATCH_ATTEMPT_TYPE {
        return Ok(None);
    }
    let Some(parent) = payload.parent_attempt else {
        return Ok(None);
    };
    Ok(AttemptQueue::new(vault)
        .get_in_txn(txn, parent)?
        .as_ref()
        .and_then(crate::context_board::children::dispatched_actor))
}

/// The actor that spawned the child whose attempt id is `child_hex`, read
/// again from the committed rows. A host asks it before a `children:` line
/// rides, and drops the line unless the answer is the connection's actor.
pub fn child_spawner(vault: &Vault, child_hex: &str) -> Result<Option<EntityId>> {
    let Some(child) = crate::task_verb::decode_hex::<16>(child_hex)
        .and_then(|bytes| AttemptId::from_bytes(&bytes).ok())
    else {
        return Ok(None);
    };
    let txn = vault.store.env.read_txn()?;
    let Some(record) = AttemptQueue::new(vault).get_in_txn(&txn, child)? else {
        return Ok(None);
    };
    spawner_in_txn(vault, &txn, &record)
}

/// The child's handle on its line: its definition's agent id.
fn dispatch_agent_label(record: &AttemptRecord) -> Option<String> {
    let payload = crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload).ok()?;
    let label = crate::agent_dispatch::agent_dispatch_payload_agent_id(&payload)?;
    let label = super::one_line_token(label.trim());
    (!label.is_empty()).then_some(label)
}

fn decode_row(key: &[u8], value: &[u8]) -> Result<(AttemptId, EntityId, ChildEnd)> {
    let invalid = || Error::CorruptedIndex("staged board child end");
    let child = key
        .get(8..)
        .and_then(|bytes| AttemptId::from_bytes(bytes).ok())
        .ok_or_else(invalid)?;
    let spawner: [u8; 16] = value
        .get(..16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(invalid)?;
    let spawner = EntityId::from_bytes(spawner).map_err(|_| invalid())?;
    let end = value
        .get(16)
        .and_then(|tag| ChildEnd::from_tag(*tag))
        .ok_or_else(invalid)?;
    Ok((child, spawner, end))
}

impl BoardStreamRegistry {
    /// Sends each taken child end to its spawner's connections that
    /// subscribe to their children, as a CARRIER delta keyed
    /// `children:<attempt id>`. A connection with no keyframe yet takes
    /// nothing, as for a done TASK's delta.
    pub fn publish_children_done(&mut self, done: Vec<ChildDone>) -> RouteObservation {
        let mut observed = RouteObservation::default();
        for child in done {
            let routed = self.route_event(BoardEvent::ChildDone {
                event: ChildEvent {
                    child_ref: child.child.clone(),
                    parent_actor_ref: child.spawner.to_hex(),
                    event_ref: format!("child:{}:{}", child.child, child.end.as_str()),
                },
                delta: DeltaRow {
                    key: format!("{CHILD_DONE_KEY_PREFIX}{}", child.child),
                    line: child.line,
                },
            });
            observed.carrier_enqueued += routed.carrier_enqueued;
        }
        observed
    }
}
