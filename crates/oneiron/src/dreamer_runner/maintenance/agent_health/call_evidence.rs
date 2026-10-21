//! The call receipts the agent-health review reads, by the attempt each
//! names (OF-568 L4). A receipt names the attempt whose live run its call
//! held, at the lease generation it held, as the host witnessed it, or none.
//!
//! One actor's calls split into streams: one per witnessed attempt and
//! generation, and one of its calls that name none. Each stream keeps every
//! eligible row, in order. A witnessed stream is judged as its attempt's:
//! its TASK, its dispatch and its dials, settled or not. The actor-only
//! stream, and a stream whose witness names no agent dispatch of that same
//! actor, are judged taskless on the vault's dials, and never join another
//! stream or another attempt's card. No call is ever given the actor's
//! newest attempt.

use std::collections::BTreeMap;

use super::{Attempts, Dispatches, task_of};
use crate::attempt_queue::AttemptId;
use crate::limit_ask::EngineLimit;
use crate::receipt::{CallAttemptRef, CallReceipt};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// The call receipt ledger, read in place.
const CALL_RECEIPTS: SideTable<EntityId, CallReceipt, Named> =
    SideTable::new(&side_table::CALL_RECEIPT);

/// Agents' calls by actor, each actor's oldest first.
pub(super) type AgentCalls = BTreeMap<EntityId, Vec<(EntityId, CallReceipt)>>;

/// Each agent's calls in the lookback, oldest first. The whole lookback is
/// read: past `limits.maintenance_scan_rows` receipts the review asks and
/// reads on.
pub(super) fn agent_calls(vault: &Vault, since: u64) -> Result<AgentCalls> {
    let rtxn = vault.store.env.read_txn()?;
    let mut calls = AgentCalls::new();
    let mut read: u64 = 0;
    for row in CALL_RECEIPTS.iter_rev_from(&vault.store, &rtxn, &[])? {
        read += 1;
        let Ok((id, receipt)) = row else {
            continue;
        };
        if receipt.at < since {
            break;
        }
        if receipt.actor_class != "agent" {
            continue;
        }
        let Ok(actor) = EntityId::from_hex(&receipt.actor_ref) else {
            continue;
        };
        calls.entry(actor).or_default().push((id, receipt));
    }
    let _ = vault.measure_limit(EngineLimit::MaintenanceScanRows, read);
    for rows in calls.values_mut() {
        rows.reverse();
    }
    Ok(calls)
}

/// One actor's calls whose receipts name one attempt at one generation, or
/// name none: every such row, oldest first.
pub(super) struct CallStream<'a> {
    pub(super) actor: EntityId,
    /// The attempt and generation its receipts name; `None` for the calls
    /// that name none.
    pub(super) witness: Option<CallAttemptRef>,
    pub(super) rows: Vec<&'a (EntityId, CallReceipt)>,
}

impl CallStream<'_> {
    /// The TASK and the attempt this stream's findings name: its witnessed
    /// attempt's, when that attempt is an agent dispatch of this same actor
    /// in the working set, settled or not. Otherwise neither: the stream
    /// stays unassigned, and is never given another attempt.
    pub(super) fn owner(
        &self,
        dispatched: &Dispatches,
        attempts: &Attempts,
    ) -> (Option<EntityId>, Option<AttemptId>) {
        let Some(witness) = self.witness else {
            return (None, None);
        };
        let key = witness.attempt.as_bytes();
        match (attempts.get(key), dispatched.get(key)) {
            (Some(record), Some(dispatch)) if dispatch.actor == self.actor => {
                (task_of(record), Some(record.id))
            }
            _ => (None, None),
        }
    }
}

/// Every actor's streams, actor by actor: its calls that name no attempt
/// first, then each witnessed attempt and generation.
pub(super) fn call_streams(calls: &AgentCalls) -> Vec<CallStream<'_>> {
    let mut streams = Vec::new();
    for (actor, rows) in calls {
        let mut by_witness: BTreeMap<Option<CallAttemptRef>, Vec<&(EntityId, CallReceipt)>> =
            BTreeMap::new();
        for row in rows {
            by_witness.entry(row.1.attempt_ref).or_default().push(row);
        }
        streams.extend(by_witness.into_iter().map(|(witness, rows)| CallStream {
            actor: *actor,
            witness,
            rows,
        }));
    }
    streams
}

/// What the review of one attempt reads of the call ledger (`targeted`).
pub(super) struct AttemptCalls {
    /// The attempt's own calls at its generation in the lookback, under its
    /// actor, oldest first.
    witnessed: AgentCalls,
    /// The actor's newest call since its attempt was claimed, whatever
    /// attempt it names: `silent` reads it as activity, as the nightly
    /// review reads the actor's newest call.
    pub(super) activity: AgentCalls,
}

impl AttemptCalls {
    /// The attempt's witnessed stream, whole; none when it made no call.
    pub(super) fn streams(&self) -> Vec<CallStream<'_>> {
        call_streams(&self.witnessed)
    }
}

/// The call ledger as the review of one attempt reads it, in one scan,
/// newest first: `actor`'s calls at or after `since` whose receipts name
/// `witness` (none for `None`), and, from `activity_since`, the actor's
/// newest call at or after it. Each part stops at the first row older than
/// its own bound, as the nightly review's reads do.
pub(super) fn attempt_calls(
    vault: &Vault,
    actor: EntityId,
    witness: Option<CallAttemptRef>,
    since: u64,
    activity_since: Option<u64>,
) -> Result<AttemptCalls> {
    let rtxn = vault.store.env.read_txn()?;
    let mut witnessed = Vec::new();
    let mut activity = AgentCalls::new();
    let mut stream_open = witness.is_some();
    let mut activity_open = activity_since.is_some();
    let mut read: u64 = 0;
    for row in CALL_RECEIPTS.iter_rev_from(&vault.store, &rtxn, &[])? {
        read += 1;
        let Ok((id, receipt)) = row else {
            continue;
        };
        stream_open &= receipt.at >= since;
        activity_open &= activity_since.is_some_and(|start| receipt.at >= start);
        let wants_activity = activity_open && activity.is_empty();
        if !stream_open && !wants_activity {
            break;
        }
        if receipt.actor_class != "agent"
            || EntityId::from_hex(&receipt.actor_ref).ok() != Some(actor)
        {
            continue;
        }
        if wants_activity {
            activity.insert(actor, vec![(id, receipt.clone())]);
        }
        if stream_open && receipt.attempt_ref == witness {
            witnessed.push((id, receipt));
        }
    }
    let _ = vault.measure_limit(EngineLimit::MaintenanceScanRows, read);
    witnessed.reverse();
    let witnessed = if witnessed.is_empty() {
        AgentCalls::new()
    } else {
        AgentCalls::from([(actor, witnessed)])
    };
    Ok(AttemptCalls {
        witnessed,
        activity,
    })
}
