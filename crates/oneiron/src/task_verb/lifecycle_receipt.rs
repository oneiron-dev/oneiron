//! The durable `TaskLifecycle` receipt (OF-220, ARCH-0079): what one
//! mutating highway call did, what it asked and resolved, and why.
//!
//! The highway assembles each mutating call's [`TaskLifecycleRecord`]
//! (`Memory::lifecycle_record`); this keeps it, projected once into the
//! receipt family's row, in the write transaction that applied the call,
//! under an id the call's own identity derives, and names that id in the
//! call's `receipt_ref`. A replay derives the same id and answers the row the
//! first call kept, writing nothing; a journaled report replays the receipt
//! it journaled, `receipt_ref` and all. A fence refusal, a take another holds
//! and a status read keep none. A call in an anonymous off-record session
//! keeps none either (Engine ruling, #1968), as every receipt writer there:
//! such a session keeps nothing. One record is exempt (Engine 10-26,
//! ARCH-0052, FIX 10694): a consult interruption's frozen consent case is an
//! authority record, kept in such a session too, with its authority fields
//! only and no conversation content, as is the ConsentRequired fact beside
//! it.
//!
//! Each receipt is indexed in the transaction that keeps it: by its TASK and
//! time, which a status read names the newest of (FIX 3270) and whose row of
//! the write that settled the TASK a replayed Done names (FIX 3272), and by
//! time alone, which a receipt query reads newest first (FIX 3271).
//!
//! The receipt is narrative, not authority: no gate or proof reads it, save
//! the one row the engine keeps for itself, a consult interruption's frozen
//! consent case (FIX 9742), which only the engine writes and reads back.

use std::ops::Bound;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{Memory, MemoryResult};
use crate::receipt::{
    ReceiptKind, ReceiptQuery, ReceiptRecord, append_task_type_fields, retain_newest_receipt,
};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::task_type::TaskTypeRef;

use super::brief::QueueTaskBrief;
use super::highway_post::brief_type_ref_in;
use super::highway_types::{TaskCallReceipt, TaskLifecycleRecord};
use super::task_actor::names_no_actor;
use super::wire_decode::task_verb_body_in;

/// Domain of a lifecycle receipt's id.
const RECEIPT_ID_DOMAIN: &[u8] = b"oneiron.tasks.lifecycle_receipt.v1";
/// What every lifecycle receipt id starts with.
const RECEIPT_ID_PREFIX: &str = "task_lifecycle:";
/// The receipt field naming the highway call it records.
const FIELD_CALL: &str = "call";
/// The lifecycle field naming a parked post's or brief revision's proposal.
const FIELD_PROPOSAL_REF: &str = "proposal_ref";

/// Receipt id → the call's receipt, as the receipt family reads it.
const RECEIPTS: SideTable<String, ReceiptRecord, Named> =
    SideTable::new(&side_table::TASK_LIFECYCLE_RECEIPT);
/// TASK, time and receipt id → the receipt's role for its TASK.
const BY_TASK: SideTable<(EntityId, u64, String), [u8; 1], Raw> =
    SideTable::new(&side_table::TASK_LIFECYCLE_RECEIPT_BY_TASK);
/// Time and receipt id → a presence marker.
const BY_TIME: SideTable<(u64, String), (), Raw> =
    SideTable::new(&side_table::TASK_LIFECYCLE_RECEIPT_BY_TIME);

/// A TASK index row's role: a receipt of its TASK.
const ROLE_PLAIN: [u8; 1] = [0];
/// A TASK index row's role: the receipt of the write that settled its TASK.
const ROLE_SETTLED: [u8; 1] = [1];

/// The id of the lifecycle receipt `call` keeps for the identity `parts`
/// name: the same for a call and every replay of it.
pub(super) fn receipt_id(call: &str, parts: &[&[u8]]) -> MemoryResult<String> {
    let mut material: Vec<&[u8]> = Vec::with_capacity(parts.len() + 1);
    material.push(call.as_bytes());
    material.extend_from_slice(parts);
    let id = EntityId::derive(RECEIPT_ID_DOMAIN, &material)?;
    Ok(format!("{RECEIPT_ID_PREFIX}{}", id.to_hex()))
}

impl Memory<'_> {
    /// Whether this surface's calls keep their lifecycle receipts: all but
    /// a call in an anonymous off-record session. Judged before the call's
    /// write opens.
    pub(super) fn keeps_lifecycle(&self) -> bool {
        !self.keeps_no_record()
    }
}

/// Keeps `lifecycle` under `id` in `wtxn`, the transaction that applied its
/// call, and answers `id`. A later step of the same call rewrites the same
/// row. Its typeRef (OF-543) is the placement of `brief`, else of the brief
/// of the TASK the lifecycle names, when either places.
pub(super) fn stamp_record_in(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    lifecycle: &TaskLifecycleRecord,
    id: String,
    brief: Option<&QueueTaskBrief>,
) -> MemoryResult<String> {
    let type_ref = match brief {
        Some(brief) => brief_type_ref_in(vault, &*wtxn, brief)?,
        None => match lifecycle
            .trigger_ref
            .as_deref()
            .and_then(|hex| EntityId::from_hex(hex).ok())
        {
            Some(task_ref) => {
                match task_verb_body_in(vault, &*wtxn, task_ref)?.and_then(|body| body.brief) {
                    Some(stored) => brief_type_ref_in(vault, &*wtxn, &stored.brief)?,
                    None => None,
                }
            }
            None => None,
        },
    };
    let row = project(&id, lifecycle, type_ref.as_ref())?;
    let old = RECEIPTS.get(&vault.store, &*wtxn, &id)?;
    index_in(&vault.store, wtxn, &id, old.as_ref(), &row)?;
    RECEIPTS.put(&vault.store, wtxn, &id, &row)?;
    Ok(id)
}

/// The TASK a receipt row names, when it names one.
fn task_of(row: &ReceiptRecord) -> Option<EntityId> {
    row.trigger_ref
        .as_deref()
        .and_then(|hex| EntityId::from_hex(hex).ok())
}

/// Indexes `row`, kept under `id`, in its write's transaction: under its TASK
/// and time, and its time. A rewrite of `old` drops `old`'s rows first, and
/// its TASK row keeps the role it had.
fn index_in(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &str,
    old: Option<&ReceiptRecord>,
    row: &ReceiptRecord,
) -> crate::Result<()> {
    let mut role = ROLE_PLAIN;
    if let Some(old) = old {
        if let Some(task) = task_of(old) {
            let key = (task, old.occurred_at, id.to_owned());
            if let Some(kept) = BY_TASK.get(store, &*wtxn, &key)? {
                role = kept;
            }
            BY_TASK.delete(store, wtxn, &key)?;
        }
        BY_TIME.delete(store, wtxn, &(old.occurred_at, id.to_owned()))?;
    }
    if let Some(task) = task_of(row) {
        BY_TASK.put(store, wtxn, &(task, row.occurred_at, id.to_owned()), &role)?;
    }
    BY_TIME.put(store, wtxn, &(row.occurred_at, id.to_owned()), &())
}

/// Drops `row`'s index rows, in the transaction that drops it.
fn unindex_in(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &str,
    row: &ReceiptRecord,
) -> crate::Result<()> {
    if let Some(task) = task_of(row) {
        BY_TASK.delete(store, wtxn, &(task, row.occurred_at, id.to_owned()))?;
    }
    BY_TIME.delete(store, wtxn, &(row.occurred_at, id.to_owned()))?;
    Ok(())
}

/// Marks the receipt kept under `id` as the one of the write that settled
/// its TASK (FIX 3272), in that write's transaction, after the receipt is
/// kept. Only a settling write marks one, so no replay ever does. A receipt
/// that names no TASK marks nothing.
pub(super) fn mark_settled_in(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &str,
) -> MemoryResult<()> {
    let Some(row) = RECEIPTS.get(&vault.store, &*wtxn, &id.to_owned())? else {
        return Ok(());
    };
    let Some(task) = task_of(&row) else {
        return Ok(());
    };
    BY_TASK.put(
        &vault.store,
        wtxn,
        &(task, row.occurred_at, id.to_owned()),
        &ROLE_SETTLED,
    )?;
    Ok(())
}

/// The receipt of the write that settled `task` at `finished_at` (FIX 3272),
/// the least id when more than one was marked then: what a replay of that
/// settlement names. `None` when that write kept none.
pub(super) fn settled_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
    finished_at: u64,
) -> MemoryResult<Option<String>> {
    let mut prefix = task.as_bytes().to_vec();
    prefix.extend_from_slice(&finished_at.to_be_bytes());
    for row in BY_TASK.iter_from(&vault.store, txn, &prefix)? {
        let ((_, _, id), role) = row?;
        if role == ROLE_SETTLED {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

/// The newest lifecycle receipt naming `task` (FIX 3270), as a receipt query
/// orders them: the latest time, and at one time the least id. `None` when
/// none names it.
pub(super) fn newest_for_task_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
) -> MemoryResult<Option<String>> {
    let mut newest: Option<(u64, String)> = None;
    // Descending, so a later row at the newest time has a lesser id.
    for row in BY_TASK.iter_rev_from(&vault.store, txn, task.as_bytes())? {
        let ((_, at, id), _) = row?;
        if newest.as_ref().is_some_and(|(time, _)| at < *time) {
            break;
        }
        newest = Some((at, id));
    }
    Ok(newest.map(|(_, id)| id))
}

/// The receipt of the newest write that settled `task`, read in `txn`: its
/// `outcome` is the terminal disposition token (`completed`, `failed`, ...)
/// and its `actor` the reporter that settled it. `None` while no kept write
/// settled the TASK. ED-07 routing pairs a run's measured work with it when
/// an anchor stands behind it (FIX 7828).
pub(crate) fn settled_receipt_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
) -> crate::Result<Option<ReceiptRecord>> {
    for row in BY_TASK.iter_rev_from(&vault.store, txn, task.as_bytes())? {
        let ((_, _, id), role) = row?;
        if role == ROLE_SETTLED {
            return RECEIPTS.get(&vault.store, txn, &id);
        }
    }
    Ok(None)
}

/// [`stamp_record_in`] for one answer: keeps its lifecycle, when it owes
/// one, and names it in `receipt_ref`.
pub(super) fn stamp_in(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipt: &mut TaskCallReceipt,
    id: String,
    brief: Option<&QueueTaskBrief>,
) -> MemoryResult<()> {
    if let Some(lifecycle) = &receipt.lifecycle {
        receipt.receipt_ref = Some(stamp_record_in(vault, wtxn, lifecycle, id, brief)?);
    }
    Ok(())
}

/// What a replay of the call kept under `id` names: `id`, when the first
/// call kept a receipt there.
pub(super) fn replayed_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: String,
) -> MemoryResult<Option<String>> {
    Ok(RECEIPTS.contains(&vault.store, txn, &id)?.then_some(id))
}

/// The row kept under `id`, as it was kept, read in `txn`: for a record the
/// engine keeps for itself and reads back (FIX 9742). `None` when none is.
pub(super) fn kept_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &str,
) -> MemoryResult<Option<ReceiptRecord>> {
    Ok(RECEIPTS.get(&vault.store, txn, &id.to_owned())?)
}

/// [`replayed_in`] in a read of its own.
pub(super) fn replayed(vault: &Vault, id: String) -> MemoryResult<Option<String>> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    replayed_in(vault, &txn, id)
}

/// One lifecycle as the receipt family reads it: its call, actor, the host
/// attempt it ran for, the try, the TASK, and what it resolved, with the
/// record's fields as written.
fn project(
    id: &str,
    lifecycle: &TaskLifecycleRecord,
    type_ref: Option<&TaskTypeRef>,
) -> MemoryResult<ReceiptRecord> {
    let mut fields = lifecycle.fields.clone();
    fields.insert(FIELD_CALL.to_owned(), lifecycle.call.clone());
    let mut row = ReceiptRecord {
        receipt_id: id.to_owned(),
        receipt_kind: ReceiptKind::TaskLifecycle,
        occurred_at: lifecycle.occurred_at,
        actor: lifecycle.actor.id().as_ref().map(EntityId::to_hex),
        on_behalf_of: lifecycle.on_behalf_of.clone(),
        outcome: lifecycle.outcome.clone(),
        job_ref: lifecycle.job_ref.clone(),
        trigger_ref: lifecycle.trigger_ref.clone(),
        policy_trace: Vec::new(),
        fields,
    };
    if let Some(type_ref) = type_ref {
        append_task_type_fields(&mut row, type_ref)?;
    }
    Ok(row)
}

/// Drops every lifecycle receipt naming `id` as its TASK or its parked
/// proposal, in the transaction that erases it; a no-op for any other
/// entity, as the report journal's erase is. The table keys on the receipt
/// id, so its rows are found by what each one names.
pub(crate) fn erase_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> crate::Result<()> {
    let hex = id.to_hex();
    for (key, row) in RECEIPTS.scan(store, txn)? {
        if row.trigger_ref.as_deref() == Some(hex.as_str())
            || row.fields.get(FIELD_PROPOSAL_REF) == Some(&hex)
        {
            unindex_in(store, txn, &key, &row)?;
            RECEIPTS.delete(store, txn, &key)?;
        }
    }
    Ok(())
}

/// Erasing `actor` from the lifecycle receipts (FIX 3520): each one that
/// names it as its actor, or as whom the call ran on behalf of, keeps its
/// row, call, outcome, time, refs and fields, and names no one there. The
/// task erase above deletes by TASK, not by actor. One-way, in the erase's
/// own transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a receipt row that cannot be read.
pub(crate) fn erase_lifecycle_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> crate::Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let hex = actor.to_hex();
    let mut rows = Vec::new();
    for (key, mut row) in RECEIPTS.scan(&vault.store, wtxn)? {
        let acted = row.actor.as_deref() == Some(hex.as_str());
        let behalf = row.on_behalf_of.as_deref() == Some(hex.as_str());
        if acted {
            row.actor = None;
        }
        if behalf {
            row.on_behalf_of = None;
        }
        if acted || behalf {
            rows.push((key, row));
        }
    }
    for (key, row) in rows {
        RECEIPTS.put(&vault.store, wtxn, &key, &row)?;
    }
    Ok(())
}

/// The kept lifecycle receipts `query` matches, for the receipt family
/// (`Vault::receipts`). Reads the time index within the query's time bounds,
/// newest first (FIX 3271), to its end or until a full page can take no
/// older row; no count cuts it short (FIX 3582), and past its threshold row
/// it raises one check (rule 5).
pub(crate) fn task_lifecycle_receipts(
    vault: &Vault,
    query: &ReceiptQuery,
) -> crate::Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let start = query.start_at.map_or(Bound::Unbounded, |start| {
        Bound::Included((start, String::new()))
    });
    let end = query
        .end_at
        .and_then(|end| end.checked_add(1))
        .map_or(Bound::Unbounded, |next| {
            Bound::Excluded((next, String::new()))
        });
    let mut out = Vec::new();
    // The time of the last row taken: the oldest a full page holds, since
    // rows come newest first. An older row cannot displace any of it; one as
    // old may, by the page's tie order.
    let mut floor: Option<u64> = None;
    let mut count = crate::scan_check::ScanCount::start(
        &vault.store,
        &rtxn,
        crate::scan_check::EngineScan::ReceiptSourceRows,
        b"task_lifecycle",
    )?;
    for row in BY_TIME.iter_rev_range(&vault.store, &rtxn, start.as_ref(), end.as_ref())? {
        count.row();
        let ((at, id), ()) = row?;
        if query.job_ref.is_none()
            && out.len() >= query.limit
            && floor.is_some_and(|floor| at < floor)
        {
            break;
        }
        let Some(receipt) = RECEIPTS.get(&vault.store, &rtxn, &id)? else {
            return Err(Error::CorruptedIndex("task lifecycle receipt time index"));
        };
        if !query.matches(&receipt) {
            continue;
        }
        floor = Some(at);
        if query.job_ref.is_some() {
            out.push(receipt);
        } else {
            retain_newest_receipt(&mut out, receipt, query.limit);
        }
    }
    count.finish(vault);
    Ok(out)
}
