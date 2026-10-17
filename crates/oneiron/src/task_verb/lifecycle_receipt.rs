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
//! such a session keeps nothing.
//!
//! The receipt is narrative, not authority: no gate or proof reads it.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{Memory, MemoryResult};
use crate::receipt::{
    MAX_RECEIPT_QUERY_SCAN, ReceiptKind, ReceiptQuery, ReceiptRecord, append_task_type_fields,
    retain_newest_receipt,
};
use crate::side_table::{self, Named, SideTable};
use crate::task_type::TaskTypeRef;

use super::brief::QueueTaskBrief;
use super::highway_post::brief_type_ref_in;
use super::highway_types::{TaskCallReceipt, TaskLifecycleRecord};
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
    RECEIPTS.put(&vault.store, wtxn, &id, &row)?;
    Ok(id)
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
        actor: Some(lifecycle.actor.to_hex()),
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
            RECEIPTS.delete(store, txn, &key)?;
        }
    }
    Ok(())
}

/// The kept lifecycle receipts `query` matches, for the receipt family
/// (`Vault::receipts`). Reads at most [`MAX_RECEIPT_QUERY_SCAN`] rows, in
/// id order, as the family's other store-backed projectors do.
pub(crate) fn task_lifecycle_receipts(
    vault: &Vault,
    query: &ReceiptQuery,
) -> crate::Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for row in RECEIPTS
        .iter_from(&vault.store, &rtxn, &[])?
        .take(MAX_RECEIPT_QUERY_SCAN)
    {
        let (_, receipt) = row?;
        if !query.matches(&receipt) {
            continue;
        }
        if query.job_ref.is_some() {
            out.push(receipt);
        } else {
            retain_newest_receipt(&mut out, receipt, query.limit);
        }
    }
    Ok(out)
}
