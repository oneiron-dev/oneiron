//! The attested record of a hold override (Fable 5.2 item 2, Engine call
//! S65-B-R3): each time a generic Resume releases an engine hold that its own
//! signal did not release, the override's own transaction writes one
//! `RunHoldOverride` receipt. It names the hold, the run, the actor and the
//! time, and the receipt family reads it. The vault owner's override through
//! run control and the engine's internal resumes alike write one, each under
//! its own actor: it is the record the owner reviews, not a gate.

use std::collections::BTreeMap;
use std::ops::Bound;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord, retain_newest_receipt};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;

use super::types::{AttemptPause, AttemptRecord};

/// Receipt id → the override's receipt, as the receipt family reads it.
const RECEIPTS: SideTable<String, ReceiptRecord, Named> =
    SideTable::new(&side_table::ATTEMPT_HOLD_OVERRIDE_RECEIPT);
/// Time and receipt id → a presence marker.
const BY_TIME: SideTable<(u64, String), (), Raw> =
    SideTable::new(&side_table::ATTEMPT_HOLD_OVERRIDE_RECEIPT_BY_TIME);

/// The receipt's outcome: the hold was released.
const OUTCOME_RELEASED: &str = "released";
/// The receipt field naming the hold kind.
const FIELD_HOLD: &str = "hold";
/// The receipt field naming the released attempt, 32 hex.
const FIELD_ATTEMPT: &str = "attempt";
/// The fan-out hold's launch.
const FIELD_LAUNCH_REF: &str = "launch_ref";
/// The annotation hold's artifact and comment thread.
const FIELD_ARTIFACT_REF: &str = "artifact_ref";
const FIELD_THREAD_REF: &str = "thread_ref";

/// Writes the receipt of an override that released `pause` from `attempt`
/// (the row as it stood before the Resume) under `actor` at `now`, in the
/// override's transaction. `sequence` is the Resume event's sequence, which
/// keeps two overrides of one row apart. A person's pause is no engine hold
/// and writes none.
pub(super) fn record_hold_override_receipt_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    pause: AttemptPause,
    attempt: &AttemptRecord,
    actor: &str,
    sequence: u64,
    now: u64,
) -> Result<()> {
    let attempt_hex = crate::receipt::hex_lower(attempt.id.as_bytes());
    let mut fields = BTreeMap::new();
    let hold = match pause {
        AttemptPause::Person => return Ok(()),
        AttemptPause::Budget => "budget",
        AttemptPause::Hook { .. } => "hook",
        AttemptPause::Fanout { launch_ref } => {
            fields.insert(FIELD_LAUNCH_REF.to_owned(), launch_ref.to_hex());
            "fanout"
        }
        AttemptPause::Annotation {
            artifact_id,
            thread_id,
        } => {
            fields.insert(FIELD_ARTIFACT_REF.to_owned(), artifact_id.to_hex());
            fields.insert(FIELD_THREAD_REF.to_owned(), thread_id.to_hex());
            "annotation"
        }
    };
    fields.insert(FIELD_HOLD.to_owned(), hold.to_owned());
    fields.insert(FIELD_ATTEMPT.to_owned(), attempt_hex.clone());
    let receipt = ReceiptRecord {
        receipt_id: format!("run_hold_override:{attempt_hex}:{sequence}"),
        receipt_kind: ReceiptKind::RunHoldOverride,
        occurred_at: now,
        actor: Some(actor.to_owned()),
        on_behalf_of: None,
        outcome: OUTCOME_RELEASED.to_owned(),
        job_ref: attempt.run_id.clone(),
        trigger_ref: attempt.task_ref.clone(),
        policy_trace: Vec::new(),
        fields,
    };
    BY_TIME.put(
        store,
        wtxn,
        &(receipt.occurred_at, receipt.receipt_id.clone()),
        &(),
    )?;
    RECEIPTS.put(store, wtxn, &receipt.receipt_id, &receipt)?;
    Ok(())
}

/// The hold override receipts `query` names, newest first, for the receipt
/// family.
///
/// # Errors
///
/// A time index row whose receipt is missing; storage errors.
pub(crate) fn hold_override_receipts(
    vault: &Vault,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
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
        b"run_hold_override",
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
            return Err(Error::CorruptedIndex("hold override receipt time index"));
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

/// The table's actor scrub (an actor's erase, and a restore's rerun of it):
/// every hold override receipt `actor` made names no actor any more. The
/// receipt and the release it records stand.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_hold_override_receipt_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let hex = actor.to_hex();
    let mut rows = Vec::new();
    for (key, mut row) in RECEIPTS.scan(&vault.store, wtxn)? {
        if row.actor.as_deref() == Some(hex.as_str()) {
            row.actor = None;
            rows.push((key, row));
        }
    }
    for (key, row) in rows {
        RECEIPTS.put(&vault.store, wtxn, &key, &row)?;
    }
    Ok(())
}

/// Whether `text` is `len` lowercase hex characters.
fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether a decoded hold-override receipt keeps the writer's pure row invariants.
fn archived_hold_override_holds(key: &str, receipt: &ReceiptRecord) -> bool {
    if key != receipt.receipt_id {
        return false;
    }
    if receipt.receipt_kind != ReceiptKind::RunHoldOverride {
        return false;
    }
    if receipt.outcome != OUTCOME_RELEASED {
        return false;
    }
    if receipt.on_behalf_of.is_some() {
        return false;
    }
    if !receipt.policy_trace.is_empty() {
        return false;
    }
    let Some(rest) = receipt.receipt_id.strip_prefix("run_hold_override:") else {
        return false;
    };
    let Some((hex, seq)) = rest.split_once(':') else {
        return false;
    };
    if !is_lower_hex(hex, 32) {
        return false;
    }
    if seq.is_empty() || !seq.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    if seq.len() > 1 && seq.starts_with('0') {
        return false;
    }
    if seq.parse::<u64>().is_err() {
        return false;
    }
    let Some(hold) = receipt.fields.get(FIELD_HOLD) else {
        return false;
    };
    let Some(attempt) = receipt.fields.get(FIELD_ATTEMPT) else {
        return false;
    };
    if attempt != hex {
        return false;
    }
    match hold.as_str() {
        "budget" | "hook" => {
            if receipt.fields.contains_key(FIELD_LAUNCH_REF)
                || receipt.fields.contains_key(FIELD_ARTIFACT_REF)
                || receipt.fields.contains_key(FIELD_THREAD_REF)
            {
                return false;
            }
            if receipt.fields.len() != 2 {
                return false;
            }
        }
        "fanout" => {
            let Some(launch) = receipt.fields.get(FIELD_LAUNCH_REF) else {
                return false;
            };
            if !is_lower_hex(launch, 32) {
                return false;
            }
            if receipt.fields.contains_key(FIELD_ARTIFACT_REF)
                || receipt.fields.contains_key(FIELD_THREAD_REF)
            {
                return false;
            }
            if receipt.fields.len() != 3 {
                return false;
            }
        }
        "annotation" => {
            let (Some(artifact), Some(thread)) = (
                receipt.fields.get(FIELD_ARTIFACT_REF),
                receipt.fields.get(FIELD_THREAD_REF),
            ) else {
                return false;
            };
            if !is_lower_hex(artifact, 32) || !is_lower_hex(thread, 32) {
                return false;
            }
            if receipt.fields.contains_key(FIELD_LAUNCH_REF) {
                return false;
            }
            if receipt.fields.len() != 4 {
                return false;
            }
        }
        _ => return false,
    }
    true
}

/// Lands one archived hold-override receipt with its time index, preserving erase-cleared actors.
fn land_archived_hold_override_receipt_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &crate::batch::export::OwnerArchiveRestorePermit,
    row: &crate::batch::export::ArchiveRetainedSideRow,
) -> Result<crate::batch::export::archive_side_install::ArchivedSideRowOutcome> {
    use crate::batch::export::RetainedSideHeldBackReason;
    use crate::batch::export::archive_side_install::{
        ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
    };
    let (key, receipt) = match decode_archived_row(&RECEIPTS, row) {
        Ok(decoded) => decoded,
        Err(reason) => return Ok(ArchivedSideRowOutcome::HeldBack(reason)),
    };
    if !archived_hold_override_holds(&key, &receipt) {
        return Ok(ArchivedSideRowOutcome::HeldBack(
            RetainedSideHeldBackReason::InvalidValue,
        ));
    }
    let outcome = install_archived_row(&RECEIPTS, vault, txn, permit, &key, row)?;
    if matches!(
        outcome,
        ArchivedSideRowOutcome::Installed | ArchivedSideRowOutcome::Unchanged
    ) {
        BY_TIME.put(vault, txn, &(receipt.occurred_at, key), &())?;
    }
    Ok(outcome)
}

impl Vault {
    /// Lands the owner's archived hold-override receipts in input order, rebuilding only their time
    /// index.
    pub(crate) fn land_archived_attempt_queue_rows_in_txn(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        permit: &crate::batch::export::OwnerArchiveRestorePermit,
        rows: &[crate::batch::export::ArchiveRetainedSideRow],
    ) -> Result<Vec<crate::batch::export::archive_side_install::ArchivedSideRowOutcome>> {
        let mut outcomes = Vec::with_capacity(rows.len());
        for row in rows {
            outcomes.push(land_archived_hold_override_receipt_row_in_txn(
                vault, txn, permit, row,
            )?);
        }
        Ok(outcomes)
    }
}
