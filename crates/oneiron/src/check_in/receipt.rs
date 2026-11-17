//! The `check_in` receipt (Engine ruling P22-SHAPE Q8 = A): one receipt per
//! transition of a pending check-in, written in the transition's own
//! transaction to its own store, which the receipt family reads.

use std::collections::BTreeMap;
use std::ops::Bound;

use super::pending::PendingCheckIn;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord, retain_newest_receipt};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;

/// Receipt id → the transition's receipt, as the receipt family reads it.
const RECEIPTS: SideTable<String, ReceiptRecord, Named> =
    SideTable::new(&side_table::CHECK_IN_RECEIPT);
/// Time and receipt id → a presence marker.
const BY_TIME: SideTable<(u64, String), (), Raw> =
    SideTable::new(&side_table::CHECK_IN_RECEIPT_BY_TIME);

/// What one transition did: the receipt's outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CheckInOutcome {
    Opened,
    Climbed,
    Skipped,
    Extended,
    Answered,
    LetGo,
    Held,
    ProceedWithUndo,
    WindowPassed,
    ObjectionHeld,
    Consumed,
}

impl CheckInOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Opened => "opened",
            Self::Climbed => "climbed",
            Self::Skipped => "skipped",
            Self::Extended => "extended",
            Self::Answered => "answered",
            Self::LetGo => "let_go",
            Self::Held => "held",
            Self::ProceedWithUndo => "proceed_with_undo",
            Self::WindowPassed => "window_passed",
            Self::ObjectionHeld => "objection_held",
            Self::Consumed => "consumed",
        }
    }
}

/// A receipt's fields: the pending check-in and its act class, then what
/// the transition adds.
pub(super) struct ReceiptFields(BTreeMap<String, String>);

impl ReceiptFields {
    pub(super) fn new(row: &PendingCheckIn) -> Self {
        Self(BTreeMap::from([
            ("pending".to_owned(), row.id.to_hex()),
            ("act_class".to_owned(), row.act.as_str().to_owned()),
        ]))
    }

    pub(super) fn with(mut self, name: &str, value: String) -> Self {
        self.0.insert(name.to_owned(), value);
        self
    }
}

/// Writes the receipt of one transition of `row` at `now`, under `actor`
/// (the asker who opened it, the holder who answered or extended; `None`
/// for a transition by time), and moves the row's receipt sequence.
pub(super) fn write_check_in_receipt_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    row: &mut PendingCheckIn,
    outcome: CheckInOutcome,
    actor: Option<EntityId>,
    fields: ReceiptFields,
    now: u64,
) -> Result<()> {
    let pending = row.id.to_hex();
    let receipt = ReceiptRecord {
        receipt_id: format!("check_in:{pending}:{:06}", row.transitions),
        receipt_kind: ReceiptKind::CheckIn,
        occurred_at: now,
        actor: actor.as_ref().map(EntityId::to_hex),
        on_behalf_of: None,
        outcome: outcome.as_str().to_owned(),
        job_ref: Some(pending),
        trigger_ref: None,
        policy_trace: Vec::new(),
        fields: fields.0,
    };
    row.transitions = row
        .transitions
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("check-in receipt sequence"))?;
    BY_TIME.put(
        store,
        wtxn,
        &(receipt.occurred_at, receipt.receipt_id.clone()),
        &(),
    )?;
    RECEIPTS.put(store, wtxn, &receipt.receipt_id, &receipt)
}

/// The check-in receipts `query` names, newest first, for the receipt
/// family.
///
/// # Errors
///
/// A time index row whose receipt is missing; storage errors.
pub(crate) fn check_in_receipts(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
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
        b"check_in",
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
            return Err(Error::CorruptedIndex("check-in receipt time index"));
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
/// every check-in receipt names the actor nowhere any more, neither as its
/// actor nor in a field. The receipt and the transition it records stand.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_check_in_receipt_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let hex = actor.to_hex();
    let mut rows = Vec::new();
    for (key, mut row) in RECEIPTS.scan(&vault.store, wtxn)? {
        let mut changed = false;
        if row.actor.as_deref() == Some(hex.as_str()) {
            row.actor = None;
            changed = true;
        }
        for value in row.fields.values_mut() {
            if value.split(',').any(|part| part == hex) {
                *value = value
                    .split(',')
                    .filter(|part| *part != hex)
                    .collect::<Vec<_>>()
                    .join(",");
                changed = true;
            }
        }
        if changed {
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

/// Whether a decoded check-in receipt keeps the writer's pure row invariants.
fn archived_check_in_holds(key: &str, receipt: &ReceiptRecord) -> bool {
    if key != receipt.receipt_id {
        return false;
    }
    if receipt.receipt_kind != ReceiptKind::CheckIn {
        return false;
    }
    match receipt.outcome.as_str() {
        "opened" | "climbed" | "skipped" | "extended" | "answered" | "let_go" | "held"
        | "proceed_with_undo" | "window_passed" | "objection_held" => {}
        _ => return false,
    }
    if receipt.on_behalf_of.is_some() {
        return false;
    }
    if receipt.trigger_ref.is_some() {
        return false;
    }
    if !receipt.policy_trace.is_empty() {
        return false;
    }
    let Some(rest) = receipt.receipt_id.strip_prefix("check_in:") else {
        return false;
    };
    let Some((hex, seq)) = rest.split_once(':') else {
        return false;
    };
    if !is_lower_hex(hex, 32) {
        return false;
    }
    let Ok(number) = seq.parse::<u32>() else {
        return false;
    };
    if seq != format!("{number:06}") {
        return false;
    }
    if receipt.job_ref.as_deref() != Some(hex) {
        return false;
    }
    let Some(pending) = receipt.fields.get("pending") else {
        return false;
    };
    if pending != hex {
        return false;
    }
    let Some(act) = receipt.fields.get("act_class") else {
        return false;
    };
    if act.is_empty() {
        return false;
    }
    true
}

/// Lands one archived check-in receipt with its time index, never touching PENDING rows.
fn land_archived_check_in_receipt_row_in_txn(
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
    if !archived_check_in_holds(&key, &receipt) {
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
    /// Lands the owner's archived check-in receipts in input order, rebuilding only their time
    /// index.
    pub(crate) fn land_archived_check_in_rows_in_txn(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        permit: &crate::batch::export::OwnerArchiveRestorePermit,
        rows: &[crate::batch::export::ArchiveRetainedSideRow],
    ) -> Result<Vec<crate::batch::export::archive_side_install::ArchivedSideRowOutcome>> {
        let mut outcomes = Vec::with_capacity(rows.len());
        for row in rows {
            outcomes.push(land_archived_check_in_receipt_row_in_txn(
                vault, txn, permit, row,
            )?);
        }
        Ok(outcomes)
    }
}
