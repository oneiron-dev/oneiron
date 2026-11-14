//! The asking side's `inquiry` receipt (federation.md #inquiry-keep): one
//! receipt per send of an inquiry, with the asker, the task, the question,
//! the time and the outcome, and never answer text. Kept whatever
//! `inquiry_keep` says: a member who uses the company's inquiry power to
//! probe a colleague leaves this trace. The receipt family reads it.

use std::collections::BTreeMap;
use std::ops::Bound;

use super::record::{Inquiry, InquiryOutcome};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord, retain_newest_receipt};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;

/// Receipt id → the send's receipt, as the receipt family reads it.
const RECEIPTS: SideTable<String, ReceiptRecord, Named> =
    SideTable::new(&side_table::INQUIRY_RECEIPT);
/// Time and receipt id → a presence marker.
const BY_TIME: SideTable<(u64, String), (), Raw> =
    SideTable::new(&side_table::INQUIRY_RECEIPT_BY_TIME);

/// The member asked about: the asking vault's row for the member, 32 hex.
const FIELD_MEMBER: &str = "member";
const FIELD_QUESTION: &str = "question";
const FIELD_PURPOSE: &str = "purpose";
const FIELD_KEEP: &str = "keep";
const FIELD_EXPIRES_AT: &str = "expires_at";

/// Writes the receipt of one send of `inquiry` about `member` that came to
/// `outcome` at `now`, in the send's transaction. Its id is the inquiry's
/// with the send's sequence; `job_ref` names the inquiry and `trigger_ref`
/// the task. It takes the outcome only, so no answer text can reach it.
///
/// # Errors
///
/// An invalid inquiry; storage errors.
pub(crate) fn write_inquiry_receipt_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    inquiry: &Inquiry,
    member: &EntityId,
    outcome: InquiryOutcome,
    now: u64,
) -> Result<ReceiptRecord> {
    inquiry.validate()?;
    let inquiry_hex = inquiry.id.to_hex();
    let sequence = next_send_sequence(store, wtxn, &inquiry_hex)?;
    let fields = BTreeMap::from([
        (FIELD_MEMBER.to_owned(), member.to_hex()),
        (FIELD_QUESTION.to_owned(), inquiry.question.clone()),
        (FIELD_PURPOSE.to_owned(), inquiry.task.purpose.clone()),
        (FIELD_KEEP.to_owned(), inquiry.keep.as_str().to_owned()),
        (FIELD_EXPIRES_AT.to_owned(), inquiry.expires_at.to_string()),
    ]);
    let receipt = ReceiptRecord {
        receipt_id: format!("inquiry:{inquiry_hex}:{sequence:06}"),
        receipt_kind: ReceiptKind::Inquiry,
        occurred_at: now,
        actor: Some(inquiry.from.actor.to_hex()),
        on_behalf_of: None,
        outcome: outcome.as_str().to_owned(),
        job_ref: Some(inquiry_hex),
        trigger_ref: Some(inquiry.task.id.to_hex()),
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
    Ok(receipt)
}

/// The sequence of the next send of the inquiry `inquiry_hex`: one past the
/// last receipt's, from zero.
fn next_send_sequence(store: &Store, txn: &heed::RoTxn<'_>, inquiry_hex: &str) -> Result<u32> {
    // `;` is the byte after `:`, so the range is every `inquiry:<hex>:` id.
    let start = format!("inquiry:{inquiry_hex}:");
    let end = format!("inquiry:{inquiry_hex};");
    let last = RECEIPTS
        .iter_rev_range(store, txn, Bound::Included(&start), Bound::Excluded(&end))?
        .next()
        .transpose()?;
    let Some((id, _)) = last else {
        return Ok(0);
    };
    id.strip_prefix(&start)
        .and_then(|sequence| sequence.parse::<u32>().ok())
        .ok_or(Error::CorruptedIndex("inquiry receipt id"))?
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("inquiry receipt sequence"))
}

/// The inquiry receipts `query` names, newest first, for the receipt family.
///
/// # Errors
///
/// A time index row whose receipt is missing; storage errors.
pub(crate) fn inquiry_receipts(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
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
        b"inquiry",
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
            return Err(Error::CorruptedIndex("inquiry receipt time index"));
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
/// no inquiry receipt names `actor` any more, neither as the asker nor as
/// the member asked about. The receipt and the send it records stand.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_inquiry_receipt_actor_in_txn(
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
        if row.fields.get(FIELD_MEMBER) == Some(&hex) {
            row.fields.remove(FIELD_MEMBER);
            changed = true;
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

/// Whether a decoded inquiry receipt keeps the writer's pure row invariants.
fn archived_inquiry_holds(key: &str, receipt: &ReceiptRecord) -> bool {
    if key != receipt.receipt_id {
        return false;
    }
    if receipt.receipt_kind != ReceiptKind::Inquiry {
        return false;
    }
    match receipt.outcome.as_str() {
        "answered" | "no_answer" | "pending" | "unavailable" => {}
        _ => return false,
    }
    if receipt.on_behalf_of.is_some() {
        return false;
    }
    if !receipt.policy_trace.is_empty() {
        return false;
    }
    let Some(rest) = receipt.receipt_id.strip_prefix("inquiry:") else {
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
    let Some(trigger) = receipt.trigger_ref.as_deref() else {
        return false;
    };
    if !is_lower_hex(trigger, 32) {
        return false;
    }
    if let Some(member) = receipt.fields.get(FIELD_MEMBER)
        && !is_lower_hex(member, 32)
    {
        return false;
    }
    let Some(question) = receipt.fields.get(FIELD_QUESTION) else {
        return false;
    };
    if question.trim().is_empty() {
        return false;
    }
    let Some(purpose) = receipt.fields.get(FIELD_PURPOSE) else {
        return false;
    };
    if purpose.trim().is_empty() || purpose.contains('\n') {
        return false;
    }
    let Some(keep) = receipt.fields.get(FIELD_KEEP) else {
        return false;
    };
    if keep != "task" && keep != "copy" {
        return false;
    }
    let Some(expires) = receipt.fields.get(FIELD_EXPIRES_AT) else {
        return false;
    };
    let Ok(expires) = expires.parse::<u64>() else {
        return false;
    };
    if expires == 0 {
        return false;
    }
    if receipt.fields.len() > 5 || receipt.fields.len() < 4 {
        return false;
    }
    for name in receipt.fields.keys() {
        if name != FIELD_MEMBER
            && name != FIELD_QUESTION
            && name != FIELD_PURPOSE
            && name != FIELD_KEEP
            && name != FIELD_EXPIRES_AT
        {
            return false;
        }
    }
    true
}

/// Lands one archived inquiry receipt with its time index, preserving erase-removed members.
fn land_archived_inquiry_receipt_row_in_txn(
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
    if !archived_inquiry_holds(&key, &receipt) {
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
    /// Lands the owner's archived inquiry receipts in input order, rebuilding only their time
    /// index.
    pub(crate) fn land_archived_inquiry_rows_in_txn(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        permit: &crate::batch::export::OwnerArchiveRestorePermit,
        rows: &[crate::batch::export::ArchiveRetainedSideRow],
    ) -> Result<Vec<crate::batch::export::archive_side_install::ArchivedSideRowOutcome>> {
        let mut outcomes = Vec::with_capacity(rows.len());
        for row in rows {
            outcomes.push(land_archived_inquiry_receipt_row_in_txn(
                vault, txn, permit, row,
            )?);
        }
        Ok(outcomes)
    }
}
