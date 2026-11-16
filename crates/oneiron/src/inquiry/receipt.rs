//! The asking side's `inquiry` receipt (federation.md #inquiry-keep): one
//! receipt per send of an inquiry, with the asker, the task, the question,
//! the time and the outcome, and never answer text. Kept whatever
//! `inquiry_keep` says: a member who uses the company's inquiry power to
//! probe a colleague leaves this trace. The receipt family reads it.
//!
//! The same store keeps, on the member's vault, a Share receipt for each
//! change of an inquiry edge's terms (FIX INQUIRY-STANDING-PER-KEEP): who
//! changed them, when, and the modes for each keep and the keep allowed,
//! before and after.

use std::collections::BTreeMap;
use std::ops::Bound;

use super::edge::{InquiryEdge, InquiryTermsChangeOutcome};
use super::record::{Inquiry, InquiryOutcome};
use super::terms::InquiryTerms;
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
/// A terms change's fields: the modes for each keep and the keep allowed,
/// after the change, then before it.
const FIELD_TASK_MODE: &str = "task_mode";
const FIELD_COPY_MODE: &str = "copy_mode";
const FIELD_KEEP_ALLOWED: &str = "keep_allowed";
const FIELD_PREVIOUS_TASK_MODE: &str = "previous_task_mode";
const FIELD_PREVIOUS_COPY_MODE: &str = "previous_copy_mode";
const FIELD_PREVIOUS_KEEP_ALLOWED: &str = "previous_keep_allowed";

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
    let sequence = next_sequence(store, wtxn, &format!("inquiry:{inquiry_hex}"))?;
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
    put_receipt_in_txn(store, wtxn, receipt)
}

/// Writes the receipt of `member`'s change of `edge`'s terms from
/// `previous` to the terms it now carries, at `now`, in the change's
/// transaction: a Share receipt, since the terms ride the edge's federation
/// grant. Its id is the grant's with the change's sequence; `trigger_ref`
/// names the grant row, as the grant's own share receipt does.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn write_inquiry_terms_receipt_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    edge: &InquiryEdge,
    previous: &InquiryTerms,
    member: &EntityId,
    outcome: InquiryTermsChangeOutcome,
    now: u64,
) -> Result<ReceiptRecord> {
    let grant_hex = edge.grant.to_hex();
    let sequence = next_sequence(store, wtxn, &format!("share:inquiry_terms:{grant_hex}"))?;
    let terms = &edge.terms;
    let fields = BTreeMap::from([
        (
            FIELD_TASK_MODE.to_owned(),
            terms.check_in_modes.task.as_str().to_owned(),
        ),
        (
            FIELD_COPY_MODE.to_owned(),
            terms.check_in_modes.copy.as_str().to_owned(),
        ),
        (
            FIELD_KEEP_ALLOWED.to_owned(),
            terms.keep_allowed.as_str().to_owned(),
        ),
        (
            FIELD_PREVIOUS_TASK_MODE.to_owned(),
            previous.check_in_modes.task.as_str().to_owned(),
        ),
        (
            FIELD_PREVIOUS_COPY_MODE.to_owned(),
            previous.check_in_modes.copy.as_str().to_owned(),
        ),
        (
            FIELD_PREVIOUS_KEEP_ALLOWED.to_owned(),
            previous.keep_allowed.as_str().to_owned(),
        ),
    ]);
    let receipt = ReceiptRecord {
        receipt_id: format!("share:inquiry_terms:{grant_hex}:{sequence:06}"),
        receipt_kind: ReceiptKind::Share,
        occurred_at: now,
        actor: Some(member.to_hex()),
        on_behalf_of: None,
        outcome: outcome.as_str().to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("federation_grant:{grant_hex}")),
        policy_trace: Vec::new(),
        fields,
    };
    put_receipt_in_txn(store, wtxn, receipt)
}

fn put_receipt_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    receipt: ReceiptRecord,
) -> Result<ReceiptRecord> {
    BY_TIME.put(
        store,
        wtxn,
        &(receipt.occurred_at, receipt.receipt_id.clone()),
        &(),
    )?;
    RECEIPTS.put(store, wtxn, &receipt.receipt_id, &receipt)?;
    Ok(receipt)
}

/// The sequence of the next receipt whose id starts `<head>:`: one past the
/// last such receipt's, from zero.
fn next_sequence(store: &Store, txn: &heed::RoTxn<'_>, head: &str) -> Result<u32> {
    // `;` is the byte after `:`, so the range is every `<head>:` id.
    let start = format!("{head}:");
    let end = format!("{head};");
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

/// The receipts of this store `query` names, newest first, for the receipt
/// family: each send of an inquiry (kind `inquiry`) and each change of an
/// inquiry edge's terms (kind `share`).
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
