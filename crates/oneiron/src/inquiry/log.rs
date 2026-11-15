//! "Asked about you" (federation.md #inquiry-keep): the member vault's own
//! full log of the inquiries companies sent it. One row per inquiry and
//! inquiry edge holds the inquiry, its current answer and who decided it.
//!
//! The row's answer is the one wire projection ([`InquiryAnswer`]): a repeat
//! of the inquiry returns it as it stands, and who decided never crosses.

use std::ops::Bound;

use serde::{Deserialize, Serialize};

use super::record::{Inquiry, InquiryAnswer, InquiryOutcome, refuse};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;

/// Inquiry edge and inquiry → the log row.
const LOG: SideTable<(EntityId, EntityId), InquiryLogEntry, Named> =
    SideTable::new(&side_table::INQUIRY_LOG);
/// Time received, inquiry edge and inquiry → a presence marker.
const BY_TIME: SideTable<(u64, EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::INQUIRY_LOG_BY_TIME);

#[doc(hidden)]
pub use oneiron_records::inquiry::log::InquiryDecider;

/// One row of "Asked about you".
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InquiryLogEntry {
    /// The inquiry edge it came over: the grant on this vault.
    pub edge: EntityId,
    pub inquiry: Inquiry,
    pub received_at: u64,
    /// The current answer: `pending` until the ladder settles it.
    pub answer: InquiryAnswer,
    pub decided_by: Option<InquiryDecider>,
    pub decided_at: Option<u64>,
}

/// Logs `inquiry`, received over `edge` at `now`, with the answer `pending`,
/// and returns its row. A repeat of a logged inquiry returns its row as it
/// stands and writes nothing.
///
/// # Errors
///
/// An invalid inquiry; a repeat whose content differs from the logged
/// inquiry; storage errors.
pub(crate) fn log_inquiry_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    edge: EntityId,
    inquiry: &Inquiry,
    now: u64,
) -> Result<InquiryLogEntry> {
    inquiry.validate()?;
    let key = (edge, inquiry.id);
    if let Some(entry) = LOG.get(store, wtxn, &key)? {
        if entry.inquiry != *inquiry {
            return Err(refuse("a repeat of the inquiry id carries another inquiry"));
        }
        return Ok(entry);
    }
    let entry = InquiryLogEntry {
        edge,
        inquiry: inquiry.clone(),
        received_at: now,
        answer: InquiryAnswer::pending(inquiry),
        decided_by: None,
        decided_at: None,
    };
    BY_TIME.put(store, wtxn, &(now, edge, inquiry.id), &())?;
    LOG.put(store, wtxn, &key, &entry)?;
    Ok(entry)
}

/// Settles the pending inquiry `inquiry_id` over `edge` with `answer`, which
/// `decided_by` decided at `now`, and returns its row. A settled row does not
/// change again.
///
/// # Errors
///
/// No such row; a row already settled; an answer that is neither
/// `answered` nor `no_answer`, or that answers another inquiry or keep;
/// storage errors.
pub(crate) fn settle_inquiry_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    edge: EntityId,
    inquiry_id: EntityId,
    answer: InquiryAnswer,
    decided_by: InquiryDecider,
    now: u64,
) -> Result<InquiryLogEntry> {
    let key = (edge, inquiry_id);
    let Some(mut entry) = LOG.get(store, wtxn, &key)? else {
        return Err(refuse("no logged inquiry to settle"));
    };
    if entry.answer.outcome() != InquiryOutcome::Pending {
        return Err(refuse("the inquiry is already settled"));
    }
    if !matches!(
        answer.outcome(),
        InquiryOutcome::Answered | InquiryOutcome::NoAnswer
    ) {
        return Err(refuse(
            "a member's vault settles an inquiry as answered or no_answer",
        ));
    }
    if !answer.answers(&entry.inquiry) {
        return Err(refuse("the answer is for another inquiry or keep"));
    }
    entry.answer = answer;
    entry.decided_by = Some(decided_by);
    entry.decided_at = Some(now);
    LOG.put(store, wtxn, &key, &entry)?;
    Ok(entry)
}

/// The logged inquiry `inquiry_id` over `edge`, as it stands in `txn`.
///
/// # Errors
///
/// Storage errors.
pub(super) fn inquiry_log_entry_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    edge: EntityId,
    inquiry_id: EntityId,
) -> Result<Option<InquiryLogEntry>> {
    LOG.get(store, txn, &(edge, inquiry_id))
}

impl Vault {
    /// "Asked about you": every logged inquiry, newest first.
    ///
    /// # Errors
    ///
    /// A time index row whose log row is missing; storage errors.
    pub fn inquiry_log(&self) -> Result<Vec<InquiryLogEntry>> {
        let txn = self.store.env.read_txn()?;
        let mut out = Vec::new();
        for row in BY_TIME.iter_rev_range(&self.store, &txn, Bound::Unbounded, Bound::Unbounded)? {
            let ((_, edge, inquiry), ()) = row?;
            let Some(entry) = LOG.get(&self.store, &txn, &(edge, inquiry))? else {
                return Err(Error::CorruptedIndex("inquiry log time index"));
            };
            out.push(entry);
        }
        Ok(out)
    }

    /// The logged inquiry `inquiry_id` over `edge`, as it stands.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn inquiry_log_entry(
        &self,
        edge: &EntityId,
        inquiry_id: &EntityId,
    ) -> Result<Option<InquiryLogEntry>> {
        let txn = self.store.env.read_txn()?;
        inquiry_log_entry_in_txn(&self.store, &txn, *edge, *inquiry_id)
    }
}

/// The table's actor scrub (an actor's erase, and a restore's rerun of it):
/// no log row names `actor` as the member who decided. The row and its
/// answer stand.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_inquiry_log_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let mut rows = Vec::new();
    for (key, mut row) in LOG.scan(&vault.store, wtxn)? {
        if let Some(InquiryDecider::Member { principal }) = &mut row.decided_by
            && *principal == Some(*actor)
        {
            *principal = None;
            rows.push((key, row));
        }
    }
    for (key, row) in rows {
        LOG.put(&vault.store, wtxn, &key, &row)?;
    }
    Ok(())
}
