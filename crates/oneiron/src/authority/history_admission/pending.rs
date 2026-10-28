//! Signed late evidence a local append could not store (FIX 2989, CALLS
//! "FIX 2989 pending history evidence").
//!
//! On a vault that adopted a checkpoint image, a batch of new rows whose fold
//! the image cannot answer for (a fork on a covered row it keeps no state
//! for, an op past it only the whole history folds) would leave every
//! authority read of the vault refusing for history. A batch of permissive
//! rows only is not stored then: the act refuses with the typed history
//! request, and the transaction owner keeps the rows' signed bytes here, as
//! evidence that admits nothing, so only what depends on them waits for the
//! history (identity.md, "A late pre-cutoff fork stops the affected
//! grants"). A batch with a restrictive row keeps today's path: it is stored,
//! and the vault's reads refuse until the history arrives, so no withdrawal
//! is ever held back.
//!
//! The history the rows need joins the vault's own request
//! ([`pending_history_request_in_txn`]); once a repair lands, the rows are
//! put again ([`Vault::retry_pending_authority_history`]) and leave only
//! when the fold with them answers and they are stored (CALLS
//! AUTHORITY_HISTORY_PENDING_END). The evidence survives a restore (LIVE).

use std::collections::BTreeMap;

use super::super::readonly_fold::{ArrivingFold, authority_view_with_rows_for_store_in_txn};
use super::*;
use crate::side_table::{self, Raw, SideTable};
use crate::{TimeRange, Vault};

/// Key: the row's entry hash. Value: its canonical signed bytes.
const AUTHORITY_HISTORY_PENDING: SideTable<AuthorityEntryHash, Vec<u8>, Raw> =
    SideTable::new(&side_table::AUTHORITY_HISTORY_PENDING);

/// When pending evidence leaves (CALLS AUTHORITY_HISTORY_PENDING_END): once
/// the same door stores it, never by age or count.
pub(crate) const AUTHORITY_HISTORY_PENDING_END: PendingEnd = PendingEnd::ResolvedByReferenceFold;

/// The policy hook behind [`AUTHORITY_HISTORY_PENDING_END`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingEnd {
    /// A row leaves when a put of it lands; a row still refused stays.
    ResolvedByReferenceFold,
}

/// A batch a local append keeps as evidence instead of storing it: the
/// history its fold needs, and each row's canonical signed bytes.
pub(crate) struct PendingAuthorityHistory {
    pub(crate) request: AuthorityHistoryRequest,
    rows: Vec<(AuthorityEntryHash, Vec<u8>)>,
}

/// What a local append of `staged` on `txn`'s snapshot does under the rule
/// above: `Some` where the vault adopted a checkpoint image, every row not
/// stored yet is permissive, and the fold with them in needs history; None
/// to store them as before. A fault of the fold with them in keeps today's
/// path (CALLS AUTHORITY_ADMISSION_UNKNOWN).
pub(crate) fn pending_history_of_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    staged: &[(AuthorityEntryHash, &AuthorityLogEntry)],
) -> Result<Option<PendingAuthorityHistory>> {
    Ok(pending_history_of(store, posture, txn, staged).unwrap_or(None))
}

/// [`pending_history_of_in_txn`], with its own faults returned.
fn pending_history_of(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    staged: &[(AuthorityEntryHash, &AuthorityLogEntry)],
) -> Result<Option<PendingAuthorityHistory>> {
    if super::super::checkpoint_adopt::adopted_authority_checkpoint_in_txn(store, txn)?.is_none() {
        return Ok(None);
    }
    let mut arriving = BTreeMap::new();
    for (hash, entry) in staged {
        if !super::super::retired_signers::authority_row_resident(store, txn, entry)? {
            arriving.insert(*hash, (*entry).clone());
        }
    }
    if arriving.is_empty()
        || !arriving
            .values()
            .all(|entry| super::super::ancestry_evaluator::skippable_permissive(&entry.op))
    {
        return Ok(None);
    }
    let Ok(ArrivingFold::NeedHistory(request)) =
        authority_view_with_rows_for_store_in_txn(store, posture, txn, &arriving)
    else {
        return Ok(None);
    };
    let rows = arriving
        .iter()
        .map(|(hash, entry)| Ok((*hash, encode_authority_log_entry_body(entry)?)))
        .collect::<Result<Vec<_>>>()?;
    Ok(Some(PendingAuthorityHistory { request, rows }))
}

/// Keeps `pending`'s rows as evidence in the owner's writer, after the act
/// that signed them rolled back. The authority generation moves on, so no
/// view cached before it answers for the evidence.
pub(crate) fn keep_pending_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    pending: &PendingAuthorityHistory,
) -> Result<()> {
    for (hash, bytes) in &pending.rows {
        AUTHORITY_HISTORY_PENDING.put(store, txn, hash, bytes)?;
    }
    super::super::readonly_fold::advance_authority_cache_generation(store, txn)
}

/// The pending rows, decoded, by hash. A row whose bytes do not decode to
/// its key is corruption.
fn pending_rows_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<AuthorityEntryHash, AuthorityLogEntry>> {
    AUTHORITY_HISTORY_PENDING
        .scan(store, txn)?
        .into_iter()
        .map(|(hash, bytes)| {
            let entry = decode_authority_log_entry_body(&bytes)?;
            if authority_entry_hash(&entry)? != hash {
                return Err(crate::error::Error::CorruptedIndex(
                    "authority history pending key",
                ));
            }
            Ok((hash, entry))
        })
        .collect()
}

/// The history the pending rows still need: the request of the fold with
/// them in, in `txn`'s snapshot. None with no pending row, where that fold
/// answers (the next retry stores them), or where it or the evidence read
/// fails: the vault's own request stands then, as before.
pub(crate) fn pending_history_request_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<AuthorityHistoryRequest>> {
    let Ok(pending) = pending_rows_in_txn(store, txn) else {
        return Ok(None);
    };
    if pending.is_empty() {
        return Ok(None);
    }
    Ok(
        match authority_view_with_rows_for_store_in_txn(store, posture, txn, &pending) {
            Ok(ArrivingFold::NeedHistory(request)) => Some(request),
            Ok(ArrivingFold::Complete(_)) | Err(_) => None,
        },
    )
}

impl Vault {
    /// Puts every pending row again, as one batch through the local append
    /// door (FIX 2989): once it lands, the rows leave the pending evidence;
    /// while the fold with them still needs history, or the door refuses,
    /// they stay (CALLS AUTHORITY_HISTORY_PENDING_END).
    pub(crate) fn retry_pending_authority_history(&self) -> Result<()> {
        match AUTHORITY_HISTORY_PENDING_END {
            PendingEnd::ResolvedByReferenceFold => {}
        }
        let (pending, now) = {
            let txn = self.store.env.read_txn()?;
            (
                pending_rows_in_txn(&self.store, &txn)?,
                self.instant_in_txn(&txn)?.secs(),
            )
        };
        if pending.is_empty() {
            return Ok(());
        }
        let entries: Vec<_> = pending
            .values()
            .map(|entry| {
                (
                    entry.clone(),
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                )
            })
            .collect();
        if self.put_authority_log_entries(&entries).is_err() {
            return Ok(());
        }
        let mut txn = self.store.env.write_txn()?;
        for hash in pending.keys() {
            AUTHORITY_HISTORY_PENDING.delete(&self.store, &mut txn, hash)?;
        }
        txn.commit()?;
        Ok(())
    }
}
