//! Staged repair of missing authority history (OF-469).
//!
//! A vault whose fold needs history it does not hold admits nothing until an
//! import closes the whole gap, and no one page has to carry it: a repair
//! page that leaves the history incomplete waits in a stage, never in the
//! log. Staged rows are checked as bytes (canonical, signed, one genesis and
//! vault, parents held, staged or beside them) but admit nothing and count
//! as no held history. Each later repair page arrives with every staged row,
//! and once together they close the gap they land as one import, judged as
//! that import is, and the stage empties.

use std::collections::BTreeSet;

use super::*;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault, error::Result};

use super::history_transfer::{DecodedRow, decode_page, history_in_txn, page_root};

/// Key: the row's entry hash. Value: its original signed bytes. Device-local
/// repair progress: no image carries it.
const AUTHORITY_HISTORY_STAGE: SideTable<AuthorityEntryHash, Vec<u8>, Raw> =
    SideTable::new(&side_table::AUTHORITY_HISTORY_STAGE);

/// What one repair page did ([`Vault::import_signed_authority_repair_page`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityRepairOutcome {
    /// The page, with every row staged before it, closed the missing history
    /// and landed: the rows written.
    Applied(Vec<EntityId>),
    /// The history is still incomplete: the page's rows wait in the stage,
    /// not in the log, and the request names what is still missing, staged
    /// rows counted as fetched.
    Staged(AuthorityHistoryRequest),
}

/// The staged rows, decoded, in hash order.
pub(super) fn staged_rows_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Vec<DecodedRow>> {
    AUTHORITY_HISTORY_STAGE
        .scan(store, txn)?
        .into_iter()
        .map(|(hash, bytes)| {
            let entry = decode_authority_log_entry_body(&bytes)?;
            if authority_entry_hash(&entry)? != hash {
                return Err(crate::error::Error::CorruptedIndex(
                    "authority history stage key",
                ));
            }
            Ok((hash, bytes, entry))
        })
        .collect()
}

/// Empties the stage in the caller's writer, once its rows landed.
pub(super) fn clear_stage_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    for hash in AUTHORITY_HISTORY_STAGE.scan_keys(store, txn, &[])? {
        AUTHORITY_HISTORY_STAGE.delete(store, txn, &hash)?;
    }
    Ok(())
}

impl Vault {
    /// [`Self::import_signed_authority_page`] for a repair: the page arrives
    /// with every row staged before it. When together they close this
    /// vault's missing history, they land as that door lands them, retired
    /// standing judged against the fold they complete, and the stage
    /// empties. When the history is still incomplete, the page's new rows
    /// are staged instead, checked as bytes only, and the request names what
    /// is still missing; delivery fetches that next, naming the staged rows
    /// ([`Self::authority_staged_history`]) as fetched. Any other refusal
    /// stages nothing.
    pub fn import_signed_authority_repair_page(
        &self,
        blobs: &[Vec<u8>],
    ) -> Result<AuthorityRepairOutcome> {
        let decoded = decode_page(blobs)?;
        match self.import_page_in(decoded.clone(), true) {
            Ok(ids) => Ok(AuthorityRepairOutcome::Applied(ids)),
            Err(error) if super::readonly_fold::is_history_incomplete(&error) => self
                .stage_repair_rows(&decoded)
                .map(AuthorityRepairOutcome::Staged),
            Err(error) => Err(error),
        }
    }

    /// The rows a repair staged and the log does not hold yet. They are no
    /// held history: delivery names them only as fetched.
    pub fn authority_staged_history(&self) -> Result<BTreeSet<AuthorityEntryHash>> {
        let txn = self.store.env.read_txn()?;
        Ok(AUTHORITY_HISTORY_STAGE
            .scan_keys(&self.store, &txn, &[])?
            .into_iter()
            .collect())
    }

    /// Stages `decoded`'s rows the log does not hold, after the byte checks
    /// a page passes before any fold: canonical bytes and signatures, one
    /// genesis and vault across the log, the stage and the page, and each
    /// new row's parents held, staged or earlier beside it.
    fn stage_repair_rows(&self, decoded: &[DecodedRow]) -> Result<AuthorityHistoryRequest> {
        let mut txn = self.store.env.write_txn()?;
        let mut merged = history_in_txn(self, &txn)?;
        let resident: BTreeSet<AuthorityEntryHash> = merged.keys().copied().collect();
        let staged = staged_rows_in_txn(&self.store, &txn)?;
        for (hash, bytes, entry) in staged.iter().chain(decoded) {
            merged
                .entry(*hash)
                .or_insert_with(|| (bytes.clone(), entry.clone()));
        }
        page_root(&merged, &resident)?.ok_or_else(invalid_authority)?;
        for (hash, bytes, entry) in decoded {
            if resident.contains(hash) {
                continue;
            }
            validate_authority_log_entry_body_bytes(bytes)?;
            verify_entry_signatures(entry)?;
            AUTHORITY_HISTORY_STAGE.put(&self.store, &mut txn, hash, bytes)?;
        }
        let waiting: BTreeSet<AuthorityEntryHash> = merged
            .keys()
            .filter(|hash| !resident.contains(*hash))
            .copied()
            .collect();
        let mut request =
            super::history_coverage::authority_missing_history_in_txn(&self.store, &txn)?;
        for hash in &waiting {
            if let Some((_, entry)) = merged.get(hash) {
                request.missing.extend(entry.parent_hashes.iter().copied());
            }
        }
        request
            .missing
            .retain(|hash| !resident.contains(hash) && !waiting.contains(hash));
        txn.commit()?;
        Ok(request)
    }
}
