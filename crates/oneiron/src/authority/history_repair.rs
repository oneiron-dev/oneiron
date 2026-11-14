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

use super::history_transfer::{
    AdoptedPrefix, DecodedRow, PageVerdict, decode_page_in_txn, history_in_txn, page_root,
};

/// Key: the row's entry hash. Value: its original signed bytes. Device-local
/// repair progress: no image carries it.
const AUTHORITY_HISTORY_STAGE: SideTable<AuthorityEntryHash, Vec<u8>, Raw> =
    SideTable::new(&side_table::AUTHORITY_HISTORY_STAGE);

/// The sealed overlay row of a staged sealed body (census L5-22 1a-ii),
/// staged in the same writer that stages the body and dropped with it when
/// the stage drops the row without landing it: the side table's own rows,
/// read here only to delete them.
const AUTHORITY_OVERLAY: SideTable<AuthorityEntryHash, Vec<u8>, Raw> =
    SideTable::new(&side_table::AUTHORITY_OVERLAY);

/// Whether AUTHORITY_LOG holds the row of `hash` itself, read from the
/// stored envelope alone, without opening any overlay: the entity id
/// truncates the hash, so the stored body's BLAKE3 must equal `hash`, and a
/// sealed row counts as held even when its record does not open here.
fn authority_log_holds_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    hash: &AuthorityEntryHash,
) -> Result<bool> {
    let id = authority_log_entity_id_from_hash(hash)?;
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
        return Ok(false);
    };
    let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
        return Ok(false);
    };
    if header.entity_type != crate::registry::ENTITY_TYPE_AUTHORITY_LOG {
        return Ok(false);
    }
    let Some(body) = raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..) else {
        return Ok(false);
    };
    Ok(*blake3::hash(body).as_bytes() == *hash)
}

/// What one repair page did ([`Vault::import_signed_authority_repair_page`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityRepairOutcome {
    /// The page, with every row staged before it, closed the missing history
    /// and landed: the rows written, and the rows refused for standing on a
    /// key a handoff retired, which left the page and the stage.
    Applied {
        written: Vec<EntityId>,
        refused: BTreeSet<AuthorityEntryHash>,
    },
    /// The history is still incomplete: the page's rows wait in the stage,
    /// not in the log, and the request names what is still missing, staged
    /// rows counted as fetched. `refused` as for `Applied`.
    Staged {
        request: AuthorityHistoryRequest,
        refused: BTreeSet<AuthorityEntryHash>,
    },
}

/// The staged rows, decoded, in hash order.
pub(super) fn staged_rows_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Vec<DecodedRow>> {
    AUTHORITY_HISTORY_STAGE
        .scan(store, txn)?
        .into_iter()
        .map(|(hash, bytes)| {
            let entry = open_vault_authority_body_in_txn(store, txn, &bytes)?;
            if authority_entry_hash(&entry)? != hash {
                return Err(crate::error::Error::CorruptedIndex(
                    "authority history stage key",
                ));
            }
            Ok((hash, bytes, entry))
        })
        .collect()
}

/// Empties the stage in the caller's writer, once its rows landed, dropping
/// each cleared row's staged overlay row with it unless AUTHORITY_LOG holds
/// that hash (a landed row keeps its overlay).
pub(super) fn clear_stage_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    for hash in AUTHORITY_HISTORY_STAGE.scan_keys(store, txn, &[])? {
        AUTHORITY_HISTORY_STAGE.delete(store, txn, &hash)?;
        if !authority_log_holds_in_txn(store, txn, &hash)? {
            AUTHORITY_OVERLAY.delete(store, txn, &hash)?;
        }
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
    /// ([`Self::authority_staged_history`]) as fetched. A row that stands on
    /// a key a handoff retired leaves the page and the stage with every row
    /// standing on it, and the rest is tried again. Any other refusal stages
    /// nothing.
    pub fn import_signed_authority_repair_page(
        &self,
        blobs: &[Vec<u8>],
        overlays: &CarriedOverlays,
    ) -> Result<AuthorityRepairOutcome> {
        let rtxn = self.store.env.read_txn()?;
        let mut decoded = decode_page_in_txn(&self.store, &rtxn, blobs, overlays)?;
        drop(rtxn);
        let mut refused = BTreeSet::new();
        loop {
            match self.import_page_in(decoded.clone(), true, overlays) {
                // The evidence a local append kept waiting on this history
                // is put again by the landing commit itself (FIX 2989).
                Ok(PageVerdict::Landed(written)) => {
                    return Ok(AuthorityRepairOutcome::Applied { written, refused });
                }
                Ok(PageVerdict::Retired(hash)) => {
                    let dropped = self.drop_from_stage(hash, &decoded)?;
                    decoded.retain(|(hash, _, _)| !dropped.contains(hash));
                    refused.extend(dropped);
                }
                Err(error) => {
                    let Some(needed) = super::readonly_fold::history_required_request(&error)
                    else {
                        return Err(error);
                    };
                    let request = self.stage_repair_rows(&decoded, needed, overlays)?;
                    return Ok(AuthorityRepairOutcome::Staged { request, refused });
                }
            }
        }
    }

    /// Drops `refused` and every page or staged row standing on it from the
    /// stage, and answers them all, dropping each pruned row's staged overlay
    /// row with it unless AUTHORITY_LOG holds that hash.
    fn drop_from_stage(
        &self,
        refused: AuthorityEntryHash,
        decoded: &[DecodedRow],
    ) -> Result<BTreeSet<AuthorityEntryHash>> {
        let mut txn = self.store.env.write_txn()?;
        let staged = staged_rows_in_txn(&self.store, &txn)?;
        let mut dropped = BTreeSet::from([refused]);
        loop {
            let before = dropped.len();
            for (hash, _, entry) in staged.iter().chain(decoded) {
                if entry
                    .parent_hashes
                    .iter()
                    .any(|parent| dropped.contains(parent))
                {
                    dropped.insert(*hash);
                }
            }
            if dropped.len() == before {
                break;
            }
        }
        for (hash, _, _) in &staged {
            if dropped.contains(hash) {
                AUTHORITY_HISTORY_STAGE.delete(&self.store, &mut txn, hash)?;
                if !authority_log_holds_in_txn(&self.store, &txn, hash)? {
                    AUTHORITY_OVERLAY.delete(&self.store, &mut txn, hash)?;
                }
            }
        }
        txn.commit()?;
        Ok(dropped)
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
    /// new row's parents held, staged or earlier beside it. On a vault that
    /// adopted a checkpoint image, its pin's genesis is the genesis and its
    /// covered rows are held for that check ([`AdoptedPrefix`]).
    ///
    /// The request is this vault's own, plus what the import that refused
    /// named (`needed`): its fold or door judged the log with this page and
    /// the stage in it. Past those checks every waiting row's parents are
    /// held, waiting or covered, so on an adopted vault a covered parent is
    /// asked for only when that fold or door needs its row, never because a
    /// waiting row names it.
    fn stage_repair_rows(
        &self,
        decoded: &[DecodedRow],
        needed: AuthorityHistoryRequest,
        overlays: &CarriedOverlays,
    ) -> Result<AuthorityHistoryRequest> {
        let mut txn = self.store.env.write_txn()?;
        let mut merged = history_in_txn(self, &txn)?;
        let resident: BTreeSet<AuthorityEntryHash> = merged.keys().copied().collect();
        let staged = staged_rows_in_txn(&self.store, &txn)?;
        for (hash, bytes, entry) in staged.iter().chain(decoded) {
            merged
                .entry(*hash)
                .or_insert_with(|| (bytes.clone(), entry.clone()));
        }
        let adopted =
            super::checkpoint_adopt::cached_adopted_authority_checkpoint_in_txn(&self.store, &txn)?;
        page_root(
            &merged,
            &resident,
            adopted.as_deref().map(AdoptedPrefix::of),
        )?
        .ok_or_else(invalid_authority)?;
        stage_carried_overlays_in_txn(
            &self.store,
            &mut txn,
            decoded
                .iter()
                .filter(|(hash, _, _)| !resident.contains(hash))
                .map(|(_, bytes, _)| bytes.as_slice()),
            overlays,
        )?;
        for (hash, bytes, entry) in decoded {
            if resident.contains(hash) {
                continue;
            }
            let opened = open_vault_authority_body_in_txn(&self.store, &txn, bytes)?;
            if opened != *entry || authority_entry_hash(&opened)? != *hash {
                return Err(invalid_authority());
            }
            verify_entry_signatures(&opened)?;
            AUTHORITY_HISTORY_STAGE.put(&self.store, &mut txn, hash, bytes)?;
        }
        let waiting: BTreeSet<AuthorityEntryHash> = merged
            .keys()
            .filter(|hash| !resident.contains(*hash))
            .copied()
            .collect();
        let mut request = super::history_coverage::authority_missing_history_in_txn(
            &self.store,
            self.privacy_posture(),
            &txn,
        )?;
        request.missing.extend(needed.missing);
        request
            .missing
            .retain(|hash| !resident.contains(hash) && !waiting.contains(hash));
        txn.commit()?;
        Ok(request)
    }
}
