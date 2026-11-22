//! The owner's history import past the owner's reserve (FIX
//! [OWNER-RESERVE-IMPORT-PARTIAL]; Engine RULING OWNER-RESERVE-IMPORT = A,
//! option B). Past the reserve under the fold's memory floor the store door
//! lands only the owner's work. The owner's import lands every row the door
//! admits and keeps each row the door holds at the reserve, with every row of
//! the import standing on one, as evidence that admits nothing: no fold reads
//! it. After each write of the observation policy, the floor row, the kept
//! rows are imported again as the owner's import, so they land once the floor
//! lets them, with no second import. Any other refusal refuses the import
//! whole, as every other import door does (the world key bundle, the
//! sealed-kit restore, the authority pages). No import passes the reserve
//! (option C stays out): a row that is not the owner's work never lands past
//! it through the owner's import.

use super::*;
use crate::authority::DoorFold;
use crate::authority::log_budget::held_at_owner_reserve_in_txn;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// Key: the row's entry hash. Value: its canonical signed bytes.
const AUTHORITY_HISTORY_RESERVE_HELD: SideTable<AuthorityEntryHash, Vec<u8>, Raw> =
    SideTable::new(&side_table::AUTHORITY_HISTORY_RESERVE_HELD);

/// How an import stages its rows.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ImportStaging {
    /// As one batch: a row the store door holds refuses the import, and
    /// nothing lands.
    Whole,
    /// The owner's import: a row the door holds at the owner's reserve is
    /// kept, with every row standing on it, and the rest land.
    HoldingAtOwnerReserve,
}

impl Vault {
    /// The owner's import of a complete signed history
    /// ([`Self::import_signed_authority_history`]). Past the owner's reserve,
    /// the rows the store door admits land, and each row it holds at the
    /// reserve is kept, with every row standing on it, until a write of the
    /// floor row lets it land ([`Self::import_owner_reserve_held_history`]).
    /// Answers the ids of the import's rows this vault holds now.
    pub(crate) fn import_owner_authority_history(
        &self,
        blobs: &[Vec<u8>],
        overlays: &CarriedOverlays,
    ) -> Result<Vec<EntityId>> {
        self.import_history_in(
            blobs,
            overlays,
            |_| Ok(()),
            |_, _| Ok(()),
            ImportStaging::HoldingAtOwnerReserve,
        )
    }

    /// Imports the rows the owner's imports kept at the reserve again, as
    /// the owner's import, after a write of the floor row: each lands once
    /// the log with it fits under the reserve's start, and the rest stay
    /// kept. A failure is logged and leaves them kept for the next write; it
    /// never fails the write that called it.
    pub(crate) fn import_owner_reserve_held_history(&self) {
        if let Err(error) = self.import_owner_reserve_held_rows() {
            tracing::warn!(
                target: "oneiron::authority::history",
                %error,
                "rows kept at the owner reserve wait for the next write of the floor row"
            );
        }
    }

    /// [`Self::import_owner_reserve_held_history`], with its faults returned.
    fn import_owner_reserve_held_rows(&self) -> Result<()> {
        let held = {
            let txn = self.store.env.read_txn()?;
            AUTHORITY_HISTORY_RESERVE_HELD.scan(&self.store, &txn)?
        };
        if held.is_empty() {
            return Ok(());
        }
        let blobs: Vec<Vec<u8>> = held.iter().map(|(_, bytes)| bytes.clone()).collect();
        // A kept sealed row's overlay record stays in AUTHORITY_OVERLAY: the
        // import that kept it staged the record in the writer it committed,
        // and the vault's own record is read first (census L5-22).
        match self.import_owner_authority_history(&blobs, &CarriedOverlays::new()) {
            Ok(_) => Ok(()),
            Err(error) if super::super::readonly_fold::is_history_incomplete(&error) => Err(error),
            // Refused for something other than the reserve, which no floor
            // row changes: the kept rows leave. Their source still holds them.
            Err(error @ Error::Record(_)) => {
                let mut txn = self.store.env.write_txn()?;
                for (hash, _) in &held {
                    AUTHORITY_HISTORY_RESERVE_HELD.delete(&self.store, &mut txn, hash)?;
                }
                txn.commit()?;
                tracing::warn!(
                    target: "oneiron::authority::history",
                    %error,
                    rows = held.len(),
                    "rows kept at the owner reserve left: their import refused"
                );
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Stages `ordered` in `txn` as the store door admits them, and answers
    /// the rows it kept: a row the door holds at the owner's reserve is left
    /// out with every row standing on it, and staging goes on past it. Any
    /// other refusal refuses the import. Rows stage in runs, each in a child
    /// writer, the first run the whole import: a run the door refuses rolls
    /// back, its rows before the refused one stage again, the refused one is
    /// judged on them, and the next run starts one row long and doubles with
    /// each run that lands, so a long run of held rows costs one row each.
    pub(super) fn stage_holding_at_owner_reserve_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        ordered: &[DecodedRow],
        resident: &BTreeSet<AuthorityEntryHash>,
        staged_rows: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        now: u64,
    ) -> Result<BTreeSet<AuthorityEntryHash>> {
        let mut held = BTreeSet::new();
        // Each row's door reads the fold beside the rows that may still land.
        let mut beside_rows = staged_rows.clone();
        let mut next = 0;
        let mut run = ordered.len();
        while next < ordered.len() {
            let mut picked = Vec::new();
            let mut end = next;
            while end < ordered.len() && picked.len() < run {
                let (hash, _, entry) = &ordered[end];
                if !resident.contains(hash)
                    && entry
                        .parent_hashes
                        .iter()
                        .any(|parent| held.contains(parent))
                {
                    held.insert(*hash);
                    beside_rows.remove(hash);
                } else {
                    picked.push(end);
                }
                end += 1;
            }
            if picked.is_empty() {
                next = end;
                continue;
            }
            let beside = || Ok(beside_rows.clone());
            let mut attempt = self.store.env.nested_write_txn(txn)?;
            let rows = import_rows(picked.iter().map(|index| &ordered[*index]), resident, now)?;
            let error = match self.stage_authority_rows_judging_re_roots_in_txn(
                &mut attempt,
                rows,
                &beside,
            ) {
                Ok(()) => {
                    attempt.commit()?;
                    next = end;
                    run = run.saturating_mul(2);
                    continue;
                }
                Err(error) => error,
            };
            drop(attempt);
            let Some(at) = refused_row(&error, ordered, &picked)? else {
                return Err(error);
            };
            let mut before = self.store.env.nested_write_txn(txn)?;
            if at > 0 {
                let rows = import_rows(
                    picked[..at].iter().map(|index| &ordered[*index]),
                    resident,
                    now,
                )?;
                self.stage_authority_rows_judging_re_roots_in_txn(&mut before, rows, &beside)?;
            }
            let (hash, _, entry) = &ordered[picked[at]];
            let fold = DoorFold::Snapshot(self.privacy_posture(), Some(&beside));
            if !held_at_owner_reserve_in_txn(&self.store, &before, entry, fold)? {
                return Err(error);
            }
            before.commit()?;
            held.insert(*hash);
            beside_rows.remove(hash);
            next = picked[at] + 1;
            run = 1;
        }
        Ok(held)
    }
}

/// The place in `picked`, indices into `ordered`, of the row `error` says
/// the store door held at a bound, when it names one of them.
fn refused_row(error: &Error, ordered: &[DecodedRow], picked: &[usize]) -> Result<Option<usize>> {
    let Error::Record(RecordError::AuthorityLogFull { id, .. }) = error else {
        return Ok(None);
    };
    for (at, index) in picked.iter().enumerate() {
        if authority_log_entity_id_from_hash(&ordered[*index].0)? == *id {
            return Ok(Some(at));
        }
    }
    Ok(None)
}

/// Keeps the owner's import's `held` rows as evidence in its writer, and lets
/// every other row of `ordered` leave the evidence: the import holds it now.
/// So does each row the import `left_out` as one the source's fold never
/// applied (H72), which no import of it lands.
pub(super) fn keep_held_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    ordered: &[DecodedRow],
    held: &BTreeSet<AuthorityEntryHash>,
    left_out: &BTreeSet<AuthorityEntryHash>,
) -> Result<()> {
    for (hash, bytes, _) in ordered {
        if held.contains(hash) {
            AUTHORITY_HISTORY_RESERVE_HELD.put(store, txn, hash, bytes)?;
        } else {
            AUTHORITY_HISTORY_RESERVE_HELD.delete(store, txn, hash)?;
        }
    }
    for hash in left_out {
        AUTHORITY_HISTORY_RESERVE_HELD.delete(store, txn, hash)?;
    }
    Ok(())
}
