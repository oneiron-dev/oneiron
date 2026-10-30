//! The first-observation receipts a stored fold reads of its rows (FIX 1854,
//! OF-469): each row's first-seen seconds and sequence floor. Both receipts
//! are write-once: each has one writer, which never puts over a row, no door
//! deletes one, and a restore keeps the live vault's. So a fold past a
//! cached base takes a pinned base row's values from the base unread, and
//! reads the tail's, an arriving row's, and those of a base row whose value
//! came from the clock or the live high-water mark.

use super::*;
use crate::authority::fold_resume::{FoldBase, RowMeta};
use crate::authority::sequence_observation::authority_local_observations_receipted_in_txn;

/// The first-seen seconds and observations a stored fold folds its rows
/// under.
pub(super) struct RowReceipts {
    pub(super) first_seen_at_secs: BTreeMap<AuthorityEntryHash, u64>,
    pub(super) observations: AuthorityLocalObservations,
    /// The rows whose first-seen seconds and sequence floor came from
    /// present write-once receipts: the base a later fold resumes from
    /// carries them unread.
    pub(super) pinned: BTreeSet<AuthorityEntryHash>,
}

impl RowReceipts {
    /// `rows`' receipts, read in `txn`. An arriving row is first seen now;
    /// no sidecar records it yet.
    pub(super) fn read_in_txn(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        rows: &[RowMeta<'_>],
        arriving: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        backfilled: bool,
        now_secs: u64,
    ) -> Result<Self> {
        let mut first_seen_at_secs = BTreeMap::new();
        let mut sidecar_held = BTreeSet::new();
        for hash in rows.iter().filter_map(|row| row.hash) {
            let first_seen = if arriving.contains_key(&hash) {
                None
            } else {
                readonly_first_seen_receipt(store, txn, &hash, backfilled)?
            };
            if first_seen.is_some() {
                sidecar_held.insert(hash);
            }
            first_seen_at_secs.insert(hash, first_seen.unwrap_or(now_secs));
        }
        let (observations, receipted) =
            authority_local_observations_receipted_in_txn(store, txn, rows)?;
        Ok(Self {
            first_seen_at_secs,
            observations,
            pinned: sidecar_held.intersection(&receipted).copied().collect(),
        })
    }

    /// The receipts of `base`'s rows and `tail`'s, as [`Self::read_in_txn`]
    /// reads them: each pinned base row's from the base, and the rest read.
    /// An arriving base row reads, first seen now.
    pub(super) fn past_base_in_txn(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        base: &FoldBase,
        tail: &[(AuthorityEntryHash, &AuthorityLogEntry)],
        arriving: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        backfilled: bool,
        now_secs: u64,
    ) -> Result<Self> {
        let carried: BTreeMap<_, _> = base
            .pinned_receipts()
            .filter(|(hash, ..)| !arriving.contains_key(hash))
            .map(|(hash, first_seen, floor)| (hash, (first_seen, floor)))
            .collect();
        let rows: Vec<_> = base
            .rows_with(tail)
            .into_iter()
            .filter(|row| row.hash.is_none_or(|hash| !carried.contains_key(&hash)))
            .collect();
        let mut receipts = Self::read_in_txn(store, txn, &rows, arriving, backfilled, now_secs)?;
        for (hash, (first_seen, floor)) in carried {
            receipts.first_seen_at_secs.insert(hash, first_seen);
            if let Some(floor) = floor {
                receipts.observations.sequence_floors.insert(hash, floor);
            }
            receipts.pinned.insert(hash);
        }
        Ok(receipts)
    }
}
