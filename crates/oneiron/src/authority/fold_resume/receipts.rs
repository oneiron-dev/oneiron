//! The receipts a base folded its rows under: what a fold past it reads
//! again and what it carries unread (FIX 1854, FIX 12282).

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// The first-seen seconds and sequence floors a base folded its rows under,
/// and which of them are write-once receipts' (FIX 1854).
pub(super) struct BaseReceipts {
    pub(super) first_seen: RowSeconds,
    pub(super) floors: RowSeconds,
    /// The rows whose first-seen seconds and floor are write-once receipts':
    /// a fold past the base carries them unread. Each is a row of the base
    /// with first-seen seconds.
    pub(super) pinned: im::OrdSet<AuthorityEntryHash>,
    /// Every other row of the base: a fold past it reads these again (FIX
    /// 12282), and finds them without a walk over the pinned rows.
    pub(super) unpinned: BTreeSet<AuthorityEntryHash>,
}

impl BaseReceipts {
    /// The receipts of the base's rows and the `new_rows` past them, as a
    /// fold over them all reads them: `log`'s for each row it read, and the
    /// base's for each row the base pins and `log` did not read (FIX 12282).
    /// Past a base that pins rows, only the rows `log` read, the new rows and
    /// the unpinned ones are visited, besides one copy of each map.
    pub(super) fn past(
        &self,
        log: &StoredTail<'_>,
        base_rows: &BaseRows,
        new_rows: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    ) -> Self {
        let read = log.first_seen_at_secs;
        let read_floors = &log.observations.sequence_floors;
        let is_row =
            |hash: &AuthorityEntryHash| base_rows.contains_key(hash) || new_rows.contains_key(hash);
        if self.pinned.is_empty() {
            // The base carries nothing: every value is `log`'s.
            let pinned: im::OrdSet<_> = log
                .pinned
                .iter()
                .filter(|&hash| is_row(hash) && read.contains_key(hash))
                .copied()
                .collect();
            let unpinned = base_rows
                .keys()
                .chain(new_rows.keys())
                .filter(|hash| !pinned.contains(*hash))
                .copied()
                .collect();
            return Self {
                first_seen: read.iter().map(|(hash, secs)| (*hash, *secs)).collect(),
                floors: read_floors
                    .iter()
                    .map(|(hash, floor)| (*hash, *floor))
                    .collect(),
                pinned,
                unpinned,
            };
        }
        // Each map is shared with the base: only the rows read and the
        // unpinned ones are visited (FIX 12308).
        let (mut first_seen, mut floors) = (self.first_seen.clone(), self.floors.clone());
        let mut pinned = self.pinned.clone();
        for hash in self.unpinned.iter().chain(read.keys()) {
            first_seen.remove(hash);
            floors.remove(hash);
            pinned.remove(hash);
        }
        first_seen.extend(read.iter().map(|(hash, secs)| (*hash, *secs)));
        floors.extend(read_floors.iter().map(|(hash, floor)| (*hash, *floor)));
        pinned.extend(
            log.pinned
                .iter()
                .filter(|&hash| is_row(hash) && first_seen.contains_key(hash))
                .copied(),
        );
        let mut unpinned = self.unpinned.clone();
        unpinned.extend(new_rows.keys());
        unpinned.extend(read.keys().filter(|hash| self.pinned.contains(*hash)));
        unpinned.retain(|hash| !pinned.contains(hash));
        Self {
            first_seen,
            floors,
            pinned,
            unpinned,
        }
    }
}
