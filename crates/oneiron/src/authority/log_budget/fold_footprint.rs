//! What the fold's memory floor prices: a log's ancestry footprint (row
//! [ROSTER-KEY-LOG-FLOOD], PR 4).

/// What one fold holds at its peak, per ancestry id, per ancestor pair, per
/// run of ids and per entry of merge gain. Fold states share what a row did
/// not change (PR 2) and the ancestry index holds runs (PR 1), so most of a
/// row's peak no longer grows with its ancestor count: an id costs its row's
/// state and its node, a run its two bounds, and a merge gain entry what
/// `merge_states` adds to its left clone. A pair costs what still grows with
/// each ancestor: chiefly the projected fold's actor write frontiers
/// (`causal_write::causal_actor_frontiers`: per active binding, every row
/// its binding is live at).
///
/// Measured on the fleet (17 Nov, job 1117-090217-f045 on gce-ci-2, scratch
/// opus-anchorsec/fold-memory-measure-v3 ee99d5bdfa20, log sha256
/// 78928a4cafe9d4b3): 13 op families (confirm, critical, enroll, residence,
/// agents, slip-mint, slip-revoke, world-edit, machine-revision, rescope and
/// the refused world edit, grant travel and export acts) on chains, stars
/// and grids of 500 and 2000 rows, and 751 actor revocation rows. Each
/// constant is the least that projects every run at 1.25 times its measured
/// peak, rounded up to 1 KiB or 8 B: a run from the index's own bytes, a pair
/// from the agents chain (19.3 B a pair), an id from the machine revision
/// chain, a merge gain entry from the critical write grid. The rescope chain
/// is left out: each of its rows held a whole copy of the pact's superseded
/// narrowings, which fold states now share.
const FOLD_BYTES_PER_ID: u64 = 34 * 1024;
const FOLD_BYTES_PER_ANCESTOR_PAIR: u64 = 32;
const FOLD_BYTES_PER_RUN: u64 = 160;
const FOLD_BYTES_PER_MERGE_GAIN: u64 = 3768;

/// The size of a log's claimed ancestry as the fold's memory floor prices
/// it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::authority) struct AncestryFootprint {
    /// Every row and every claimed parent the log lacks: the ancestor
    /// index's ids.
    pub(in crate::authority) ids: u64,
    /// The sum of every row's ancestor count. The headroom advisory and the
    /// index's reference door read it too.
    pub(in crate::authority) pairs: u64,
    /// The runs of ids that hold every row's ancestry, summed.
    pub(in crate::authority) runs: u64,
    /// For each row with two parents or more, the ancestors its first
    /// parent's ancestry lacks: its ancestor count, less one, less its first
    /// parent's ancestor count. 0 on a chain or a star.
    pub(in crate::authority) merge_gain: u64,
}

impl AncestryFootprint {
    /// The footprint a gate that knows only `rows` and their `pairs` (an
    /// image stores no runs or merge gain) prices: never below the whole
    /// fold's, since a row's runs are at most its ancestors plus one and its
    /// merge gain at most its ancestors.
    pub(in crate::authority) fn of_pairs(rows: usize, pairs: u64) -> Self {
        let rows = rows as u64;
        Self {
            ids: rows,
            pairs,
            runs: pairs.saturating_add(rows),
            merge_gain: pairs,
        }
    }
}

/// What a fold of a log with ancestry `footprint` holds at its peak. It
/// grows with each part of the footprint, so a check on a partial footprint
/// refuses no log the whole one admits.
pub(in crate::authority) fn fold_projected_bytes(footprint: AncestryFootprint) -> u64 {
    footprint
        .ids
        .saturating_mul(FOLD_BYTES_PER_ID)
        .saturating_add(footprint.pairs.saturating_mul(FOLD_BYTES_PER_ANCESTOR_PAIR))
        .saturating_add(footprint.runs.saturating_mul(FOLD_BYTES_PER_RUN))
        .saturating_add(
            footprint
                .merge_gain
                .saturating_mul(FOLD_BYTES_PER_MERGE_GAIN),
        )
}
