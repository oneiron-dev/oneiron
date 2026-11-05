//! Owner-retained queue kind and identifier range classification.

use crate::attempt_id::AttemptId;

/// Whether rows of `kind` are job state whose owner settles, prunes and
/// bounds them itself (the tagging marker: its settled tries leave the ledger
/// for a bounded trace history). No content-side cleanup proposes such a row,
/// and no scan of another kind reads one.
pub fn owner_retained_kind(kind: &str) -> bool {
    kind == crate::config::tagging::TAGGING_MARKER_KIND
}

/// The first byte of every owner-retained row's id: those rows sit at the
/// top of the ledger's key order, apart from every other kind's. A minted id
/// starts with the top byte of its 48-bit millisecond clock, below this until
/// the year 10889, and only an owner-retained kind derives its ids itself; a
/// new row in the wrong range is refused. A scan of another kind stops before
/// the range, so owner-retained rows cost it nothing.
pub const OWNER_RETAINED_ID_PREFIX: u8 = 0xFF;

/// Whether `id` lies in the owner-retained range.
pub fn owner_retained_id(id: &AttemptId) -> bool {
    id.as_bytes()[0] == OWNER_RETAINED_ID_PREFIX
}

/// The first key of the owner-retained range, as a ledger scan bound.
pub const OWNER_RETAINED_RANGE_START: [u8; 1] = [OWNER_RETAINED_ID_PREFIX];
