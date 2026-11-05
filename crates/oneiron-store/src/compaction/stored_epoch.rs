//! Whether a stored SUMMARY is an epoch summary, in every form it is stored
//! in (Astra 1384e).

use rmpv::Value;

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// What a stored SUMMARY body is, whichever form it is stored in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredEpoch {
    /// No epoch summary.
    No,
    /// An epoch summary, its text inline or on the document plane.
    Yes,
    /// A document pointer that keeps an epoch's keyframe, whose head in this
    /// transaction does not complete it. A reader holds it as an epoch it
    /// cannot place.
    Unresolved,
}

impl StoredEpoch {
    /// Whether a reader takes the row as an epoch summary.
    pub fn may_be(self) -> bool {
        self != Self::No
    }
}
