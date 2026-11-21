//! Moved from `crates/oneiron/src/feedback/conversation_training/custody.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Where a submission stands here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubmissionState {
    /// Prepared, staged, awaiting its release.
    Held,
    /// Released and published.
    Published,
    /// Its release held it back.
    Withheld,
    /// Withdrawn after it was prepared: a deleted source, a person's erase,
    /// a world no longer everywhere, or a newer offer of its source.
    Withdrawn,
}

/// What a control says, as the engine keeps it: raw ids, coded for the
/// control's month only when it is signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlChange {
    /// Remove these submissions of one source.
    ForgetSource {
        source: EntityId,
        submissions: Vec<[u8; 16]>,
    },
    /// A world's eligibility now.
    WorldEligibility { world: EntityId, everywhere: bool },
    /// Purge everything under the control's own scope (TL-5).
    PurgeScope,
    /// Remove these hosted submissions of one source, named by the source
    /// code their offers carried, kept on their rows from their hold (FIX
    /// 9855). Its wire spelling is a forget of that source, made with no
    /// key.
    ForgetHosted {
        source_code: [u8; 32],
        submissions: Vec<[u8; 16]>,
    },
}

impl ControlChange {
    /// Whether the wire spelling of this change carries codes made when it
    /// is signed, so signing it needs its generation's key. A purge names
    /// none, and a hosted forget carries its code already.
    pub const fn needs_codes(&self) -> bool {
        !matches!(self, Self::PurgeScope | Self::ForgetHosted { .. })
    }
}
