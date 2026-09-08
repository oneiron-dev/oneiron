//! PsychProfile snapshot record substrate.
//!
//! PsychProfile rows are derived, engine-authored snapshots over profile and
//! affect Claims. The record stores three render tiers plus deterministic
//! source-revision tracking so callers can distinguish a missing profile from
//! a stale one without stringly sentinel states.

mod codec;
mod keys;
mod mirror;
mod record;
mod store;

pub use self::codec::{decode_psych_profile_body, encode_psych_profile_body};
pub use self::keys::{PsychProfileKey, psych_profile_entity_id};
pub use self::mirror::{
    PSYCH_MIRROR_SELECTION_WEIGHTS, PsychMirrorDriftAnchor, PsychMirrorDriftAnchorEvent,
    PsychMirrorDriftAnchorState, PsychMirrorSelectedSource, PsychMirrorSelectionScore,
    PsychMirrorSelectionWeights, PsychMirrorSourceCandidate, psych_mirror_drift_anchor_events,
    psych_mirror_drift_anchors, psych_mirror_text_entropy, rank_psych_mirror_sources,
    rank_psych_mirror_sources_with_weights,
};
pub use self::record::{
    PSYCH_PROFILE_BODY_KEYS, PSYCH_PROFILE_SCHEMA_VERSION, PsychProfile, PsychProfileConfidence,
    PsychProfileSnapshotStatus, PsychProfileStaleReason, PsychProfileState,
};

pub(crate) use self::codec::validate_psych_profile_body_bytes;
pub(crate) use self::record::{
    PSYCH_PROFILE_FIELDS_FULL, PSYCH_PROFILE_FIELDS_MINIMAL, PSYCH_PROFILE_FIELDS_STANDARD,
};

#[cfg(test)]
mod tests;

// The flat psych_profile.rs module used to provide these names to the sibling
// test module through `use super::*`: every psych_profile-internal item the
// tests name bare. After the directory split the seam re-imports them so
// `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::{codec::*, record::*};
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::registry::ENTITY_TYPE_PSYCH_PROFILE;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use std::io::Cursor;
