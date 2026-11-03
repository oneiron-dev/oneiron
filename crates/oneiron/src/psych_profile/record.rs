//! Profile snapshot record; definitions live in the core write vocabulary.

pub use crate::write_envelope::profile_snapshot::record::{PSYCH_PROFILE_BODY_KEYS, PSYCH_PROFILE_SCHEMA_VERSION, PsychProfile, PsychProfileConfidence, PsychProfileSnapshotStatus, PsychProfileSource, PsychProfileStaleReason, PsychProfileState};
pub(super) use crate::write_envelope::profile_snapshot::record::{KEY_SCHEMA_VERSION, KEY_SUBJECT_REF, KEY_COMPACT, KEY_TEXT, KEY_NARRATIVE, KEY_SOURCE_REVISION_PAGES, KEY_CONFIDENCE, KEY_STATUS, KEY_SOURCE_PAGES, CONFIDENCE_KEYS, MAX_COMPACT_BYTES, MAX_TEXT_BYTES, MAX_NARRATIVE_BYTES};
pub(crate) use crate::write_envelope::profile_snapshot::record::{PSYCH_PROFILE_FIELDS_MINIMAL, PSYCH_PROFILE_FIELDS_STANDARD, PSYCH_PROFILE_FIELDS_FULL};
