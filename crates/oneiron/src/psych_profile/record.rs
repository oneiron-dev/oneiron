//! Profile snapshot record; definitions live in the core write vocabulary.

pub(super) use crate::write_envelope::profile_snapshot::record::{
    CONFIDENCE_KEYS, KEY_COMPACT, KEY_CONFIDENCE, KEY_NARRATIVE, KEY_SCHEMA_VERSION,
    KEY_SOURCE_PAGES, KEY_SOURCE_REVISION_PAGES, KEY_STATUS, KEY_SUBJECT_REF, KEY_TEXT,
    MAX_COMPACT_BYTES, MAX_NARRATIVE_BYTES, MAX_TEXT_BYTES,
};
pub use crate::write_envelope::profile_snapshot::record::{
    PSYCH_PROFILE_BODY_KEYS, PSYCH_PROFILE_SCHEMA_VERSION, PSYCH_PROFILE_WORDS_PIN_DOMAIN,
    PsychProfile, PsychProfileByteRange, PsychProfileConfidence, PsychProfileSnapshotStatus,
    PsychProfileSource, PsychProfileSourceWords, PsychProfileSpanText, PsychProfileStaleReason,
    PsychProfileState, PsychProfileWordsPin, psych_profile_words_pin,
};
pub(crate) use crate::write_envelope::profile_snapshot::record::{
    PSYCH_PROFILE_FIELDS_FULL, PSYCH_PROFILE_FIELDS_MINIMAL, PSYCH_PROFILE_FIELDS_STANDARD,
};
