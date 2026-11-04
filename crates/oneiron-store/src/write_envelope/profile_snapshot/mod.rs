//! Profile snapshot records, addressing and canonical MessagePack codec.

pub mod codec;
pub mod keys;
pub mod record;

pub use codec::validate_psych_profile_body_bytes;
pub use codec::{
    PSYCH_PROFILE_SOURCE_IDS_PER_CODEC_PAGE, decode_psych_profile_body, encode_psych_profile_body,
};
pub use keys::{PsychProfileKey, psych_profile_entity_id};
pub use record::{
    PSYCH_PROFILE_BODY_KEYS, PSYCH_PROFILE_SCHEMA_VERSION, PsychProfile, PsychProfileConfidence,
    PsychProfileSnapshotStatus, PsychProfileSource, PsychProfileStaleReason, PsychProfileState,
};
pub use record::{
    PSYCH_PROFILE_FIELDS_FULL, PSYCH_PROFILE_FIELDS_MINIMAL, PSYCH_PROFILE_FIELDS_STANDARD,
};
