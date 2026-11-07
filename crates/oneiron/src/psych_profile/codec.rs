//! Profile snapshot codec; definitions live in the core write vocabulary.

pub(crate) use crate::write_envelope::profile_snapshot::codec::validate_psych_profile_body_bytes;
pub use crate::write_envelope::profile_snapshot::codec::{
    PSYCH_PROFILE_SOURCE_IDS_PER_CODEC_PAGE, PsychProfileBodyEnvelope, decode_psych_profile_body,
    encode_psych_profile_body, psych_profile_body_envelope,
};
pub(super) use crate::write_envelope::profile_snapshot::codec::{
    canonical_expected_source_revision_ids, canonical_revision_refs_allow_empty,
    canonical_source_revision_ids, encode_confidence, invalid_profile, required_value,
    validate_confidence, validate_text,
};
