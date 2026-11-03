//! Skill record vocabulary, defined below the skill behavior layer.

pub(super) use crate::write_envelope::skill_record::codec::text_value;
pub use crate::write_envelope::skill_record::codec::{decode_skill_record, encode_skill_record};
pub(crate) use crate::write_envelope::skill_record::codec::{
    is_legacy_opaque_skill_body, validate_skill_record_bytes,
};
