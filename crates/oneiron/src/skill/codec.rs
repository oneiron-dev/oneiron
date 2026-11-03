//! Skill record vocabulary, defined below the skill behavior layer.

pub use crate::write_envelope::skill_record::codec::{
    encode_skill_record, decode_skill_record,
};
pub(crate) use crate::write_envelope::skill_record::codec::{
    validate_skill_record_bytes, is_legacy_opaque_skill_body,
};
pub(super) use crate::write_envelope::skill_record::codec::text_value;
