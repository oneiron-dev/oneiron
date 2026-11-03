//! Skill record vocabulary, defined below the skill behavior layer.

pub(super) use crate::write_envelope::skill_record::validate::{
    skill_content_changed, validate_skill_record, validate_text_field,
};
pub(crate) use crate::write_envelope::skill_record::validate::{
    validate_hub_sync_skill_update, validate_skill_update,
};
