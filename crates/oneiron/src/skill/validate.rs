//! Skill record vocabulary, defined below the skill behavior layer.

pub(crate) use crate::write_envelope::skill_record::validate::{
    validate_skill_update, validate_hub_sync_skill_update,
};
pub(super) use crate::write_envelope::skill_record::validate::{
    validate_skill_record, validate_text_field, skill_content_changed,
};
