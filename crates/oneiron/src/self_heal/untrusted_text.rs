//! Untrusted detail-text validation and escaping.
pub(super) use crate::store::diagnostic_record::untrusted_text::is_forbidden_text_scalar;
pub(crate) use crate::store::diagnostic_record::untrusted_text::{
    canonical_untrusted_detail, validate_untrusted_detail,
};
