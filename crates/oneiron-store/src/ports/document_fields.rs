//! Field vocabulary shared by document writes and value-based recovery.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use rmpv::Value;

pub fn invalid(reason: &'static str) -> Error {
    oneiron_base::error::ArtifactError::InvalidEditManifest(reason).into()
}

/// Editable labels and prose, never identity, scope, authority or claim values.
pub fn is_metadata_field(field: &str) -> bool {
    matches!(
        field,
        "title"
            | "tags"
            | "kind_label"
            | "pins"
            | "keep"
            | "name"
            | "label"
            | "description"
            | "desc"
            | "summary"
            | "instructions"
            | "why"
    )
}

pub fn is_text_field(field: &str) -> bool {
    matches!(field, "body" | "text" | "txt" | "content" | "markdown")
        || (is_metadata_field(field) && !matches!(field, "tags" | "pins"))
}
