//! Context-pack output formats and field profiles.

pub use crate::store::context_field_profile::FieldProfile;

/// Output serialization format for context packing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum PackFormat {
    OpenaiCompat,
    AnthropicMessages,
    Gemini,
    #[default]
    Json,
    Yaml,
    Toon,
    Markdown,
    Plaintext,
}
