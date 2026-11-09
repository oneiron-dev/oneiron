//! Immutable UTF-8 edit spans. The public value is still a JSON string.

use super::SandboxProposalBody;
use crate::{Error, Result};
use memmap2::{Mmap, MmapOptions};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{ops::Deref, sync::Arc};

/// A proposal's text, either decoded from a public string or borrowed from its
/// settled spool. Clones retain the same bytes and the spool's disk-floor claim.
#[derive(Clone, Default)]
pub struct SandboxProposalText(Text);

#[derive(Clone, Default)]
pub enum Text {
    #[default]
    Empty,
    Inline(Arc<String>),
    Mapped(Arc<MappedText>),
}

pub struct MappedText {
    // Unmap before releasing the body and its disk-floor claim.
    pub map: Mmap,
    pub _body: SandboxProposalBody,
}

impl From<String> for SandboxProposalText {
    fn from(text: String) -> Self {
        if text.is_empty() {
            Self::default()
        } else {
            Self(Text::Inline(Arc::new(text)))
        }
    }
}

impl Deref for SandboxProposalText {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl std::fmt::Debug for SandboxProposalText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.as_str(), f)
    }
}

impl PartialEq for SandboxProposalText {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}
impl Eq for SandboxProposalText {}

impl Serialize for SandboxProposalText {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SandboxProposalText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from)
    }
}

impl schemars::JsonSchema for SandboxProposalText {
    fn schema_name() -> String {
        <String as schemars::JsonSchema>::schema_name()
    }

    fn is_referenceable() -> bool {
        false
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <String as schemars::JsonSchema>::json_schema(generator)
    }
}
