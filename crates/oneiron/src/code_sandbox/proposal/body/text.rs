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
enum Text {
    #[default]
    Empty,
    Inline(Arc<String>),
    Mapped(Arc<MappedText>),
}

struct MappedText {
    // Unmap before releasing the body and its disk-floor claim.
    map: Mmap,
    _body: SandboxProposalBody,
}

impl SandboxProposalText {
    pub(in crate::code_sandbox::proposal) fn from_body(
        body: &SandboxProposalBody,
        offset: u64,
        len: u64,
        invalid_utf8: &'static str,
        mut checkpoint: impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        checkpoint()?;
        if offset.checked_add(len).is_none_or(|end| end > body.len) {
            return Err(Error::InvalidClaimBody("proposal body range out of bounds"));
        }
        if len == 0 {
            return Ok(Self::default());
        }
        let len = usize::try_from(len)
            .map_err(|_| Error::InvalidClaimBody("code edit span exceeds host memory"))?;
        let file = body
            .spooled
            .file
            .lock()
            .map_err(|_| Error::InvalidClaimBody("proposal body poisoned"))?;
        // SAFETY: finish consumes the only writer. The settled body's file is
        // private; all subsequent access only seeks or reads it, never writes or
        // truncates it. Its anonymous file is not exposed by path or descriptor.
        // The checked span lies within that immutable file, retained below.
        let map = unsafe {
            MmapOptions::new()
                .offset(body.offset + offset)
                .len(len)
                .map(&*file)?
        };
        drop(file);
        let mut at = 0;
        while at < map.len() {
            checkpoint()?;
            let end = at.saturating_add(super::super::LOWER_FRAME).min(map.len());
            match std::str::from_utf8(&map[at..end]) {
                Ok(_) => at = end,
                Err(error) if error.error_len().is_none() && end < map.len() => {
                    // Revisit only the incomplete scalar in the next frame.
                    at += error.valid_up_to();
                }
                Err(_) => return Err(Error::InvalidClaimBody(invalid_utf8)),
            }
        }
        checkpoint()?;
        Ok(Self(Text::Mapped(Arc::new(MappedText {
            map,
            _body: body.clone(),
        }))))
    }

    /// The exact text. No changed span is recollected into a `String`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match &self.0 {
            Text::Empty => "",
            Text::Inline(text) => text.as_str(),
            // SAFETY: from_body validated the entire span as UTF-8 before
            // publishing it. The backing file cannot change, and MappedText
            // retains both the mapping and its body for this borrow's lifetime.
            Text::Mapped(text) => unsafe { std::str::from_utf8_unchecked(&text.map) },
        }
    }
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
