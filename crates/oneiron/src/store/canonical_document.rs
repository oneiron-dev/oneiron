//! CRDT-independent EntityDoc snapshot values and causal history.

use crate::error::{ArtifactError, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Current generic EntityDoc value, independent of the document's Loro op log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEntityDocument {
    pub entity_id: [u8; 16],
    pub document_id: [u8; 16],
    /// None is a UTF-8 body; Some is the document's MessagePack body field.
    pub field: Option<String>,
    pub text: String,
    /// Editable fields, each encoded as one MessagePack value.
    pub metadata: BTreeMap<String, Vec<u8>>,
    /// A scope summary's typed purpose and derivation, as its meta map holds
    /// them; never editable fields (FIX 756).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub summary_meta: BTreeMap<String, Vec<u8>>,
    /// Native record fields projected by the immutable adapter at birth.
    pub record_fields: Vec<String>,
    /// The stamp token the birth names, as stored (FIX 11964); None once the
    /// birth named no one (FIX 6072): it stays no one.
    pub birth_actor: Option<[u8; 16]>,
    pub birth_at: u64,
    /// The document's causal state, by value. Absent for a document with no
    /// fork, pin, receipt or purge: that one is its current value alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<CanonicalEntityDocumentHistory>,
    /// Where the value was captured (FIX 3553). Absent for a head whose
    /// incarnation is no id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<CanonicalDocumentOrigin>,
}

#[doc(hidden)]
pub(crate) use oneiron_records::store::canonical_document::invalid;
#[doc(hidden)]
pub use oneiron_records::store::canonical_document::{
    CanonicalDocumentFork, CanonicalDocumentOrigin, CanonicalDocumentPin, CanonicalDocumentPurge,
    CanonicalDocumentReceipt, CanonicalDocumentVersion, CanonicalEntityDocumentHistory,
    CanonicalForkStatus, CanonicalSettleVerb,
};

/// Resumable reconstruction of the same canonical history text vector.
pub(crate) struct CanonicalDocumentTexts {
    texts: Vec<String>,
}

impl CanonicalDocumentTexts {
    pub(crate) fn new(history: &CanonicalEntityDocumentHistory) -> Self {
        Self {
            texts: Vec::with_capacity(history.versions.len()),
        }
    }

    pub(crate) fn advance_row(&mut self, history: &CanonicalEntityDocumentHistory) -> Result<bool> {
        let index = self.texts.len();
        let Some(version) = history.versions.get(index) else {
            return Ok(true);
        };
        let base: Vec<char> = match version.parents.first() {
            None => Vec::new(),
            Some(&parent) => {
                let parent = parent as usize;
                if parent >= index {
                    return Err(invalid("entity document version parent"));
                }
                self.texts[parent].chars().collect()
            }
        };
        let prefix = version.prefix as usize;
        let suffix = version.suffix as usize;
        if prefix
            .checked_add(suffix)
            .is_none_or(|kept| kept > base.len())
        {
            return Err(invalid("entity document version splice"));
        }
        let mut text: String = base[..prefix].iter().collect();
        text.push_str(&version.middle);
        text.extend(&base[base.len() - suffix..]);
        self.texts.push(text);
        Ok(false)
    }

    pub(crate) fn into_texts(self) -> Vec<String> {
        self.texts
    }
}
