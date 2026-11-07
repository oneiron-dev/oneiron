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

/// The incarnation a value was captured at and that incarnation's version
/// there, as (peer, counter) pairs in peer order (FIX 3553): the one Loro
/// value a snapshot carries, and never replayed. A restore names it in the
/// rebuilt document as the history that document replaces, so a peer that
/// holds exactly that incarnation adopts it. It names where a value was
/// captured, never the value: a recovery whose document holds the value is
/// equivalent to the artifact whatever its origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDocumentOrigin {
    pub incarnation: [u8; 16],
    pub version: Vec<(u64, i32)>,
}

/// The causal state of a generic EntityDoc, CRDT-independent: the retained
/// versions its citations, receipts, forks and purges name, never Loro
/// frontiers, cursors or exports. A restore replays the versions into fresh
/// history and binds every row to its replayed version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEntityDocumentHistory {
    /// Retained versions in canonical causal order. Every version precedes
    /// the last, which is the live head.
    pub versions: Vec<CanonicalDocumentVersion>,
    /// An owner purge dropped the history before version 0: none is carried,
    /// and the restored document refuses every older version.
    pub shallow: bool,
    pub pins: Vec<CanonicalDocumentPin>,
    pub receipts: Vec<CanonicalDocumentReceipt>,
    pub forks: Vec<CanonicalDocumentFork>,
    pub purges: Vec<CanonicalDocumentPurge>,
}

/// One retained version: the earlier versions it directly follows, and its
/// text as one splice of its first parent's text (of the empty text for a
/// version with no parent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDocumentVersion {
    pub parents: Vec<u32>,
    /// Characters kept from the start of the first parent's text.
    pub prefix: u32,
    /// Characters kept from its end.
    pub suffix: u32,
    pub middle: String,
    pub metadata: BTreeMap<String, Vec<u8>>,
    /// A scope summary's purpose and derivation at this version (FIX 756).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub summary_meta: BTreeMap<String, Vec<u8>>,
}

/// An immutable citation pin: the quoted span of one version, in characters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDocumentPin {
    pub citation: [u8; 16],
    pub document: [u8; 16],
    /// None once the actor was erased (FIX 3520).
    pub actor: Option<[u8; 16]>,
    pub version: u32,
    pub start: u32,
    pub end: u32,
    pub quote: String,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanonicalSettleVerb {
    Merge,
    Switch,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanonicalForkStatus {
    Pending,
    Merged,
    Switched,
    Rejected,
}

/// A settlement or direct-update receipt between two versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDocumentReceipt {
    pub receipt: [u8; 16],
    pub proposal: [u8; 16],
    pub fork: [u8; 16],
    /// None once the actor was erased (FIX 3520).
    pub actor: Option<[u8; 16]>,
    pub verb: CanonicalSettleVerb,
    pub at: u64,
    pub before: u32,
    pub after: u32,
    pub read_refs: Vec<[u8; 16]>,
}

/// A fork and its place in its proposal bundle, which the snapshot carries
/// whole or refuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDocumentFork {
    pub fork: [u8; 16],
    pub proposal: [u8; 16],
    pub parent_document: [u8; 16],
    /// None once the actor was erased (FIX 3520).
    pub actor: Option<[u8; 16]>,
    pub opened_at: u64,
    pub rewrite: bool,
    pub status: CanonicalForkStatus,
    /// None only for a settled fork whose base a purge dropped.
    pub base: Option<u32>,
    /// The retained output text of a pending fork.
    pub output: Option<String>,
    pub output_metadata: Option<BTreeMap<String, Vec<u8>>>,
    /// Its place in its bundle, and the bundle's size: no count bounds a
    /// bundle (Rule 5, FIX 8822).
    pub proposal_index: u64,
    pub proposal_len: u64,
    pub proposal_settled: bool,
    /// The credential lineage its bundle froze as it opened (FIX 10931).
    pub proposal_opener_lineage: Vec<[u8; 32]>,
    pub read_refs: Vec<[u8; 16]>,
    pub keep: Option<String>,
}

/// Durable proof of one owner purge, bound to the versions it named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDocumentPurge {
    pub receipt: [u8; 16],
    pub document: [u8; 16],
    /// None once the actor was erased (FIX 3520).
    pub actor: Option<[u8; 16]>,
    pub requested: u32,
    pub applied: u32,
    pub at: u64,
    pub live_text_hash: [u8; 32],
}

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

impl CanonicalEntityDocumentHistory {
    /// Every version's full text, rebuilt from its splice, in version order.
    pub fn texts(&self) -> Result<Vec<String>> {
        let mut texts = CanonicalDocumentTexts::new(self);
        while !texts.advance_row(self)? {}
        Ok(texts.into_texts())
    }

    /// The splice that turns `parent` into `text`: the longest common prefix,
    /// then the longest common suffix of what remains.
    pub fn splice(parent: &str, text: &str) -> Result<CanonicalDocumentVersion> {
        let old: Vec<char> = parent.chars().collect();
        let new: Vec<char> = text.chars().collect();
        let prefix = old.iter().zip(&new).take_while(|(a, b)| a == b).count();
        let suffix = old[prefix..]
            .iter()
            .rev()
            .zip(new[prefix..].iter().rev())
            .take_while(|(a, b)| a == b)
            .count();
        Ok(CanonicalDocumentVersion {
            parents: Vec::new(),
            prefix: u32::try_from(prefix).map_err(|_| invalid("entity document version size"))?,
            suffix: u32::try_from(suffix).map_err(|_| invalid("entity document version size"))?,
            middle: new[prefix..new.len() - suffix].iter().collect(),
            metadata: BTreeMap::new(),
            summary_meta: BTreeMap::new(),
        })
    }
}

pub(crate) fn invalid(reason: &'static str) -> Error {
    ArtifactError::InvalidRecoveryArtifact(reason).into()
}
