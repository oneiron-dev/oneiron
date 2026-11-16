//! Moved from `crates/oneiron/src/store/canonical_document.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

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
    /// The delta receipt id this rework answered (FIX 11967).
    #[serde(default)]
    pub delta_receipt: Option<String>,
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

pub fn invalid(reason: &'static str) -> Error {
    ArtifactError::InvalidRecoveryArtifact(reason).into()
}
