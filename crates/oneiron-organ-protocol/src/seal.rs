//! The seal organ's revision classification, as its verdicts carry it
//! (OF-415, C032). A serde vocabulary only: the seal organ fills it from its
//! own native verification, and the engine's host reads it, and neither
//! links the other (the of060 F4 fence). The host never parses a PDF; it
//! compares these offsets, digests and kinds with the revision it bound.
//!
//! Every field is required: a verdict without its classification is not a
//! verdict the host can admit a sealed PDF on.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// The longest caller operation id the seal sends its backend as it is: the
/// backend's 256-byte bound less the 32 bytes the seal's own suffix takes
/// (`:{16 hex}:{phase}:{capacity}`).
pub const DIRECT_OPERATION_ID_BYTES: usize = 224;

/// What a backend operation id that aliases a caller's begins with.
pub const OPERATION_ALIAS_PREFIX: &str = "alias:";

/// The key-derivation context of an operation alias: no other BLAKE3 use
/// in the engine derives under it.
const OPERATION_ALIAS_CONTEXT: &str = "oneiron seal backend operation id v1";

/// The operation id the seal's backend sees for a caller's `operation_id`
/// (FIX 6271), shared by the seal organ's sub-operation ids and the engine
/// host's binding of them. One of at most [`DIRECT_OPERATION_ID_BYTES`]
/// that does not begin with [`OPERATION_ALIAS_PREFIX`] goes as it is; any
/// other becomes the prefix and the hex of its BLAKE3 derived under its own
/// context (70 bytes). No caller id is refused for its length, and two
/// caller ids never share a backend id.
#[must_use]
pub fn backend_operation_id(operation_id: &str) -> Cow<'_, str> {
    if operation_id.len() <= DIRECT_OPERATION_ID_BYTES
        && !operation_id.starts_with(OPERATION_ALIAS_PREFIX)
    {
        return Cow::Borrowed(operation_id);
    }
    let digest = blake3::derive_key(OPERATION_ALIAS_CONTEXT, operation_id.as_bytes());
    Cow::Owned(format!(
        "{OPERATION_ALIAS_PREFIX}{}",
        blake3::Hash::from(digest).to_hex()
    ))
}

/// What one native verification proved about a PDF's revisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealRevisionClassification {
    /// SHA-256 of the bytes verified, 32 bytes.
    pub artifact_sha256: ByteBuf,
    /// The end of the bytes one proven revision chain classifies, through
    /// its final EOF framing: the PDF's length when the whole file is one
    /// complete, classified chain; `None` when any part is not.
    pub classified_through: Option<u64>,
    pub modifications: SealModifications,
    /// In chain order.
    pub revisions: Vec<SealRevisionEvidence>,
    pub signatures: Vec<SealSignatureEvidence>,
}

/// How the revisions after the first signature changed the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealModifications {
    NotRun,
    Clean(SealModificationLevel),
    Suspicious,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealModificationLevel {
    None,
    LtaUpdates,
    FormFilling,
    Other,
}

/// One revision of the proven chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealRevisionEvidence {
    pub index: u64,
    pub kind: SealRevisionKind,
    /// The end of its `%%EOF`.
    pub byte_end: u64,
    /// The id of the signature whose ByteRange this revision ends.
    pub signed_by: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealRevisionKind {
    Original,
    Signature,
    DocumentTimestamp,
    Dss,
    Other,
}

/// One signature the verification found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealSignatureEvidence {
    pub id: String,
    pub kind: SealSignatureKind,
    pub byte_range: SealByteRangeEvidence,
    /// Its envelope's integrity alone.
    pub integrity: SealCheckVerdict,
    /// All of its checks.
    pub verdict: SealCheckVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealSignatureKind {
    Signature,
    DocumentTimestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealCheckVerdict {
    Passed,
    Failed,
    Indeterminate,
}

/// A signature's ByteRange as the PDF wrote it, and what it covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealByteRangeEvidence {
    pub values: [u64; 4],
    pub well_formed: bool,
    pub covers_to: Option<u64>,
    pub file_len: u64,
}
