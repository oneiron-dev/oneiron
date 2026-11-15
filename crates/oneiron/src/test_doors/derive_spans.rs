//! Doors to the stored span locators a derive item lands: a landed
//! claim's envelope locators and a support record's provenance locators, each
//! with source, stored byte range, content hash and MESSAGE slices.

use std::fmt::Write as _;

use crate::EntityId;
use crate::Vault;
use crate::error::Result;

/// One MESSAGE-local slice behind a stored range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessageSlice {
    /// The MESSAGE row.
    pub message: EntityId,
    /// The first byte within the MESSAGE's own content, inclusive.
    pub start: u64,
    /// The end within the MESSAGE's own content, exclusive.
    pub end: u64,
    /// `blake3:<hex>`: the evidence hash of the MESSAGE revision read.
    pub revision: String,
    /// The MESSAGE's document frontier, in hex, when it has a document.
    pub frontier: Option<String>,
}

/// One stored locator: a TURN range or a claim, with its quote hash and the
/// MESSAGE slices a TURN range covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredLocator {
    /// The source row.
    pub source: EntityId,
    /// The claim, for a claim locator; `None` for a TURN range.
    pub claim: Option<EntityId>,
    /// The stored byte range, for a TURN range; `None` for a claim locator.
    pub byte_range: Option<(u64, u64)>,
    /// `blake3:<hex>` of the range's exact stored bytes, or of the claim body.
    pub content_hash: String,
    /// The MESSAGE-local slices the range covers; empty for inline text.
    pub messages: Vec<StoredMessageSlice>,
}

/// The stored locators in the envelope of the landed claim `claim`: empty
/// when the envelope carries no `locators` key.
///
/// # Errors
///
/// The vault's, and a stored envelope that does not decode.
pub fn claim_locators(vault: &Vault, claim: EntityId) -> Result<Vec<StoredLocator>> {
    let Some(body) = vault.get_claim(&claim)? else {
        return Ok(Vec::new());
    };
    let Some(evidence) = body.evidence.as_ref() else {
        return Ok(Vec::new());
    };
    locators_of(evidence)
}

/// The stored locators in the provenance of the support record `record`: the
/// `derived_evidence` envelope's `locators`, empty when absent.
///
/// # Errors
///
/// The vault's, and a stored envelope that does not decode.
pub fn support_locators(vault: &Vault, record: EntityId) -> Result<Vec<StoredLocator>> {
    let Some(body) = vault.get_claim(&record)? else {
        return Ok(Vec::new());
    };
    let Some(scope) = body.scope.as_ref() else {
        return Ok(Vec::new());
    };
    let rmpv::Value::Map(fields) = scope else {
        return Ok(Vec::new());
    };
    let Some(derived) = fields
        .iter()
        .find(|(key, _)| key.as_str() == Some("derived_evidence"))
        .map(|(_, value)| value)
    else {
        return Ok(Vec::new());
    };
    locators_of(derived)
}

/// The `locators` of one stored evidence envelope: empty when the envelope
/// carries none.
fn locators_of(evidence: &rmpv::Value) -> Result<Vec<StoredLocator>> {
    let rmpv::Value::Map(fields) = evidence else {
        return Ok(Vec::new());
    };
    if !fields
        .iter()
        .any(|(key, _)| key.as_str() == Some("locators"))
    {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for (locator, hash, messages) in
        crate::dreamer_consolidation::decode_verified_citations(evidence)?
    {
        out.push(StoredLocator {
            source: locator.source_id,
            claim: locator.claim_id,
            byte_range: locator
                .byte_range
                .map(|(start, end)| (to_u64(start), to_u64(end))),
            content_hash: blake3_ref(&hash),
            messages: messages
                .iter()
                .map(|span| StoredMessageSlice {
                    message: span.message,
                    start: to_u64(span.start),
                    end: to_u64(span.end),
                    revision: blake3_ref(&span.revision),
                    frontier: span.frontier.as_deref().map(hex),
                })
                .collect(),
        });
    }
    Ok(out)
}

/// `value` as a `u64`, saturating on overflow.
fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// `blake3:<hex>` of `hash`.
fn blake3_ref(hash: &[u8; 32]) -> String {
    format!("blake3:{}", hex(hash))
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
