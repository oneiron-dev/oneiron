//! Typed document citations a claim's evidence carries (ARCH-0032, FIX 904):
//! the [`EvidenceRef`] vocabulary, its MessagePack codec, and the one
//! accessor that reads them from every slot a stored claim's evidence holds.
//! There is no second stored copy: the citations ride inside the evidence.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::ClaimBody;
use crate::error::{Error, Result};
use crate::write_envelope::{
    WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
    WRITE_ENVELOPE_EVIDENCE_CARRIED_KEY, envelope_carried_evidence,
};

/// The evidence map key the typed citations ride under.
pub(crate) const EVIDENCE_REFS_KEY: &str = "evidence_refs";

/// ARCH-0032: one citation of the entity's own document at an exact frontier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub kind: EvidenceKind,
    pub entity: String,
    pub doc: String,
    pub at: Vec<u8>,
    pub span: Option<CursorSpan>,
    pub quote_sha256: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Turn,
    Message,
    Note,
    AssetText,
    ImportRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CursorSpan {
    pub start: Vec<u8>,
    pub end: Vec<u8>,
}

/// A candidate may carry these citations into the promotion writer, which
/// verifies them again inside its own commit. No source or actor rides here.
pub(crate) fn public_evidence_refs(value: Option<&Value>) -> Result<Vec<EvidenceRef>> {
    let Some(value) = value
        .and_then(Value::as_map)
        .and_then(|fields| {
            fields
                .iter()
                .find(|(key, _)| key.as_str() == Some(EVIDENCE_REFS_KEY))
        })
        .map(|(_, value)| value)
    else {
        return Ok(Vec::new());
    };
    let bytes = rmp_serde::to_vec_named(value)
        .map_err(|_| Error::InvalidClaimBody("evidence refs do not encode"))?;
    rmp_serde::from_slice(&bytes)
        .map_err(|_| Error::InvalidClaimBody("evidence refs do not decode"))
}

pub(crate) fn public_evidence_value(refs: &[EvidenceRef]) -> Result<Value> {
    let bytes = rmp_serde::to_vec_named(refs)
        .map_err(|_| Error::InvalidClaimBody("evidence refs do not encode"))?;
    rmpv::decode::read_value(&mut bytes.as_slice())
        .map_err(|_| Error::InvalidClaimBody("evidence refs do not decode"))
}

impl ClaimBody {
    /// The typed citations this claim's evidence carries, in slot order: a
    /// raw body's own evidence, or a stamped body's `candidate_evidence` then
    /// the raw predecessor evidence it carries. Other evidence stays opaque.
    /// A citation is what the writer pinned; it is never proof of creation.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClaimBody`] when a slot, or a stamp's slot name, is
    /// named twice.
    pub fn evidence_refs(&self) -> Result<Vec<EvidenceRef>> {
        let (mut written, carried) = self.evidence_ref_slots()?;
        written.extend(carried);
        Ok(written)
    }

    /// [`Self::evidence_refs`] by where they ride: the citations this body's
    /// own writer gave (a raw body's evidence, a stamped body's
    /// `candidate_evidence`), then those it carries from a raw predecessor.
    pub(crate) fn evidence_ref_slots(&self) -> Result<(Vec<EvidenceRef>, Vec<EvidenceRef>)> {
        let Some(evidence) = self.evidence.as_ref() else {
            return Ok((Vec::new(), Vec::new()));
        };
        if field(evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY).is_none() {
            return Ok((slot_refs(evidence)?, Vec::new()));
        }
        // A stamp naming a recognized slot twice is malformed, never read
        // as either copy.
        for slot in [
            WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
            WRITE_ENVELOPE_EVIDENCE_CARRIED_KEY,
        ] {
            if named(evidence, slot) > 1 {
                return Err(Error::InvalidClaimBody("evidence names one slot twice"));
            }
        }
        let written = match field(evidence, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY) {
            Some(candidate) => slot_refs(candidate)?,
            None => Vec::new(),
        };
        let carried = match envelope_carried_evidence(evidence) {
            Some(carried) => slot_refs(carried)?,
            None => Vec::new(),
        };
        Ok((written, carried))
    }
}

/// The citations one evidence slot holds; a slot that names the field twice
/// is malformed, never read as either copy. A value under the field that is
/// not in the citation shape holds no typed citation: it stays the opaque
/// evidence it always was, and nothing refuses it.
fn slot_refs(slot: &Value) -> Result<Vec<EvidenceRef>> {
    if named(slot, EVIDENCE_REFS_KEY) > 1 {
        return Err(Error::InvalidClaimBody(
            "evidence names evidence_refs twice",
        ));
    }
    Ok(public_evidence_refs(Some(slot)).unwrap_or_default())
}

/// How many times the map `value` names `key`.
fn named(value: &Value, key: &str) -> usize {
    value.as_map().map_or(0, |fields| {
        fields
            .iter()
            .filter(|(name, _)| name.as_str() == Some(key))
            .count()
    })
}

fn field<'v>(value: &'v Value, name: &str) -> Option<&'v Value> {
    value
        .as_map()?
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
}
