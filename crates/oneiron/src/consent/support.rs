use rmpv::Value;

use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, RawValue, SideTable};
use crate::store::GateDecisionId;

use super::bound::{MAX_CONSENT_REF_LEN, MAX_ENVELOPE_SELECTORS};
use super::effect::UndoFidelity;
use crate::error::GateError;

// ---------------------------------------------------------------------------
// Storage identity — no entity type, no type byte
// ---------------------------------------------------------------------------

const CONSENT_APPROVE_ONCE_MARKER_VERSION: u8 = 1;
pub(super) const CONSENT_APPROVE_ONCE_AVAILABLE: u8 = 0;
pub(super) const CONSENT_APPROVE_ONCE_SPENT: u8 = 1;
const CONSENT_APPROVE_ONCE_MARKER_LEN: usize = 18;

/// Approve-once state, keyed by the 32-byte effect digest. Minting writes an
/// available marker in the same transaction as its receipt. Delivery
/// atomically changes that marker to spent in the transaction that authorizes
/// the effect. Presence therefore rejects a duplicate mint, while the state
/// distinguishes the one live tap from a replay (DEC-0006 invariant 2).
pub(super) const APPROVE_ONCE_MARKERS: SideTable<[u8; 32], ApproveOnceMarker, side_table::Raw> =
    SideTable::new(&side_table::CONSENT_APPROVE_ONCE_MARKER);

pub(super) const SUBJECT_KIND_ACTOR: &str = "actor";
pub(super) const SUBJECT_KIND_AUDIENCE: &str = "audience";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub(super) struct ApproveOnceMarker {
    pub(super) state: u8,
    pub(super) decision_id: GateDecisionId,
}

impl RawValue for ApproveOnceMarker {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut marker = [0_u8; CONSENT_APPROVE_ONCE_MARKER_LEN];
        marker[0] = CONSENT_APPROVE_ONCE_MARKER_VERSION;
        marker[1] = self.state;
        marker[2..].copy_from_slice(&self.decision_id.as_bytes());
        Ok(marker.to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let (state, decision_id) = decode_approve_once_marker(bytes)?;
        Ok(Self { state, decision_id })
    }
}

pub(super) fn decode_approve_once_marker(raw: &[u8]) -> Result<(u8, GateDecisionId)> {
    if raw.len() != CONSENT_APPROVE_ONCE_MARKER_LEN || raw[0] != CONSENT_APPROVE_ONCE_MARKER_VERSION
    {
        return Err(Error::CorruptedIndex("consent approve-once marker"));
    }
    let decision_id = GateDecisionId::from_bytes(
        raw[2..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("consent approve-once marker"))?,
    );
    Ok((raw[1], decision_id))
}

pub(super) fn normalized_ref(label: &'static str, value: String) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Error::Gate(GateError::InvalidConsentBound(label)));
    }
    if trimmed.len() > MAX_CONSENT_REF_LEN {
        return Err(Error::Gate(GateError::InvalidConsentBound(label)));
    }
    Ok(trimmed.to_owned())
}

pub(super) fn normalized_selectors(
    selectors: impl IntoIterator<Item = String>,
) -> Result<Vec<String>> {
    let mut selectors = selectors
        .into_iter()
        .map(|selector| normalized_ref("envelope selector", selector))
        .collect::<Result<Vec<_>>>()?;
    selectors.sort_unstable();
    selectors.dedup();
    if selectors.is_empty() {
        return Err(invalid_bound(
            "envelope has no selectors; an empty envelope is not a bound",
        ));
    }
    if selectors.len() > MAX_ENVELOPE_SELECTORS {
        return Err(invalid_bound("envelope exceeds the selector cap"));
    }
    Ok(selectors)
}

/// Selector containment over two sorted, deduped sets.
pub(super) fn selectors_contain(bound: &[String], candidate: &[String]) -> bool {
    candidate
        .iter()
        .all(|selector| bound.binary_search(selector).is_ok())
}

/// Length-prefixed field hashing, so `["ab","c"]` and `["a","bc"]` never
/// collide into the same digest.
pub(super) fn hash_field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

pub(super) const fn undo_fidelity_byte(fidelity: UndoFidelity) -> u8 {
    match fidelity {
        UndoFidelity::Full => 0,
        UndoFidelity::Partial => 1,
        UndoFidelity::None => 2,
        UndoFidelity::Unknown => 3,
    }
}

pub(super) fn hex_to_16_bytes(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0_u8; 16];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

pub(super) fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_row)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_row());
        };
        if seen[index] {
            return Err(invalid_row());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|present| present) {
        Ok(())
    } else {
        Err(invalid_row())
    }
}

pub(super) fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(invalid_row)
}

pub(super) const fn invalid_bound(message: &'static str) -> Error {
    Error::Gate(GateError::InvalidConsentBound(message))
}

pub(super) const fn invalid_row() -> Error {
    Error::Gate(GateError::InvalidConsentGrantRow("body failed validation"))
}
