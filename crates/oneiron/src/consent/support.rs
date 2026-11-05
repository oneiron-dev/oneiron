use rmpv::Value;

use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, RawValue, SideTable};
use crate::store::GateDecisionId;

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

pub(super) use crate::store::consent_bound::{SUBJECT_KIND_ACTOR, SUBJECT_KIND_AUDIENCE};

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

pub(super) use crate::store::consent_bound::{
    hash_field, normalized_ref, normalized_selectors, selectors_contain,
};

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

pub(super) use crate::store::consent_bound::invalid_bound;

pub(super) const fn invalid_row() -> Error {
    Error::Gate(GateError::InvalidConsentGrantRow("body failed validation"))
}
