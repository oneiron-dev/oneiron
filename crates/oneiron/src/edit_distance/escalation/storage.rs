//! Stored rows, msgpack codec, key builders, token parsers.

use serde::{Deserialize, Serialize};

use super::types::{EscalationRuling, EscalationTrigger};
use crate::edit_distance::delta::AmendmentDelta;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Keyspace + pinned strings
// ---------------------------------------------------------------------------

/// `vault_meta` key prefix of the escalation ledger. The full key is this
/// prefix ‖ [`scope_key`] (16 B) ‖ row id (16 B).
///
/// Scope-major so one scope's history is a contiguous range, and the trailing
/// id is a UUIDv7 so key order is WRITE order. A caller-supplied `at` is data,
/// never ordering — which is what keeps "the newest N rulings" meaningful when
/// an ask is recorded with a backdated clock.
pub(super) const ESCALATION_KEY_PREFIX: &[u8] = b"edit_distance/escalation/v1\0";

/// `vault_meta` key prefix of the standing-policy family. The full key is this
/// prefix ‖ [`scope_key`] (16 B) ‖ [`EscalationTrigger::key_byte`] (1 B).
///
/// Keyed by what the row GOVERNS rather than by its own id: "at most one
/// standing policy per (scope, trigger)" is then a property of the keyspace
/// instead of an invariant something has to check, and [`standing_policy_for`]
/// — the read ES-07 runs before every ask — is a single lookup.
pub(super) const STANDING_POLICY_KEY_PREFIX: &[u8] = b"edit_distance/escalation_policy/v1\0";

/// Receipt-id prefix of a ruled-escalation receipt — the
/// [`is_escalation_receipt`] discriminator inside the `Gate` family.
pub(super) const ESCALATION_RECEIPT_PREFIX: &str = "escalation:";

/// Receipt-id prefix of a standing-policy receipt. Disjoint from
/// [`ESCALATION_RECEIPT_PREFIX`] at the separator, so neither prefix test can
/// match the other family.
pub(super) const STANDING_POLICY_RECEIPT_PREFIX: &str = "escalation_policy:";

/// Only accepted schema version for either stored row.
pub(super) const ROW_VERSION: u8 = 1;

/// Domain separator for the scope digest.
const SCOPE_DIGEST_DOMAIN: &[u8] = b"oneiron.edit_distance.escalation.scope.v1";

pub(super) const ESCALATION_ROW_LABEL: &str = "escalation row";

pub(super) const STANDING_POLICY_ROW_LABEL: &str = "escalation standing policy row";

/// The separator joining cited receipt ids in a receipt field. A receipt id is
/// a prefix plus hex, so it never contains one.
pub(super) const CITED_RECEIPTS_SEPARATOR: &str = ",";

/// Longest accepted escalation scope, borrowed from the consent bound every
/// other scope axis in the engine is measured against.
pub(super) const MAX_ESCALATION_SCOPE_LEN: usize = crate::consent::MAX_CONSENT_REF_LEN;

// ---------------------------------------------------------------------------
// Stored rows
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredEscalation {
    pub(super) v: u8,
    pub(super) task_ref: String,
    pub(super) scope: String,
    pub(super) trigger: String,
    pub(super) question: String,
    pub(super) ruling: String,
    /// Exactly the bytes [`AmendmentDelta::encode`] produced; `Some` if and
    /// only if `ruling` is `amend`.
    pub(super) delta: Option<Vec<u8>>,
    pub(super) rationale: String,
    pub(super) budget_band: Option<u64>,
    pub(super) at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredStandingPolicy {
    pub(super) v: u8,
    pub(super) row_ref: String,
    pub(super) scope: String,
    pub(super) trigger: String,
    pub(super) ruling: String,
    pub(super) delta: Option<Vec<u8>>,
    pub(super) band_ceiling: Option<u64>,
    pub(super) cited_receipts: Vec<String>,
    pub(super) proposed_at: u64,
    /// Set by the acceptance door, and the whole of what
    /// [`StandingPolicyStatus`] is derived from — two spellings of one fact are
    /// two things that can disagree.
    pub(super) accepted_at: Option<u64>,
}

pub(super) fn encode_row<T: Serialize>(row: &T, label: &'static str) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row).map_err(|_| Error::InvariantViolation(label))
}

pub(super) fn escalation_row(raw: &[u8]) -> Result<StoredEscalation> {
    let row: StoredEscalation =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex(ESCALATION_ROW_LABEL))?;
    if row.v == ROW_VERSION {
        Ok(row)
    } else {
        Err(Error::CorruptedIndex(ESCALATION_ROW_LABEL))
    }
}

pub(super) fn standing_policy_row(raw: &[u8]) -> Result<StoredStandingPolicy> {
    let row: StoredStandingPolicy =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex(STANDING_POLICY_ROW_LABEL))?;
    if row.v == ROW_VERSION {
        Ok(row)
    } else {
        Err(Error::CorruptedIndex(STANDING_POLICY_ROW_LABEL))
    }
}

/// The 16-byte storage handle of a scope.
pub(super) fn scope_key(scope: &str) -> [u8; ENTITY_ID_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SCOPE_DIGEST_DOMAIN);
    hasher.update(scope.as_bytes());
    let mut key = [0_u8; ENTITY_ID_LEN];
    key.copy_from_slice(&hasher.finalize().as_bytes()[..ENTITY_ID_LEN]);
    key
}

/// The ledger key range of one scope.
pub(super) fn escalation_scope_prefix(scope: &str) -> Vec<u8> {
    let mut key = ESCALATION_KEY_PREFIX.to_vec();
    key.extend_from_slice(&scope_key(scope));
    key
}

pub(super) fn escalation_key(scope: &str, id: &EntityId) -> Vec<u8> {
    let mut key = escalation_scope_prefix(scope);
    key.extend_from_slice(id.as_bytes());
    key
}

pub(super) fn standing_policy_key(scope: &str, trigger: EscalationTrigger) -> Vec<u8> {
    let mut key = STANDING_POLICY_KEY_PREFIX.to_vec();
    key.extend_from_slice(&scope_key(scope));
    key.push(trigger.key_byte());
    key
}

/// The row id embedded in a ledger key.
pub(super) fn escalation_key_id(key: &[u8]) -> Result<EntityId> {
    let tail = key
        .get(ESCALATION_KEY_PREFIX.len() + ENTITY_ID_LEN..)
        .and_then(|tail| <[u8; ENTITY_ID_LEN]>::try_from(tail).ok())
        .ok_or(Error::CorruptedIndex(ESCALATION_ROW_LABEL))?;
    EntityId::from_bytes(tail).map_err(|_| Error::CorruptedIndex(ESCALATION_ROW_LABEL))
}

pub(super) fn escalation_receipt_id(id: &EntityId) -> String {
    format!("{ESCALATION_RECEIPT_PREFIX}{}", id.to_hex())
}

// ---------------------------------------------------------------------------
// Validation + the ruling codec
// ---------------------------------------------------------------------------

/// The trimmed scope, or the reason it is not one.
pub(super) fn normalized_scope(scope: &str) -> Result<&str> {
    let trimmed = scope.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_ESCALATION_SCOPE_LEN {
        return Err(Error::InvalidConsentBound(
            "an escalation scope must be non-empty and within the consent-ref bound",
        ));
    }
    Ok(trimmed)
}

/// The stored `(ruling token, Δ bytes)` pair for a ruling.
pub(super) fn ruling_parts(ruling: &EscalationRuling) -> Result<(String, Option<Vec<u8>>)> {
    let delta = ruling.delta().map(AmendmentDelta::encode).transpose()?;
    Ok((ruling.as_str().to_owned(), delta))
}

/// Rebuilds a ruling from its stored pair.
///
/// The token and the Δ must agree: an `amend` with no Δ, or a non-`amend`
/// carrying one, is a row this engine did not write.
pub(super) fn ruling_from_parts(
    token: &str,
    delta: Option<&[u8]>,
    label: &'static str,
) -> Result<EscalationRuling> {
    match (token, delta) {
        ("approve", None) => Ok(EscalationRuling::Approve),
        ("deny", None) => Ok(EscalationRuling::Deny),
        ("amend", Some(bytes)) => AmendmentDelta::decode(bytes).map(EscalationRuling::Amend),
        _ => Err(Error::CorruptedIndex(label)),
    }
}

pub(super) fn trigger_from_token(token: &str, label: &'static str) -> Result<EscalationTrigger> {
    EscalationTrigger::from_token(token).ok_or(Error::CorruptedIndex(label))
}

impl StoredEscalation {
    pub(super) fn ruling(&self) -> Result<EscalationRuling> {
        ruling_from_parts(&self.ruling, self.delta.as_deref(), ESCALATION_ROW_LABEL)
    }

    pub(super) fn trigger(&self) -> Result<EscalationTrigger> {
        trigger_from_token(&self.trigger, ESCALATION_ROW_LABEL)
    }
}
