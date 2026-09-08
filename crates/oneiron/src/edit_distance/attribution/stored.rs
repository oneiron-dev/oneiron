//! Stored rows: key prefixes, row shapes, and the row codec.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Keyspace + pinned strings
// ---------------------------------------------------------------------------

/// `vault_meta` prefix of the recorded routing facts, keyed by receipt id —
/// the same join key ED-01's Δ side-ledger uses, so evidence and measurement
/// are read with one lookup each and cannot drift apart.
pub(super) const EVIDENCE_KEY_PREFIX: &[u8] = b"edit_distance/amendment_evidence/v1\0";

/// `vault_meta` prefix of the routed judgments, keyed by receipt id.
pub(super) const JUDGMENT_KEY_PREFIX: &[u8] = b"edit_distance/amendment_judgment/v1\0";

/// `vault_meta` prefix of minted preference proposals, keyed by receipt id.
pub(super) const PREFERENCE_KEY_PREFIX: &[u8] = b"edit_distance/preference_proposal/v1\0";

/// `vault_meta` prefix of the `(predicate, subject, scope)` tuples this
/// projector holds a live cost head for — the retraction ledger. Without it a
/// re-judged receipt's OLD tuple is unreachable: no judgment names it any more,
/// and nothing else knows a row was ever landed there.
pub(super) const TARGET_KEY_PREFIX: &[u8] = b"edit_distance/edit_cost_target/v1\0";

/// `vault_meta` prefix of persisted audit reports: prefix ‖ at (8 BE) ‖
/// sequence (8 BE), so reports read back oldest-first and two runs in one
/// second stay two rows.
pub(super) const AUDIT_KEY_PREFIX: &[u8] = b"edit_distance/judge_audit/v1\0";

/// Monotonic counter behind the audit key's sequence half.
pub(super) const AUDIT_SEQUENCE_KEY: &[u8] = b"edit_distance/judge_audit_sequence/v1";

/// Only accepted schema version for any row this module stores.
pub(super) const ROW_VERSION: u8 = 1;

pub(super) const EVIDENCE_ROW_LABEL: &str = "amendment evidence row";

pub(super) const JUDGMENT_ROW_LABEL: &str = "amendment judgment row";

pub(super) const PREFERENCE_ROW_LABEL: &str = "preference proposal row";

pub(super) const TARGET_ROW_LABEL: &str = "edit cost target row";

pub(super) const AUDIT_ROW_LABEL: &str = "amendment judge audit row";

/// Longest accepted amendment scope — the ED lane's scope bound, shared with
/// `edit_distance::escalation` and the `actor.edit_cost` row it feeds.
pub(super) const MAX_AMENDMENT_SCOPE_LEN: usize = crate::consent::MAX_CONSENT_REF_LEN;

/// Upper bound on the receipts one cost row cites, matching the `actor.*`
/// ledger's own bound so a skill row and an actor row cite alike.
pub(super) const MAX_CITED_RECEIPTS: usize = crate::actor_claims::ACTOR_CLAIM_MAX_CITED_EVIDENCE;

pub(super) const fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

// ---------------------------------------------------------------------------
// Stored rows
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredEvidence {
    pub(super) v: u8,
    pub(super) actor: String,
    pub(super) skill: Option<String>,
    pub(super) scope: String,
    pub(super) cause: Option<String>,
    pub(super) followed_skill: Option<bool>,
    pub(super) skill_covered_step: Option<bool>,
    pub(super) at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredJudgment {
    pub(super) v: u8,
    pub(super) class: String,
    pub(super) subject: Option<String>,
    pub(super) scope: String,
    pub(super) evidence_receipts: Vec<String>,
    pub(super) d_norm: f32,
    pub(super) at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredPreference {
    pub(super) v: u8,
    pub(super) scope: String,
    pub(super) evidence_receipts: Vec<String>,
    pub(super) at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredTarget {
    pub(super) v: u8,
    pub(super) predicate: String,
    pub(super) subject: String,
    pub(super) scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredAudit {
    pub(super) v: u8,
    pub(super) total: u64,
    pub(super) passed: u64,
    pub(super) abstained: u64,
    pub(super) at: u64,
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub(super) fn encode_row<T: Serialize>(row: &T, label: &'static str) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row).map_err(|_| Error::InvariantViolation(label))
}

pub(super) fn decode_row<T: serde::de::DeserializeOwned>(
    raw: &[u8],
    label: &'static str,
) -> Result<T> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex(label))
}

pub(super) fn meta_key(prefix: &[u8], handle: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + handle.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(handle);
    key
}

/// The receipt id a keyed row was stored under.
pub(super) fn key_tail(key: &[u8], prefix: &[u8], label: &'static str) -> Result<String> {
    let tail = key
        .get(prefix.len()..)
        .ok_or(Error::CorruptedIndex(label))?;
    String::from_utf8(tail.to_vec()).map_err(|_| Error::CorruptedIndex(label))
}

pub(super) fn hex_entity(hex: &str, label: &'static str) -> Result<EntityId> {
    EntityId::from_hex(hex).map_err(|_| Error::CorruptedIndex(label))
}

/// The trimmed scope, or the reason it is not one — `escalation`'s rule, so one
/// scope string means one thing lane-wide.
pub(super) fn normalized_scope(scope: &str) -> Result<&str> {
    let trimmed = scope.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_AMENDMENT_SCOPE_LEN {
        return Err(invalid(
            "an amendment scope must be non-empty and within the consent-ref bound",
        ));
    }
    Ok(trimmed)
}

pub(super) fn next_audit_sequence_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>) -> Result<u64> {
    let current = match vault.store.vault_meta.get(&*wtxn, AUDIT_SEQUENCE_KEY)? {
        Some(raw) => {
            let bytes: [u8; 8] = raw
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex(AUDIT_ROW_LABEL))?;
            u64::from_be_bytes(bytes)
        }
        None => 0,
    };
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("judge audit sequence"))?;
    vault
        .store
        .vault_meta
        .put(wtxn, AUDIT_SEQUENCE_KEY, &next.to_be_bytes())?;
    Ok(next)
}
