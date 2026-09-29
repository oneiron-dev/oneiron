//! Stored rows: key shapes, row shapes, and the row codec.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, FixedSideKey, HexId, Raw, RawValue, SideKey, SideTable};

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/// Recorded routing facts, keyed by receipt id — the same join key ED-01's Δ
/// side-ledger uses, so evidence and measurement are read with one lookup
/// each and cannot drift apart.
pub(super) const EVIDENCE: SideTable<String, StoredEvidence, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_AMENDMENT_EVIDENCE);

/// Routed judgments, keyed by receipt id.
pub(super) const JUDGMENT: SideTable<String, StoredJudgment, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_AMENDMENT_JUDGMENT);

/// Minted preference proposals, keyed by receipt id.
pub(super) const PREFERENCE: SideTable<String, StoredPreference, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_PREFERENCE_PROPOSAL);

/// The `(predicate, subject, scope)` tuples this projector holds a live cost
/// head for — the retraction ledger. Without it a re-judged receipt's OLD
/// tuple is unreachable: no judgment names it any more, and nothing else
/// knows a row was ever landed there.
pub(super) const TARGET: SideTable<TargetKey, StoredTarget, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_EDIT_COST_TARGET);

/// Persisted audit reports, keyed by (at, sequence) so reports read back
/// oldest-first and two runs in one second stay two rows.
pub(super) const AUDIT: SideTable<(u64, u64), StoredAudit, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_JUDGE_AUDIT);

/// Monotonic counter behind the audit key's sequence half.
pub(super) const AUDIT_SEQUENCE: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_JUDGE_AUDIT_SEQUENCE);

/// `edit_distance/edit_cost_target/v1` row key: `predicate "\0" hex32(subject)
/// "\0" scope`. The scope goes LAST: it is the only field a caller supplies,
/// so nothing it can contain shifts another. Not a [`FixedSideKey`] tuple
/// because the fixed-width hex id sits BETWEEN two variable-length strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TargetKey {
    pub(super) predicate: String,
    pub(super) subject: HexId,
    pub(super) scope: String,
}

impl SideKey for TargetKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.predicate.as_bytes());
        out.push(0);
        self.subject.encode_into(out);
        out.push(0);
        out.extend_from_slice(self.scope.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let separator = bytes.iter().position(|&byte| byte == 0)?;
        let (predicate, rest) = bytes.split_at(separator);
        let (subject_bytes, rest) = rest[1..].split_at_checked(HexId::WIDTH)?;
        let scope_bytes = rest.strip_prefix(&[0][..])?;
        Some(Self {
            predicate: String::from_utf8(predicate.to_vec()).ok()?,
            subject: HexId::decode_key(subject_bytes)?,
            scope: String::from_utf8(scope_bytes.to_vec()).ok()?,
        })
    }
}

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

macro_rules! row_codec {
    ($ty:ty, $label:expr) => {
        impl RawValue for $ty {
            fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
                Ok(encode_row(self, $label)?)
            }

            fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
                let row: $ty = decode_row(bytes, $label)?;
                if row.v != ROW_VERSION {
                    return Err(CodecError::Value(Error::CorruptedIndex($label)));
                }
                Ok(row)
            }
        }
    };
}

row_codec!(StoredEvidence, EVIDENCE_ROW_LABEL);
row_codec!(StoredJudgment, JUDGMENT_ROW_LABEL);
row_codec!(StoredPreference, PREFERENCE_ROW_LABEL);
row_codec!(StoredTarget, TARGET_ROW_LABEL);
row_codec!(StoredAudit, AUDIT_ROW_LABEL);

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
    let current = AUDIT_SEQUENCE.get(&vault.store, &*wtxn, &())?.unwrap_or(0);
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("judge audit sequence"))?;
    AUDIT_SEQUENCE.put(&vault.store, wtxn, &(), &next)?;
    Ok(next)
}
