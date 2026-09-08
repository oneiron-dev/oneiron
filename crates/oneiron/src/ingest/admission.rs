//! Imported-evidence admission: typed claim and entity intake with JSON-to-MessagePack bridging.

use rmpv::Value as MsgpackValue;
use serde_json::Value;

use super::{NormalizedIngestClaim, NormalizedIngestEntity};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::entity_id::EntityId;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

/// Explicit entity-resolution result required before imported evidence can
/// become a candidate claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportedEvidenceEntityResolution {
    /// The resolved subject every admitted claim is written against.
    ///
    /// Waterfall-driven callers pass the `selected` subject of a NON-provisional
    /// [`EntityResolutionWaterfallDecision`]. A provisional decision selects
    /// nothing, and inventing a subject for it here would defeat the band that
    /// declined to link — a provisional mention belongs to whatever path mints
    /// provisional entities, not to this admission door.
    /// A waterfall `selected` is always a canonical Active head.
    pub subject: EntityId,
}

impl ImportedEvidenceEntityResolution {
    #[must_use]
    pub const fn subject(subject: EntityId) -> Self {
        Self { subject }
    }
}

/// Write metadata for admitting one normalized imported evidence claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedEvidenceAdmission {
    pub source_id: String,
    pub claim_id: EntityId,
    pub entity_resolution: ImportedEvidenceEntityResolution,
    pub actor: WriteActor,
    pub occurred: TimeRange,
    pub learned_at: u64,
    pub approval: ClaimApprovalStatus,
}

impl ImportedEvidenceAdmission {
    /// Creates the default imported-evidence admission state: proposed review,
    /// not an automatically confirmed claim.
    #[must_use]
    pub fn proposed(
        source_id: impl Into<String>,
        claim_id: EntityId,
        entity_resolution: ImportedEvidenceEntityResolution,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            claim_id,
            entity_resolution,
            actor,
            occurred,
            learned_at,
            approval: ClaimApprovalStatus::Proposed,
        }
    }

    /// Overrides the admission approval when a caller has an explicit
    /// higher-trust import policy. The Gate still decides before persistence.
    #[must_use]
    pub const fn with_approval(mut self, approval: ClaimApprovalStatus) -> Self {
        self.approval = approval;
        self
    }
}

/// Admits imported evidence as a claim candidate after explicit entity
/// resolution and before persistence through the normal Gate write path.
///
/// # Errors
///
/// Returns the underlying claim-candidate write error. Gate/source-trust
/// denial and missing actor or subject entities abort the batch, leaving no
/// persisted candidate claim.
pub fn admit_imported_evidence_claim(
    vault: &crate::Vault,
    claim: &NormalizedIngestClaim,
    admission: ImportedEvidenceAdmission,
) -> crate::Result<()> {
    admit_imported_evidence_claim_typed(
        vault,
        &claim.predicate,
        json_to_msgpack_value(&claim.value),
        &claim.source_record_id,
        &admission,
    )
}

/// Typed-value sibling of [`admit_imported_evidence_claim`]: the same
/// Gate-backed imported-evidence door — identical provenance, envelope,
/// candidate path, and failure semantics — for claim values JSON cannot
/// express. CAL-02's `calendar.passport` carries a MessagePack-binary
/// content hash, which the `serde_json::Value` in [`NormalizedIngestClaim`]
/// cannot represent.
///
/// # Errors
///
/// Same contract as [`admit_imported_evidence_claim`].
pub fn admit_imported_evidence_claim_typed(
    vault: &crate::Vault,
    predicate: &str,
    value: MsgpackValue,
    source_record_id: &str,
    admission: &ImportedEvidenceAdmission,
) -> crate::Result<()> {
    // `companion.expression.*` has typed doors that own its supersession
    // chain: writing a head means closing the one the family's own precedence
    // rules pick, and the candidate path below supersedes on
    // `subject+scope+predicate` alone. An imported preference admitted here
    // would break the chain a typed retraction later walks back, so the family
    // is refused and pointed at the door that owns it — the same rule
    // `Vault::retract_claim` and the facade's generic claim doors hold.
    if crate::claim::is_expression_preference_predicate(predicate) {
        return Err(crate::error::Error::InvalidClaimBody(
            "expression preference lifecycle is owned by set_expression_preference",
        ));
    }
    if admission.source_id.trim().is_empty() {
        return Err(crate::error::Error::InvalidClaimBody(
            "imported evidence missing source_id",
        ));
    }
    if source_record_id.trim().is_empty() {
        return Err(crate::error::Error::InvalidClaimBody(
            "imported evidence missing source_record_id",
        ));
    }

    let imported_evidence = imported_evidence_value(&admission.source_id, source_record_id);
    let candidate = ClaimCandidate::new(
        predicate.to_owned(),
        ClaimSubject::Entity(admission.entity_resolution.subject),
        value,
        1.0,
    )
    .with_evidence(imported_evidence.clone());
    let envelope = WriteEnvelope::new(
        admission.actor,
        ClaimSource::Imported,
        WriteProvenance::new(imported_evidence)?,
        admission.approval,
    );

    vault
        .batch()
        .claim_candidate(
            &admission.claim_id,
            candidate,
            &envelope,
            admission.occurred,
            admission.learned_at,
        )
        .commit()
}

/// Persists a normalized asset-text entity through the vault's normal entity
/// write door. The caller supplies its identifier and temporal envelope.
pub fn admit_imported_entity(
    vault: &crate::Vault,
    entity_id: &EntityId,
    entity: &NormalizedIngestEntity,
    occurred: TimeRange,
    learned_at: u64,
) -> crate::Result<()> {
    if entity.entity_type != crate::registry::ENTITY_TYPE_ASSET_TEXT {
        return Err(crate::error::Error::InvalidClaimBody(
            "imported entity must be ASSET_TEXT",
        ));
    }
    vault.put_entity(
        entity_id,
        entity.entity_type,
        occurred,
        learned_at,
        entity.body.as_bytes(),
    )
}

fn imported_evidence_value(source_id: &str, source_record_id: &str) -> MsgpackValue {
    MsgpackValue::Map(vec![
        (
            MsgpackValue::from("kind"),
            MsgpackValue::from("imported_evidence"),
        ),
        (
            MsgpackValue::from("source_id"),
            MsgpackValue::from(source_id),
        ),
        (
            MsgpackValue::from("source_record_id"),
            MsgpackValue::from(source_record_id),
        ),
    ])
}

fn json_to_msgpack_value(value: &Value) -> MsgpackValue {
    match value {
        Value::Null => MsgpackValue::Nil,
        Value::Bool(value) => MsgpackValue::Boolean(*value),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                MsgpackValue::from(value)
            } else if let Some(value) = value.as_u64() {
                MsgpackValue::from(value)
            } else if let Some(value) = value.as_f64() {
                MsgpackValue::F64(value)
            } else {
                MsgpackValue::Nil
            }
        }
        Value::String(value) => MsgpackValue::from(value.as_str()),
        Value::Array(values) => {
            MsgpackValue::Array(values.iter().map(json_to_msgpack_value).collect())
        }
        Value::Object(entries) => MsgpackValue::Map(
            entries
                .iter()
                .map(|(key, value)| {
                    (
                        MsgpackValue::from(key.as_str()),
                        json_to_msgpack_value(value),
                    )
                })
                .collect(),
        ),
    }
}
