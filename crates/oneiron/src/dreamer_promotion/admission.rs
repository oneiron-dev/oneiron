//! The promotion writer's evidence decision, also exposed by the typed evidence read.
use crate::claim::{
    ClaimApprovalStatus, claim_consolidatable, claim_evidence_admissible,
    claim_generated_origin, claim_surfaceable,
};
use crate::gate::ConsolidationReader;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

/// Why a visible source does not corroborate a generated claim. These are
/// evidence decisions, never an outbound authorization or a consent grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PromotionEvidenceReason {
    Missing,
    NotEvidence,
    NotSurfaceable,
    UnvettedGenerated,
    UnvettedTaint,
    GeneratedOrigin,
    PendingCriticalConfirmation,
    UnsupportedTurnRole,
}

/// The exact decision the promotion writer uses, in the caller's snapshot.
pub(crate) fn evidence_ref_refusal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entry: &EntityId,
) -> Result<Option<PromotionEvidenceReason>> {
    use PromotionEvidenceReason::*;
    match vault.get_entity_type_in_txn(txn, entry)? {
        None => Ok(Some(Missing)),
        Some(ENTITY_TYPE_PERSON | ENTITY_TYPE_SESSION) => Ok(Some(NotEvidence)),
        Some(ENTITY_TYPE_CLAIM) => {
            let Some(body) = vault.get_claim_in_txn(txn, entry)? else {
                return Ok(Some(Missing));
            };
            if !claim_surfaceable(&body) {
                return Ok(Some(NotSurfaceable));
            }
            if body.approval == ClaimApprovalStatus::Auto && claim_generated_origin(&body) {
                return Ok(Some(UnvettedGenerated));
            }
            if !claim_consolidatable(&body) {
                return Ok(Some(UnvettedTaint));
            }
            if !claim_evidence_admissible(&body) {
                return Ok(Some(GeneratedOrigin));
            }
            if !crate::gate::claim_consolidation_eligible_in_txn(
                &vault.store, txn, entry, ConsolidationReader::PromotionEvidence,
            )? {
                return Ok(Some(PendingCriticalConfirmation));
            }
            Ok(None)
        }
        Some(ENTITY_TYPE_TURN) => {
            let Some(raw) = vault.get_raw_in(txn, entry)? else {
                return Ok(Some(Missing));
            };
            let body = raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                .ok_or(crate::Error::CorruptedIndex("evidence TURN header"))?;
            Ok(crate::dreamer_consolidation::resources::native_turn_source(vault, body)
                .err().map(|_| UnsupportedTurnRole))
        }
        Some(_) => Ok(None),
    }
}

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
pub(crate) fn public_evidence_refs(value: Option<&rmpv::Value>) -> Result<Vec<EvidenceRef>> {
    let Some(value) = value.and_then(rmpv::Value::as_map)
        .and_then(|fields| fields.iter().find(|(key, _)| key.as_str() == Some("evidence_refs")))
        .map(|(_, value)| value)
    else {
        return Ok(Vec::new());
    };
    let bytes = rmp_serde::to_vec_named(value)
        .map_err(|_| crate::Error::InvalidClaimBody("evidence refs do not encode"))?;
    rmp_serde::from_slice(&bytes)
        .map_err(|_| crate::Error::InvalidClaimBody("evidence refs do not decode"))
}

pub(crate) fn public_evidence_value(refs: &[EvidenceRef]) -> Result<rmpv::Value> {
    let bytes = rmp_serde::to_vec_named(refs)
        .map_err(|_| crate::Error::InvalidClaimBody("evidence refs do not encode"))?;
    rmpv::decode::read_value(&mut bytes.as_slice())
        .map_err(|_| crate::Error::InvalidClaimBody("evidence refs do not decode"))
}
