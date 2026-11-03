//! Typed affect evidence setup through ordinary claim admission and VAD consolidation.
use serde::{Deserialize, Serialize};

use super::{ClaimScope, CommitReceipt, Memory, MemoryError, MemoryResult, ScopedClaimInput};
use crate::consent::AuthenticatedOwner;
use crate::registry::ENTITY_TYPE_TURN;
use oneiron_contracts::affect::{VadAnnotation, VadAnnotationSource};
/// A query's affect: valence in -1..=1, arousal and dominance in 0..=1.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryAffect {
    pub valence: f32,
    pub arousal: f32,
    pub dominance: f32,
}

impl QueryAffect {
    /// The affect as the engine takes it, refused out of range.
    pub fn vad(self) -> MemoryResult<oneiron_contracts::affect::Vad> {
        let vad = oneiron_contracts::affect::Vad {
            valence: self.valence,
            arousal: self.arousal,
            dominance: self.dominance,
        };
        vad.validate()
            .map_err(|error| MemoryError::bad_request(format!("query_affect: {error}")))?;
        Ok(vad)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AffectAnnotationPut {
    pub turn_ref: String,
    pub vad: QueryAffect,
    pub source: VadAnnotationSource,
    pub annotated_at: u64,
    pub scope: ClaimScope,
    pub sensitivity: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AffectClaimConsolidateRequest {
    pub claim_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AffectTurnEvidence {
    pub turn_ref: String,
    pub vad: QueryAffect,
    pub source: VadAnnotationSource,
    pub annotated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AffectClaimConsolidation {
    pub claim_ref: String,
    pub vad: Option<QueryAffect>,
    pub evidence_turns: Vec<AffectTurnEvidence>,
    pub semantic_edges_updated: usize,
    pub structural_edges_skipped: usize,
    pub active_state_ref: Option<String>,
    pub created_state_ref: Option<String>,
    pub superseded_state_refs: Vec<String>,
}

fn query_affect(vad: oneiron_contracts::affect::Vad) -> QueryAffect {
    QueryAffect {
        valence: vad.valence,
        arousal: vad.arousal,
        dominance: vad.dominance,
    }
}

impl Memory<'_> {
    /// The annotation is an ordinary scoped, attributed, gated claim, not a raw seed.
    pub fn affect_annotation_put(
        &self,
        input: &AffectAnnotationPut,
    ) -> MemoryResult<CommitReceipt> {
        let turn = self.resolve_ref(&input.turn_ref)?;
        let entity = self
            .get_entity(&input.turn_ref)?
            .value
            .ok_or_else(|| MemoryError::not_found("annotation requires a readable TURN"))?;
        if entity.kind != "TURN" {
            return Err(MemoryError::bad_request("annotation requires a TURN"));
        }
        let annotation = VadAnnotation::new(input.vad.vad()?, input.source, input.annotated_at)?;
        let body =
            crate::write_envelope::vad_annotation::vad_annotation_claim_body(&turn, &annotation)?;
        let id = crate::write_envelope::vad_annotation::vad_annotation_claim_id(
            ENTITY_TYPE_TURN,
            &turn,
        )?;
        self.claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: body.predicate,
            subject_ref: turn.to_hex(),
            value: crate::serialize::msgpack_value_to_json(&body.value),
            confidence: body.confidence,
            source: match input.source {
                VadAnnotationSource::ModelInference => "inferred",
                VadAnnotationSource::UserSelfReport => "user_stated",
            }
            .to_owned(),
            scope: input.scope.clone(),
            sensitivity: input.sensitivity,
            evidence_turn_refs: vec![turn.to_hex()],
            valid_from: body.valid_from,
            valid_to: body.valid_to,
            occurred_at: Some(input.annotated_at),
            learned_at: Some(input.annotated_at),
            salience: None,
        })
    }

    /// Reuses the canonical consolidation transaction; it reads, never rewrites, the source claim.
    pub fn affect_claim_consolidate_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &AffectClaimConsolidateRequest,
    ) -> MemoryResult<AffectClaimConsolidation> {
        owner.revalidate(self.vault)?;
        self.get_entity(&input.claim_ref)?
            .value
            .ok_or_else(|| MemoryError::not_found("consolidation requires a readable claim"))?;
        let claim = self.resolve_ref(&input.claim_ref)?;
        let result = self.vault.consolidate_claim_vad_as_owner(
            owner,
            &claim,
            self.vault.store.clock.now_recorded_at(),
        )?;
        Ok(AffectClaimConsolidation {
            claim_ref: result.claim_id.to_hex(),
            vad: result.vad.map(query_affect),
            evidence_turns: result
                .evidence_turns
                .into_iter()
                .map(|evidence| AffectTurnEvidence {
                    turn_ref: evidence.turn_id.to_hex(),
                    vad: query_affect(evidence.annotation.vad),
                    source: evidence.annotation.source,
                    annotated_at: evidence.annotation.annotated_at,
                })
                .collect(),
            semantic_edges_updated: result.semantic_edges_updated,
            structural_edges_skipped: result.structural_edges_skipped,
            active_state_ref: result.reappraisal.active_claim_id.map(|id| id.to_hex()),
            created_state_ref: result.reappraisal.created_claim_id.map(|id| id.to_hex()),
            superseded_state_refs: result
                .reappraisal
                .superseded_claim_ids
                .into_iter()
                .map(|id| id.to_hex())
                .collect(),
        })
    }
}
