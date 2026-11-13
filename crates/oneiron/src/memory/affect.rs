//! Typed affect evidence setup through ordinary claim admission and VAD consolidation.
use serde::{Deserialize, Serialize};

use super::{ClaimScope, CommitReceipt, Memory, MemoryError, MemoryResult, ScopedClaimInput};
use crate::consent::AuthenticatedOwner;
use crate::registry::ENTITY_TYPE_TURN;
use oneiron_contracts::affect::{VadAnnotation, VadAnnotationSource};
#[doc(hidden)]
pub use oneiron_verb_wire::memory::affect::{
    AffectAnnotationPut, AffectClaimConsolidateRequest, AffectClaimConsolidation,
    AffectTurnEvidence, QueryAffect,
};

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
