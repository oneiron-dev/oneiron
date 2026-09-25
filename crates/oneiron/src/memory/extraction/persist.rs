//! One transaction composes mention, VAD and identity-proposal doors.
use super::types::*;
use crate::affect::{VadAnnotation, VadAnnotationSource};
use crate::identity_topology::{
    IdentityOpEvidence, IdentityOpWrite, IdentityTopologyOp, MergeOp, SurvivorshipPlan,
};
use crate::memory::{Memory, MemoryResult};
use crate::{
    EntityId, Error,
    claim::{ClaimApprovalStatus, ClaimSource},
    edge::EdgeKind,
    registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN},
    write_envelope::WriteActor,
};
impl Memory<'_> {
    /// Persists a parity-checked shadow output. The host resolves span targets;
    /// conflicting coreference identities are proposed, never silently merged.
    /// Any refusal aborts mentions, annotations, consolidation and proposals.
    pub fn persist_extraction(
        &self,
        trace: &ShadowTrace,
        parity: &EncoderParity,
        targets: &[EntityId],
        claims: &[EntityId],
        now: u64,
    ) -> MemoryResult<ExtractionReceipt> {
        if parity.model != trace.model {
            return Err(
                Error::InvalidConfig("encoder has no matching parity receipt".into()).into(),
            );
        }
        let output = trace
            .output
            .as_ref()
            .ok_or_else(|| Error::InvalidConfig("shadow did not produce a valid output".into()))?;
        if output.spans.len() != targets.len() {
            return Err(
                Error::InvalidConfig("one resolved target per NER span required".into()).into(),
            );
        }
        let turn = EntityId::from_hex(&trace.input.turn)?;
        self.with_verified_actor_write_txn(|txn| {
            require_type(self.vault, txn, &turn, ENTITY_TYPE_TURN)?;
            for message in &trace.input.messages {
                let id = EntityId::from_hex(&message.id)?;
                let raw = require_type(self.vault, txn, &id, ENTITY_TYPE_MESSAGE)?;
                let value =
                    rmpv::decode::read_value(&mut &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                        .map_err(|_| Error::CorruptedIndex("extraction source message"))?;
                if value
                    .as_map()
                    .and_then(|map| map.iter().find(|(key, _)| key.as_str() == Some("content")))
                    .and_then(|(_, value)| value.as_str())
                    != Some(message.text.as_str())
                {
                    return Err(Error::InvalidConfig(
                        "source changed after shadow inference".into(),
                    )
                    .into());
                }
            }
            let mut batch = self.vault.batch_in();
            for (span, target) in output.spans.iter().zip(targets) {
                if !matches!(
                    crate::vault::live_entity_row_in_txn(&self.vault.store, txn, target)?,
                    crate::vault::LiveEntityRow::Live { .. }
                ) {
                    return Err(Error::EntityNotFound.into());
                }
                batch = batch.edge_with_created_at_and_vad(
                    &EntityId::from_hex(&trace.input.messages[span.message].id)?,
                    EdgeKind::Mentions,
                    target,
                    span.confidence,
                    now,
                    output.vad,
                );
            }
            batch.apply(txn)?;
            let annotation = self.vault.annotate_entity_vad_in_txn(
                txn,
                &turn,
                ENTITY_TYPE_TURN,
                VadAnnotation::new(output.vad, VadAnnotationSource::ModelInference, now)?,
            )?;
            let mut consolidated = Vec::new();
            for claim in claims {
                consolidated.push(
                    self.vault
                        .consolidate_claim_vad_in_write_txn(txn, claim, now)?,
                );
            }
            let mut coref_proposals = Vec::new();
            let mut seen = std::collections::BTreeSet::new();
            for link in &output.links {
                let source = targets[link.span];
                let survivor = targets[link.antecedent];
                if source != survivor && seen.insert((source, survivor)) {
                    coref_proposals.push(self.vault.apply_identity_topology_op_in_txn(
                        txn,
                        &IdentityTopologyOp::Merge(MergeOp {
                            sources: vec![source],
                            survivor,
                            evidence: IdentityOpEvidence {
                                refs: vec![turn],
                                rationale: format!(
                                    "encoder {} input {}",
                                    trace.model, trace.input_hash
                                ),
                            },
                            survivorship_plan: SurvivorshipPlan::ReadThrough,
                        }),
                        &IdentityOpWrite {
                            source: ClaimSource::Inferred,
                            approval: ClaimApprovalStatus::Proposed,
                            confidence: output.spans[link.span].confidence,
                            actor: Some(WriteActor::new(self.actor, self.actor_class)),
                        },
                        now,
                    )?);
                }
            }
            Ok(ExtractionReceipt {
                model: trace.model.clone(),
                input_hash: trace.input_hash.clone(),
                turn,
                mention_targets: targets.to_vec(),
                annotation,
                consolidated,
                coref_proposals,
            })
        })
    }
}
fn require_type(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    kind: u8,
) -> crate::Result<Vec<u8>> {
    let raw = vault
        .store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("extraction source header"))?;
    if header.entity_type != kind {
        return Err(Error::InvalidEntityType(header.entity_type));
    }
    Ok(raw.to_vec())
}
