//! Pre-materialized author seam and durable maintenance execution. No delivery here.
use super::context::{validate_citations, validate_packet};
use super::{
    PREDICATE, Packet, RECORD_PREFIX, REPRESENTATION_FACET, RepresentationCitation,
    RepresentationContext, RepresentationRequest, invalid, key,
};
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EntityId, Result, TimeRange,
    Vault, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;
use serde::{Deserialize, Serialize};

/// The host chooses the wording. The engine verifies every citation, stores
/// the immutable UTF-8 bytes, and keeps source quotes beside the review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepresentationDraft {
    pub text: String,
    pub evidence: Vec<RepresentationCitation>,
    pub voice: Vec<RepresentationCitation>,
}
/// Synchronous, deterministic author seam, like CommitmentWakeProposalPlanner.
/// Model hosts must pre-materialize the answer (with their budgeted call seam)
/// and return it here. Queue replay never invokes a model or charges again.
pub trait RepresentationPlanner {
    fn plan(&mut self, context: &RepresentationContext) -> Result<RepresentationDraft>;
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredProposal {
    pub packet: Packet,
    pub run: String,
    pub revision: [u8; 32],
}
impl Vault {
    /// Reads real context, verifies the pre-materialized draft, stores it below
    /// the claim graph, then queues a proposal-only maintenance facet.
    pub fn schedule_representation(
        &self,
        request: &RepresentationRequest,
        planner: &mut dyn RepresentationPlanner,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let context = self.representation_context(request)?;
        let draft = planner.plan(&context)?;
        if draft.text.trim().is_empty() || draft.text.len() > 65_536 {
            return Err(invalid());
        }
        validate_citations(&context.evidence, &draft.evidence, Some(&draft.text))?;
        validate_citations(&context.voice, &draft.voice, None)?;
        let packet = Packet {
            request: request.clone(),
            content: crate::compaction::output::store_output(self, draft.text.as_bytes())?,
            evidence: draft.evidence,
            voice: draft.voice,
        };
        // Re-read after the host callback. A source edited while authoring is
        // not the source the model saw, even when its old quote still exists.
        validate_packet(self, &packet)?;
        let id = packet.id()?;
        let input = String::from_utf8(packet.bytes()?).map_err(|_| invalid())?;
        DreamerRunnerStore::new(self).enqueue_maintenance(
            REPRESENTATION_FACET,
            Value::from(input),
            format!("representation:{}", id.to_hex()),
            now,
        )
    }
}
pub(in crate::dreamer_runner::maintenance) fn run(
    vault: &Vault,
    attempt: &DreamerAdmittedAttempt,
    now: u64,
) -> Result<EntityId> {
    let packet: Packet =
        serde_json::from_str(attempt.status.payload.input.as_str().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
    validate_packet(vault, &packet)?;
    let id = packet.id()?;
    let shared =
        vault.dreamer_proposal_envelope(REPRESENTATION_FACET, attempt.status.attempt.id)?;
    let run = crate::entity_id::bytes_to_hex_lower(attempt.status.attempt.id.as_bytes());
    let mut provenance = shared
        .provenance()
        .value()
        .as_map()
        .ok_or_else(invalid)?
        .clone();
    // The shared authority stamp is retained. These are the existing gate's
    // run-tray keys, not another policy or another Dreamer actor.
    for (key, value) in [("runner", "dreamer"), ("run", run.as_str())] {
        let existing = provenance
            .iter()
            .filter(|(k, _)| k.as_str() == Some(key))
            .collect::<Vec<_>>();
        if existing.len() > 1
            || existing
                .first()
                .is_some_and(|(_, v)| v.as_str() != Some(value))
        {
            return Err(invalid());
        }
        if existing.is_empty() {
            provenance.push((Value::from(key), Value::from(value)));
        }
    }
    let envelope = WriteEnvelope::new(
        shared.actor(),
        shared.source(),
        WriteProvenance::new(Value::Map(provenance))?,
        shared.approval(),
    );
    let value = String::from_utf8(packet.bytes()?).map_err(|_| invalid())?;
    let evidence = crate::dreamer_consolidation::encode_consolidation_evidence(
        &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
            refs: packet
                .evidence
                .iter()
                .chain(&packet.voice)
                .map(|c| c.claim)
                .collect(),
            chain: Vec::new(),
            source_meet: ClaimSource::Generated,
        },
    );
    let candidate = ClaimCandidate::new(
        PREDICATE,
        ClaimSubject::Entity(packet.request.owner),
        Value::from(value),
        1.0,
    )
    .with_evidence(evidence);
    vault.with_write_txn(|txn| {
        if let Some(bytes) = vault
            .store
            .vault_meta
            .get(&*txn, &key(RECORD_PREFIX, &id))?
        {
            let existing: StoredProposal = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            if existing.packet != packet || vault.get_claim_in_txn(&*txn, &id)?.is_none() {
                return Err(invalid());
            }
            // Approval/rejection is terminal owner state, never reset by replay.
            return Ok(id);
        }
        if vault.get_claim_in_txn(&*txn, &id)?.is_some() {
            return Err(invalid());
        }
        vault
            .batch_in()
            .claim_candidate(
                &id,
                candidate,
                &envelope,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
            .apply_recording_gate_decisions(txn)?;
        let landed = vault.get_claim_in_txn(&*txn, &id)?.ok_or_else(invalid)?;
        if landed.approval != ClaimApprovalStatus::Proposed {
            return Err(invalid());
        }
        let record = StoredProposal {
            packet,
            run,
            revision: review_revision(&landed)?,
        };
        vault.store.vault_meta.put(
            txn,
            &key(RECORD_PREFIX, &id),
            &serde_json::to_vec(&record).map_err(|_| invalid())?,
        )?;
        Ok(id)
    })
}
pub(super) fn review_revision(body: &crate::ClaimBody) -> Result<[u8; 32]> {
    let mut normalized = body.clone();
    normalized.approval = ClaimApprovalStatus::Proposed;
    Ok(*blake3::hash(&crate::claim::encode_claim_body(&normalized)?).as_bytes())
}
pub(super) fn read_proposal(
    vault: &Vault,
    id: &EntityId,
) -> Result<(StoredProposal, crate::ClaimBody)> {
    let record: StoredProposal = {
        let txn = vault.store.env.read_txn()?;
        let bytes = vault
            .store
            .vault_meta
            .get(&txn, &key(RECORD_PREFIX, id))?
            .ok_or_else(invalid)?;
        serde_json::from_slice(&bytes).map_err(|_| invalid())?
    };
    let body = vault.get_claim(id)?.ok_or_else(invalid)?;
    if record.packet.id()? != *id
        || body.predicate != PREDICATE
        || body.subject != ClaimSubject::Entity(record.packet.request.owner)
        || body.source != Some(ClaimSource::Generated)
        || body.lifecycle != crate::ClaimLifecycleStatus::Active
        || body.stale
        || review_revision(&body)? != record.revision
        || crate::claim::session_claim_producer(&body)
            != Some(vault.dreamer_authority()?.entity_ref())
        || body.value.as_str() != std::str::from_utf8(&record.packet.bytes()?).ok()
    {
        return Err(invalid());
    }
    Ok((record, body))
}
