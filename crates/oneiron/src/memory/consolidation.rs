//! Typed promotion and evidence observation over the existing Dreamer writer.
//! The owner invokes the writer; the queued Dreamer, not request JSON, supplies
//! its author, run and source. This door neither completes jobs nor sends effects.
use super::{ClaimScope, Memory, MemoryError, MemoryResult};
use crate::claim::{
    ClaimReadStatus, PointRead, ScopedReadResult, claim_consolidatable, claim_evidence_taint,
    claim_generated_origin,
};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_consolidation::{
    PromotionCandidate, decode_consolidation_evidence, decode_verified_citations,
    evidence_chain_source,
};
use crate::dreamer_promotion::{
    DreamerRunContext, EvidenceRef, PromotionEvidenceReason, evidence_ref_refusal_in_txn,
    promote_consolidated_claims_with_checker, public_evidence_refs, public_evidence_value,
};
use crate::dreamer_runner::{DreamerConsolidationScope, DreamerRunnerStore};
use crate::entity_id::ForeignWorldId;
use crate::llm::BoundedAutoChecker;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_TURN};
use crate::write_envelope::ClaimCandidate;
use crate::{EdgeActorClass, EntityId, Error, TimeRange};
use serde::{Deserialize, Serialize};

/// One generated proposal. Source, approval, actor, provenance and clocks are
/// deliberately absent: only the host promotion writer may stamp those axes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GeneratedClaimInput {
    pub claim_ref: String,
    pub predicate: String,
    pub subject_ref: String,
    pub value: serde_json::Value,
    pub confidence: f32,
    pub scope: ClaimScope,
    pub sensitivity: Option<u8>,
    pub evidence_refs: Vec<EvidenceRef>,
    /// Visible claim candidates are assessed separately: a CLAIM is not a
    /// document EvidenceKind and generated claims contribute zero signals.
    #[serde(default)]
    pub claim_evidence_refs: Vec<String>,
    pub supersedes: Option<String>,
    pub valid_from: Option<u64>,
    pub valid_to: Option<u64>,
}

/// Promote explicitly named candidates in an already admitted consolidation
/// attempt. The attempt must carry its real run_id; no alternate run is minted.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationPromoteRequest {
    pub job_ref: String,
    pub candidates: Vec<GeneratedClaimInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationEvidenceRequest {
    pub source_refs: Vec<String>,
}

/// A stored, parent-verified locator. content_hash is the engine's BLAKE3
/// hash, not a quote_sha256 or a newly invented document frontier.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationEvidenceLocator {
    pub source_ref: String,
    pub claim_ref: Option<String>,
    pub byte_range: Option<(usize, usize)>,
    pub content_hash: [u8; 32],
    pub messages: Vec<ConsolidationMessageEvidence>,
}

/// The exact MESSAGE-local slice and causal frontier retained by the parent
/// verifier. Byte offsets are not stable cursors; no current head is substituted.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationMessageEvidence {
    pub message_ref: String,
    pub start: usize,
    pub end: usize,
    pub revision: [u8; 32],
    pub frontier: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationEvidenceHop {
    pub kind: String,
    pub entity_ref: String,
    pub actor_ref: Option<String>,
}

/// Source facts and the engine's separate read-admission axes. Effector
/// evidence eligibility is not permission to perform any outbound action.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationEvidenceSource {
    pub source_ref: String,
    pub source: Option<String>,
    pub approval: Option<String>,
    pub lifecycle: Option<String>,
    pub evidence_taint: Option<String>,
    pub generated_origin: bool,
    pub writer_ref: Option<String>,
    pub foreign_world_ref: Option<String>,
    pub consolidation_eligible: bool,
    pub corroboration_eligible: bool,
    pub first_party_corroboration: bool,
    pub effector_evidence_eligible: bool,
    pub refusal: Option<PromotionEvidenceReason>,
    /// The exact stored promotion source ids, not equal-text matches or counts.
    pub source_refs: Vec<String>,
    /// Canonical document citations, at the versions the writer verified.
    pub evidence_refs: Vec<EvidenceRef>,
    pub source_meet: Option<String>,
    pub chain: Vec<ConsolidationEvidenceHop>,
    pub locators: Vec<ConsolidationEvidenceLocator>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationRejection {
    pub claim_ref: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationPromotion {
    pub job_ref: String,
    pub landed: Vec<String>,
    pub pended: Vec<String>,
    pub held: Vec<String>,
    pub rejected: Vec<ConsolidationRejection>,
    /// Decisions on the input refs before promotion, one per distinct source.
    pub input_evidence: Vec<ConsolidationEvidenceSource>,
    /// Evidence actually retained by the generated claims after the writer.
    pub output_evidence: Vec<ConsolidationEvidenceSource>,
}

impl Memory<'_> {
    fn consolidation_owner(&self, owner: &AuthenticatedOwner) -> MemoryResult<()> {
        if owner.revalidate(self.vault)? != self.actor || self.actor_class != EdgeActorClass::Human
        {
            return Err(MemoryError::new(
                super::MEMORY_CODE_FORBIDDEN,
                "consolidation acts on the owner's own credential handle",
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        Ok(())
    }

    /// Source and generated-claim evidence, admitted and projected in the same
    /// scoped-read snapshot. An unreadable named source refuses the whole read.
    pub fn consolidation_evidence_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &ConsolidationEvidenceRequest,
    ) -> MemoryResult<ScopedReadResult<Vec<ConsolidationEvidenceSource>>> {
        self.consolidation_owner(owner)?;
        super::caps::check_batch_len("source_refs", input.source_refs.len())?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let refs = input
            .source_refs
            .iter()
            .map(|reference| {
                self.resolve_ref_in_lane(&lane, reference)
                    .map(PointRead::id)
            })
            .collect::<MemoryResult<Vec<_>>>()?;
        lane.read_projected(&refs, None, |txn, rows| {
            let mut evidence = Vec::with_capacity(rows.len());
            for row in rows {
                let row = row
                    .filter(|row| row.body.is_some())
                    .ok_or_else(|| MemoryError::not_found("no readable evidence has that ref"))?;
                self.produced_from([row.id]);
                let refusal = evidence_ref_refusal_in_txn(self.vault, txn, &row.id)?;
                let mut view = ConsolidationEvidenceSource {
                    source_ref: row.id.to_hex(),
                    source: None,
                    approval: None,
                    lifecycle: None,
                    evidence_taint: None,
                    generated_origin: false,
                    writer_ref: None,
                    foreign_world_ref: None,
                    consolidation_eligible: refusal.is_none(),
                    corroboration_eligible: refusal.is_none(),
                    first_party_corroboration: false,
                    effector_evidence_eligible: refusal.is_none(),
                    refusal,
                    source_refs: Vec::new(),
                    evidence_refs: Vec::new(),
                    source_meet: None,
                    chain: Vec::new(),
                    locators: Vec::new(),
                };
                if row.entity_type == ENTITY_TYPE_CLAIM {
                    let body = crate::claim::decode_claim_body(
                        row.body.as_deref().ok_or(Error::EntityNotFound)?,
                        true,
                    )?;
                    view.source = body.source.map(|source| source.as_str().to_owned());
                    view.approval = Some(body.approval.as_str().to_owned());
                    view.lifecycle = Some(body.lifecycle.as_str().to_owned());
                    view.evidence_taint =
                        claim_evidence_taint(&body).map(|source| source.as_str().to_owned());
                    view.generated_origin = claim_generated_origin(&body);
                    view.writer_ref = super::claim_author(&body).map(|actor| actor.to_hex());
                    view.foreign_world_ref = body
                        .world
                        .filter(|world| ForeignWorldId::from_entity_id(*world).is_ok())
                        .map(|world| world.to_hex());
                    let confirmed = crate::gate::claim_consolidation_eligible_in_txn(
                        &self.vault.store,
                        txn,
                        &row.id,
                        crate::gate::ConsolidationReader::PromotionEvidence,
                    )?;
                    view.consolidation_eligible = claim_consolidatable(&body) && confirmed;
                    view.effector_evidence_eligible = view.consolidation_eligible;
                    view.first_party_corroboration = view.corroboration_eligible
                        && view.foreign_world_ref.is_none()
                        && matches!(
                            body.source,
                            Some(
                                crate::claim::ClaimSource::UserStated
                                    | crate::claim::ClaimSource::Observed
                                    | crate::claim::ClaimSource::Inferred
                            )
                        );
                    let stored = body.evidence.as_ref().and_then(candidate_evidence);
                    if let Some(stored) = stored {
                        if let Some(envelope) = decode_consolidation_evidence(stored)? {
                            view.evidence_refs = public_evidence_refs(Some(stored))?;
                            let document_sources = view
                                .evidence_refs
                                .iter()
                                .map(|reference| EntityId::from_hex(&reference.entity))
                                .collect::<crate::Result<Vec<_>>>()?;
                            let named: Vec<_> = envelope
                                .refs
                                .iter()
                                .copied()
                                .chain(document_sources)
                                .chain(envelope.chain.iter().flat_map(|hop| {
                                    [Some(hop.entity_ref), hop.actor_ref].into_iter().flatten()
                                }))
                                .collect();
                            if lane
                                .entities_readable_in_txn(txn, &named)?
                                .iter()
                                .any(|readable| !readable)
                            {
                                return Err(MemoryError::not_found(
                                    "claim evidence is not readable",
                                ));
                            }
                            self.produced_from(named);
                            view.source_refs = envelope.refs.iter().map(EntityId::to_hex).collect();
                            view.source_meet = Some(envelope.source_meet.as_str().to_owned());
                            view.chain = envelope
                                .chain
                                .iter()
                                .map(|hop| ConsolidationEvidenceHop {
                                    kind: hop.kind.as_str().to_owned(),
                                    entity_ref: hop.entity_ref.to_hex(),
                                    actor_ref: hop.actor_ref.map(|actor| actor.to_hex()),
                                })
                                .collect();
                            if stored.as_map().is_some_and(|fields| {
                                fields
                                    .iter()
                                    .any(|(key, _)| key.as_str() == Some("locators"))
                            }) {
                                view.locators = decode_verified_citations(stored)?
                                    .into_iter()
                                    .map(|(locator, content_hash, messages)| {
                                        ConsolidationEvidenceLocator {
                                            source_ref: locator.source_id.to_hex(),
                                            claim_ref: locator.claim_id.map(|id| id.to_hex()),
                                            byte_range: locator.byte_range,
                                            content_hash,
                                            messages: messages
                                                .into_iter()
                                                .map(|message| ConsolidationMessageEvidence {
                                                    message_ref: message.message.to_hex(),
                                                    start: message.start,
                                                    end: message.end,
                                                    revision: message.revision,
                                                    frontier: message.frontier,
                                                })
                                                .collect(),
                                        }
                                    })
                                    .collect();
                            }
                        }
                    }
                } else if row.entity_type == ENTITY_TYPE_TURN
                    && view.refusal != Some(PromotionEvidenceReason::UnsupportedTurnRole)
                {
                    view.source = Some(
                        crate::dreamer_consolidation::resources::native_turn_source(
                            self.vault,
                            row.body.as_deref().ok_or(Error::EntityNotFound)?,
                        )?
                        .as_str()
                        .to_owned(),
                    );
                    view.first_party_corroboration =
                        view.corroboration_eligible && view.source.as_deref() != Some("imported");
                }
                evidence.push(view);
            }
            Ok::<_, MemoryError>(evidence)
        })
    }

    /// Host-stamped generated claims through the one promotion writer and the
    /// host's configured checker. No approval or source is accepted from JSON.
    pub fn consolidation_promote_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &ConsolidationPromoteRequest,
        checker: Option<&BoundedAutoChecker>,
    ) -> MemoryResult<ConsolidationPromotion> {
        self.consolidation_owner(owner)?;
        super::caps::check_batch_len("candidates", input.candidates.len())?;
        let attempt = super::outbound::parse_job_ref(&input.job_ref)?;
        let status = DreamerRunnerStore::new(self.vault)
            .status(attempt)?
            .ok_or_else(|| MemoryError::not_found("no consolidation attempt has that job_ref"))?;
        if ![
            DreamerConsolidationScope::Micro,
            DreamerConsolidationScope::Meso,
            DreamerConsolidationScope::Macro,
        ]
        .iter()
        .any(|scope| scope.attempt_kind() == status.payload.attempt_type)
            || !matches!(
                status.attempt.state,
                crate::attempt_queue::AttemptState::Queued
                    | crate::attempt_queue::AttemptState::Leased
                    | crate::attempt_queue::AttemptState::Paused
            )
        {
            return Err(MemoryError::bad_request(
                "job_ref must name an active consolidation attempt",
            ));
        }
        let run_id = status
            .attempt
            .run_id
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| {
                MemoryError::bad_request("the consolidation attempt must name its run_id")
            })?;
        let mut source_refs: Vec<_> = input
            .candidates
            .iter()
            .flat_map(|candidate| {
                candidate
                    .evidence_refs
                    .iter()
                    .map(|reference| reference.entity.clone())
                    .chain(candidate.claim_evidence_refs.iter().cloned())
            })
            .collect();
        source_refs.sort();
        source_refs.dedup();
        let input_evidence = self
            .consolidation_evidence_as_owner(owner, &ConsolidationEvidenceRequest { source_refs })?
            .value;
        let now = self.vault.store.clock.now_recorded_at();
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let mut candidates = Vec::with_capacity(input.candidates.len());
        for input in &input.candidates {
            if input.sensitivity.is_some_and(|band| band > 3) {
                return Err(MemoryError::bad_request("sensitivity must be in 0..=3"));
            }
            let id = EntityId::from_hex(&input.claim_ref)?;
            let subject = self.resolve_ref_in_lane(&lane, &input.subject_ref)?;
            let supersedes = input
                .supersedes
                .as_deref()
                .map(|reference| self.resolve_ref_in_lane(&lane, reference))
                .transpose()?;
            let named: Vec<_> = std::iter::once(subject)
                .chain(supersedes)
                .map(PointRead::id)
                .collect();
            if lane
                .read(&named, None)?
                .value
                .iter()
                .any(|row| row.as_ref().is_none_or(|row| row.body.is_none()))
            {
                return Err(MemoryError::not_found(
                    "a candidate names an unreadable subject or prior",
                ));
            }
            self.produced_from(std::iter::once(subject).chain(supersedes));
            let world = self.resolve_ref(&input.scope.world_id)?;
            let facet = self.resolve_ref(&input.scope.scope_facet_id)?;
            let project = self.resolve_ref(&input.scope.scope_project_id)?;
            if self.vault.get_entity_type(&facet)? != Some(ENTITY_TYPE_FACET) {
                return Err(MemoryError::bad_request("scope facet must name a FACET"));
            }
            let mut candidate = ClaimCandidate::new(
                &input.predicate,
                crate::claim::ClaimSubject::Entity(subject),
                super::support::json_to_rmpv(&input.value),
                input.confidence,
            )
            .with_world(world)
            .with_scope_stamps(facet, project)
            .with_validity(input.valid_from, input.valid_to);
            if let Some(band) = input.sensitivity {
                candidate = candidate.with_scope(rmpv::Value::Map(vec![(
                    rmpv::Value::from("sensitivity"),
                    rmpv::Value::from(band),
                )]));
            }
            match &input.scope.scope_relationship_id {
                super::ClaimRelationships::All(super::AllRelationships::All) => {}
                super::ClaimRelationships::Relationships(refs) if refs.len() == 1 => {
                    candidate = candidate.with_relationship(self.resolve_ref(&refs[0])?);
                }
                _ => {
                    return Err(MemoryError::bad_request(
                        "a claim relationship position is all or exactly one relationship",
                    ));
                }
            }
            candidate = candidate.with_evidence(rmpv::Value::Map(vec![(
                rmpv::Value::from("evidence_refs"),
                public_evidence_value(&input.evidence_refs)?,
            )]));
            let mut evidence_refs = input
                .claim_evidence_refs
                .iter()
                .map(|reference| self.resolve_ref(reference))
                .collect::<MemoryResult<Vec<_>>>()?;
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            for reference in &input.evidence_refs {
                evidence_refs.push(crate::entity_doc::promotion_evidence_source_in_txn(
                    self.vault, &txn, reference,
                )?);
            }
            evidence_refs.sort();
            evidence_refs.dedup();
            let admitted = evidence_refs
                .iter()
                .map(|id| {
                    evidence_ref_refusal_in_txn(self.vault, &txn, id)
                        .map(|reason| reason.is_none().then_some(*id))
                })
                .collect::<crate::Result<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            drop(txn);
            let evidence_meet = evidence_chain_source(self.vault, &[], &admitted)?;
            candidates.push(PromotionCandidate {
                claim_id: id,
                candidate,
                evidence_turn_refs: evidence_refs,
                provenance_chain: Vec::new(),
                supersedes,
                evidence_meet,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                decisions: Vec::new(),
            });
        }
        // Revalidate the caller's authority immediately before reaching the
        // engine writer. Each candidate still runs its ordinary claim Gate.
        self.consolidation_owner(owner)?;
        let run = DreamerRunContext {
            run_id,
            attempt_id: attempt,
            agent_actor: self.vault.dreamer_actor_for_attempt(attempt)?,
            now_ms: now.saturating_mul(1_000),
        };
        let outcome =
            promote_consolidated_claims_with_checker(self.vault, &run, candidates, checker)?;
        let source_refs = outcome
            .landed
            .iter()
            .chain(&outcome.pended)
            .chain(&outcome.held)
            .map(EntityId::to_hex)
            .collect();
        let output_evidence = self
            .consolidation_evidence_as_owner(owner, &ConsolidationEvidenceRequest { source_refs })?
            .value;
        Ok(ConsolidationPromotion {
            job_ref: input.job_ref.clone(),
            landed: outcome.landed.iter().map(EntityId::to_hex).collect(),
            pended: outcome.pended.iter().map(EntityId::to_hex).collect(),
            held: outcome.held.iter().map(EntityId::to_hex).collect(),
            rejected: outcome
                .rejected
                .into_iter()
                .map(|(id, reason)| ConsolidationRejection {
                    claim_ref: id.to_hex(),
                    reason,
                })
                .collect(),
            input_evidence,
            output_evidence,
        })
    }
}

fn candidate_evidence(value: &rmpv::Value) -> Option<&rmpv::Value> {
    let fields = value.as_map()?;
    fields
        .iter()
        .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
        .map(|(_, value)| value)
        .or(Some(value))
}
