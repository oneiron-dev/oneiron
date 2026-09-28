//! Sealed resource handoff. Only the executor can construct one; every real
//! promotion and attachment checks its pins inside the write transaction.
use super::{BranchResources, FallbackOutputPin, SourcePin, document_version};
#[cfg(test)]
use crate::claim::ClaimSource;
use crate::claim::{ScopedReadActorKey, ScopedReadReceipt};
use crate::dreamer_consolidation::PromotionCandidate;
use crate::dreamer_consolidation::evidence::{VerifiedCandidate, VerifiedEvidenceSet};
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::llm::Scope;
use crate::{EntityId, Result, Vault, WriteActor};
use std::collections::{BTreeMap, BTreeSet};

pub struct ScopedConsolidationWrite {
    pub(crate) candidates: Vec<PromotionCandidate>,
    pub(crate) candidate_evidence: Vec<VerifiedEvidenceSet>,
    pub(crate) attachments: Vec<(EntityId, PromotionCandidate, VerifiedEvidenceSet)>,
    pub(crate) fence: ConsolidationFence,
    read_receipt: ScopedReadReceipt,
}

impl ScopedConsolidationWrite {
    /// Inspection for non-writing sinks. Persistence must use the sealed write.
    pub fn candidates(&self) -> &[PromotionCandidate] {
        &self.candidates
    }

    /// Every scoped read behind these candidates, folded: sources, priors,
    /// graph signals and the wake's pinned read. Rows withheld from the Dreamer
    /// actor are counted here, never silently dropped.
    pub fn read_receipt(&self) -> &ScopedReadReceipt {
        &self.read_receipt
    }
}

pub(crate) struct ConsolidationFence {
    actor: WriteActor,
    attempt: crate::attempt_queue::AttemptId,
    fallback_binding: Option<FallbackOutputPin>,
    sources: BTreeMap<EntityId, SourcePin>,
    turns: BTreeSet<EntityId>,
    conversation: EntityId,
    rules: crate::dreamer_consolidation::routing::PredicateKeyRules,
}

impl BranchResources<'_> {
    pub(super) fn prepare_write_verified(
        &self,
        scope: &Scope,
        candidates: Vec<VerifiedCandidate>,
    ) -> Result<ScopedConsolidationWrite> {
        self.require_output(scope)?;
        let rules = self.key_rules();
        let mut writes = Vec::new();
        let mut written_evidence = Vec::new();
        let mut attachments = Vec::new();
        for verified in candidates {
            verified.evidence.check_pins(self)?;
            let mut candidate = verified.proposal;
            let evidence = verified.evidence;
            if candidate.evidence_turn_refs != evidence.refs()
                || candidate.evidence_meet != evidence.meet()
            {
                return Err(invalid_consolidation(
                    "candidate does not match verified evidence",
                ));
            }
            // Supersession is an engine resolution, never a model-selected id.
            let prior = candidate.supersedes.take();
            self.validate_candidates(scope, std::slice::from_ref(&candidate))?;
            if let Some(id) = prior {
                self.require_prior_write(scope, id)?;
            }
            let matches = self.matching_priors(&candidate, rules)?;
            if prior.is_some_and(|id| !matches.iter().any(|(matched, _)| *matched == id)) {
                return Err(invalid_consolidation(
                    "resolved supersession crossed its prior question",
                ));
            }
            if matches.len() > 1 && prior.is_some() {
                return Err(invalid_consolidation(
                    "multiple admitted prior heads for one question",
                ));
            }
            if let [(id, true)] = matches.as_slice() {
                let id = *id;
                if candidate.evidence_turn_refs.contains(&id) {
                    return Err(invalid_consolidation(
                        "claim evidence cannot support itself",
                    ));
                }
                self.require_prior_write(scope, id)?;
                attachments.push((id, candidate, evidence));
            } else {
                candidate.supersedes = prior;
                writes.push(candidate);
                written_evidence.push(evidence);
            }
        }
        Ok(ScopedConsolidationWrite {
            candidates: writes,
            candidate_evidence: written_evidence,
            attachments,
            fence: self.write_fence(),
            read_receipt: self.read_receipt()?,
        })
    }

    pub(in crate::dreamer_consolidation) fn write_fence(&self) -> ConsolidationFence {
        ConsolidationFence {
            actor: WriteActor::new(
                EntityId::from_hex(self.read.actor_key().actor_ref()).expect("admitted actor"),
                crate::edge::EdgeActorClass::Agent,
            ),
            attempt: self.attempt,
            fallback_binding: self.fallback_binding(),
            sources: self.sources.clone(),
            turns: self.turns.clone(),
            conversation: self.partition.conversation_ref,
            rules: self.rules.clone(),
        }
    }
}

impl ConsolidationFence {
    pub(crate) fn validate_run(
        &self,
        run: &crate::dreamer_promotion::DreamerRunContext,
    ) -> Result<()> {
        if run.agent_actor != self.actor || run.attempt_id != self.attempt {
            return Err(invalid_consolidation(
                "scoped sink run does not match executor",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<()> {
        let actor = ScopedReadActorKey::with_actor_class(
            self.actor.entity_ref().to_hex(),
            self.actor.actor_class().gate_actor_class(),
        )
        .ok_or_else(|| invalid_consolidation("invalid pinned actor"))?;
        let read = vault.scoped_read(actor);
        let rules: crate::dreamer_consolidation::routing::PredicateKeyRules =
            match crate::dreamer_consolidation::routing::KEY_RULES.get(&vault.store, txn, &())? {
                Some(rules) => rules,
                None => serde_json::from_str(include_str!("../key_defaults.json"))
                    .map_err(|_| invalid_consolidation("invalid default key rules"))?,
            };
        if rules != self.rules {
            return Err(invalid_consolidation("consolidation key rules changed"));
        }
        // Resolve fresh policy here. ScopedRead's cached manifest is not a
        // lease to retain a grant revoked during model or checker work.
        let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
        if let Some(binding) = self.fallback_binding
            && !crate::llm::verified_step_consolidation_eligible_in_txn(
                vault,
                txn,
                &policy,
                binding.step,
                self.actor.entity_ref(),
                binding.response_hash,
            )
            .map_err(|_| invalid_consolidation("invalid extraction fallback checkpoint"))?
        {
            return Err(invalid_consolidation(
                "extraction fallback eligibility revoked",
            ));
        }
        for (id, pin) in &self.sources {
            if !read.is_entity_readable_with_policy_in(txn, &policy, id)? {
                return Err(invalid_consolidation("pinned source read revoked"));
            }
            let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)?
                .ok_or_else(|| invalid_consolidation("pinned source missing"))?;
            let header = crate::batch::EntityMetadataHeader::parse(&raw)
                .ok_or_else(|| invalid_consolidation("pinned source header"))?;
            if header.entity_type != pin.entity_type
                || header.learned_at != pin.learned_at
                || document_version(*id, &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                    != pin.resource
            {
                return Err(invalid_consolidation("pinned source revision changed"));
            }
        }
        for turn in &self.turns {
            let peers = crate::ports::EdgeStoreRead::port_edge_peers(
                &vault.store,
                txn,
                turn,
                crate::ports::EdgeDirection::Out,
                crate::edge::EdgeKind::ChildOf,
            )?
            .collect::<Result<Vec<_>>>()?;
            if peers != [self.conversation] {
                return Err(invalid_consolidation("pinned source partition changed"));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn evidence_source(&self, candidate: &PromotionCandidate) -> Result<ClaimSource> {
        if candidate.evidence_turn_refs.is_empty() || !candidate.provenance_chain.is_empty() {
            return Err(invalid_consolidation("unadmitted consolidation evidence"));
        }
        let stored_meet =
            candidate
                .evidence_turn_refs
                .iter()
                .try_fold(ClaimSource::Generated, |meet, id| {
                    if !self.turns.contains(id) {
                        return Err(invalid_consolidation("unadmitted consolidation evidence"));
                    }
                    let trust = self
                        .sources
                        .get(id)
                        .and_then(|pin| pin.trust_class)
                        .ok_or_else(|| {
                            invalid_consolidation("unclassified consolidation evidence")
                        })?;
                    Ok(crate::dreamer_consolidation::source_meet(meet, trust))
                })?;
        if crate::dreamer_consolidation::source_meet(stored_meet, candidate.evidence_meet)
            != candidate.evidence_meet
        {
            return Err(invalid_consolidation(
                "native branch evidence source mismatch",
            ));
        }
        Ok(candidate.evidence_meet)
    }
}
