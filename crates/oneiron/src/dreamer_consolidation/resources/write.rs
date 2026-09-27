//! Sealed resource handoff. Only the executor can construct one; every real
//! promotion and attachment checks its pins inside the write transaction.
use super::{BranchResources, SourcePin, document_version};
use crate::claim::{ClaimSource, ScopedReadActorKey};
use crate::dreamer_consolidation::PromotionCandidate;
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::llm::Scope;
use crate::{EntityId, Result, Vault, WriteActor};
use std::collections::{BTreeMap, BTreeSet};

pub struct ScopedConsolidationWrite {
    pub(crate) candidates: Vec<PromotionCandidate>,
    pub(crate) attachments: Vec<(EntityId, PromotionCandidate)>,
    pub(crate) fence: ConsolidationFence,
}

impl ScopedConsolidationWrite {
    /// Inspection for non-writing sinks. Persistence must use the sealed write.
    pub fn candidates(&self) -> &[PromotionCandidate] {
        &self.candidates
    }
}

pub(crate) struct ConsolidationFence {
    actor: WriteActor,
    attempt: crate::attempt_queue::AttemptId,
    sources: BTreeMap<EntityId, SourcePin>,
    turns: BTreeSet<EntityId>,
    conversation: EntityId,
    rules: crate::dreamer_consolidation::routing::PredicateKeyRules,
}

impl BranchResources<'_> {
    pub(super) fn prepare_write(
        &self,
        scope: &Scope,
        candidates: Vec<PromotionCandidate>,
    ) -> Result<ScopedConsolidationWrite> {
        self.require_output(scope)?;
        let rules = self.key_rules();
        let mut writes = Vec::new();
        let mut attachments = Vec::new();
        for mut candidate in candidates {
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
                attachments.push((id, candidate));
            } else {
                candidate.supersedes = prior;
                writes.push(candidate);
            }
        }
        Ok(ScopedConsolidationWrite {
            candidates: writes,
            attachments,
            fence: self.write_fence(),
        })
    }

    pub(in crate::dreamer_consolidation) fn write_fence(&self) -> ConsolidationFence {
        ConsolidationFence {
            actor: WriteActor::new(
                EntityId::from_hex(self.read.actor_key().actor_ref()).expect("admitted actor"),
                crate::edge::EdgeActorClass::Agent,
            ),
            attempt: self.attempt,
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
        let rules: crate::dreamer_consolidation::routing::PredicateKeyRules = match vault
            .store
            .vault_meta
            .get(txn, b"dreamer:consolidation:keys:v1")?
        {
            Some(raw) => serde_json::from_slice(&raw)
                .map_err(|_| invalid_consolidation("invalid key rules"))?,
            None => serde_json::from_str(include_str!("../key_defaults.json"))
                .map_err(|_| invalid_consolidation("invalid default key rules"))?,
        };
        if rules != self.rules {
            return Err(invalid_consolidation("consolidation key rules changed"));
        }
        // Resolve fresh policy here. ScopedRead's cached manifest is not a
        // lease to retain a grant revoked during model or checker work.
        let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
        for (id, pin) in &self.sources {
            if !read.is_entity_readable_with_policy_in(txn, &policy, id)? {
                return Err(invalid_consolidation("pinned source read revoked"));
            }
            let raw = vault
                .store
                .entities
                .get(txn, id.as_bytes())?
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
            let prefix = [
                turn.as_bytes().as_slice(),
                &[crate::edge::EdgeKind::ChildOf as u8],
            ]
            .concat();
            let expected = crate::store::Store::encode_edge_key(
                turn,
                crate::edge::EdgeKind::ChildOf,
                &self.conversation,
            );
            let keys = vault
                .store
                .edges_out
                .prefix_iter(txn, &prefix)?
                .map(|row| row.map(|(key, _)| key.to_vec()))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if keys.len() != 1 || keys[0] != expected {
                return Err(invalid_consolidation("pinned source partition changed"));
            }
        }
        Ok(())
    }

    /// The pinned body is the only hash/trust input; the candidate supplies
    /// locators and judgement, not content hashes or source classification.
    pub(crate) fn verified_locators(
        &self,
        candidate: &PromotionCandidate,
    ) -> Result<Vec<(crate::dreamer_consolidation::SwarmEvidenceRef, [u8; 32])>> {
        let locators = crate::dreamer_consolidation::conflict::candidate_locators(candidate)?;
        let cited: BTreeSet<_> = locators.iter().map(|entry| entry.source_id).collect();
        let projected: BTreeSet<_> = candidate.evidence_turn_refs.iter().copied().collect();
        if cited != projected || cited.is_empty() {
            return Err(invalid_consolidation("unadmitted consolidation evidence"));
        }
        let mut verified: Vec<_> = locators
            .into_iter()
            .map(|locator| {
                let pin = self
                    .sources
                    .get(&locator.source_id)
                    .ok_or_else(|| invalid_consolidation("unadmitted consolidation evidence"))?;
                if locator.claim_id.is_some() {
                    if locator.claim_id != Some(locator.source_id)
                        || locator.byte_range.is_some()
                        || pin.entity_type != crate::registry::ENTITY_TYPE_CLAIM
                    {
                        return Err(invalid_consolidation("unadmitted claim locator"));
                    }
                    let body = crate::claim::decode_claim_body(&pin.body, true)?;
                    if !crate::claim::claim_evidence_admissible(&body) {
                        return Err(invalid_consolidation("generated claim cannot corroborate"));
                    }
                } else if !self.turns.contains(&locator.source_id)
                    || pin.entity_type != crate::registry::ENTITY_TYPE_TURN
                {
                    return Err(invalid_consolidation("unadmitted turn locator"));
                }
                let bytes = super::cited_evidence_bytes(locator, &pin.body)?;
                Ok((
                    locator,
                    crate::dreamer_consolidation::swarm_evidence_content_hash(&bytes),
                ))
            })
            .collect::<Result<_>>()?;
        verified.sort_by_key(|(locator, hash)| (locator.source_id, *hash, *locator));
        verified.dedup_by_key(|(locator, hash)| (locator.source_id, *hash));
        Ok(verified)
    }

    pub(crate) fn evidence_source(&self, candidate: &PromotionCandidate) -> Result<ClaimSource> {
        if !candidate.provenance_chain.is_empty() {
            return Err(invalid_consolidation("unadmitted consolidation evidence"));
        }
        let locators = self.verified_locators(candidate)?;
        let mut stored_meet = ClaimSource::Generated;
        for (locator, _) in locators {
            let trust = self
                .sources
                .get(&locator.source_id)
                .and_then(|pin| pin.trust_class)
                .ok_or_else(|| invalid_consolidation("unclassified consolidation evidence"))?;
            stored_meet = crate::dreamer_consolidation::provenance::source_meet(stored_meet, trust);
        }
        if crate::dreamer_consolidation::provenance::source_meet(
            stored_meet,
            candidate.evidence_meet,
        ) != candidate.evidence_meet
        {
            return Err(invalid_consolidation(
                "native branch evidence source mismatch",
            ));
        }
        Ok(candidate.evidence_meet)
    }
}
