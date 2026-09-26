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
            actor: self.actor,
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

    pub(crate) fn evidence_source(&self, candidate: &PromotionCandidate) -> Result<ClaimSource> {
        if candidate.evidence_turn_refs.is_empty()
            || !candidate.provenance_chain.is_empty()
            || candidate
                .evidence_turn_refs
                .iter()
                .any(|id| !self.turns.contains(id))
        {
            return Err(invalid_consolidation("unadmitted consolidation evidence"));
        }
        // This branch admits native user/assistant TURNs only. Imported histories
        // are RECORDs, not TURNs. Generated is the existing evidence-meet floor;
        // a prior is context, never corroboration or a source upgrade.
        if crate::dreamer_consolidation::provenance::source_meet(
            ClaimSource::Generated,
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
