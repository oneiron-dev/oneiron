//! Exact stored-head admission and question routing. Stored ids are not
//! candidate ids, and no resource is inferred from an extracted value.
use super::{BranchResources, SourcePin, document_version};
use crate::claim::{claim_consolidatable, decode_claim_body};
use crate::dreamer_consolidation::routing::{CandidateKeys, PredicateKeyRules, candidate_keys};
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::dreamer_consolidation::{ConflictSet, PriorHead, PromotionCandidate};
use crate::llm::{Scope, ScopeResource};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::{EntityId, Result};
use std::collections::BTreeSet;

impl BranchResources<'_> {
    pub(super) fn admit_priors(&mut self) -> Result<()> {
        // Only explicit exact document rights can introduce persisted heads.
        // Signal/output projections never grant a stored-head write right.
        let documents: BTreeSet<_> = self
            .scope
            .readable
            .iter()
            .chain(&self.scope.writable)
            .filter_map(|resource| match resource {
                ScopeResource::DocumentVersion { document, .. } => Some(*document),
                _ => None,
            })
            .collect();
        for id in documents {
            if self.sources.contains_key(&id)
                || self.read.vault().get_entity_type(&id)? != Some(ENTITY_TYPE_CLAIM)
            {
                continue;
            }
            let crate::claim::ScopedReadResult {
                value,
                receipt: _receipt,
            } = self.read.get_entity_parts_with_receipt(&id, None)?;
            let (kind, learned_at, bytes) =
                value.ok_or_else(|| invalid_consolidation("prior head is not actor-readable"))?;
            let resource = document_version(id, &bytes);
            if kind != ENTITY_TYPE_CLAIM || !self.scope.allows_read(&resource) {
                return Err(invalid_consolidation("prior head exact read refused"));
            }
            let body = decode_claim_body(&bytes, true)?;
            if !claim_consolidatable(&body)
                || !matches!(body.subject, crate::ClaimSubject::Entity(_))
            {
                continue;
            }
            let prior = PriorHead { claim_id: id, body };
            let keys = prior_keys(&prior, &Default::default())?;
            let facet = super::signals::facet(prior.body.scope.as_ref())?;
            if keys.identity.world != self.scope.world
                || facet != self.scope.facet
                || self
                    .scope
                    .relationship
                    .is_some_and(|r| keys.identity.rel != Some(r))
            {
                continue;
            }
            // A project is exactly the admitted document slice, not a new
            // claim identity axis. The exact read above binds it.
            self.sources.insert(
                id,
                SourcePin {
                    resource,
                    entity_type: kind,
                    learned_at,
                },
            );
            self.priors.insert(id, prior);
        }
        Ok(())
    }

    pub(in crate::dreamer_consolidation) fn prior(&self, id: EntityId) -> Result<&PriorHead> {
        self.priors
            .get(&id)
            .ok_or_else(|| invalid_consolidation("unadmitted prior head"))
    }

    pub(super) fn require_prior_write(&self, scope: &Scope, id: EntityId) -> Result<()> {
        self.check_axes(scope)?;
        self.prior(id)?;
        let pin = self
            .sources
            .get(&id)
            .ok_or_else(|| invalid_consolidation("missing prior pin"))?;
        if !scope.allows_read(&pin.resource) || !scope.allows_write(&pin.resource) {
            return Err(invalid_consolidation("prior head exact read/write refused"));
        }
        Ok(())
    }

    pub(in crate::dreamer_consolidation) fn matching_priors(
        &self,
        candidate: &PromotionCandidate,
        rules: &PredicateKeyRules,
    ) -> Result<Vec<(EntityId, bool)>> {
        let key = candidate_keys(candidate, rules)?;
        self.priors
            .values()
            .filter_map(|prior| {
                let prior_key = match prior_keys(prior, rules) {
                    Ok(key) => key,
                    Err(error) => return Some(Err(error)),
                };
                (key.identity == prior_key.identity && key.topic_key == prior_key.topic_key)
                    .then_some(Ok((prior.claim_id, key.value_key == prior_key.value_key)))
            })
            .collect()
    }

    pub(in crate::dreamer_consolidation) fn route_priors(
        &self,
        candidates: &[PromotionCandidate],
        mut conflicts: Vec<ConflictSet>,
        rules: &PredicateKeyRules,
    ) -> Result<Vec<ConflictSet>> {
        let mut exact = BTreeSet::new();
        let mut priors = Vec::new();
        for (index, candidate) in candidates.iter().enumerate() {
            let matches = self.matching_priors(candidate, rules)?;
            for (id, _) in &matches {
                self.require_prior_write(self.scope(), *id)?;
            }
            if matches.len() == 1 && matches[0].1 {
                exact.insert(index);
            }
            priors.push(matches);
        }
        // Keep all sibling/cosine connected components. An exact member is
        // replaced by its admitted stored head as context, not sent to judge.
        for conflict in &mut conflicts {
            let ids: BTreeSet<_> = conflict
                .candidate_indexes
                .iter()
                .flat_map(|index| priors[*index].iter().map(|(id, _)| *id))
                .collect();
            conflict.prior_head = (ids.len() == 1).then(|| *ids.first().expect("one prior"));
            conflict.prior_heads = ids.into_iter().collect();
            conflict
                .candidate_indexes
                .retain(|index| !exact.contains(index));
        }
        conflicts.retain(|conflict| !conflict.candidate_indexes.is_empty());
        for (index, matches) in priors.into_iter().enumerate() {
            if matches.iter().any(|(_, equal)| !equal)
                && !conflicts
                    .iter()
                    .any(|set| set.candidate_indexes.contains(&index))
            {
                conflicts.push(ConflictSet {
                    identity: candidate_keys(&candidates[index], rules)?.identity,
                    candidate_indexes: vec![index],
                    prior_head: (matches.len() == 1).then(|| matches[0].0),
                    prior_heads: matches.into_iter().map(|(id, _)| id).collect(),
                });
            }
        }
        Ok(conflicts)
    }
}

fn prior_keys(prior: &PriorHead, rules: &PredicateKeyRules) -> Result<CandidateKeys> {
    // Reuse the key derivation; this probe never enters candidate-id admission.
    let body = &prior.body;
    let mut candidate = crate::ClaimCandidate::new(
        body.predicate.clone(),
        body.subject,
        body.value.clone(),
        body.confidence,
    );
    if let Some(world) = body.world {
        candidate = candidate.with_world(world);
    }
    if let Some(rel) = body.rel {
        candidate = candidate.with_relationship(rel);
    }
    if let Some(scope) = &body.scope {
        candidate = candidate.with_scope(scope.clone());
    }
    candidate_keys(
        &PromotionCandidate {
            claim_id: prior.claim_id,
            candidate,
            evidence_turn_refs: Vec::new(),
            provenance_chain: Vec::new(),
            supersedes: None,
            evidence_meet: crate::ClaimSource::Generated,
            occurred: crate::TimeRange { start: 0, end: 0 },
            learned_at: 0,
        },
        rules,
    )
}
