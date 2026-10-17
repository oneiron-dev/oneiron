//! Exact stored-head admission and question routing. Stored ids are not
//! candidate ids, and no resource is inferred from an extracted value.
use super::{BranchResources, SourcePin, document_version};
use crate::claim::{claim_consolidatable, claim_correctable_generated, decode_claim_body};
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
            if self.sources.contains_key(&id) {
                continue;
            }
            let (kind, learned_at, bytes) = if let Some(wake) = self.prepared_wake {
                // Bytes from the wake's one read, whose receipt the branch holds.
                let Some(row) = wake.source(&id) else {
                    continue;
                };
                if row.0 != ENTITY_TYPE_CLAIM {
                    continue;
                }
                // A head the wake read may be closed or withheld since, as
                // by an earlier branch of the same pass. The branch holds
                // only what it may read now; the rest is counted on its
                // receipt (the row-authority axis), and the turn proceeds.
                if !self.read.is_entity_readable(&id)? {
                    self.read_receipt
                        .lock()
                        .map_err(|_| crate::Error::InvariantViolation("branch read receipt lock"))?
                        .add_suppressed(1);
                    tracing::info!(
                        target: "oneiron::dreamer",
                        "a prior head the wake listed is no longer readable; the branch runs without it"
                    );
                    continue;
                }
                row
            } else {
                if self.read.vault().get_entity_type(&id)? != Some(ENTITY_TYPE_CLAIM) {
                    continue;
                }
                let head = self
                    .read
                    .read(&[crate::claim::PointRead::id(id)], None)?
                    .single();
                self.fold_read_receipt(&head.receipt)?;
                // A withheld head is counted on the read's own receipt.
                let Some(crate::claim::ReadRow {
                    entity_type: kind,
                    learned_at,
                    body: Some(bytes),
                    ..
                }) = head.value
                else {
                    continue;
                };
                (kind, learned_at, bytes)
            };
            let resource = document_version(id, &bytes);
            if kind != ENTITY_TYPE_CLAIM || !self.scope.allows_read(&resource) {
                return Err(invalid_consolidation("prior head exact read refused"));
            }
            // A head awaiting its owner's confirmation is no prior for anyone.
            if !self.read.vault().claim_consolidation_eligible(
                &id,
                crate::gate::ConsolidationReader::ExplicitPrior,
            )? {
                continue;
            }
            let prior = PriorHead {
                claim_id: id,
                body: decode_claim_body(&bytes, true)?,
            };
            match standing(&prior, &self.scope)? {
                Some(Standing::Prior) => {}
                // Only a head the passage's listing names stands provisionally.
                Some(Standing::Provisional) if self.known.lists(id) => {
                    self.provisional.insert(id);
                }
                _ => continue,
            }
            // The exact read above binds the admitted document slice; the
            // project axis of the identity keeps a head in another project
            // from ever matching a candidate here.
            self.sources.insert(
                id,
                SourcePin {
                    resource,
                    entity_type: kind,
                    learned_at,
                    project: Some(prior.body.scope_project),
                    body_hash: *blake3::hash(&bytes).as_bytes(),
                    #[cfg(test)]
                    trust_class: Some(crate::dreamer_consolidation::provenance::source_meet(
                        prior.body.source.unwrap_or(crate::ClaimSource::Imported),
                        crate::claim::claim_evidence_taint(&prior.body)
                            .unwrap_or(prior.body.source.unwrap_or(crate::ClaimSource::Imported)),
                    )),
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

/// How a stored head stands on a branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::dreamer_consolidation) enum Standing {
    /// A consolidatable head: merge context, an attachment target, a prior.
    Prior,
    /// The Dreamer's own unvetted `Auto` head: a correction may close it,
    /// and nothing attaches to it.
    Provisional,
}

/// How a stored head can stand on a branch with `axes`, if at all: an
/// entity claim in the branch's world and facet, and in its relationship
/// and project when the branch is bound to one.
pub(in crate::dreamer_consolidation) fn standing(
    prior: &PriorHead,
    axes: &Scope,
) -> Result<Option<Standing>> {
    let standing = if claim_consolidatable(&prior.body) {
        Standing::Prior
    } else if claim_correctable_generated(&prior.body) {
        Standing::Provisional
    } else {
        return Ok(None);
    };
    if !matches!(prior.body.subject, crate::ClaimSubject::Entity(_)) {
        return Ok(None);
    }
    let keys = prior_keys(prior, &Default::default())?;
    let facet = super::signals::facet(prior.body.scope.as_ref())?;
    let fits = keys.identity.world == axes.world
        && facet == axes.facet
        && axes
            .relationship
            .is_none_or(|r| keys.identity.rel == Some(r))
        && axes.project.is_none_or(|p| keys.identity.project == p);
    Ok(fits.then_some(standing))
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
    let mut keys = candidate_keys(
        &PromotionCandidate {
            claim_id: prior.claim_id,
            candidate,
            evidence_turn_refs: Vec::new(),
            provenance_chain: Vec::new(),
            supersedes: None,
            evidence_meet: crate::ClaimSource::Generated,
            occurred: crate::TimeRange { start: 0, end: 0 },
            learned_at: 0,
            decisions: Vec::new(),
        },
        rules,
    )?;
    // The stored body's own stamp is the head's project; a scope-map entry
    // can never move it.
    keys.identity.project = body.scope_project;
    Ok(keys)
}

impl crate::Vault {
    #[cfg(test)]
    pub(crate) fn explicit_prior_ids_for_test(
        &self,
        actor: crate::WriteActor,
        conversation: EntityId,
        claim: EntityId,
    ) -> Result<Vec<EntityId>> {
        let partition = crate::dreamer_consolidation::ConsolidationPartitionKey {
            conversation_ref: conversation,
            world_ref: None,
            facet_ref: None,
        };
        let mut scope = Scope::default();
        scope.readable.insert(ScopeResource::Bucket {
            key: crate::entity_id::bytes_to_hex_lower(&partition.partition_hash()),
        });
        for id in [conversation, claim] {
            let raw = self.get_raw(&id)?.ok_or(crate::Error::EntityNotFound)?;
            scope.readable.insert(document_version(
                id,
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            ));
        }
        let resources = BranchResources::open(
            self,
            actor,
            partition,
            &[],
            crate::attempt_queue::AttemptId::now(),
            Some(&scope),
        )?;
        Ok(resources.priors.keys().copied().collect())
    }
}
