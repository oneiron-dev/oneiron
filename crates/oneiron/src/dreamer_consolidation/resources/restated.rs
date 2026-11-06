//! A candidate that restates the Dreamer's own unvetted head is already
//! said (FIX 12043), whether or not the round's listing named that head. A
//! later round (a sitting's Meso round after its Micro rounds, a Macro round
//! after both) lists only the heads of the subjects its passage names, read
//! at its wake's snapshot, so the head an earlier round wrote for the same
//! words was often outside its listing and the round wrote the same claim a
//! second time. Before a candidate that matched no admitted prior is written,
//! the branch now reads the subject's claims the Dreamer may read now: one
//! that stands on this branch only provisionally (the Dreamer's own `Auto`,
//! generated, unvetted head), that its owner has not held, with the same
//! identity, topic and value, born in the same facet, project and taint
//! scope, makes the candidate already said, exactly as a listed one does.
//! Nothing attaches to such a head and nothing else changes: a vetted head
//! still needs the listing's pin to take evidence, and every other case
//! writes as before.

use super::BranchResources;
use super::prior::{Standing, prior_keys, standing};
use crate::claim::{ClaimSource, PointRead, ReadRow, decode_claim_body};
use crate::dreamer_consolidation::conflict::candidate_probe_body;
use crate::dreamer_consolidation::routing::{PredicateKeyRules, candidate_keys};
use crate::dreamer_consolidation::{PriorHead, PromotionCandidate};
use crate::dreamer_promotion::scope_with_taint;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::{ClaimSubject, EntityId, Result};
use std::collections::{BTreeMap, BTreeSet};

/// Each subject's unvetted Dreamer heads under one predicate that this
/// branch may read now, read once per write: the heads that stand on the
/// branch only provisionally.
#[derive(Default)]
pub(super) struct UnlistedHeads {
    by_question: BTreeMap<(EntityId, String), Vec<PriorHead>>,
}

impl BranchResources<'_> {
    /// Whether `candidate`, which matched no admitted prior, restates an
    /// unvetted head of the Dreamer's own that this branch did not admit:
    /// see the module note. `meet` is the candidate's evidence meet; an
    /// imported restatement is never judged here, it keeps its review.
    pub(super) fn restates_unlisted_head(
        &self,
        candidate: &PromotionCandidate,
        rules: &PredicateKeyRules,
        meet: ClaimSource,
        heads: &mut UnlistedHeads,
    ) -> Result<bool> {
        if meet == ClaimSource::Imported {
            return Ok(false);
        }
        let fresh = candidate_probe_body(&candidate.candidate)?;
        let ClaimSubject::Entity(subject) = fresh.subject else {
            return Ok(false);
        };
        let question = (subject, fresh.predicate.clone());
        if !heads.by_question.contains_key(&question) {
            let read = self.unlisted_heads_of(subject, &fresh.predicate)?;
            heads.by_question.insert(question.clone(), read);
        }
        let Some(standing_heads) = heads.by_question.get(&question) else {
            return Ok(false);
        };
        if standing_heads.is_empty() {
            return Ok(false);
        }
        let key = candidate_keys(candidate, rules)?;
        // The facet the candidate's write stamps: the one its scope names,
        // else the vault's default, since a new id has no birth facet yet. A
        // scope whose facet does not read is judged by its write, as before.
        let Ok(named) = super::signals::facet(fresh.scope.as_ref()) else {
            return Ok(false);
        };
        let fresh_facet = match named {
            Some(facet) => facet,
            None => self.read.vault().default_facet()?,
        };
        let fresh_scope = scope_with_taint(fresh.scope.clone(), meet);
        for head in standing_heads {
            // This attempt's own head met again is its replay, not a
            // restatement.
            if head.claim_id == candidate.claim_id {
                continue;
            }
            let head_key = prior_keys(head, rules)?;
            if key.identity != head_key.identity
                || key.topic_key != head_key.topic_key
                || key.value_key != head_key.value_key
            {
                continue;
            }
            if fresh_facet == head.body.scope_facet
                && fresh.scope_project == head.body.scope_project
                && fresh_scope == scope_with_taint(head.body.scope.clone(), meet)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `subject`'s claims under `predicate`, other than the branch's
    /// admitted priors, that the Dreamer may read now, that its owner has
    /// not held and that stand on this branch only provisionally: the
    /// subject's whole cohort, met with the predicate's posting list. Each
    /// read folds into the branch's receipt; a withheld one is counted there.
    fn unlisted_heads_of(&self, subject: EntityId, predicate: &str) -> Result<Vec<PriorHead>> {
        let vault = self.read.vault();
        let ids: Vec<EntityId> = {
            let txn = vault.store.env.read_txn()?;
            let asked: BTreeSet<EntityId> =
                crate::store::claim_projection::claim_ids_for_predicate_in_txn(
                    &vault.store,
                    &txn,
                    predicate,
                )?
                .into_iter()
                .collect();
            vault
                .claims_for_subject_in_txn(&txn, &subject)?
                .into_iter()
                .filter(|id| asked.contains(id) && !self.priors.contains_key(id))
                .collect()
        };
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let reads: Vec<_> = ids.iter().copied().map(PointRead::id).collect();
        let read = self.read.read(&reads, None)?;
        self.fold_read_receipt(&read.receipt)?;
        let mut standing_heads = Vec::new();
        for (id, row) in ids.into_iter().zip(read.value) {
            let Some(ReadRow {
                entity_type,
                body: Some(bytes),
                ..
            }) = row
            else {
                continue;
            };
            if entity_type != ENTITY_TYPE_CLAIM {
                continue;
            }
            let Ok(body) = decode_claim_body(&bytes, true) else {
                continue;
            };
            let head = PriorHead { claim_id: id, body };
            if standing(&head, &self.scope)? != Some(Standing::Provisional) {
                continue;
            }
            // A head awaiting its owner's confirmation is no prior for anyone.
            if !vault.claim_consolidation_eligible(
                &id,
                crate::gate::ConsolidationReader::ExplicitPrior,
            )? {
                continue;
            }
            standing_heads.push(head);
        }
        Ok(standing_heads)
    }
}
