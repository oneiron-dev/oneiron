//! Claims the owner's review already holds or decided, which a later pass
//! meets again: this attempt's own outputs after a crash or a held
//! selection's retry, and a claim the owner declined from the same imported
//! words.
use std::collections::BTreeSet;

use super::conflict::{CandidateFacts, candidate_facts, canonical_value_bytes, topic_key};
use super::provenance::PromotionCandidate;
use super::resources::signals::facet;
use super::support::invalid_consolidation;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject};
use crate::ports::{DependencyIndex, SourceSpan};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::{EntityId, Result, Vault};

/// Whether `body` is the claim `facts` name: the same subject, predicate,
/// value, coordinates and topic.
pub(super) fn names(facts: &CandidateFacts, body: &ClaimBody) -> Result<bool> {
    Ok(body.subject == ClaimSubject::Entity(facts.subject)
        && body.predicate == facts.predicate
        && canonical_value_bytes(&body.value)? == canonical_value_bytes(&facts.value)?
        && body.world == facts.world
        && facet(body.scope.as_ref())? == facts.facet
        && body.rel == facts.rel
        && topic_key(body.scope.as_ref())? == facts.topic)
}

/// Whether the claim at `candidate`'s id is one an earlier pass of this
/// attempt committed into the owner's review, which still holds it or which
/// the owner has decided since: a crash before the attempt completed, or a
/// held selection's retry, meets it again. The id is this attempt's own, so a
/// different claim stored there is an error.
pub(crate) fn reviewed_output(vault: &Vault, candidate: &PromotionCandidate) -> Result<bool> {
    if vault.get_entity_type(&candidate.claim_id)? != Some(ENTITY_TYPE_CLAIM) {
        return Ok(false);
    }
    let Some(stored) = vault.get_claim(&candidate.claim_id)? else {
        return Ok(false);
    };
    if stored.approval == ClaimApprovalStatus::Auto {
        return Ok(false);
    }
    if !names(&candidate_facts(&candidate.candidate)?, &stored)? {
        return Err(invalid_consolidation("candidate identity changed"));
    }
    Ok(true)
}

/// A claim from imported words that the owner declined and that says what
/// `candidate` says, citing every MESSAGE in `cited`. A message that lands
/// later in the same TURN re-reads its old words too; what they yield again
/// is not proposed again.
pub(crate) fn declined_from_same_words(
    vault: &Vault,
    candidate: &PromotionCandidate,
    cited: &[EntityId],
) -> Result<Option<EntityId>> {
    if cited.is_empty() {
        return Ok(None);
    }
    let mut citing: Option<BTreeSet<EntityId>> = None;
    for message in cited {
        let Some(header) = vault.read_entity_header(message)? else {
            return Ok(None);
        };
        let txn = vault.store.env.read_txn()?;
        let dependents: BTreeSet<_> = vault
            .port_dependency_list_by_source(
                &txn,
                SourceSpan {
                    document: *message,
                    frontier: header.learned_at,
                },
            )?
            .into_iter()
            .collect();
        citing = Some(match citing {
            Some(so_far) => so_far.intersection(&dependents).copied().collect(),
            None => dependents,
        });
    }
    let facts = candidate_facts(&candidate.candidate)?;
    for id in citing.unwrap_or_default() {
        if vault.get_entity_type(&id)? != Some(ENTITY_TYPE_CLAIM) {
            continue;
        }
        let Some(body) = vault.get_claim(&id)? else {
            continue;
        };
        if body.approval == ClaimApprovalStatus::Rejected
            && body.source == Some(ClaimSource::Imported)
            && names(&facts, &body)?
        {
            return Ok(Some(id));
        }
    }
    Ok(None)
}
