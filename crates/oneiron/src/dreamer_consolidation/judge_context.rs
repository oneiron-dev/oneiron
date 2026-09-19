//! Prior-head judge context and deterministic conflict markers.
use super::conflict::{ConflictSet, PriorHead, candidate_facts, conflict_open_marker_id};
use super::provenance::PromotionCandidate;
use crate::claim::{ClaimSubject, claim_consolidatable, claim_source_widens_beyond};
use crate::{EntityId, Result, Vault};
use rmpv::Value;

pub(super) fn prior_heads(
    vault: &Vault,
    candidates: &[PromotionCandidate],
) -> Result<Vec<PriorHead>> {
    let mut subjects = std::collections::BTreeSet::new();
    for candidate in candidates {
        subjects.insert(candidate_facts(&candidate.candidate)?.subject);
    }
    let mut heads = Vec::new();
    for subject in subjects {
        for claim_id in vault.claims_for_subject(&subject)? {
            if candidates
                .iter()
                .any(|candidate| candidate.claim_id == claim_id)
            {
                continue;
            }
            if let Some(body) = vault.get_claim(&claim_id)?
                && claim_consolidatable(&body)
            {
                heads.push(PriorHead { claim_id, body });
            }
        }
    }
    heads.sort_by_key(|head| head.claim_id);
    Ok(heads)
}

pub(super) fn fast_path(
    policy: &crate::gate::PolicyManifestResolution,
    conflict: &ConflictSet,
    members: &[&PromotionCandidate],
    prior: Option<&PriorHead>,
) -> bool {
    members.len() == 1
        && policy.is_single_valued_predicate(&conflict.identity.predicate)
        && prior.is_some_and(|prior| {
            !claim_source_widens_beyond(
                prior
                    .body
                    .source
                    .unwrap_or(crate::claim::ClaimSource::UserStated),
                members[0].evidence_meet,
            )
        })
}

pub(super) fn open_marker(
    conflict: &ConflictSet,
    members: &[&PromotionCandidate],
    attempt: crate::attempt_queue::AttemptId,
    now: u64,
) -> PromotionCandidate {
    let mut marker = (*members[0]).clone();
    marker.claim_id = conflict_open_marker_id(conflict, attempt);
    marker.candidate = crate::write_envelope::ClaimCandidate::new(
        crate::claim::PREDICATE_CONFLICT_OPEN,
        ClaimSubject::Entity(conflict.identity.subject),
        Value::from(conflict.identity.predicate.as_str()),
        1.0,
    );
    if let Some(world) = conflict.identity.world {
        marker.candidate = marker.candidate.with_world(world);
    }
    if let Some(facet) = conflict.identity.facet {
        marker.candidate = marker.candidate.with_scope(Value::Map(vec![(
            Value::from("facet_ref"),
            Value::Binary(facet.as_bytes().to_vec()),
        )]));
    }
    marker.supersedes = None;
    marker.learned_at = now;
    marker.evidence_turn_refs = members
        .iter()
        .flat_map(|member| member.evidence_turn_refs.iter().copied())
        .collect::<std::collections::BTreeSet<EntityId>>()
        .into_iter()
        .collect();
    marker
}
