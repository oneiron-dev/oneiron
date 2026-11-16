//! Rebuilds the crate's observed-beside conflict route over verified bound operands.

use std::collections::BTreeSet;

use super::super::conflict::{ConflictSet, PriorHead, bound_matching_priors, route_bound_priors};
use super::super::provenance::PromotionCandidate;
use super::super::routing::candidate_keys;
use super::super::support::invalid_consolidation;
use super::{BoundBranchRead, ExtractionRebuildContext};
use crate::claim::ClaimSource;
use crate::entity_id::EntityId;
use crate::memory::MemoryResult;

/// Holds one routed set with the coverage of its original nomination component.
pub(super) struct RoutedConflict {
    /// Holds the crate-equivalent set without changing its original identity.
    pub(super) set: ConflictSet,
    /// Covers the component's routed members and qualifying removals, excluding exact members.
    /// A removed member's singleton retains this same component coverage.
    pub(super) component_coverage: Vec<usize>,
}

/// The kept matches of one candidate: the matches that stand after the
/// observed-beside exclusion, the stated heads that were excluded, and
/// whether the candidate exactly restates its one kept match.
struct KeptCandidateMatches {
    /// The matches that stand, each with whether its value key equals too.
    kept: Vec<(EntityId, bool)>,
    /// The stated heads the observed-beside rule excluded.
    stated: BTreeSet<EntityId>,
    /// Whether the kept matches are exactly one equal match.
    exact: bool,
}

/// The loop body of [`route_observed_priors`] for one candidate: its
/// matched heads, every one checked for a prior write, the stated heads
/// excluded when the candidate qualifies as observed-beside, and the kept
/// matches with the exact flag.
fn kept_matches_for_candidate(
    candidate: &PromotionCandidate,
    heads: &[PriorHead],
    bound: &BoundBranchRead,
    observed_qualifies: bool,
) -> MemoryResult<KeptCandidateMatches> {
    let matches = bound_matching_priors(candidate, heads, bound.key_rules())?;
    for (id, _) in &matches {
        bound.require_prior_write(*id)?;
    }
    let stated: BTreeSet<EntityId> = matches
        .iter()
        .filter(|(id, _)| {
            observed_qualifies
                && bound.prior(*id).is_some_and(|head| {
                    head.body.source.unwrap_or(ClaimSource::Imported) == ClaimSource::UserStated
                })
        })
        .map(|(id, _)| *id)
        .collect();
    let kept: Vec<_> = matches
        .into_iter()
        .filter(|(id, _)| !stated.contains(id))
        .collect();
    let exact = kept.len() == 1 && kept[0].1;
    Ok(KeptCandidateMatches {
        kept,
        stated,
        exact,
    })
}

/// The kept matches of one checked proposal, whose operand is the one
/// operand of `context`: its observed-beside qualification as
/// [`route_observed_priors`] computes it, then the heads it stands against
/// after the exclusion, each with whether its value key equals too. A
/// proposal that does not qualify keeps every match, as the bound route
/// without a qualifying candidate matches it.
pub(crate) fn kept_matches_for_one_proposal(
    bound: &BoundBranchRead,
    context: &ExtractionRebuildContext<'_>,
    proposal: &PromotionCandidate,
) -> MemoryResult<Vec<(EntityId, bool)>> {
    let observed = qualifying_candidates(std::slice::from_ref(proposal), bound, context)?;
    let heads: Vec<PriorHead> = bound.priors().values().cloned().collect();
    Ok(kept_matches_for_candidate(proposal, &heads, bound, observed.contains(&true))?.kept)
}

/// Verifies qualification and mirrors the crate's kept-match, component and singleton rules.
/// Every original matching head must admit a write before any stated head is excluded.
/// With no qualifying candidate, the existing bound route supplies every set and exact member.
pub(super) fn route_observed_priors(
    candidates: &[PromotionCandidate],
    bound: &BoundBranchRead,
    context: &ExtractionRebuildContext<'_>,
    nominated: Vec<ConflictSet>,
) -> MemoryResult<(Vec<RoutedConflict>, BTreeSet<usize>)> {
    let observed = qualifying_candidates(candidates, bound, context)?;
    let heads: Vec<PriorHead> = bound.priors().values().cloned().collect();
    if !observed.iter().any(|qualifies| *qualifies) {
        let (sets, exact) =
            route_bound_priors(candidates, &heads, nominated, bound.key_rules(), |id| {
                bound.require_prior_write(id)
            })?;
        let routed = sets
            .into_iter()
            .map(|set| RoutedConflict {
                component_coverage: set.candidate_indexes.clone(),
                set,
            })
            .collect();
        return Ok((routed, exact));
    }

    let mut exact = BTreeSet::new();
    let mut stated = Vec::with_capacity(candidates.len());
    let mut kept = Vec::with_capacity(candidates.len());
    for (index, candidate) in candidates.iter().enumerate() {
        let kept_matches = kept_matches_for_candidate(candidate, &heads, bound, observed[index])?;
        if kept_matches.exact {
            exact.insert(index);
        }
        stated.push(kept_matches.stated);
        kept.push(kept_matches.kept);
    }

    let components: Vec<Vec<usize>> = nominated
        .iter()
        .map(|set| set.candidate_indexes.clone())
        .collect();
    let mut routed = Vec::new();
    for mut set in nominated {
        let ids: BTreeSet<EntityId> = set
            .candidate_indexes
            .iter()
            .flat_map(|index| kept[*index].iter().map(|(id, _)| *id))
            .collect();
        let component_coverage: Vec<usize> = set
            .candidate_indexes
            .iter()
            .copied()
            .filter(|index| !exact.contains(index))
            .collect();
        set.candidate_indexes.retain(|index| !exact.contains(index));
        set.candidate_indexes
            .retain(|index| stated[*index].is_disjoint(&ids));
        if set.candidate_indexes.is_empty() {
            continue;
        }
        set.prior_head = if ids.len() == 1 {
            ids.first().copied()
        } else {
            None
        };
        set.prior_heads = ids.into_iter().collect();
        routed.push(RoutedConflict {
            set,
            component_coverage,
        });
    }
    for (index, matches) in kept.into_iter().enumerate() {
        if routed
            .iter()
            .any(|routed| routed.set.candidate_indexes.contains(&index))
            || matches.iter().all(|(_, equal)| *equal)
        {
            continue;
        }
        let component_coverage = components
            .iter()
            .find(|members| members.contains(&index))
            .map_or_else(
                || vec![index],
                |members| {
                    members
                        .iter()
                        .copied()
                        .filter(|member| !exact.contains(member))
                        .collect()
                },
            );
        routed.push(RoutedConflict {
            set: ConflictSet {
                identity: candidate_keys(&candidates[index], bound.key_rules())?.identity,
                candidate_indexes: vec![index],
                prior_head: (matches.len() == 1).then(|| matches[0].0),
                prior_heads: matches.into_iter().map(|(id, _)| id).collect(),
            },
            component_coverage,
        });
    }
    Ok((routed, exact))
}

/// Recomputes qualification from verified spans without stamping unused proposal times.
fn qualifying_candidates(
    candidates: &[PromotionCandidate],
    bound: &BoundBranchRead,
    context: &ExtractionRebuildContext<'_>,
) -> MemoryResult<Vec<bool>> {
    if candidates.len() != context.operands.len() {
        return Err(invalid_consolidation(
            "extraction observation operands differ from checked candidates",
        )
        .into());
    }
    candidates
        .iter()
        .zip(context.operands)
        .map(|(checked, operand)| {
            let candidate = bound.verify_observation_evidence_in_txn(
                context.memory,
                context.turn_read,
                context.txn,
                operand,
                checked,
            )?;
            BoundBranchRead::observation_qualification_in_txn(
                context.read.vault(),
                context.txn,
                &candidate,
            )
            .map(|(_, observed)| observed)
        })
        .collect()
}
