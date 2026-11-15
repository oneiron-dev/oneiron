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
        let matches = bound_matching_priors(candidate, &heads, bound.key_rules())?;
        for (id, _) in &matches {
            bound.require_prior_write(*id)?;
        }
        let excluded: BTreeSet<EntityId> = matches
            .iter()
            .filter(|(id, _)| {
                observed[index]
                    && bound.prior(*id).is_some_and(|head| {
                        head.body.source.unwrap_or(ClaimSource::Imported) == ClaimSource::UserStated
                    })
            })
            .map(|(id, _)| *id)
            .collect();
        let matches: Vec<_> = matches
            .into_iter()
            .filter(|(id, _)| !excluded.contains(id))
            .collect();
        if matches.len() == 1 && matches[0].1 {
            exact.insert(index);
        }
        stated.push(excluded);
        kept.push(matches);
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
