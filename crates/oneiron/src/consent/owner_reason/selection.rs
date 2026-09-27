//! Pure nearest-reason selection: remove dominated covering bounds first.

use std::cmp::Reverse;

use super::super::bound::{BoundEnvelope, GrantBound};

/// The fallback is an implementation tie policy, not authorization precedence.
/// It only chooses among incomparable or equivalent covering candidates, or
/// among same-class advisory candidates when no recorded bound covers the ask.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RelevanceRank {
    exact_bound: bool,
    matching_target: bool,
    shared_selectors: usize,
    selector_specificity: Reverse<usize>,
    issuance_id: [u8; 16],
}

/// One eligible rule and the exact requirement it matched. The index addresses
/// the rule kept by the caller; neither this index nor the rank is authority.
#[derive(Debug)]
pub(super) struct ReasonCandidate {
    rule_index: usize,
    bound: GrantBound,
    matched_requirement: GrantBound,
    covers_requirement: bool,
    relevance: RelevanceRank,
}

impl ReasonCandidate {
    pub(super) fn new(
        rule_index: usize,
        bound: GrantBound,
        matched_requirement: GrantBound,
        issuance_id: [u8; 16],
    ) -> Option<Self> {
        let covers_requirement = bound.contains(&matched_requirement);
        if !covers_requirement
            && (bound.domain() != matched_requirement.domain()
                || bound.subject() != matched_requirement.subject()
                || bound.class() != matched_requirement.class())
        {
            return None;
        }
        let (selectors, required_selectors, matching_target) =
            match (bound.envelope(), matched_requirement.envelope()) {
                (BoundEnvelope::Action(recorded), BoundEnvelope::Action(required)) => (
                    recorded.selectors(),
                    required.selectors(),
                    recorded.target().is_some() && recorded.target() == required.target(),
                ),
                (BoundEnvelope::Disclosure(recorded), BoundEnvelope::Disclosure(required)) => {
                    (recorded.selectors(), required.selectors(), false)
                }
                _ => return None,
            };
        let relevance = RelevanceRank {
            exact_bound: bound == matched_requirement,
            matching_target,
            shared_selectors: required_selectors
                .iter()
                .filter(|selector| selectors.binary_search(selector).is_ok())
                .count(),
            selector_specificity: Reverse(selectors.len()),
            issuance_id,
        };
        Some(Self {
            rule_index,
            bound,
            matched_requirement,
            covers_requirement,
            relevance,
        })
    }
}

/// Covering has a live grant to examine; prefill-only is never authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReasonSelection {
    Covering(usize),
    PrefillOnly(usize),
    None,
}

/// Select over the COMPLETE eligible set, not a running winner. A covering
/// bound is removed whenever another live covering bound is strictly narrower
/// under the existing full-bound containment law. Incomparable and equivalent
/// survivors use only the deterministic fallback. This intentionally retains
/// every candidate: a silent cap would let an omitted narrow bound lose.
pub(super) fn select_reason(candidates: &[ReasonCandidate]) -> ReasonSelection {
    debug_assert!(candidates.iter().all(|candidate| {
        candidate.covers_requirement == candidate.bound.contains(&candidate.matched_requirement)
    }));
    let covering: Vec<_> = candidates
        .iter()
        .filter(|candidate| candidate.covers_requirement)
        .collect();
    if !covering.is_empty() {
        let survivor = covering
            .iter()
            .copied()
            .filter(|candidate| {
                !covering.iter().any(|other| {
                    candidate.bound.contains(&other.bound)
                        && !other.bound.contains(&candidate.bound)
                })
            })
            .max_by_key(|candidate| candidate.relevance)
            .expect("a finite partial order has a non-dominated candidate");
        return ReasonSelection::Covering(survivor.rule_index);
    }
    candidates
        .iter()
        .max_by_key(|candidate| candidate.relevance)
        .map_or(ReasonSelection::None, |candidate| {
            ReasonSelection::PrefillOnly(candidate.rule_index)
        })
}

#[cfg(test)]
mod tests;
