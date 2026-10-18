//! Whether one resolved policy is no wider than another (ARCH-0070 vault
//! shape): a manifest change lands with a receipt only as a narrowing.
//!
//! Each axis below has a restrict whose result is never wider than its left
//! side, so `restrict(before, after) == after` proves `after` no wider on
//! it. Every other field must be equal: a row table, a fold that depends on
//! order or provenance, and any field added later. A narrowing the
//! comparator cannot prove reads as a widening and waits for the owner.
use super::PolicyManifestResolution;
use crate::gate::fanout_policy::merge_controls;

/// `probe` takes `before`'s value where `narrower(before, after)` holds.
fn settle<T: Clone>(probe: &mut T, before: &T, after: &T, narrower: impl FnOnce(&T, &T) -> bool) {
    if narrower(before, after) {
        *probe = before.clone();
    }
}

/// Both present and `narrower` holds; a value appearing or going reverts to
/// a fallback this does not order.
fn both<T>(before: &Option<T>, after: &Option<T>, narrower: impl FnOnce(&T, &T) -> bool) -> bool {
    match (before, after) {
        (Some(before), Some(after)) => narrower(before, after),
        _ => false,
    }
}

/// Both present and `after` no greater: a lower depth or threshold.
fn no_greater<T: PartialOrd>(before: &Option<T>, after: &Option<T>) -> bool {
    both(before, after, |before, after| after <= before)
}

/// `restrict(before, after) == after`, for a restrict by value.
fn meet<T: Clone + PartialEq>(before: &T, after: &T, restrict: impl FnOnce(T, T) -> T) -> bool {
    restrict(before.clone(), after.clone()) == *after
}

/// [`meet`], for a restrict in place.
fn meet_in<T: Clone + PartialEq>(before: &T, after: &T, restrict: impl FnOnce(&mut T, T)) -> bool {
    let mut met = before.clone();
    restrict(&mut met, after.clone());
    met == *after
}

/// Whether `after` is no wider than `before` on every axis. A fail-closed
/// side, or any unequal field with no proved direction, says no.
pub(crate) fn manifest_resolution_narrows(
    before: &PolicyManifestResolution,
    after: &PolicyManifestResolution,
) -> bool {
    if before.diagnostics.is_fail_closed() || after.diagnostics.is_fail_closed() {
        return false;
    }
    let mut probe = after.clone();
    // Past fail-closed, the count of manifests is bookkeeping.
    probe.diagnostics = before.diagnostics;
    macro_rules! axis {
        ($field:ident, $narrower:expr) => {
            settle(&mut probe.$field, &before.$field, &after.$field, $narrower)
        };
    }
    // `restrict(before, after) == after`: by value or in place, on a value
    // always there or on one present on both sides.
    macro_rules! by_value {
        ($field:ident) => {
            by_value!($field, |b, a| b.restrict(a))
        };
        ($field:ident, $restrict:expr) => {
            axis!($field, |b, a| meet(b, a, $restrict))
        };
    }
    macro_rules! in_place {
        ($field:ident) => {
            axis!($field, |b, a| meet_in(b, a, |b, a| b.restrict(a)))
        };
    }
    macro_rules! by_value_both {
        ($field:ident) => {
            by_value_both!($field, |b, a| b.restrict(a))
        };
        ($field:ident, $restrict:expr) => {
            axis!($field, |b, a| both(b, a, |b, a| meet(b, a, $restrict)))
        };
    }
    macro_rules! in_place_both {
        ($field:ident) => {
            in_place_both!($field, |b, a| b.restrict(a))
        };
        ($field:ident, $restrict:expr) => {
            axis!($field, |b, a| both(b, a, |b, a| meet_in(b, a, $restrict)))
        };
    }
    // Permit sets shrink; a protected set grows; a cap appears or shrinks.
    axis!(single_valued_predicates, |b, a| a.is_subset(b));
    axis!(persona_core_prefixes, |b, a| b.is_subset(a));
    axis!(sync_world_ceiling, |b, a| match (b, a) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(b), Some(a)) => a.is_subset(b),
    });
    // A lower depth or threshold, a report switched off, a stricter order.
    axis!(project_depth_default, no_greater);
    axis!(project_depth_max, no_greater);
    axis!(consult_fanout_approval_threshold, no_greater);
    axis!(weave_report_policy_empty, |b, a| *a || !*b);
    by_value!(weave_report_precedence, std::cmp::max);
    by_value_both!(consult_fanout_precedence, |b, a| b.stricter(a));
    by_value_both!(consult_fanout_controls, |b, a| merge_controls(&b, &a));
    by_value!(owner_policy_precedence);
    by_value!(project_conversion);
    in_place!(connector_admission);
    in_place!(residence_operation_budgets);
    in_place!(attribution_limits);
    by_value_both!(project_collaboration);
    by_value_both!(goal_limits);
    by_value_both!(judge_calibration);
    by_value_both!(docedit_resource_policy);
    by_value_both!(dreamer_failure_precedence);
    in_place_both!(livequery_tracker_limits);
    in_place_both!(credential_lifetimes);
    probe == *before
}
