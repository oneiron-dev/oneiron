//! Whether one resolved policy is no wider than another (ARCH-0070 vault
//! shape): a manifest change lands with a receipt only as a narrowing.
//!
//! Each axis below has a restrict whose result is never wider than its left
//! side, so `restrict(before, after) == after` proves `after` no wider on
//! it. A row table that meets all its matching rows, whatever their order,
//! counts when every row it held is still there and each row added only
//! restricts. Every other field must be equal: any other row table, a fold
//! that depends on order or provenance, and any field added later. A
//! narrowing the comparator cannot prove reads as a widening and waits for
//! the owner.
use super::{CommOptOutPosture, PolicyManifestResolution};
use crate::gate::ceiling::{
    ActorCeiling, PolicyApprovalCeiling, PolicyAxes, PolicyCriticality, PolicyPack,
    PolicySensitivity,
};
use crate::gate::class_policy::{ActPolicyTable, ActPosture, ClassPolicyPrecedence};
use crate::gate::fanout_policy::merge_controls;
use crate::gate::policy_values::{PolicyPrecedence, PolicyRowScope, PolicyValue, PolicyValueRow};

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

/// Every row of `before` is still in `after`, counting copies, and each row
/// `after` adds is `narrow`.
fn adds_only<T: PartialEq>(before: &[T], after: &[T], narrow: impl Fn(&T) -> bool) -> bool {
    let mut added: Vec<&T> = after.iter().collect();
    for row in before {
        let Some(at) = added.iter().position(|kept| *kept == row) else {
            return false;
        };
        added.remove(at);
    }
    added.into_iter().all(narrow)
}

/// Axes the meet leaves as they were, or at their restrictive pole. Normal
/// is no identity: an axis no pack sets reads Critical and Sensitive, so a
/// new Normal one opens it.
fn axes_narrow(axes: &PolicyAxes) -> bool {
    matches!(axes.criticality, None | Some(PolicyCriticality::Critical))
        && matches!(axes.sensitivity, None | Some(PolicySensitivity::Sensitive))
        && !axes.unknown_axis_seen
}

/// A new pack: every pack's selected axes meet, so one whose defaults and
/// rules all narrow only narrows.
fn pack_narrows(pack: &PolicyPack) -> bool {
    axes_narrow(&pack.defaults) && pack.rules.iter().all(|rule| axes_narrow(&rule.axes))
}

/// A new actor ceiling row: all matching rows meet, and no matching row
/// reads as Proposed, so only a Proposed row narrows. An Auto one can mint the
/// explicit system-author permit.
fn ceiling_narrows(row: &ActorCeiling) -> bool {
    matches!(row.ceiling, PolicyApprovalCeiling::Proposed)
}

/// New act rows, each a vault-wide Deny at the default precedence. A
/// RequireCapability row opens a pairing silence denied, and VaultOnly
/// drops the holders' denials.
fn act_rows_narrow(before: &ActPolicyTable, after: &ActPolicyTable) -> bool {
    adds_only(before.rows(), after.rows(), |row| {
        matches!(row.posture, ActPosture::Deny)
            && row.holder_ref.is_none()
            && matches!(row.precedence, ClassPolicyPrecedence::NestedNarrowing)
    })
}

/// A new value row under nested narrowing: a world or project proposal
/// threshold meets its parents, and a vault opt-out or max wait at its
/// restrictive pole caps every fallback. An override releases a parent, a
/// precedence row can switch to most-specific, and any other new vault
/// value replaces a fallback this does not order.
fn value_row_narrows(row: &PolicyValueRow) -> bool {
    use PolicyRowScope::{Project, Vault, World};
    !row.override_parent
        && match (row.value, row.scope) {
            (PolicyValue::ProposalCheckThreshold(_), World(_) | Project(_)) => true,
            (PolicyValue::CommOptOutPosture(posture), Vault) => {
                posture == CommOptOutPosture::Escalate
            }
            (PolicyValue::ProviderCooldownMaxWaitSeconds(wait), Vault) => wait == 0,
            _ => false,
        }
}

/// New value rows, each [`value_row_narrows`] in a slot `before` left empty.
fn value_rows_narrow(before: &[PolicyValueRow], after: &[PolicyValueRow]) -> bool {
    let held = |row: &PolicyValueRow| {
        before
            .iter()
            .any(|old| (old.key, old.scope) == (row.key, row.scope))
    };
    adds_only(before, after, |row| value_row_narrows(row) && !held(row))
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
    // A replaced or dropped row proves nothing here.
    axis!(packs, |b, a| adds_only(b, a, pack_narrows));
    axis!(actor_ceilings, |b, a| adds_only(b, a, ceiling_narrows));
    axis!(act_policy, act_rows_narrow);
    // A new scoped row meets its parents only under nested narrowing; under
    // most-specific it can release one.
    let nested = [before, after]
        .iter()
        .all(|side| side.scope_precedence().0 == PolicyPrecedence::NestedNarrowing);
    axis!(policy_values, |b, a| nested && value_rows_narrow(b, a));
    probe == *before
}
