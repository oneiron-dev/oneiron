//! Whether one resolved policy is no wider than another (ARCH-0070 vault
//! shape): a manifest change lands with a receipt only as a narrowing.
//!
//! Each axis below has a restrict whose result is never wider than its left
//! side, so `restrict(before, after) == after` proves `after` no wider on
//! it. A row table counts when every row it held is still there (in place
//! where its readers run rows in order) or gives way at its key to one that
//! only restricts it, and each row added only restricts. Wait rows compare
//! what they resolve, source trust its folded slots, and delegation grants
//! what the gate admits by them. Every other field must be equal: the owner
//! policy rows, a fold that depends on provenance, and any field added
//! later. A narrowing the comparator cannot prove reads as a widening and
//! waits for the owner.
use super::{CommOptOutPosture, PolicyManifestResolution};
use crate::EntityId;
use crate::claim::ClaimSource;
use crate::gate::ceiling::{
    ActorCeiling, DelegationFoldCache, DelegationGrantRecord, PolicyApprovalCeiling, PolicyAxes,
    PolicyCriticality, PolicyPack, PolicySensitivity, SourceTrustCeiling, SourceTrustRow,
};
use crate::gate::class_policy::{
    ActPolicyTable, ActPosture, ClassPolicyPrecedence, WaitPolicyTable, WaitResolution,
};
use crate::gate::fanout_policy::{self, FanoutScopedRow, merge_controls};
use crate::gate::grants::{PolicyScopedGrant, scoped_read_grant_has_read_effector};
use crate::gate::mail_policy::MailPolicy;
use crate::gate::policy_values::{PolicyPrecedence, PolicyRowScope, PolicyValue, PolicyValueRow};
use crate::gate::room_policy::RoomPolicyRow;
use crate::gate::weave_policy;
use crate::llm::BudgetPolicyTable;
use std::collections::BTreeSet;

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

/// [`both`], or absent on both sides.
fn both_or_neither<T>(
    before: &Option<T>,
    after: &Option<T>,
    narrower: impl FnOnce(&T, &T) -> bool,
) -> bool {
    (before.is_none() && after.is_none()) || both(before, after, narrower)
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
    replaces_or_adds(before, after, |_, _| false, narrow)
}

/// [`adds_only`], where a row `before` held may instead give way to one row
/// that `replaces` it. Rows kept as they were pair off first.
fn replaces_or_adds<T: PartialEq>(
    before: &[T],
    after: &[T],
    replaces: impl Fn(&T, &T) -> bool,
    narrow: impl Fn(&T) -> bool,
) -> bool {
    let mut added: Vec<&T> = after.iter().collect();
    let mut gone = Vec::new();
    for row in before {
        if let Some(at) = added.iter().position(|kept| *kept == row) {
            added.remove(at);
        } else {
            gone.push(row);
        }
    }
    for row in gone {
        let Some(at) = added.iter().position(|&new| replaces(row, new)) else {
            return false;
        };
        added.remove(at);
    }
    added.into_iter().all(narrow)
}

/// [`adds_only`], for a table whose readers run its rows in order: `before`
/// is all of `after`'s front, as it was.
fn appends_only<T: PartialEq>(before: &[T], after: &[T], narrow: impl Fn(&T) -> bool) -> bool {
    after
        .strip_prefix(before)
        .is_some_and(|added| added.iter().all(narrow))
}

/// An optional cap, none unbounded, that appears or shrinks.
fn cap_no_higher(before: Option<u64>, after: Option<u64>) -> bool {
    match (before, after) {
        (_, None) => before.is_none(),
        (None, Some(_)) => true,
        (Some(before), Some(after)) => after <= before,
    }
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

/// One class's wait, no wider: a window whose floor stays or rises and whose
/// ceiling stays or falls, or a contradiction, which its caller refuses. An
/// ungoverned class stays so; a first window is not ordered against it.
fn wait_no_wider(before: WaitResolution, after: WaitResolution) -> bool {
    use WaitResolution::{Contradictory, Resolved, Ungoverned};
    match (before, after) {
        (_, Contradictory) | (Ungoverned, Ungoverned) => true,
        (Resolved(before), Resolved(after)) => {
            after.min_secs >= before.min_secs && cap_no_higher(before.max_secs, after.max_secs)
        }
        _ => false,
    }
}

/// Wait rows on what they resolve, for every class and holder either side
/// names. A holder no row names reads as none, and a holder row's clamps
/// depend on the rows before it, so no row-wise rule replaces this.
fn wait_rows_narrow(before: &WaitPolicyTable, after: &WaitPolicyTable) -> bool {
    let rows = || before.rows().iter().chain(after.rows());
    let classes: BTreeSet<&str> = rows().map(|row| row.wait_class.as_str()).collect();
    let holders: BTreeSet<Option<EntityId>> =
        rows().map(|row| row.holder_ref).chain([None]).collect();
    classes.iter().all(|class| {
        holders.iter().all(|&holder| {
            wait_no_wider(before.resolve(class, holder), after.resolve(class, holder))
        })
    })
}

/// A source-trust slot on the same binding, its cap no higher (none, the
/// denial, sits below every band) and no restricted-source permit newly set.
fn trust_row_narrows(before: &SourceTrustRow, after: &SourceTrustRow) -> bool {
    after.actor_ref == before.actor_ref
        && after.max_auto_sensitivity <= before.max_auto_sensitivity
        && (before.receipted || !after.receipted)
        && (before.warned || !after.warned)
}

/// Source trust on its folded slots: each slot stays and narrows, and a new
/// actor slot only denies. A class slot appearing or rebinding moves every
/// writer's baseline, and a new permitting actor slot admits a writer the
/// class row did not.
fn trust_narrows(before: &SourceTrustCeiling, after: &SourceTrustCeiling) -> bool {
    use ClaimSource::{Generated, Imported, Inferred, Observed, ToolOutput, UserStated};
    let sources = [
        UserStated, Observed, Inferred, Imported, ToolOutput, Generated,
    ];
    let class_slots = sources
        .into_iter()
        .all(|source| both_or_neither(&before.row(source), &after.row(source), trust_row_narrows));
    let (old, new) = (&before.additional_bound_rows, &after.additional_bound_rows);
    let kept = old
        .iter()
        .all(|(key, row)| new.get(key).is_some_and(|now| trust_row_narrows(row, now)));
    let denials = new
        .iter()
        .all(|(key, row)| old.contains_key(key) || row.max_auto_sensitivity.is_none());
    class_slots
        && kept
        && denials
        && before.malformed_manifest_seen == after.malformed_manifest_seen
}

/// The actor a delegation grant ref admits at Auto: its record's binding,
/// where its chain's ceiling is Auto. The gate holds anything else Pending.
fn delegation_admits<'a>(
    fold: &'a DelegationFoldCache,
    grant_ref: &str,
) -> Option<(&'a str, Option<&'a str>)> {
    if fold.effective_ceiling(grant_ref) != Some(PolicyApprovalCeiling::Auto) {
        return None;
    }
    match fold.records.get(grant_ref)? {
        DelegationGrantRecord::Grant {
            actor_class,
            actor_ref,
            ..
        } => Some((actor_class.trim(), actor_ref.as_deref())),
        DelegationGrantRecord::RevokeGrant { .. } => None,
    }
}

/// Delegation grants on what the gate admits by them: each ref that admits
/// after admitted before, bound to the same actor. A grant revoked, dropped,
/// lowered or cut off by its parent only narrows; a new or rebound one can
/// admit an actor the vault held Pending.
fn delegation_narrows(before: &DelegationFoldCache, after: &DelegationFoldCache) -> bool {
    after.records.keys().all(|grant_ref| {
        delegation_admits(after, grant_ref)
            .is_none_or(|bound| delegation_admits(before, grant_ref) == Some(bound))
    })
}

/// A new scoped grant that grants nothing: it carries a budget and no read
/// effector, so no read, effect or note door admits by it and no read
/// fallback moves. A matching one can only veto a coach offer.
fn grant_narrows(grant: &PolicyScopedGrant) -> bool {
    grant.budget.is_some() && !scoped_read_grant_has_read_effector(grant)
}

/// Budget rows: each old row in its place, its selector and floor kept and
/// its cap no higher, then rows that only cap. A floor reserves capacity
/// for its matches out of everyone else's, so no floor moves either way and
/// no added row reserves.
fn budget_rows_narrow(before: &BudgetPolicyTable, after: &BudgetPolicyTable) -> bool {
    let (before, after) = (before.rows(), after.rows());
    let kept = before.iter().zip(after).all(|(before, after)| {
        after.selector() == before.selector()
            && after.floor_units() == before.floor_units()
            && cap_no_higher(before.cap_units(), after.cap_units())
    });
    kept && after.get(before.len()..).is_some_and(|added| {
        added
            .iter()
            .all(|row| matches!(row.floor_units(), None | Some(0)) && row.cap_units().is_some())
    })
}

/// Mail rows beside a vault row the vault already had: an old row narrowed
/// in place, and new rows that only meet. With no vault row there is no mail
/// policy, and a first one can class a recipient cold and make a graduation
/// grant usable.
fn mail_rows_narrow(before: &[MailPolicy], after: &[MailPolicy]) -> bool {
    before.iter().any(MailPolicy::is_vault_row)
        && replaces_or_adds(
            before,
            after,
            MailPolicy::narrows_in_place,
            MailPolicy::only_meets_beside_vault,
        )
}

/// A weave row standing in for one at the same role and holder: its
/// sections a subset and each count no greater, which is what the meet
/// would leave.
fn weave_row_replaces(before: &weave_policy::Row, after: &weave_policy::Row) -> bool {
    after.role == before.role
        && after.holder == before.holder
        && after.sections.is_subset(&before.sections)
        && after.max_sections <= before.max_sections
        && after.max_predicates <= before.max_predicates
        && after.max_edge_kinds <= before.max_edge_kinds
        && after.max_rows <= before.max_rows
}

/// Weave rows narrowed in place, and new ones each for a role the vault
/// already rows, where every matching row meets. A first row replaces the
/// shipped table, a new role opens a reader, and under holder-required a
/// row for a holder that had none turns it on.
fn weave_rows_narrow(
    before: &[weave_policy::Row],
    after: &[weave_policy::Row],
    precedence: weave_policy::Precedence,
) -> bool {
    let held = |role: &str, holder: Option<EntityId>| {
        before
            .iter()
            .any(|old| old.role == role && old.holder == holder)
    };
    !before.is_empty()
        && replaces_or_adds(before, after, weave_row_replaces, |row| {
            held(&row.role, None)
                && (precedence == weave_policy::Precedence::NestedNarrowing
                    || held(&row.role, row.holder))
        })
}

fn room_rows_narrow(before: &[RoomPolicyRow], after: &[RoomPolicyRow]) -> bool {
    appends_only(before, after, RoomPolicyRow::only_narrows_appended)
}

/// Fan-out scope rows: an old row whose policy narrows in place under the
/// same ref, scope and holder, and new rows with no holder, which meet what
/// they match. A new holder row restarts from the vault under nested
/// narrowing, and a row moved to another scope or holder can cross one.
fn fanout_rows_narrow(before: &[FanoutScopedRow], after: &[FanoutScopedRow]) -> bool {
    let replaces = |old: &FanoutScopedRow, new: &FanoutScopedRow| {
        (&new.row_ref, &new.scope, &new.holder_ref) == (&old.row_ref, &old.scope, &old.holder_ref)
            && fanout_policy::narrow(&old.policy, &new.policy) == new.policy
    };
    replaces_or_adds(before, after, replaces, |row| row.holder_ref.is_none())
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
    // A dropped row proves nothing here, and a replaced one only where it
    // keeps its key and meets: a budget cap, a fan-out, mail or weave row.
    axis!(packs, |b, a| adds_only(b, a, pack_narrows));
    axis!(actor_ceilings, |b, a| adds_only(b, a, ceiling_narrows));
    axis!(act_policy, act_rows_narrow);
    axis!(wait_policy, wait_rows_narrow);
    axis!(source_trust, trust_narrows);
    axis!(delegation_fold, delegation_narrows);
    axis!(scoped_grants, |b, a| adds_only(b, a, grant_narrows));
    axis!(budget_policy, budget_rows_narrow);
    axis!(native_mail_policy, |b, a| mail_rows_narrow(b, a));
    axis!(room_policy_rows, |b, a| room_rows_narrow(b, a));
    axis!(consult_fanout_scope_rows, |b, a| fanout_rows_narrow(b, a));
    // Weave rows read under the order the vault already had; the order
    // itself only grows stricter, above.
    let order = before.weave_report_precedence;
    axis!(weave_report_policy, |b, a| weave_rows_narrow(b, a, order));
    // A new scoped row meets its parents only under nested narrowing; under
    // most-specific it can release one.
    let nested = [before, after]
        .iter()
        .all(|side| side.scope_precedence().0 == PolicyPrecedence::NestedNarrowing);
    axis!(policy_values, |b, a| nested && value_rows_narrow(b, a));
    probe == *before
}
