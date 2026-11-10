//! FIX AGENT-GRAPHFS-GRANT-WORLDS (Engine RULING GRANT-COMBINE, 11 Nov
//! 04:30): a credential an agent holds reads only inside the owner's live
//! Grants that name that agent. ARCH-0051:54 "A read is `read(&grant, q)`
//! dressed as a path"; :84 "a walk lists only what the grant allows"; :97
//! "clamped by the scope of the walking principal".
//!
//! A pairing slip is minted at the top Scope with its verbs narrowed
//! (`oneiron token pair`), so on its own it reads every world. Once the
//! owner names its holder in an owner-agent Grant, the holder reads under
//! that slip met with each Grant that stands for `read` now, each Grant
//! alone: Grants are never unioned (authority/principal_standing.rs,
//! federation/repo_access.rs, FIX 7462). The verbs stay the slip's.
//!
//! - No Grant row names the holder: the slip reads as its Scope allows, as
//!   before (ruling Q2 = B: `oneiron token agent`, `token read` and
//!   `token pair` pair agents with no Grant). A revoke removes the Grant's
//!   row, so revoking an agent's last Grant gives it back its slip's Scope:
//!   FIX AGENT-REVOKE-WIDENS.
//! - A Grant row names the holder, but none stands for `read` now (expired,
//!   no `read`, its owner gone, its pact lapsed): it reads nothing, so an
//!   expiry never widens it.
//! - One or several stand: the key's Scope is met with their per-axis
//!   envelope, so a one-axis question (the worlds a walk lists) answers
//!   exactly, and the key carries the slip's Scope met with each Grant
//!   alone: a row needs one of them to admit its whole position
//!   (`ScopedRead::one_grant_alternative_admits_in`), as FIX 7462 judges a
//!   row under a Grant.
//!
//! The credential itself is left whole: only the read key's Scope narrows,
//! so a guard that asks for the exact credential (a phone line's) still
//! finds it.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{AgentGrantStanding, AgentVerbClasses};
use oneiron_authority::federation::{Scope, ScopeAxis, SensitivityCeiling};

/// What the owner's agent Grants that name a credential's holder bind its
/// read key to.
pub(crate) struct AgentGrantReadBound {
    /// The standing Grants' per-axis envelope, its verbs left open: the read
    /// key's Scope is met with it. Bottom on every other axis when none
    /// stands, so the key reads nothing.
    pub(crate) envelope: Scope,
    /// The credential's Scope met with each standing Grant alone, in Grant
    /// id order: a row must lie inside one of them.
    pub(crate) alternatives: Vec<Scope>,
}

impl Vault {
    /// The bound the owner-agent Grants that name `holder` in `txn` put on a
    /// read under a credential of Scope `slip` that `holder` holds (module
    /// docs); `None` when no Grant row names `holder`.
    ///
    /// # Errors
    /// A store, fold or clock failure; never a refusal.
    pub(crate) fn agent_grant_read_bound_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        slip: &Scope,
        holder: EntityId,
    ) -> Result<Option<AgentGrantReadBound>> {
        let (grants, undecoded) = self.agent_grants_reporting_in_txn(txn)?;
        let naming: Vec<&AgentGrantStanding> = grants
            .iter()
            .filter(|standing| standing.grant.member_ref == holder)
            .collect();
        if !undecoded.is_empty() {
            let undecoded: Vec<String> = undecoded.iter().map(EntityId::to_hex).collect();
            tracing::warn!(
                count = undecoded.len(),
                grants = ?undecoded,
                naming = naming.len(),
                "a credential's read key is bound by the agent Grants that decode; \
                 these did not (FIX AGENT-GRAPHFS-GRANT-WORLDS)"
            );
        }
        if naming.is_empty() {
            return Ok(None);
        }
        let now = self.instant_in_txn(txn)?.secs();
        let owners = crate::policy_model::owners_in_txn(self, txn)?;
        let classes = AgentVerbClasses::for_grants_in_txn(
            &self.store,
            txn,
            naming.iter().map(|standing| &standing.grant),
        )?;
        let bounds: Vec<Scope> = naming
            .iter()
            .filter(|standing| {
                standing.stands_in_txn(self, txn, holder, "read", now, &owners, &classes)
            })
            .map(|standing| disclosure_axes(&standing.grant.scope_for_verb("read", &classes)))
            .collect();
        let envelope = bounds
            .iter()
            .fold(disclosure_axes(&Scope::default()), |envelope, bound| {
                join(&envelope, bound)
            });
        let alternatives = bounds.iter().map(|bound| slip.meet(bound)).collect();
        Ok(Some(AgentGrantReadBound {
            envelope,
            alternatives,
        }))
    }
}

/// `scope` on every axis but its verbs, which it leaves to the credential it
/// meets: a Grant bounds where a read reaches, the slip which verbs it calls.
fn disclosure_axes(scope: &Scope) -> Scope {
    Scope {
        verbs: ScopeAxis::All,
        ..scope.clone()
    }
}

/// The least Scope above both `left` and `right`, axis by axis: a candidate
/// envelope only, never an admission by itself.
fn join(left: &Scope, right: &Scope) -> Scope {
    Scope {
        worlds: join_axis(&left.worlds, &right.worlds),
        facets: join_axis(&left.facets, &right.facets),
        bands: join_axis(&left.bands, &right.bands),
        audience: join_axis(&left.audience, &right.audience),
        verbs: join_axis(&left.verbs, &right.verbs),
        sensitivity: match (left.sensitivity, right.sensitivity) {
            (SensitivityCeiling::Bottom, other) | (other, SensitivityCeiling::Bottom) => other,
            (SensitivityCeiling::AtMost(left), SensitivityCeiling::AtMost(right)) => {
                SensitivityCeiling::AtMost(left.max(right))
            }
        },
    }
}

fn join_axis<T: Ord + Clone>(left: &ScopeAxis<T>, right: &ScopeAxis<T>) -> ScopeAxis<T> {
    match (left, right) {
        (ScopeAxis::All, _) | (_, ScopeAxis::All) => ScopeAxis::All,
        (ScopeAxis::Bottom, other) | (other, ScopeAxis::Bottom) => other.clone(),
        (ScopeAxis::Some(left), ScopeAxis::Some(right)) => {
            ScopeAxis::Some(left.union(right).cloned().collect())
        }
    }
}
