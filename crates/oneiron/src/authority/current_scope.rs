//! The current scope a pact and a guest's credential stand in (Phase2 C).
//!
//! One resolver for both rows: a pact's outbound half is its dual-signed
//! ceiling met with every party's own narrowing (FIX 7933), and a Connect
//! guest's slip is met with the current effective scope of every pact bound
//! to its grant at mint and at each verification (FIX 7929). An Ask guest's
//! slip carries the ask's disclosure as its signed record bound, and an empty
//! disclosure is the explicit no-access bound, never the unrestricted empty
//! record set (FIX 7928). A live Owner, an in-Grant agent and an own-device
//! grant are no guest: none of them is met with a pact here.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::EntityId;
use crate::federation::{
    FederationDirectionScope, FederationGrant, FederationGrantScope, Scope, ScopeAxis,
    selector_range_of,
};

/// A narrowing widens back by its own party only, within the dual-signed
/// ceiling; any other widening takes an epoch-advancing dual-signed re-pact
/// (FIX 7933; CALLS "Phase2 rescope other party", Engine 10-22 02:0x).
pub(in crate::authority) const NARROWING_WIDENS_BACK_BY_OWN_PARTY_ONLY: bool = true;

/// An Ask guest's slip signs the ask's disclosed facts as its record bound,
/// and every slip door holds it to the grant's current disclosure (FIX 7928;
/// CALLS "Phase2 Ask slip disclosure bound").
pub(in crate::authority) const ASK_SLIP_BOUND_IS_DISCLOSURE: bool = true;

/// A Connect guest's slip is met with its grant's current effective scope at
/// mint and at every verification; a verified view wider than a later
/// narrowing is no longer live (FIX 7929; CALLS "Phase2 Connect slip current
/// scope").
pub(in crate::authority) const CONNECT_SLIP_MEETS_CURRENT_SCOPE: bool = true;

/// Our outbound half of `pact`: its dual-signed ceiling met with every
/// party's narrowing, but `except`'s when it names one. With `except` the
/// party's own bound: what it may restore its narrowing to.
pub(in crate::authority) fn pact_scope_beside(
    local: &AuthorityVaultId,
    pact: &FederationPactState,
    except: Option<&EntityId>,
) -> FederationDirectionScope {
    let ceiling =
        super::op_apply::local_outbound_scope(local, &pact.peer_vault_id, &pact.pact_scope);
    if except.is_some() && !NARROWING_WIDENS_BACK_BY_OWN_PARTY_ONLY {
        return ceiling;
    }
    narrowed(ceiling, &pact.narrowings, except)
}

/// `ceiling` met with each narrowing but `except`'s.
fn narrowed(
    ceiling: FederationDirectionScope,
    narrowings: &BTreeMap<EntityId, FederationDirectionScope>,
    except: Option<&EntityId>,
) -> FederationDirectionScope {
    narrowings
        .iter()
        .filter(|(party, _)| Some(*party) != except)
        .fold(ceiling, |scope, (_, narrowing)| scope.intersect(narrowing))
}

/// The current effective scope of a pact-bound grant: the meet of every pact
/// that binds it, or `None` for a grant no pact binds (an Ask guest's, an
/// own-device or agent grant, an owner's). The sync selector's ceiling reads
/// the same meet (ONE-1591).
pub(in crate::authority) fn current_grant_scope(
    fold: &AuthorityFold,
    grant: &EntityId,
) -> Option<FederationDirectionScope> {
    fold.federation_pacts
        .values()
        .filter(|pact| pact.grant_ref == *grant)
        .map(|pact| pact.effective_scope.clone())
        .reduce(|left, right| left.intersect(&right))
}

/// `scope` met with a pact direction: worlds and facets as sets, and each
/// type-byte band kept only while its kind's replication range is in.
pub(in crate::authority) fn clamp_scope(
    scope: &Scope,
    current: &FederationDirectionScope,
) -> Scope {
    Scope {
        worlds: scope.worlds.meet(&current.worlds),
        facets: scope.facets.meet(&current.facets),
        bands: bands_within(&scope.bands, &current.bands),
        ..scope.clone()
    }
}

fn bands_within(
    bands: &ScopeAxis<u8>,
    ranges: &ScopeAxis<crate::federation::SelectorRange>,
) -> ScopeAxis<u8> {
    if matches!(ranges, ScopeAxis::All) {
        return bands.clone();
    }
    let kinds: Vec<u8> = match bands {
        ScopeAxis::Bottom => Vec::new(),
        ScopeAxis::All => (0..=u8::MAX).collect(),
        ScopeAxis::Some(kinds) => kinds.iter().copied().collect(),
    };
    kinds
        .into_iter()
        .filter(|kind| selector_range_of(*kind).is_some_and(|range| ranges.contains(&range)))
        .collect()
}

/// Whether `scope` stands inside `current` on every axis a pact narrows.
fn within(scope: &Scope, current: &FederationDirectionScope) -> bool {
    scope.worlds.is_narrowing_of(&current.worlds)
        && scope.facets.is_narrowing_of(&current.facets)
        && bands_within(&scope.bands, &current.bands) == scope.bands
}

/// A slip's claims met with its grant's current effective scope (FIX 7929):
/// unchanged for a slip under no pact-bound grant.
pub(in crate::authority) fn meet_current_grant_scope(
    fold: &AuthorityFold,
    claims: &mut SlipClaims,
) {
    if let Some(current) = slip_grant_scope(fold, claims) {
        claims.scope = clamp_scope(&claims.scope, &current);
    }
}

/// Whether a verified slip's scope still stands inside its grant's current
/// effective scope: false once a known narrowing landed after it verified.
pub(in crate::authority) fn within_current_grant_scope(
    fold: &AuthorityFold,
    claims: &SlipClaims,
) -> bool {
    slip_grant_scope(fold, claims).is_none_or(|current| within(&claims.scope, &current))
}

fn slip_grant_scope(fold: &AuthorityFold, claims: &SlipClaims) -> Option<FederationDirectionScope> {
    if !CONNECT_SLIP_MEETS_CURRENT_SCOPE {
        return None;
    }
    // A grant reference that does not parse names no pact here; the slip
    // doors refuse it on their own.
    let grant = EntityId::from_hex(claims.grant_ref.as_deref()?).ok()?;
    current_grant_scope(fold, &grant)
}

/// The scope and record bound a guest slip minted under `grant` carries: an
/// Ask guest's disclosed facts (the explicit no-access scope for an empty
/// disclosure), a Connect guest's grant scope met with its current effective
/// scope.
pub(in crate::authority) fn guest_slip_bounds(
    fold: &AuthorityFold,
    grant_ref: &EntityId,
    grant: &FederationGrant,
) -> (Scope, BTreeSet<String>) {
    if let FederationGrantScope::Ask { .. } = grant.scope
        && ASK_SLIP_BOUND_IS_DISCLOSURE
    {
        let records = disclosed(grant);
        let scope = if records.is_empty() {
            Scope::default()
        } else {
            grant.authority_scope.clone()
        };
        return (scope, records);
    }
    let scope = match current_grant_scope(fold, grant_ref) {
        Some(current) if CONNECT_SLIP_MEETS_CURRENT_SCOPE => {
            clamp_scope(&grant.authority_scope, &current)
        }
        _ => grant.authority_scope.clone(),
    };
    (scope, BTreeSet::new())
}

/// Whether an Ask guest's slip stays inside its grant's current disclosure
/// (FIX 7928): every record it names is a disclosed fact, or it is the
/// explicit no-access bound (no record, no scope). An unrestricted empty
/// record set is outside it. Any other grant passes.
pub(in crate::authority) fn ask_bounds_hold(grant: &FederationGrant, claims: &SlipClaims) -> bool {
    if !ASK_SLIP_BOUND_IS_DISCLOSURE || !matches!(grant.scope, FederationGrantScope::Ask { .. }) {
        return true;
    }
    if claims.records.is_empty() {
        return claims.scope == Scope::default();
    }
    let disclosed = disclosed(grant);
    claims
        .records
        .iter()
        .all(|record| disclosed.contains(record))
}

fn disclosed(grant: &FederationGrant) -> BTreeSet<String> {
    grant
        .guest
        .as_ref()
        .map(|guest| guest.disclosed_refs.iter().map(EntityId::to_hex).collect())
        .unwrap_or_default()
}
