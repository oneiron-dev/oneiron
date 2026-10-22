//! The current scope a pact and a guest's credential stand in (Phase2 C).
//!
//! One resolver for both rows: a pact's outbound half is its dual-signed
//! ceiling met with every standing narrowing, each kept under the party whose
//! signed entry made it (FIX 7933), and a Connect guest's credential is met
//! with the current effective scope of every pact bound to its grant (FIX
//! 7929). An Ask guest's slip carries the ask's disclosure as its signed
//! record bound, and an empty disclosure is the explicit no-access bound,
//! never the unrestricted empty record set (FIX 7928). Only a non-owner guest
//! grant, read from its own row in the caller's transaction, is a guest's: a
//! live Owner, an own-device or member grant and an in-Grant agent never meet
//! a pact here, whatever a pact binding names.

use std::collections::BTreeSet;

use super::*;
use crate::EntityId;
use crate::Vault;
use crate::error::Result;
use crate::federation::{
    FederationDirectionScope, FederationGrant, FederationGrantScope, Scope, ScopeAxis,
    selector_range_of,
};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// A narrowing widens back by its own party only, within the dual-signed
/// ceiling; any other widening takes an epoch-advancing dual-signed re-pact
/// (FIX 7933; CALLS "Phase2 rescope other party", Engine 10-22 02:0x).
pub(in crate::authority) const NARROWING_WIDENS_BACK_BY_OWN_PARTY_ONLY: bool = true;

/// An Ask guest's slip signs the ask's disclosed facts as its record bound,
/// and every slip door and task proof holds it to the grant's current
/// disclosure (FIX 7928; CALLS "Phase2 Ask slip disclosure bound").
pub(in crate::authority) const ASK_SLIP_BOUND_IS_DISCLOSURE: bool = true;

/// A Connect guest's credential is met with its grant's current effective
/// scope at mint, at verification, at each row a cached view reads and at
/// each task it proves (FIX 7929; CALLS "Phase2 Connect slip current scope").
pub(in crate::authority) const CONNECT_SLIP_MEETS_CURRENT_SCOPE: bool = true;

/// Who signed a narrowing, read from the signer's live human binding in the
/// entry's ancestry, else the signing key itself (FIX 7933). Nothing the
/// entry asserts names its party.
pub(in crate::authority) fn narrowing_party(
    state: &FoldState,
    signer: &AuthorityKey,
) -> NarrowingParty {
    state
        .live_actor_binding(signer)
        .filter(|binding| binding.actor_class == ACTOR_CLASS_HUMAN)
        .map_or_else(
            || NarrowingParty::Key(signer.clone()),
            |binding| NarrowingParty::Owner(binding.actor_ref),
        )
}

/// [`narrowing_party`] as this install's projected fold reads the signer:
/// the party a door expects the fold to judge its own entry by.
pub(in crate::authority) fn projected_narrowing_party(
    fold: &AuthorityFold,
    signer: &AuthorityKey,
) -> NarrowingParty {
    fold.actor_bindings
        .get(signer)
        .filter(|binding| {
            binding.status == ActorBindingStatus::Active && binding.actor_class == ACTOR_CLASS_HUMAN
        })
        .map_or_else(
            || NarrowingParty::Key(signer.clone()),
            |binding| NarrowingParty::Owner(binding.actor_ref),
        )
}

/// Our outbound half of `pact`: its dual-signed ceiling met with every
/// standing narrowing but `except`'s when it names a party. With `except`
/// the party's own bound: what it may restore its narrowing to.
pub(in crate::authority) fn pact_scope_beside(
    local: &AuthorityVaultId,
    pact: &FederationPactState,
    except: Option<&NarrowingParty>,
) -> FederationDirectionScope {
    let ceiling =
        super::op_apply::local_outbound_scope(local, &pact.peer_vault_id, &pact.pact_scope);
    if except.is_some() && !NARROWING_WIDENS_BACK_BY_OWN_PARTY_ONLY {
        return ceiling;
    }
    pact.narrowings
        .values()
        .filter(|narrowing| Some(&narrowing.party) != except)
        .fold(ceiling, |scope, narrowing| {
            scope.intersect(&narrowing.scope)
        })
}

/// Records `party`'s narrowing at `entry`: every standing narrowing of that
/// party is in the entry's ancestry, so the new one supersedes them.
pub(in crate::authority) fn record_narrowing(
    pact: &mut FederationPactState,
    entry: AuthorityEntryHash,
    party: NarrowingParty,
    scope: FederationDirectionScope,
) {
    let superseded: Vec<AuthorityEntryHash> = pact
        .narrowings
        .iter()
        .filter(|(_, narrowing)| {
            !NARROWING_WIDENS_BACK_BY_OWN_PARTY_ONLY || narrowing.party == party
        })
        .map(|(hash, _)| *hash)
        .collect();
    for hash in superseded {
        pact.narrowings.remove(&hash);
        pact.superseded_narrowings.insert(hash);
    }
    pact.narrowings
        .insert(entry, FederationNarrowing { party, scope });
}

/// Joins `right`'s narrowings into `merged` at one epoch: every narrowing
/// either side holds, less every one either side saw superseded, and the
/// effective scope derived again from what stands. Commutative, associative
/// and idempotent, so a fold that merges every historical state agrees with
/// one that merges heads.
pub(in crate::authority) fn merge_narrowings(
    local: &AuthorityVaultId,
    merged: &mut FederationPactState,
    right: &FederationPactState,
) {
    merged
        .superseded_narrowings
        .extend(right.superseded_narrowings.iter().copied());
    for (hash, narrowing) in &right.narrowings {
        merged
            .narrowings
            .entry(*hash)
            .or_insert_with(|| narrowing.clone());
    }
    let superseded = merged.superseded_narrowings.clone();
    merged
        .narrowings
        .retain(|hash, _| !superseded.contains(hash));
    merged.effective_scope = pact_scope_beside(local, merged, None);
}

/// The current effective scope of a pact-bound grant: the meet of every pact
/// that binds it, or `None` when none does. The sync selector's ceiling reads
/// the same meet (ONE-1591).
fn current_grant_scope(fold: &AuthorityFold, grant: &EntityId) -> Option<FederationDirectionScope> {
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

/// Whether `scope` (a credential's, or a row's position) stands inside
/// `current` on every axis a pact narrows.
fn within(scope: &Scope, current: &FederationDirectionScope) -> bool {
    scope.worlds.is_narrowing_of(&current.worlds)
        && scope.facets.is_narrowing_of(&current.facets)
        && bands_within(&scope.bands, &current.bands) == scope.bands
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

impl Vault {
    /// The live non-owner guest grant `grant_ref` names, read from its own row
    /// in `txn`: `None` for any other grant, and where the row is missing,
    /// deleted, unreadable or does not decode (today's path; the slip doors
    /// judge a dead grant on their own).
    fn guest_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        grant_ref: EntityId,
    ) -> Option<FederationGrant> {
        let Ok(LiveEntityRow::Live {
            entity_type: crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
            body,
        }) = live_entity_row_in_txn(&self.store, txn, &grant_ref)
        else {
            return None;
        };
        crate::federation::decode_federation_grant_body(&body)
            .ok()
            .filter(|grant| grant.role.is_guest())
    }

    /// The current effective scope a Connect guest's credential stands in
    /// (FIX 7929): `None` for every credential that is not a live Connect
    /// guest grant's, and where no pact binds the grant or the fold cannot
    /// be read (today's path).
    fn current_guest_scope_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        grant_ref: EntityId,
    ) -> Option<FederationDirectionScope> {
        if !CONNECT_SLIP_MEETS_CURRENT_SCOPE {
            return None;
        }
        let grant = self.guest_grant_in_txn(txn, grant_ref)?;
        if !matches!(grant.scope, FederationGrantScope::Connect { .. }) {
            return None;
        }
        let fold = self.authority_view_readonly_in_txn(txn).ok()?;
        current_grant_scope(&fold, &grant_ref)
    }

    /// The current effective scope of a guest credential whose own scope
    /// reaches past it, as after a narrowing landed once its view was taken.
    /// `None` while the view stands inside it, and for every non-guest
    /// credential.
    fn guest_view_narrowed_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claims: &SlipClaims,
    ) -> Option<FederationDirectionScope> {
        let grant_ref = EntityId::from_hex(claims.grant_ref.as_deref()?).ok()?;
        self.current_guest_scope_in_txn(txn, grant_ref)
            .filter(|current| !within(&claims.scope, current))
    }

    /// Whether a row a credential with `claims` reads stands inside the
    /// guest's current effective scope (FIX 7929): true for every non-guest
    /// credential and for a guest view still inside it; once a narrowing
    /// landed after the view was taken, false for a row whose `position`
    /// stands outside the narrowed scope. In-scope rows keep reading, and a
    /// row whose position cannot be read or names none keeps today's path.
    pub(crate) fn guest_row_admitted_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claims: &SlipClaims,
        position: impl FnOnce() -> Result<Option<Scope>>,
    ) -> bool {
        let Some(current) = self.guest_view_narrowed_in_txn(txn, claims) else {
            return true;
        };
        // A NOTE in several worlds stands inside at one `current` holds
        // (FIX-LIST 9433).
        position().ok().flatten().is_none_or(|position| {
            let position = crate::federation::record_scope::note_world::any_world_at(
                &position,
                &current.worlds,
            );
            within(&position, &current)
        })
    }

    /// A slip verified in `txn`: its grant, invitation and delegation still
    /// stand, and a Connect guest's view is met with its grant's current
    /// effective scope (FIX 7929).
    pub(super) fn admitted_slip_view_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        verified: VerifiedSlip,
        now: u64,
    ) -> Result<VerifiedSlip> {
        self.require_live_slip_refs_in_txn(txn, verified.claims(), now)?;
        Ok(
            match self.guest_view_narrowed_in_txn(txn, verified.claims()) {
                Some(current) => verified.meet_current_scope(&current),
                None => verified,
            },
        )
    }

    /// Whether a guest grant reaches TASK `task` (FIX 7928, 7929): an Ask
    /// guest's its own ask's member TASKs and its disclosed facts, a Connect
    /// guest's a TASK whose position stands inside its current effective
    /// scope. Any other grant, and a grant, ask record or TASK that cannot
    /// be read, keeps today's path.
    pub(super) fn guest_reaches_task_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        grant_ref: EntityId,
        task: EntityId,
    ) -> bool {
        let Some(grant) = self.guest_grant_in_txn(txn, grant_ref) else {
            return true;
        };
        match grant.scope {
            FederationGrantScope::Ask { ask_ref } if ASK_SLIP_BOUND_IS_DISCLOSURE => {
                disclosed(&grant).contains(&task.to_hex())
                    || crate::task_verb::ask_member_task_in(self, txn, ask_ref, task)
                        .unwrap_or(true)
            }
            FederationGrantScope::Connect { .. } => {
                let Some(current) = self.current_guest_scope_in_txn(txn, grant_ref) else {
                    return true;
                };
                let Ok(Some(raw)) = self.get_raw_in(txn, &task) else {
                    return true;
                };
                let credential = Scope {
                    worlds: current.worlds,
                    facets: current.facets,
                    ..Scope::top()
                };
                crate::federation::record_scope::task_inside_credential(
                    &self.store,
                    txn,
                    task,
                    &raw,
                    &credential,
                )
                .unwrap_or(true)
            }
            _ => true,
        }
    }
}
