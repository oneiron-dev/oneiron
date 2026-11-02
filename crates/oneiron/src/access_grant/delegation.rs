//! What a credential may delegate of an access grant (FIX 8140, 1379).
//!
//! A credential delegates no more than it reads: its whole effective record
//! ceiling (worlds, facets, kind bands, audience, sensitivity) bounds every
//! grant it issues or approves, and a credential bound to named records or
//! channels, spent on one act, handed to another key or bound to a pact
//! delegates nothing reusable. Verbs are not compared: the power to write a
//! grant is the delegation, never a demand to hold the read it grants.

use std::collections::BTreeSet;

use crate::EntityId;
use crate::authority::VerifiedSlip;
use crate::error::Result;
use crate::federation::{Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
use crate::registry::ENTITY_TYPE_PSYCH_PROFILE;

use super::{AccessGrant, CompanionGrantBounds};

/// Policy hook (CALLS "OF-8141 profile sensitivity", open): the sensitivity
/// a companion profile read is judged at against a delegating credential's
/// ceiling. A profile is derived psychological text.
pub const COMPANION_PROFILE_SENSITIVITY: Sensitivity = Sensitivity::Sensitive;

/// Policy hook (CALLS "OF-8140 issuer lifetime", open): a grant a credential
/// issues or approves outlives that credential, as an owner-approved grant
/// does; false keeps it to the credential's own expiry, and a longer one is
/// excess.
pub const COMPANION_GRANT_OUTLIVES_ISSUER: bool = true;

/// The record ceiling `slip` may delegate, or none when it delegates
/// nothing reusable.
pub(super) fn delegable_ceiling(slip: &VerifiedSlip) -> Option<Scope> {
    let claims = slip.claims();
    if !claims.records.is_empty()
        || !claims.channels.is_empty()
        || claims.single_use
        || slip.is_transferred()
        || slip.pact().is_some()
    {
        return None;
    }
    Some(Scope {
        verbs: ScopeAxis::All,
        ..slip.scope().clone()
    })
}

/// Where a read of a companion profile sits: at `world` (every world for
/// the world-free profile), at `facet` (every facet for the unfaceted one),
/// in the profile kind's band, the default project and
/// [`COMPANION_PROFILE_SENSITIVITY`].
pub(super) fn companion_profile_position(
    world: Option<EntityId>,
    facet: Option<EntityId>,
) -> Scope {
    let axis = |value: Option<EntityId>| {
        value.map_or(ScopeAxis::All, |id| {
            ScopeAxis::Some(BTreeSet::from([ScopeId(id)]))
        })
    };
    Scope {
        worlds: axis(world),
        facets: axis(facet),
        bands: ScopeAxis::Some(BTreeSet::from([ENTITY_TYPE_PSYCH_PROFILE])),
        audience: ScopeAxis::Some(BTreeSet::from([
            ScopeId(crate::claim::default_project_id()),
        ])),
        verbs: ScopeAxis::Bottom,
        sensitivity: SensitivityCeiling::AtMost(COMPANION_PROFILE_SENSITIVITY),
    }
}

/// Whether `grant`'s lifetime lies inside `slip`'s.
fn lifetime_within(grant: &AccessGrant, slip: &VerifiedSlip) -> bool {
    COMPANION_GRANT_OUTLIVES_ISSUER
        || grant
            .expires_at
            .is_some_and(|end| end <= slip.claims().expires_at)
}

/// The bounds a grant `slip` issues carries.
fn bounds_of(slip: &VerifiedSlip, ceiling: Scope) -> CompanionGrantBounds {
    CompanionGrantBounds {
        issuer_slip: crate::entity_id::bytes_to_hex_lower(&slip.claims().slip_id),
        ceiling,
    }
}

/// The bounds a companion `grant` carries when `slip`'s ceiling holds its
/// whole reach: every world, its facet or every facet, the profile kind,
/// and its lifetime.
pub(super) fn whole_companion_bounds(
    slip: &VerifiedSlip,
    grant: &AccessGrant,
) -> Option<CompanionGrantBounds> {
    let (_, facet) = grant.scope.companion_profile_refs()?;
    let ceiling = delegable_ceiling(slip)?;
    (companion_profile_position(None, facet).is_narrowing_of(&ceiling)
        && lifetime_within(grant, slip))
    .then(|| bounds_of(slip, ceiling))
}

/// What a delegating credential's ceiling covers of a requested grant.
pub(super) enum Coverage {
    /// All of it: the grant as requested, carrying the delegator's bounds.
    Whole(AccessGrant),
    /// Part of it: the grant narrowed to the delegator's ceiling and
    /// lifetime. The rest stays a request.
    Part(AccessGrant),
    /// None of it: no read the grant names lies inside the ceiling.
    Nothing,
}

/// What `slip` may delegate of `requested`. A companion profile grant keeps
/// its resource authority and carries the ceiling as its bounds; a
/// relationship grant's authority is met with the ceiling, so each read is
/// judged against it at its own record position.
pub(super) fn delegated_grant(requested: &AccessGrant, slip: &VerifiedSlip) -> Coverage {
    let Some(ceiling) = delegable_ceiling(slip) else {
        return Coverage::Nothing;
    };
    let whole_life = lifetime_within(requested, slip);
    let expires_at = if whole_life {
        requested.expires_at
    } else {
        Some(slip.claims().expires_at)
    };
    if let Some((_, facet)) = requested.scope.companion_profile_refs() {
        // Some read inside the ceiling: a world and a facet it names, the
        // profile kind, the default project and the profile's sensitivity.
        let mut least = companion_profile_position(None, facet);
        least.worlds = ScopeAxis::Bottom;
        if facet.is_none() {
            least.facets = ScopeAxis::Bottom;
        }
        if ceiling.worlds.is_bottom()
            || ceiling.facets.is_bottom()
            || !least.is_narrowing_of(&ceiling)
        {
            return Coverage::Nothing;
        }
        let whole = whole_life && companion_profile_position(None, facet).is_narrowing_of(&ceiling);
        let grant = AccessGrant {
            expires_at,
            companion_bounds: Some(bounds_of(slip, ceiling)),
            ..requested.clone()
        };
        return if whole {
            Coverage::Whole(grant)
        } else {
            Coverage::Part(grant)
        };
    }
    let authority_scope = requested.authority_scope.meet(&ceiling);
    if authority_scope.worlds.is_bottom()
        || authority_scope.bands.is_bottom()
        || authority_scope.audience.is_bottom()
        || authority_scope.sensitivity == SensitivityCeiling::Bottom
    {
        return Coverage::Nothing;
    }
    let whole = whole_life && authority_scope == requested.authority_scope;
    let grant = AccessGrant {
        authority_scope,
        expires_at,
        ..requested.clone()
    };
    if whole {
        Coverage::Whole(grant)
    } else {
        Coverage::Part(grant)
    }
}

/// The id of the request that keeps the rest of request `id` for the owner
/// once a delegator approved part of it: derived, so one answer files one.
pub(super) fn excess_request_id(id: &EntityId) -> Result<EntityId> {
    let digest = blake3::Hasher::new()
        .update(b"oneiron.access_request.excess.v1\0")
        .update(id.as_bytes())
        .finalize();
    let mut raw = [0_u8; 16];
    raw.copy_from_slice(&digest.as_bytes()[..16]);
    EntityId::from_bytes(raw).map_err(|_| super::codec::invalid_grant())
}
