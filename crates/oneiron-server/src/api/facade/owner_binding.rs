//! WILL-PLAN L13 row 01: one revalidated binding for a managed vault's
//! attested owner, shared by the policy doors, `POST /v1/core/actions/{verb}`
//! and a held lens card's events.
//!
//! A request its supervisor attested as the vault's owner
//! (`ManagedOwnerAction`, verified at managed ingress) carries no slip: its
//! credential is the host root's, which reads and acts as nobody (FIX 2222).
//! The owner's say-so still counts from that surface. This binding gives such
//! a request the owner's own in-request proof (`owner_routes::owner`'s
//! managed arm: the recorded owner the holder names, while that owner is
//! live), the proof's actual person as a human, and the owner's read key held
//! to that proof at the caller's locality, so every read proves the owner
//! again in its own snapshot. The proof rides into the act, where each
//! committing door revalidates it in its own transaction.
//!
//! The lack of a slip never implies an owner: only an attested holder binds
//! here, and only while the vault records that person as a live owner. No
//! host root, no embedded-owner read and no agent run is reached through it.
//! The proof is this request's alone, never a durable owner authorization.

use oneiron::authority::ActSurface;
use oneiron::claim::ScopedReadActorKey;
use oneiron::consent::AuthenticatedOwner;
use oneiron::{EdgeActorClass, EntityId};

use super::FacadeApiError;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// A managed vault's attested owner, bound for one request.
pub(super) struct OwnerBinding {
    /// The proof's own person: the attested holder.
    pub(super) actor: EntityId,
    /// Always [`EdgeActorClass::Human`]: a person, never an agent.
    pub(super) class: EdgeActorClass,
    /// The owner's read key, held to [`Self::owner`], at the caller's
    /// locality.
    pub(super) key: ScopedReadActorKey,
    /// The request's own owner proof.
    pub(super) owner: AuthenticatedOwner,
}

/// The binding of `auth`'s attested owner. `None` for a request no
/// `ManagedOwnerAction` attested, which keeps its own credential's path. An
/// attested holder the vault does not record as a live owner is refused,
/// never read as an ordinary caller.
pub(super) fn managed_owner_binding(
    server: &SyncServer,
    auth: &CoreAuth,
) -> Result<Option<OwnerBinding>, FacadeApiError> {
    let Some(holder) = auth.managed_owner() else {
        return Ok(None);
    };
    let refused = || {
        FacadeApiError::forbidden(
            "the attested owner is not this vault's live owner",
            ["Sign in again as this vault's owner, then retry."],
        )
    };
    let owner =
        crate::api::owner_routes::managed_owner_proof(server, holder)?.ok_or_else(refused)?;
    // The proof's own person, which must be the holder the supervisor named.
    let actor = owner
        .actor_for_read(server.vault())
        .map_err(|_| refused())?;
    if actor != holder {
        return Err(refused());
    }
    let key = server
        .vault()
        .owner_proof_read_key(&owner)
        .map_err(|_| refused())?
        .at(auth.locality());
    Ok(Some(OwnerBinding {
        actor,
        class: EdgeActorClass::Human,
        key,
        owner,
    }))
}

/// Where an owner's say-so on `auth` reached this install, for the act's
/// audit record only: no admission rule reads it (owner ruling 10-19, "it
/// doesn't matter where you said yes"). The owner doors' rule
/// (`owner_routes::machine_routes::act_surface`) for a door that holds no
/// request headers: the hosted console for a managed vault's attested owner,
/// else this install. A linked machine's own proof rides the headers, so
/// these doors label its request this install's.
pub(super) fn act_surface(auth: &CoreAuth) -> ActSurface {
    if auth.managed_owner().is_some() {
        ActSurface::HostedConsole
    } else {
        ActSurface::ThisInstall
    }
}
