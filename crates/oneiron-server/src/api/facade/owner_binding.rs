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
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
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
            [crate::error::MANAGED_OWNER_SIGN_IN_AGAIN],
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

/// A hosted operator's root, refused typed before a facade door judges its
/// caller (FIX 4371): `HOST_ACTION_REQUIRES_SUPPORT_GRANT` with its
/// suggestion, never the door's generic refusal. A self-hosted root, the dev
/// mode and every other credential pass on to the door's own check, which
/// keeps its own wording.
pub(super) fn host_preflight(server: &SyncServer, auth: &CoreAuth) -> MemoryResult<()> {
    crate::api::host_action::facade_host_action(server, auth)
        .map(drop)
        .map_err(FacadeApiError::into_memory_error)
}

/// The owner's own in-request proof for a facade owner door, as
/// `/v1/owner` takes it, after [`host_preflight`]. Any other caller gets
/// `refused`, the door's own owner refusal; a managed vault's attested
/// holder the vault no longer records as its live owner gets it told to
/// sign in again (FIX 5327).
pub(super) fn facade_owner_or(
    server: &SyncServer,
    auth: &CoreAuth,
    refused: impl FnOnce() -> MemoryError,
) -> MemoryResult<AuthenticatedOwner> {
    host_preflight(server, auth)?;
    crate::api::owner_routes::owner(auth, server).map_err(|error| {
        let mut refusal = refused();
        if error == crate::error::ApiError::managed_owner_not_live() {
            refusal.suggestions = vec![crate::error::MANAGED_OWNER_SIGN_IN_AGAIN.to_owned()];
        }
        refusal
    })
}

/// [`facade_owner_or`] with the owner doors' common refusal: `verb` is the
/// vault owner's.
pub(super) fn facade_owner(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<AuthenticatedOwner> {
    facade_owner_or(server, auth, || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        )
    })
}

/// The credential's own actor for a facade door, as the facade binds a
/// write to one, after [`host_preflight`]. A credential that binds none
/// gets `refused`, the door's own refusal.
pub(super) fn facade_caller_or(
    server: &SyncServer,
    auth: &CoreAuth,
    refused: impl FnOnce() -> MemoryError,
) -> MemoryResult<(EntityId, EdgeActorClass)> {
    host_preflight(server, auth)?;
    super::facade_actor(server, auth).map_err(|_| refused())
}

/// Where an owner's say-so on `auth` reached this install, for the act's
/// audit record only: no admission rule reads it (owner ruling 10-19, "it
/// doesn't matter where you said yes"). The owner doors' rule
/// (`owner_routes::machine_routes::act_surface`) for a call that carries no
/// request headers (a held socket's, a drain's resumed call, an MCP row, a
/// lens card's event): the hosted console for a managed vault's attested
/// owner; the linked machine the caller's connection proved at its binding
/// door, as a managed vault's forwarded device proves one (WILL-PLAN L14
/// row 01); else this install. An HTTP request's surface is its own, read
/// from the machine proof its headers carry (`FacadeCall::http`, and each
/// route that hands `action_bound` its headers' surface; FIX 4625).
pub(crate) fn act_surface(auth: &CoreAuth) -> ActSurface {
    if auth.managed_owner().is_some() {
        return ActSurface::HostedConsole;
    }
    match auth.peer() {
        oneiron::authority::PeerMachine::Proven { machine, .. } => {
            ActSurface::LinkedDevice { machine }
        }
        oneiron::authority::PeerMachine::Unknown => ActSurface::ThisInstall,
    }
}

/// The admission `door_admits` runs for a host-door row that left the
/// owner-only list for a caller's own act, before the row's hooks; `None`
/// for any other row. Each admits the owner as before, then the caller its
/// door acts as, and keeps the owner refusal for anyone else.
pub(super) fn caller_bound_admits(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> Option<MemoryResult<()>> {
    Some(match verb {
        // A person's own trusted-contact acts (FIX 8169): the live person
        // whose own slip the engine door revalidates.
        "vault.trusted_contacts.name"
        | "vault.trusted_contacts.dial.set"
        | "vault.trusted_contacts.concern.asks"
        | "vault.trusted_contacts.concern.authorize"
        | "vault.trusted_contacts.concern.propose" => {
            super::trusted_contact_doors::own_person(server, auth, verb).map(drop)
        }
        // The responsible role's own tradeoff asks (FIX 8178): the person or
        // agent the credential binds, as REST admits them.
        "vault.skills.optimize.tradeoff_asks" | "vault.skills.optimize.tradeoff_asks.pick" => {
            super::goal_optimize_doors::picker(server, auth, verb).map(drop)
        }
        // A fork as the caller itself (FIX 8167): a person or agent on its
        // own slip, whose write Grant the fork's writer checks.
        "vault.skills.fork" => super::skill_doors::forker(server, auth, verb).map(drop),
        // A policy put by a person holding the policy power (FIX 8177),
        // which the manifest writer checks.
        "vault.gate.policy.put" => {
            super::gate_policy_doors::policy_putter(server, auth, verb).map(drop)
        }
        // A publish or repoint as the caller on its own slip (FIX 8161),
        // which the outbound Gate judges.
        "vault.artifacts.publish" | "vault.artifacts.repoint" => {
            super::artifact_hosting_doors::publisher(server, auth, verb).map(drop)
        }
        _ => return None,
    })
}
