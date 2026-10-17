//! The host doors of the owner's legal-hold rows (OF-470):
//! `vault.legal_holds.place`, `.widen`, `.list`, `.log` and
//! `.lift_and_erase`. `host_doors` re-exports them, so the generated HTTP
//! facade handler and the MCP dispatcher call them by the name every host
//! door has, and a tool call, a code-mode call and an SDK call meet one
//! admission: the vault owner's proof, as `/v1/owner/legal-holds` takes it
//! (`owner_routes::owner`). Each engine door rechecks that proof in its own
//! transaction. Oneiron's host-order doors are never routed here.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::{LegalHold, LegalHoldEvent};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult, ProducerRows};
use oneiron::task_verb::sdk::{
    self, EmptyRequest, LegalHoldLiftAndEraseRequest, LegalHoldLiftAndErased,
    LegalHoldPlaceRequest, LegalHoldWidenRequest,
};

use super::host_doors::{Listed, internal, off_runtime_listing, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The vault owner's proof, as `/v1/owner` takes it from the request.
fn owner_proof(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<AuthenticatedOwner> {
    crate::api::owner_routes::owner(auth, server).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        )
    })
}

/// `act` off the runtime, as the vault owner: every legal-hold door reads or
/// writes LMDB, and the confirm erases. The embedding-space doors run on it
/// too.
pub(super) async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> MemoryResult<T> {
    let owner = owner_proof(server, auth, verb)?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || act(&*server, &owner))
        .await
        .map_err(|_| internal(verb))?
}

/// [`as_owner`] for a door that lists its rows (`host_door_lists`): `act`
/// gets a fresh collector its handles list into, and beside its answer come
/// the rows they listed. A refusal of the proof lists none.
pub(super) async fn as_owner_listing<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &AuthenticatedOwner, &ProducerRows) -> MemoryResult<T>
    + Send
    + 'static,
) -> Listed<T> {
    let owner = match owner_proof(server, auth, verb) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    let server = Arc::clone(server);
    off_runtime_listing(verb, move |producers| act(&*server, &owner, producers)).await
}

/// `vault.legal_holds.place`: the owner's customer hold.
pub(crate) async fn vault_legal_holds_place(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LegalHoldPlaceRequest,
) -> MemoryResult<LegalHold> {
    as_owner(
        server,
        auth,
        "vault.legal_holds.place",
        move |server, owner| sdk::place_legal_hold_as(server.vault(), owner, input),
    )
    .await
}

/// `vault.legal_holds.widen`: more targets for a standing customer hold.
pub(crate) async fn vault_legal_holds_widen(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LegalHoldWidenRequest,
) -> MemoryResult<LegalHold> {
    as_owner(
        server,
        auth,
        "vault.legal_holds.widen",
        move |server, owner| sdk::widen_legal_hold_as(server.vault(), owner, input),
    )
    .await
}

/// `vault.legal_holds.list`: every hold the owner may see.
pub(crate) async fn vault_legal_holds_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> MemoryResult<Vec<LegalHold>> {
    as_owner(server, auth, "vault.legal_holds.list", |server, owner| {
        sdk::read_legal_holds(server.vault(), owner)
    })
    .await
}

/// `vault.legal_holds.log`: the owner-visible hold log, oldest first.
pub(crate) async fn vault_legal_holds_log(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> MemoryResult<Vec<LegalHoldEvent>> {
    as_owner(server, auth, "vault.legal_holds.log", |server, owner| {
        sdk::read_legal_hold_log(server.vault(), owner)
    })
    .await
}

/// `vault.legal_holds.lift_and_erase`: the owner's one "Lift the hold and
/// erase?" confirm. It erases; the engine takes the owner's proof and the
/// records, and nothing here adds a token of its own.
pub(crate) async fn vault_legal_holds_lift_and_erase(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LegalHoldLiftAndEraseRequest,
) -> MemoryResult<LegalHoldLiftAndErased> {
    as_owner(
        server,
        auth,
        "vault.legal_holds.lift_and_erase",
        move |server, owner| sdk::lift_legal_hold_and_erase_as(server.vault(), owner, input),
    )
    .await
}
