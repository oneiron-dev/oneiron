//! The host doors of the owner's legal-hold rows (OF-470):
//! `vault.legal_holds.place`, `.widen`, `.list`, `.log` and
//! `.lift_and_erase`. `host_doors` re-exports them, so the generated HTTP
//! facade handler and the MCP dispatcher call them by the name every host
//! door has, and a tool call, a code-mode call and an SDK call meet one
//! admission: the vault owner's proof, as `/v1/owner/legal-holds` takes it
//! (`owner_routes::owner`). Each engine door rechecks that proof in its own
//! transaction. Oneiron's host-order doors are never routed here.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::{LegalHold, LegalHoldEvent, LegalHoldTarget};
use oneiron::memory::{MemoryResult, ProducerRows};
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
    super::owner_binding::facade_owner(server, auth, verb)
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

/// [`as_owner`] for a door whose answer derives from no row but those it
/// names (`host_door_lists`): its proof, its input, side tables and the
/// authority log, which hold no row. Beside its answer come the rows
/// `named` reads off it; a refusal lists none.
pub(super) async fn as_owner_naming<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
    named: impl FnOnce(&T) -> Vec<EntityId>,
) -> Listed<T> {
    let answer = as_owner(server, auth, verb, act).await;
    let rows = answer.as_ref().map_or_else(|_| Vec::new(), named);
    (answer, rows)
}

/// The records a hold's targets name: a claim's partition names its claim,
/// the claim-free partition none.
fn hold_targets(targets: &[LegalHoldTarget]) -> impl Iterator<Item = EntityId> + '_ {
    targets.iter().filter_map(LegalHoldTarget::id)
}

/// `vault.legal_holds.place`: the owner's customer hold. It reads no row:
/// it lists the records it holds.
pub(crate) async fn vault_legal_holds_place(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LegalHoldPlaceRequest,
) -> Listed<LegalHold> {
    as_owner_naming(
        server,
        auth,
        "vault.legal_holds.place",
        move |server, owner| sdk::place_legal_hold_as(server.vault(), owner, input),
        |hold| hold_targets(&hold.targets).collect(),
    )
    .await
}

/// `vault.legal_holds.widen`: more targets for a standing customer hold,
/// listing every record it now holds.
pub(crate) async fn vault_legal_holds_widen(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LegalHoldWidenRequest,
) -> Listed<LegalHold> {
    as_owner_naming(
        server,
        auth,
        "vault.legal_holds.widen",
        move |server, owner| sdk::widen_legal_hold_as(server.vault(), owner, input),
        |hold| hold_targets(&hold.targets).collect(),
    )
    .await
}

/// `vault.legal_holds.list`: every hold the owner may see, from the hold
/// tables, listing every record they hold.
pub(crate) async fn vault_legal_holds_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<Vec<LegalHold>> {
    as_owner_naming(
        server,
        auth,
        "vault.legal_holds.list",
        |server, owner| sdk::read_legal_holds(server.vault(), owner),
        |holds| {
            holds
                .iter()
                .flat_map(|hold| hold_targets(&hold.targets))
                .collect()
        },
    )
    .await
}

/// `vault.legal_holds.log`: the owner-visible hold log, oldest first,
/// listing every record its events name.
pub(crate) async fn vault_legal_holds_log(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<Vec<LegalHoldEvent>> {
    as_owner_naming(
        server,
        auth,
        "vault.legal_holds.log",
        |server, owner| sdk::read_legal_hold_log(server.vault(), owner),
        |events| {
            events
                .iter()
                .flat_map(|event| hold_targets(&event.targets))
                .collect()
        },
    )
    .await
}

/// `vault.legal_holds.lift_and_erase`: the owner's one "Lift the hold and
/// erase?" confirm. It erases; the engine takes the owner's proof and the
/// records, and nothing here adds a token of its own. It lists the records
/// its receipt names.
pub(crate) async fn vault_legal_holds_lift_and_erase(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LegalHoldLiftAndEraseRequest,
) -> Listed<LegalHoldLiftAndErased> {
    as_owner_naming(
        server,
        auth,
        "vault.legal_holds.lift_and_erase",
        move |server, owner| sdk::lift_legal_hold_and_erase_as(server.vault(), owner, input),
        |erased| erased.records.iter().map(|erased| erased.record).collect(),
    )
    .await
}
