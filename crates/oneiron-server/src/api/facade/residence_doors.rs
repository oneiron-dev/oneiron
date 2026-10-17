//! The host doors of the owner's residence rows (OF-534, FIX 531):
//! `vault.residence.mode`, `.open`, `.index` and `.prune`. Each takes the
//! vault owner's proof, as `/v1/owner` does, and the machine id the call
//! names; the named machine's own `SyncConnection`, as this host registered
//! it (`crate::residence_machines`), applies it. A machine with no
//! connection registered here is refused, never another machine acted on.
use std::sync::Arc;

use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError,
    MemoryResult,
};
use oneiron::sync::SyncConnection;
use oneiron::task_verb::sdk::{
    ResidenceIndex, ResidenceMachineRequest, ResidenceModeChanged, ResidenceModeRequest,
    ResidenceOpenRequest, ResidenceOpened, ResidencePruneRequest, ResidencePruned,
};

use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The owner's proof, then the connection the named machine runs here.
fn machine_connection(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
    machine: &oneiron::EntityId,
) -> MemoryResult<Arc<SyncConnection>> {
    crate::api::owner_routes::owner(auth, server).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        )
    })?;
    crate::residence_machines::connection(machine).ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            format!(
                "machine {} runs no sync connection this host can reach",
                machine.to_hex()
            ),
            &["Call it on the server that runs the named machine's sync connection."],
        )
    })
}

/// The machine's refusal of a residence step, as the row's.
fn refused(verb: &str, error: &oneiron::sync::TransportError) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_BAD_REQUEST,
        format!("{verb} was refused on the machine: {error}"),
        &["Check the machine's residence mode and its home's reachability, then retry."],
    )
}

/// `vault.residence.mode`: switches the named machine's residence mode.
pub(crate) async fn vault_residence_mode(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResidenceModeRequest,
) -> MemoryResult<ResidenceModeChanged> {
    const VERB: &str = "vault.residence.mode";
    let connection = machine_connection(server, auth, VERB, &input.machine)?;
    Ok(connection
        .set_residence_mode(input.mode.into())
        .await
        .map_err(|error| refused(VERB, &error))?
        .into())
}

/// `vault.residence.open`: opens one item on the named machine.
pub(crate) async fn vault_residence_open(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResidenceOpenRequest,
) -> MemoryResult<ResidenceOpened> {
    const VERB: &str = "vault.residence.open";
    let window = oneiron::sync::WindowKey::try_new(input.window)
        .ok_or_else(|| MemoryError::bad_request("window must be YYYY-MM"))?;
    let connection = machine_connection(server, auth, VERB, &input.machine)?;
    Ok(connection
        .open_item(&window, input.item)
        .await
        .map_err(|error| refused(VERB, &error))?
        .into())
}

/// `vault.residence.index`: the named machine's thin index.
pub(crate) async fn vault_residence_index(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResidenceMachineRequest,
) -> MemoryResult<ResidenceIndex> {
    const VERB: &str = "vault.residence.index";
    let connection = machine_connection(server, auth, VERB, &input.machine)?;
    Ok(connection
        .residence_index()
        .map_err(|error| refused(VERB, &error))?
        .into())
}

/// `vault.residence.prune`: drops the named machine's opened-item caches
/// last touched before `before`.
pub(crate) async fn vault_residence_prune(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResidencePruneRequest,
) -> MemoryResult<ResidencePruned> {
    const VERB: &str = "vault.residence.prune";
    let connection = machine_connection(server, auth, VERB, &input.machine)?;
    Ok(ResidencePruned {
        dropped: connection
            .prune_opened_items(input.before)
            .map_err(|error| refused(VERB, &error))?,
    })
}
