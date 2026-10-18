//! The host doors of the owner's residence rows (OF-534, FIX 531):
//! `vault.residence.mode`, `.open`, `.index` and `.prune`. Each takes the
//! vault owner's proof, as `/v1/owner` does, and the machine id the call
//! names; the named machine's own `SyncConnection`, as this host registered
//! it (`crate::residence_machines`), applies it. A machine with no
//! connection registered here gets the row as the owner's residence
//! directive instead, which that machine's own connection applies once when
//! it next syncs; no other machine is ever acted on.
use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, ResidenceAct};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError,
    MemoryResult,
};
use oneiron::sync::SyncConnection;
use oneiron::task_verb::sdk::{
    ResidenceIndex, ResidenceMachineRequest, ResidenceModeChanged, ResidenceModeName,
    ResidenceModeRequest, ResidenceOpenRequest, ResidenceOpened, ResidencePruneRequest,
    ResidencePruned,
};

use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The owner's proof, then the connection the named machine runs here, or
/// `act` relayed to it as a residence directive ([`relay`]).
fn machine_connection(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
    machine: &oneiron::EntityId,
    act: ResidenceAct,
) -> MemoryResult<Arc<SyncConnection>> {
    let owner = crate::api::owner_routes::owner(auth, server).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        )
    })?;
    crate::residence_machines::connection(machine)
        .ok_or_else(|| relay(server, &owner, verb, *machine, act))
}

/// `act` as the owner's residence directive to `machine`, which runs no
/// connection here (FIX 531): the machine applies it once when it next
/// syncs. A directive still pending with the same act is answered again, so
/// a repeated row queues it once. Nothing has run yet, so the answer is the
/// refusal it was, naming the directive.
fn relay(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    verb: &str,
    machine: oneiron::EntityId,
    act: ResidenceAct,
) -> MemoryError {
    let vault = server.vault();
    let queued = vault
        .residence_directives_as(owner, Some(machine))
        .and_then(|states| {
            if let Some(state) = states
                .into_iter()
                .find(|state| state.result.is_none() && state.directive.act == act)
            {
                return Ok(state);
            }
            let secret = server.config.auth_secret.as_deref().ok_or_else(|| {
                oneiron::Error::InvalidConfig(
                    "this host holds no signing key for a residence directive".to_owned(),
                )
            })?;
            let issuer = HostSlipIssuer::from_secret(secret.as_bytes())?;
            vault.issue_residence_directive_as(
                owner,
                &issuer,
                oneiron::EntityId::now(),
                machine,
                act,
            )
        });
    match queued {
        Ok(state) => MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            format!(
                "machine {} runs no sync connection this host can reach; {verb} is queued for \
                 it as residence directive {}, which it applies when it next syncs",
                machine.to_hex(),
                state.directive.id.to_hex()
            ),
            &[
                "The machine records the directive's result when it applies it; calling again \
               queues nothing new.",
            ],
        ),
        Err(error) => MemoryError::from(error),
    }
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
    let act = match input.mode {
        ResidenceModeName::All => ResidenceAct::SyncAll,
        ResidenceModeName::Opened => ResidenceAct::SyncOpened,
    };
    let connection = machine_connection(server, auth, VERB, &input.machine, act)?;
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
    let act = ResidenceAct::Open {
        window: window.as_str().to_owned(),
        item: input.item,
    };
    let connection = machine_connection(server, auth, VERB, &input.machine, act)?;
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
    let connection = machine_connection(server, auth, VERB, &input.machine, ResidenceAct::Index)?;
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
    let act = ResidenceAct::Prune {
        before: input.before,
    };
    let connection = machine_connection(server, auth, VERB, &input.machine, act)?;
    Ok(ResidencePruned {
        dropped: connection
            .prune_opened_items(input.before)
            .map_err(|error| refused(VERB, &error))?,
    })
}
