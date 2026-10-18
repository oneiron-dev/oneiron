//! The host doors of the owner's residence rows (OF-534, FIX 531):
//! `vault.residence.mode`, `.open`, `.index` and `.prune`. Each takes the
//! vault owner's proof, as `/v1/owner` does, and the machine id the call
//! names; the named machine's own `SyncConnection`, as this host registered
//! it (`crate::residence_machines`), applies it. A machine with no
//! connection registered here gets the row as the owner's residence
//! directive instead, which that machine's own connection applies once when
//! it next syncs; no other machine is ever acted on. That answer is typed
//! (FIX 3570): `state: "queued"` with the directive and its machine, beside
//! `state: "applied"` with what the machine did.
//!
//! Each lists its rows (`host_door_lists`): the item an open fetched, and
//! each entry the thin index shows (its title is that row's). A mode switch
//! and a prune answer the machine's windows and counts, and list none; a
//! queued directive lists none.
use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, ResidenceAct};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::sync::SyncConnection;
use oneiron::task_verb::sdk::{
    ResidenceIndexAnswer, ResidenceMachineRequest, ResidenceModeAnswer, ResidenceModeName,
    ResidenceModeRequest, ResidenceOpenAnswer, ResidenceOpenRequest, ResidenceOpened,
    ResidencePruneAnswer, ResidencePruneRequest, ResidencePruned, ResidenceQueued,
};

use super::host_doors::{Listed, naming};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Where a residence row runs: the named machine's connection here, or the
/// directive [`relay`] queued for it.
enum Reach {
    Connection(Arc<SyncConnection>),
    Queued(ResidenceQueued),
}

/// The owner's proof, then the connection the named machine runs here, or
/// `act` relayed to it as a residence directive ([`relay`]).
fn machine_connection(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
    machine: &oneiron::EntityId,
    act: ResidenceAct,
) -> MemoryResult<Reach> {
    let owner = crate::api::owner_routes::owner(auth, server).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        )
    })?;
    match crate::residence_machines::connection(machine) {
        Some(connection) => Ok(Reach::Connection(connection)),
        None => relay(server, &owner, *machine, act).map(Reach::Queued),
    }
}

/// `act` as the owner's residence directive to `machine`, which runs no
/// connection here (FIX 531): the machine applies it once when it next
/// syncs. A directive still pending with the same act is answered again, so
/// a repeated row queues it once. Nothing has run yet, so the answer is the
/// queued directive (FIX 3570), never a result.
fn relay(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    machine: oneiron::EntityId,
    act: ResidenceAct,
) -> MemoryResult<ResidenceQueued> {
    let vault = server.vault();
    let state = vault
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
        })
        .map_err(MemoryError::from)?;
    Ok(ResidenceQueued {
        directive: state.directive.id,
        machine: state.directive.machine,
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

/// [`vault_residence_mode`]'s answer: switches the named machine's residence mode.
async fn residence_mode(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResidenceModeRequest,
) -> MemoryResult<ResidenceModeAnswer> {
    const VERB: &str = "vault.residence.mode";
    let act = match input.mode {
        ResidenceModeName::All => ResidenceAct::SyncAll,
        ResidenceModeName::Opened => ResidenceAct::SyncOpened,
    };
    let connection = match machine_connection(server, auth, VERB, &input.machine, act)? {
        Reach::Connection(connection) => connection,
        Reach::Queued(queued) => return Ok(ResidenceModeAnswer::Queued(queued)),
    };
    Ok(ResidenceModeAnswer::Applied(
        connection
            .set_residence_mode(input.mode.into())
            .await
            .map_err(|error| refused(VERB, &error))?
            .into(),
    ))
}

/// [`vault_residence_open`]'s answer: opens one item on the named machine.
async fn residence_open(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResidenceOpenRequest,
) -> MemoryResult<ResidenceOpenAnswer> {
    const VERB: &str = "vault.residence.open";
    let window = oneiron::sync::WindowKey::try_new(input.window)
        .ok_or_else(|| MemoryError::bad_request("window must be YYYY-MM"))?;
    let act = ResidenceAct::Open {
        window: window.as_str().to_owned(),
        item: input.item,
    };
    let connection = match machine_connection(server, auth, VERB, &input.machine, act)? {
        Reach::Connection(connection) => connection,
        Reach::Queued(queued) => return Ok(ResidenceOpenAnswer::Queued(queued)),
    };
    let local = connection
        .item_is_local(input.item)
        .map_err(|error| refused(VERB, &error))?;
    let opened = connection
        .open_item(&window, input.item)
        .await
        .map_err(|error| refused(VERB, &error))?;
    let (actor, class) =
        super::facade_actor(server, auth).map_err(|error| error.into_memory_error())?;
    let source = if local {
        oneiron::note::NoteReadSource::Local
    } else {
        oneiron::note::NoteReadSource::Home
    };
    let mut note = connection.opened_note_view(
        &opened,
        oneiron::WriteActor::new(actor, class),
        auth.verified_slip(),
        auth.locality(),
        input.reason.as_deref(),
        &input.spans,
    )?;
    if let Some(note) = &mut note {
        note.source = source;
    }
    Ok(ResidenceOpenAnswer::Applied(Box::new(
        ResidenceOpened::from_opened(opened, source, note),
    )))
}

/// [`vault_residence_index`]'s answer: the named machine's thin index.
async fn residence_index(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResidenceMachineRequest,
) -> MemoryResult<ResidenceIndexAnswer> {
    const VERB: &str = "vault.residence.index";
    let connection =
        match machine_connection(server, auth, VERB, &input.machine, ResidenceAct::Index)? {
            Reach::Connection(connection) => connection,
            Reach::Queued(queued) => return Ok(ResidenceIndexAnswer::Queued(queued)),
        };
    Ok(ResidenceIndexAnswer::Applied(
        connection
            .residence_index()
            .map_err(|error| refused(VERB, &error))?
            .into(),
    ))
}

/// [`vault_residence_prune`]'s answer: drops the named machine's opened-item caches
/// last touched before `before`.
async fn residence_prune(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResidencePruneRequest,
) -> MemoryResult<ResidencePruneAnswer> {
    const VERB: &str = "vault.residence.prune";
    let act = ResidenceAct::Prune {
        before: input.before,
    };
    let connection = match machine_connection(server, auth, VERB, &input.machine, act)? {
        Reach::Connection(connection) => connection,
        Reach::Queued(queued) => return Ok(ResidencePruneAnswer::Queued(queued)),
    };
    Ok(ResidencePruneAnswer::Applied(ResidencePruned {
        dropped: connection
            .prune_opened_items(input.before)
            .map_err(|error| refused(VERB, &error))?,
    }))
}

/// `vault.residence.mode`: switches the named machine's residence mode, listing no row.
pub(crate) async fn vault_residence_mode(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResidenceModeRequest,
) -> Listed<ResidenceModeAnswer> {
    naming(residence_mode(server, auth, input).await, |_| Vec::new())
}

/// `vault.residence.open`: opens one item on the named machine, listing it.
pub(crate) async fn vault_residence_open(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResidenceOpenRequest,
) -> Listed<ResidenceOpenAnswer> {
    naming(
        residence_open(server, auth, input).await,
        |answer| match answer {
            ResidenceOpenAnswer::Applied(opened) => vec![opened.item],
            ResidenceOpenAnswer::Queued(_) => Vec::new(),
        },
    )
}

/// `vault.residence.index`: the named machine's thin index, listing each row it shows.
pub(crate) async fn vault_residence_index(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResidenceMachineRequest,
) -> Listed<ResidenceIndexAnswer> {
    naming(
        residence_index(server, auth, input).await,
        |answer| match answer {
            ResidenceIndexAnswer::Applied(index) => index
                .windows
                .iter()
                .flat_map(|window| window.items.iter())
                .filter_map(|entry| oneiron::EntityId::from_hex(&entry.entity_id).ok())
                .collect(),
            ResidenceIndexAnswer::Queued(_) => Vec::new(),
        },
    )
}

/// `vault.residence.prune`: drops the named machine's opened-item caches
/// last touched before `before`, listing no row.
pub(crate) async fn vault_residence_prune(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResidencePruneRequest,
) -> Listed<ResidencePruneAnswer> {
    naming(residence_prune(server, auth, input).await, |_| Vec::new())
}
