use super::host_doors::support::{Listed, hex_rows, internal};
//! The typed owner federation doors share the existing owner HTTP operations.
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, federation_connect};
use crate::server::SyncServer;
use oneiron::memory::{MEMORY_CODE_INVALID_STATE, MemoryError};
use oneiron::task_verb::sdk::*;
use std::sync::Arc;

fn refusal(verb: &str, error: OwnerError) -> MemoryError {
    match error {
        OwnerError::Invalid(message) => MemoryError::bad_request(message),
        OwnerError::NotFound(what, which) => MemoryError::not_found(format!("no {what} {which}")),
        OwnerError::Changed(message) | OwnerError::Refused(message) => {
            MemoryError::new(MEMORY_CODE_INVALID_STATE, message, &[])
        }
        OwnerError::Engine(error) => MemoryError::from(*error),
        OwnerError::Host(_) => internal(verb),
    }
}

pub(crate) async fn vault_federation_connect_identity(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<ConnectIdentity> {
    const VERB: &str = "vault.federation.connect.identity";
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, _owner| {
            federation_connect::identity(server).map_err(|error| refusal(VERB, error))
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_federation_connect_grants_mint(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MintConnectGrant,
) -> Listed<ConnectGrant> {
    const VERB: &str = "vault.federation.connect.grants.mint";
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            federation_connect::mint_grant(server, owner, &input)
                .map_err(|error| refusal(VERB, error))
        },
        |grant| hex_rows([&grant.grant, &grant.guest_actor]),
    )
    .await
}

pub(crate) async fn vault_federation_connect_offer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OfferConnect,
) -> Listed<Offer> {
    const VERB: &str = "vault.federation.connect.offer";
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            federation_connect::offer(server, owner, &input).map_err(|error| refusal(VERB, error))
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_federation_connect_accept(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AcceptConnect,
) -> Listed<ConnectAccepted> {
    const VERB: &str = "vault.federation.connect.accept";
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            federation_connect::accept(server, owner, &input).map_err(|error| refusal(VERB, error))
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_federation_connect_narrow(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: NarrowConnect,
) -> Listed<ConnectPactReceipt> {
    const VERB: &str = "vault.federation.connect.narrow";
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            federation_connect::narrow(server, owner, &input).map_err(|error| refusal(VERB, error))
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_federation_connect_rescope_offer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RescopeConnect,
) -> Listed<RescopeOffer> {
    const VERB: &str = "vault.federation.connect.rescope.offer";
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            federation_connect::rescope_offer(server, owner, &input)
                .map_err(|error| refusal(VERB, error))
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_federation_connect_rescope_accept(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AcceptRescopeConnect,
) -> Listed<ConnectRescoped> {
    const VERB: &str = "vault.federation.connect.rescope.accept";
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            federation_connect::rescope_accept(server, owner, &input)
                .map_err(|error| refusal(VERB, error))
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_federation_connect_disconnect(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectPactRequest,
) -> Listed<ConnectDisconnected> {
    const VERB: &str = "vault.federation.connect.disconnect";
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            federation_connect::disconnect(server, owner, &input)
                .map_err(|error| refusal(VERB, error))
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_federation_connect_export(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectExportRequest,
) -> Listed<ConnectDelivery> {
    const VERB: &str = "vault.federation.connect.export";
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            federation_connect::export(server, owner, input).map_err(|error| refusal(VERB, error))
        },
        |delivery| vec![delivery.body.world_ref],
    )
    .await
}

pub(crate) async fn vault_federation_connect_rejoin(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectDelivery,
) -> Listed<ConnectRejoined> {
    const VERB: &str = "vault.federation.connect.rejoin";
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            federation_connect::rejoin(server, owner, input).map_err(|error| refusal(VERB, error))
        },
        |joined| vec![joined.world_ref],
    )
    .await
}
