//! The owner's pack, connector subscription, lens and pack setup doors.
//! `vault_packs_*`, `vault_connectors_subscriptions_*` and `vault_lenses_*` are its call surface.
//! The engine's `oneiron::task_verb::sdk` and `oneiron::lens` define the records forwarded here.

use std::sync::Arc;

use oneiron::EntityId;
use oneiron::lens::{LensActivateRequest, LensDeactivateRequest};
use oneiron::memory::MemoryResult;
use oneiron::receipt::LensActivationReceipt;
use oneiron::task_verb::sdk::{
    ChannelSubscriptionRequest, ChannelSubscriptionRevokeRequest, ChannelSubscriptionRevoked,
    ChannelSubscriptions, ChannelSubscriptionsRequest, PackPutReceipt, PackPutRequest,
    PackRemoveRequest, PackSetupAnswerRequest, PackSetupReceipt, PackSetupRequest,
    PackSetupVerifyRequest,
};

use super::support::{Listed, MaybeListed, hex_rows, internal, naming, owner_proof};
use crate::api::clock_ingress;
use crate::auth::CoreAuth;
use crate::builtin_host::HostConnectionChecks;
use crate::server::SyncServer;

/// `vault.packs.put`: the owner installs a pack folder, or replaces the one
/// installed under its name, under the proof `/v1/owner` takes from the
/// request. The put is the consent for the pack's hooks.
pub(super) async fn vault_packs_put_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackPutRequest,
) -> MemoryResult<PackPutReceipt> {
    let owner = owner_proof(auth, server, "vault.packs.put")?;
    let server = Arc::clone(server);
    clock_ingress::run_blocking(move || {
        oneiron::task_verb::sdk::put_pack_as_owner(server.vault(), &owner, input)
    })
    .await
    .map_err(|_| internal("vault.packs.put"))?
}

/// [`vault_packs_put_answer`], listing the pack's source row its receipt names, when it installed
/// one (`host_door_lists`).
pub(crate) async fn vault_packs_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackPutRequest,
) -> Listed<PackPutReceipt> {
    naming(vault_packs_put_answer(server, auth, input).await, |put| {
        put.receipt
            .as_deref()
            .and_then(pack_source)
            .into_iter()
            .collect()
    })
}

/// `vault.packs.remove`: the owner removes an installed pack, under the
/// proof `/v1/owner/packs/remove` takes. Answers the removed receipt.
pub(super) async fn vault_packs_remove_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackRemoveRequest,
) -> MemoryResult<oneiron::skill_hub::pack_catalog::PackInstallReceipt> {
    let owner = owner_proof(auth, server, "vault.packs.remove")?;
    let server = Arc::clone(server);
    clock_ingress::run_blocking(move || {
        oneiron::task_verb::sdk::remove_pack_as_owner(server.vault(), &owner, &input)
    })
    .await
    .map_err(|_| internal("vault.packs.remove"))?
}

/// [`vault_packs_remove_answer`], listing the removed pack's source row (`host_door_lists`).
pub(crate) async fn vault_packs_remove(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackRemoveRequest,
) -> Listed<oneiron::skill_hub::pack_catalog::PackInstallReceipt> {
    naming(
        vault_packs_remove_answer(server, auth, input).await,
        |removed| pack_source(removed).into_iter().collect(),
    )
}

/// `vault.connectors.subscriptions.put`: the owner subscribes an agent to
/// the messages a built-in channel's pack routes to it (OF-519), as
/// `POST /v1/owner/connectors/subscriptions` does.
pub(super) async fn vault_connectors_subscriptions_put_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelSubscriptionRequest,
) -> MemoryResult<oneiron::connector_key::ChannelMessageSubscription> {
    let owner = owner_proof(auth, server, "vault.connectors.subscriptions.put")?;
    let server = Arc::clone(server);
    clock_ingress::run_blocking(move || {
        oneiron::task_verb::sdk::subscribe_channel_as_owner(server.vault(), &owner, &input)
    })
    .await
    .map_err(|_| internal("vault.connectors.subscriptions.put"))?
}

/// [`vault_connectors_subscriptions_put_answer`], listing the subscription, its connector key and
/// its agent (`host_door_lists`).
pub(crate) async fn vault_connectors_subscriptions_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelSubscriptionRequest,
) -> Listed<oneiron::connector_key::ChannelMessageSubscription> {
    naming(
        vault_connectors_subscriptions_put_answer(server, auth, input).await,
        |subscribed| {
            hex_rows([
                &subscribed.subscription,
                &subscribed.connector_key,
                &subscribed.agent,
            ])
        },
    )
}

/// `vault.connectors.subscriptions.list`: an agent's connector event
/// subscriptions, standing and revoked, for the owner.
pub(super) async fn vault_connectors_subscriptions_list_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelSubscriptionsRequest,
) -> MemoryResult<ChannelSubscriptions> {
    let owner = owner_proof(auth, server, "vault.connectors.subscriptions.list")?;
    let server = Arc::clone(server);
    clock_ingress::run_blocking(move || {
        oneiron::task_verb::sdk::channel_subscriptions_as_owner(server.vault(), &owner, &input)
    })
    .await
    .map_err(|_| internal("vault.connectors.subscriptions.list"))?
}

/// [`vault_connectors_subscriptions_list_answer`], listing each subscription it shows and its
/// connector key (`host_door_lists`).
pub(crate) async fn vault_connectors_subscriptions_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelSubscriptionsRequest,
) -> Listed<ChannelSubscriptions> {
    naming(
        vault_connectors_subscriptions_list_answer(server, auth, input).await,
        |listed| {
            listed
                .subscriptions
                .iter()
                .flat_map(|row| hex_rows([&row.subscription, &row.connector_key]))
                .collect()
        },
    )
}

/// `vault.connectors.subscriptions.revoke`: the owner stops a subscription;
/// its key stays.
pub(super) async fn vault_connectors_subscriptions_revoke_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelSubscriptionRevokeRequest,
) -> MemoryResult<ChannelSubscriptionRevoked> {
    let owner = owner_proof(auth, server, "vault.connectors.subscriptions.revoke")?;
    let server = Arc::clone(server);
    clock_ingress::run_blocking(move || {
        oneiron::task_verb::sdk::revoke_channel_subscription_as_owner(
            server.vault(),
            &owner,
            &input,
        )
    })
    .await
    .map_err(|_| internal("vault.connectors.subscriptions.revoke"))?
}

/// [`vault_connectors_subscriptions_revoke_answer`], listing the subscription it stopped
/// (`host_door_lists`).
pub(crate) async fn vault_connectors_subscriptions_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelSubscriptionRevokeRequest,
) -> Listed<ChannelSubscriptionRevoked> {
    naming(
        vault_connectors_subscriptions_revoke_answer(server, auth, input).await,
        |revoked| hex_rows([&revoked.subscription]),
    )
}

/// The pack source row an install receipt is read from.
pub(super) fn pack_source(
    receipt: &oneiron::skill_hub::pack_catalog::PackInstallReceipt,
) -> Option<EntityId> {
    EntityId::from_hex(&receipt.source_id).ok()
}

/// The lenses a slot decision names: the one it selected or cleared, and
/// the one the slot held before. Its pack slot and decision live in side
/// tables.
pub(super) fn lens_rows(receipt: &LensActivationReceipt) -> Vec<EntityId> {
    hex_rows(std::iter::once(&receipt.lens_ref).chain(receipt.previous_ref.iter()))
}

/// A pack setup door's act off the runtime as the owner, listing what its
/// view is read from (`host_door_lists`): the pack's source row, each
/// connection's connector key, each standing grant and each stored secret's
/// custody record, as the view's own read found it. The session and its
/// checks live in side tables.
pub(super) async fn setup_listing(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(
        &Arc<SyncServer>,
        &oneiron::consent::AuthenticatedOwner,
    ) -> MemoryResult<PackSetupReceipt>
    + Send
    + 'static,
) -> MaybeListed<PackSetupReceipt> {
    let owner = match owner_proof(auth, server, verb) {
        Ok(owner) => owner,
        Err(refusal) => return (Err(refusal), Some(Vec::new())),
    };
    let server = Arc::clone(server);
    clock_ingress::run_blocking(move || {
        let answer = act(&server, &owner);
        let rows = match &answer {
            Ok(receipt) => Some(setup_rows(&receipt.setup)),
            Err(_) => Some(Vec::new()),
        };
        (answer, rows)
    })
    .await
    .unwrap_or_else(|_| (Err(internal(verb)), Some(Vec::new())))
}

/// The rows a pack setup view is read from, as [`setup_listing`] lists them.
pub(super) fn setup_rows(setup: &oneiron::skill_hub::pack_catalog::PackSetupView) -> Vec<EntityId> {
    let mut rows = hex_rows([&setup.source_id]);
    for connection in &setup.connections {
        rows.extend(hex_rows(connection.connector_key.iter()));
        rows.extend(hex_rows(
            connection
                .permissions
                .iter()
                .filter_map(|permission| permission.grant_ref.as_ref()),
        ));
        rows.extend(
            connection
                .secrets
                .iter()
                .filter_map(|secret| secret.custody_id),
        );
    }
    rows
}

/// `vault.lenses.activate`: the owner selects a proposed lens revision for
/// its pack slot, under the proof `/v1/owner` takes from the request. The
/// owner's confirmation is the consent; an agent can only propose.
pub(super) async fn vault_lenses_activate_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LensActivateRequest,
) -> MemoryResult<LensActivationReceipt> {
    let owner = owner_proof(auth, server, "vault.lenses.activate")?;
    let server = Arc::clone(server);
    clock_ingress::run_blocking(move || server.vault().activate_lens(&owner, input))
        .await
        .map_err(|_| internal("vault.lenses.activate"))?
}

/// [`vault_lenses_activate_answer`], listing the lens it selected and the one the slot held before
/// (`host_door_lists`).
pub(crate) async fn vault_lenses_activate(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LensActivateRequest,
) -> Listed<LensActivationReceipt> {
    naming(
        vault_lenses_activate_answer(server, auth, input).await,
        lens_rows,
    )
}

/// `vault.lenses.deactivate`: the owner clears a pack slot's selected lens,
/// under the same proof. The pack, its skill and the proposal stay.
pub(super) async fn vault_lenses_deactivate_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LensDeactivateRequest,
) -> MemoryResult<LensActivationReceipt> {
    let owner = owner_proof(auth, server, "vault.lenses.deactivate")?;
    let server = Arc::clone(server);
    clock_ingress::run_blocking(move || server.vault().deactivate_lens(&owner, input))
        .await
        .map_err(|_| internal("vault.lenses.deactivate"))?
}

/// [`vault_lenses_deactivate_answer`], listing the lens it cleared (`host_door_lists`).
pub(crate) async fn vault_lenses_deactivate(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LensDeactivateRequest,
) -> Listed<LensActivationReceipt> {
    naming(
        vault_lenses_deactivate_answer(server, auth, input).await,
        lens_rows,
    )
}

/// `vault.packs.setup.prepare`: the owner opens, or resumes, a pack's guided
/// setup (OF-378), under the proof `/v1/owner` takes from the request.
/// Opening grants nothing.
pub(crate) async fn vault_packs_setup_prepare(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackSetupRequest,
) -> MaybeListed<PackSetupReceipt> {
    setup_listing(
        server,
        auth,
        "vault.packs.setup.prepare",
        move |server, owner| {
            oneiron::task_verb::sdk::prepare_pack_setup_as_owner(server.vault(), owner, &input)
        },
    )
    .await
}

/// `vault.packs.setup.get`: a pack's guided setup as it stands, under the
/// same proof.
pub(crate) async fn vault_packs_setup_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackSetupRequest,
) -> MaybeListed<PackSetupReceipt> {
    setup_listing(
        server,
        auth,
        "vault.packs.setup.get",
        move |server, owner| {
            oneiron::task_verb::sdk::pack_setup_as_owner(server.vault(), owner, &input)
        },
    )
    .await
}

/// `vault.packs.setup.answer`: one answer or card action, under the same
/// proof. The verb never answers `allow` (the owner's review stays at
/// `/v1/owner/packs/setup/answer`), and a store action answers with the
/// owner secrets door; a credential value never passes here.
pub(crate) async fn vault_packs_setup_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackSetupAnswerRequest,
) -> MaybeListed<PackSetupReceipt> {
    setup_listing(
        server,
        auth,
        "vault.packs.setup.answer",
        move |server, owner| {
            let checks = HostConnectionChecks::new(&server)?;
            oneiron::task_verb::sdk::answer_pack_setup_as_owner(
                server.vault(),
                owner,
                &input,
                &checks,
            )
        },
    )
    .await
}

/// `vault.packs.setup.verify`: checks one connection with the engine's fixed
/// read-only provider call for its declared check, under the same proof.
pub(crate) async fn vault_packs_setup_verify(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackSetupVerifyRequest,
) -> MaybeListed<PackSetupReceipt> {
    setup_listing(
        server,
        auth,
        "vault.packs.setup.verify",
        move |server, owner| {
            let checks = HostConnectionChecks::new(&server)?;
            oneiron::task_verb::sdk::verify_pack_setup_as_owner(
                server.vault(),
                owner,
                &input,
                &checks,
            )
        },
    )
    .await
}
