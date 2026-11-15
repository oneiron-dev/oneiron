//! The host doors of the Setting primitive's verbs (DESIGN 15-setting-primitive, stage 0.1):
//! `vault.settings.get`, `vault.settings.list` and `vault.settings.set`, and from stage 6.0
//! `vault.settings.accept_defaults`, each on the calling actor's own credential (`facade_actor`).
//! The engine door judges the caller itself: the vault owner on the owner's own live slip, or an
//! agent on its verified binding (an owner act refuses any other caller).
use std::sync::Arc;

use oneiron::runtime_hooks::InvocationId;
use oneiron::setting::{SetSettingOutcome, SettingView};
use oneiron::task_verb::sdk::{
    self, SettingAcceptDefaultsRequest, SettingAcceptedDefaults, SettingCatalogue,
    SettingGetRequest, SettingListRequest, SettingSetRequest,
};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.settings.get`: the value in force for one key.
pub(crate) async fn vault_settings_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: SettingGetRequest,
) -> Listed<SettingView> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.settings.get",
        move |_, _, memory| sdk::setting_get_embedded(&memory, input),
    )
    .await
}

/// `vault.settings.list`: the catalogue keys the caller may read.
pub(crate) async fn vault_settings_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: SettingListRequest,
) -> Listed<SettingCatalogue> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.settings.list",
        move |_, _, memory| sdk::setting_list_embedded(&memory, input),
    )
    .await
}

/// `vault.settings.set`: one row's change, applied or waiting on a check-in.
pub(crate) async fn vault_settings_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: SettingSetRequest,
) -> Listed<SetSettingOutcome> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.settings.set",
        move |_, _, memory| sdk::setting_set_embedded(&memory, input),
    )
    .await
}

/// `vault.settings.accept_defaults`: the owner's yes to a pack's waiting defaults.
pub(crate) async fn vault_settings_accept_defaults(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: SettingAcceptDefaultsRequest,
) -> Listed<SettingAcceptedDefaults> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.settings.accept_defaults",
        move |_, _, memory| sdk::setting_accept_defaults_embedded(&memory, input),
    )
    .await
}
