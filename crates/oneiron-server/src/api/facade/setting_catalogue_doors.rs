//! The host doors of the Setting primitive's verbs (DESIGN 15-setting-primitive, stage 0.1):
//! `vault.settings.get`, `vault.settings.list` and `vault.settings.set`, and from stage 6.0
//! `vault.settings.accept_defaults`, each on the calling actor's own credential (`facade_actor`).
//! The engine door judges the caller itself: the vault owner on the owner's own live slip, or an
//! agent on its verified binding (an owner act refuses any other caller). `vault.settings.set`
//! also takes where the owner's say-so reached this install (`host_door_surface`): the owner's
//! applied change is signed from it (stage 7a-1); an agent's change ignores it.
//!
//! A human caller the engine door does not take as the owner (a co-owner: the handle's own owner
//! proof is the embedded owner's alone) is then the owner when the request proves a live owner
//! as `/v1/owner` takes one ([`request_owner`]; FIX SETTINGS-SET-DOOR-CO-OWNER), so each owner
//! keeps the say the owner doors these keys replaced gave them.
use std::sync::Arc;

use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::runtime_hooks::InvocationId;
use oneiron::setting::{SetSettingOutcome, SettingView};
use oneiron::task_verb::sdk::{
    self, SettingAcceptDefaultsRequest, SettingAcceptedDefaults, SettingCatalogue,
    SettingGetRequest, SettingListRequest, SettingSetRequest,
};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The live owner `auth` proves for `verb`, as the owner doors take one (the owner's own
/// verified, unattenuated human slip; a co-owner's included); `None` for any other request. The
/// engine door asks it only for a human caller its own owner proof refuses.
fn request_owner<'a>(
    server: &'a SyncServer,
    auth: &'a CoreAuth,
    verb: &'a str,
) -> impl FnOnce() -> Option<AuthenticatedOwner> + 'a {
    move || owner_proof(auth, server, verb).ok()
}

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
        move |server, auth, memory| {
            sdk::setting_get_with_request_owner(
                &memory,
                request_owner(server, auth, "vault.settings.get"),
                input,
            )
        },
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
        move |server, auth, memory| {
            sdk::setting_list_with_request_owner(
                &memory,
                request_owner(server, auth, "vault.settings.list"),
                input,
            )
        },
    )
    .await
}

/// `vault.settings.set`: one row's change, applied or waiting on a check-in. The owner's
/// applied change is signed from `surface`.
pub(crate) async fn vault_settings_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    surface: ActSurface,
    input: SettingSetRequest,
) -> Listed<SetSettingOutcome> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.settings.set",
        move |server, auth, memory| {
            sdk::setting_set_with_request_owner(
                &memory.with_owner_surface(surface),
                request_owner(server, auth, "vault.settings.set"),
                input,
            )
        },
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
        move |server, auth, memory| {
            sdk::setting_accept_defaults_with_request_owner(
                &memory,
                request_owner(server, auth, "vault.settings.accept_defaults"),
                input,
            )
        },
    )
    .await
}
