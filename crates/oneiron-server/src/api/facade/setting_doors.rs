//! The host doors of the owner's learned-setting rows:
//! `vault.settings.learning`, `.put` and `.clear`. `host_doors` re-exports
//! them, so the generated HTTP facade handler and the MCP dispatcher call
//! them by the name every host door has, and a tool call, a code-mode call
//! and an SDK call meet one admission: the vault owner's proof, as
//! `/v1/owner/settings/learning` takes it (`owner_routes::owner`). The
//! engine's writers check the owner again in their own write.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::learning_setting_doors::{
    self, LearningSettingClear, LearningSettingPut, LearningSettingsRequest, LearningSettingsView,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};

use super::host_doors::internal;
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

/// `act` off the runtime, as the vault owner: every setting door reads or
/// writes LMDB.
async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &AuthenticatedOwner) -> oneiron::Result<T> + Send + 'static,
) -> MemoryResult<T> {
    let owner = owner_proof(server, auth, verb)?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || act(&*server, &owner).map_err(MemoryError::from))
        .await
        .map_err(|_| internal(verb))?
}

/// `vault.settings.learning`: the catalog and the owner's rows.
pub(crate) async fn vault_settings_learning(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LearningSettingsRequest,
) -> MemoryResult<LearningSettingsView> {
    as_owner(server, auth, "vault.settings.learning", move |server, owner| {
        learning_setting_doors::learning_settings_as_owner(server.vault(), owner, &input)
    })
    .await
}

/// `vault.settings.learning.put`: one seed or pin.
pub(crate) async fn vault_settings_learning_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LearningSettingPut,
) -> MemoryResult<LearningSettingsView> {
    as_owner(server, auth, "vault.settings.learning.put", move |server, owner| {
        learning_setting_doors::put_learning_setting_as_owner(server.vault(), owner, input)
    })
    .await
}

/// `vault.settings.learning.clear`: one row cleared.
pub(crate) async fn vault_settings_learning_clear(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LearningSettingClear,
) -> MemoryResult<LearningSettingsView> {
    as_owner(server, auth, "vault.settings.learning.clear", move |server, owner| {
        learning_setting_doors::clear_learning_setting_as_owner(server.vault(), owner, input)
    })
    .await
}
