//! Typed owner doors over the vault's sandbox provider switch (L8-43): whose
//! machines run its finite Foreign and Untrusted guests. Both are the
//! owner's, under the owner's proof, as the web connector's switch is.
use std::sync::Arc;

use oneiron::settings::sandbox_provider::{
    READ_VERB, REPLACE_VERB, SandboxProviderAnswer, SandboxProviderSetting,
};
use oneiron::task_verb::sdk::EmptyRequest;

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_settings_sandbox_provider(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<SandboxProviderAnswer> {
    as_owner_naming(
        server,
        auth,
        READ_VERB,
        |server, owner| Ok(server.vault().sandbox_provider_setting_as_owner(owner)?),
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_settings_sandbox_provider_replace(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SandboxProviderSetting,
) -> Listed<SandboxProviderAnswer> {
    as_owner_naming(
        server,
        auth,
        REPLACE_VERB,
        move |server, owner| {
            Ok(server
                .vault()
                .replace_sandbox_provider_setting_as_owner(owner, input)?)
        },
        |_| Vec::new(),
    )
    .await
}
