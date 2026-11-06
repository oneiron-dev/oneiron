//! Typed owner doors over the vault's model pack setting (FIX 5367).
use std::sync::Arc;

use oneiron::llm::model_pack::ModelPackSetting;
use oneiron::settings::ModelStackPreference;
use oneiron::task_verb::sdk::EmptyRequest;

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_settings_model_pack(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<ModelPackSetting> {
    as_owner_naming(
        server,
        auth,
        "vault.settings.model_pack",
        |server, owner| Ok(server.vault().model_pack_setting_as_owner(owner)?),
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_settings_model_pack_replace(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelStackPreference,
) -> Listed<ModelPackSetting> {
    as_owner_naming(
        server,
        auth,
        "vault.settings.model_pack.replace",
        move |server, owner| {
            Ok(server
                .vault()
                .replace_model_pack_preference_as_owner(owner, input)?)
        },
        |_| Vec::new(),
    )
    .await
}
