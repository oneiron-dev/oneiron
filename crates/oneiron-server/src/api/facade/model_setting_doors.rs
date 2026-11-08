//! Field-specific owner doors for the host's Responses store setting.

use std::sync::Arc;

use oneiron::memory::MemoryError;
use oneiron::task_verb::sdk::{EmptyRequest, ModelResponsesStoreSettings};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_settings_models_responses_store_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<ModelResponsesStoreSettings> {
    as_owner_naming(
        server,
        auth,
        "vault.settings.models.responses_store.read",
        |server, _owner| {
            Ok(ModelResponsesStoreSettings {
                responses_store: server
                    .vault()
                    .responses_store()
                    .map_err(MemoryError::from)?,
            })
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_settings_models_responses_store_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelResponsesStoreSettings,
) -> Listed<ModelResponsesStoreSettings> {
    as_owner_naming(
        server,
        auth,
        "vault.settings.models.responses_store.set",
        move |server, owner| {
            server
                .apply_responses_store(owner, input.responses_store)
                .map_err(MemoryError::from)?;
            Ok(input)
        },
        |_| Vec::new(),
    )
    .await
}
