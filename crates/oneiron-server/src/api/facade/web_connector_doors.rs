//! Typed owner doors over the built-in web connector's switch and usage rows (FIX 11598).
use std::sync::Arc;

use oneiron::task_verb::sdk::EmptyRequest;
use oneiron::web_connector::{WebConnectorSetting, WebConnectorUsagePage, WebConnectorUsageRead};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_settings_web_connector(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<WebConnectorSetting> {
    as_owner_naming(
        server,
        auth,
        "vault.settings.web_connector",
        |server, owner| Ok(server.vault().web_connector_setting_as_owner(owner)?),
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_settings_web_connector_replace(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WebConnectorSetting,
) -> Listed<WebConnectorSetting> {
    as_owner_naming(
        server,
        auth,
        "vault.settings.web_connector.replace",
        move |server, owner| {
            Ok(server
                .vault()
                .replace_web_connector_setting_as_owner(owner, input)?)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_connectors_web_usage(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WebConnectorUsageRead,
) -> Listed<WebConnectorUsagePage> {
    as_owner_naming(
        server,
        auth,
        "vault.connectors.web.usage",
        move |server, owner| Ok(server.vault().web_connector_usage_as_owner(owner, &input)?),
        |_| Vec::new(),
    )
    .await
}
