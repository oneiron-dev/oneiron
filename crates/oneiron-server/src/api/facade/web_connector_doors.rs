//! Typed owner door over the built-in web connector's usage rows (FIX 11598). Its switch is the
//! catalogue key `connectors.web`, served by `vault.settings.*`.
use std::sync::Arc;

use oneiron::web_connector::{WebConnectorUsagePage, WebConnectorUsageRead};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

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
