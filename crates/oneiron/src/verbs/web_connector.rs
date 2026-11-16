//! Embedded-owner projection of the web connector's usage door (FIX 11598). Its switch is the
//! catalogue key `connectors.web`, read and set through `vault.settings.*`.
use crate::memory::{Memory, MemoryResult};
use crate::settings::web_connector::{WebConnectorUsagePage, WebConnectorUsageRead};

pub fn read_web_connector_usage(
    memory: &Memory<'_>,
    input: WebConnectorUsageRead,
) -> MemoryResult<WebConnectorUsagePage> {
    Ok(memory.vault().web_connector_usage_as_owner(
        &memory.embedded_owner("vault.connectors.web.usage")?,
        &input,
    )?)
}
