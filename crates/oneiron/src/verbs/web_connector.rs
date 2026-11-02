//! Embedded-owner projection of the web connector's switch and usage doors (FIX 11598).
use crate::memory::{Memory, MemoryResult};
use crate::web_connector::{WebConnectorSetting, WebConnectorUsagePage, WebConnectorUsageRead};

pub fn read_web_connector_setting(memory: &Memory<'_>) -> MemoryResult<WebConnectorSetting> {
    Ok(memory
        .vault()
        .web_connector_setting_as_owner(&memory.embedded_owner("vault.settings.web_connector")?)?)
}

pub fn replace_web_connector_setting(
    memory: &Memory<'_>,
    input: WebConnectorSetting,
) -> MemoryResult<WebConnectorSetting> {
    Ok(memory.vault().replace_web_connector_setting_as_owner(
        &memory.embedded_owner("vault.settings.web_connector.replace")?,
        input,
    )?)
}

pub fn read_web_connector_usage(
    memory: &Memory<'_>,
    input: WebConnectorUsageRead,
) -> MemoryResult<WebConnectorUsagePage> {
    Ok(memory.vault().web_connector_usage_as_owner(
        &memory.embedded_owner("vault.connectors.web.usage")?,
        &input,
    )?)
}
