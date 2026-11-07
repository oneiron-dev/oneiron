//! Embedded-owner projection of the model pack setting doors (FIX 5367).
use crate::llm::model_pack::ModelPackSetting;
use crate::memory::{Memory, MemoryResult};
use crate::settings::ModelStackPreference;

pub fn read_model_pack_setting(memory: &Memory<'_>) -> MemoryResult<ModelPackSetting> {
    Ok(memory
        .vault()
        .model_pack_setting_as_owner(&memory.embedded_owner("vault.settings.model_pack")?)?)
}

pub fn replace_model_pack_preference(
    memory: &Memory<'_>,
    input: ModelStackPreference,
) -> MemoryResult<ModelPackSetting> {
    Ok(memory.vault().replace_model_pack_preference_as_owner(
        &memory.embedded_owner("vault.settings.model_pack.replace")?,
        input,
    )?)
}
