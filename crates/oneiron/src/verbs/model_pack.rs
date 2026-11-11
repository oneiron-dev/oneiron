//! Embedded-owner projection of the model pack setting doors (FIX 5367) and
//! the pack change revert (FIX 5369).
use crate::llm::model_pack::{ModelPackRevert, ModelPackRevertRequest, ModelPackSetting};
use crate::memory::{Memory, MemoryResult};
use crate::settings::model_pack::ModelPackPreference;

pub fn read_model_pack_setting(memory: &Memory<'_>) -> MemoryResult<ModelPackSetting> {
    Ok(memory
        .vault()
        .model_pack_setting_as_owner(&memory.embedded_owner("vault.settings.model_pack")?)?)
}

pub fn replace_model_pack_preference(
    memory: &Memory<'_>,
    input: ModelPackPreference,
) -> MemoryResult<ModelPackSetting> {
    Ok(memory.vault().replace_model_pack_preference_as_owner(
        &memory.embedded_owner("vault.settings.model_pack.replace")?,
        input,
    )?)
}

pub fn revert_model_pack(
    memory: &Memory<'_>,
    input: ModelPackRevertRequest,
) -> MemoryResult<ModelPackRevert> {
    Ok(memory.vault().revert_model_pack_change_as_owner(
        &memory.embedded_owner("vault.model_pack.revert")?,
        &input,
    )?)
}
