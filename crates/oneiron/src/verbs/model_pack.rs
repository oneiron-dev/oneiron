//! Embedded-owner projection of the model pack setting read (FIX 5367) and
//! the pack change revert (FIX 5369). The owner sets the preference through
//! `vault.settings.set` of `models.pack_preference`.
use crate::llm::model_pack::{ModelPackRevert, ModelPackRevertRequest, ModelPackSetting};
use crate::memory::{Memory, MemoryResult};

pub fn read_model_pack_setting(memory: &Memory<'_>) -> MemoryResult<ModelPackSetting> {
    Ok(memory
        .vault()
        .model_pack_setting_as_owner(&memory.embedded_owner("vault.settings.model_pack")?)?)
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
