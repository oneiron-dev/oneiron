//! Embedded-owner projection of the model-manifest and slot-route doors.
use crate::llm::manifest::ModelManifest;
use crate::llm::manifest::doors::{
    ModelManifestReplace, ModelRoleRead, ModelRoleReceipt, ModelRouteRead, ModelRouteReplace,
    ModelRouteView,
};
use crate::memory::{Memory, MemoryResult};

pub fn read_model_manifest(memory: &Memory<'_>) -> MemoryResult<Option<ModelManifest>> {
    Ok(memory
        .vault()
        .model_manifest_as_owner(&memory.embedded_owner("vault.models.manifest.read")?)?)
}

pub fn replace_model_manifest(
    memory: &Memory<'_>,
    input: ModelManifestReplace,
) -> MemoryResult<ModelManifest> {
    Ok(memory.vault().replace_model_manifest_as_owner(
        &memory.embedded_owner("vault.models.manifest.replace")?,
        input,
    )?)
}

pub fn read_model_route(
    memory: &Memory<'_>,
    input: ModelRouteRead,
) -> MemoryResult<ModelRouteView> {
    Ok(memory
        .vault()
        .model_route_as_owner(&memory.embedded_owner("vault.models.routes.read")?, input)?)
}

pub fn replace_model_route(
    memory: &Memory<'_>,
    input: ModelRouteReplace,
) -> MemoryResult<ModelRouteView> {
    Ok(memory.vault().replace_model_route_as_owner(
        &memory.embedded_owner("vault.models.routes.replace")?,
        input,
    )?)
}

pub fn read_model_role(
    memory: &Memory<'_>,
    input: ModelRoleRead,
) -> MemoryResult<ModelRoleReceipt> {
    Ok(memory
        .vault()
        .model_role_as_owner(&memory.embedded_owner("vault.models.roles.read")?, input)?)
}
