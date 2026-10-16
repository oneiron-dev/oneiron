//! Exact, inert PACK.md source catalogs. A source blob is never an install grant.
mod advisories;
mod agent_facets;
mod builtin;
pub(crate) use builtin::seed_builtin_packs;
mod codec;
mod doors;
mod hooks;
mod hub_install;
mod local;
mod manifest;
mod migrations;
mod organs;
mod setup;
mod setup_cards;
mod setup_session;
mod source;

pub use crate::gate::PackInstallPolicyOverride;
pub use agent_facets::AgentPackFacets;
pub(crate) use codec::{decode as decode_source_body, validate_pack_source_put};
pub(crate) use hooks::is_hook_binding;
pub use hooks::{
    HookActorClass, HookOutcomeKind, HookPhase, HookRenderClass, HookSelector, PackHook,
    PackHookBinding,
};
pub use hub_install::hub_pin;
pub use local::LOCAL_PACK_NAME;
pub use manifest::{PackAdapter, PackKind, PackManifest};
pub use migrations::PackMigration;
pub use organs::{
    MAX_ORGAN_BUILD_BYTES, PackOrgan, PackOrganBinary, PackOrganBuild, PackOrganEntry, PackTree,
    host_platform,
};
pub use screening::PackInstallRules;
pub use setup::{
    MAX_SETUP_ACCOUNTS, MAX_SETUP_CONNECTIONS, MAX_SETUP_PERMISSIONS, MAX_SETUP_SECRETS, PackSetup,
    PackSetupAccount, PackSetupAuth, PackSetupConnection, PackSetupPermission, PackSetupRisk,
    PackSetupSecret,
};
pub use setup_cards::PackSetupCardAction;
pub use setup_session::{
    PackSetupAnswer, PackSetupCheck, PackSetupCheckRecord, PackSetupConnectionState,
    PackSetupCustodyRef, PackSetupGrantRef, PackSetupKeyRef, PackSetupPermissionState,
    PackSetupSecretState, PackSetupSession, PackSetupView,
};
pub(crate) use setup_session::{live_custody_in_txn, pin_connection_custody_in_txn};
pub use source::{PackSection, PackSource};

pub(crate) fn export_source_body(
    source: &PackSource,
) -> crate::error::Result<crate::serialize::ExportBody> {
    Ok(crate::serialize::ExportBody::from_bytes(
        &codec::encode(source)?,
        crate::registry::ENTITY_TYPE_ASSET,
    ))
}

#[cfg(test)]
mod tests;

fn invalid(reason: &'static str) -> crate::error::Error {
    crate::error::Error::InvalidConfig(format!("pack source: {reason}"))
}

mod admission;
mod admission_types;
mod bundled_skills;
mod qualify;
#[cfg(test)]
pub(in crate::skill_hub) use bundled_skills::pack_skill_hub_ref;
pub use qualify::{
    ConnectorPackQualification, PackConnectorReceipt, ProbePackQualifier, QualifiedPackFitPolicy,
    SetupCheckQualifier,
};
mod schema;
mod screening;
mod script_plan;
mod script_policy;
mod script_runtime;
mod tool_schema;
pub use admission_types::{
    BundledSkillPermissions, PackCandidateReason, PackFitPolicy, PackFitVerdict, PackInstallAsk,
    PackInstallDisposition, PackInstallReceipt, PackInstallStatus, PackObservedTool,
    PackPermissions, PackQualification, PackQualifier, PackRuntimeRecipe,
};
#[cfg(all(test, feature = "microvm-firecracker", target_os = "linux"))]
pub(crate) use script_plan::script_output_bytes;
pub use script_runtime::{PackScriptGrant, PackScriptOutcome, PackScriptRun};
#[cfg(test)]
mod admission_tests;
#[cfg(test)]
mod screening_tests;

mod transport;
pub use transport::PackSourceAdapter;
